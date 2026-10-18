package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bpf"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/hsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/lsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/pqc"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/remediate"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/replication"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sandbox"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sbom"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/webhook"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgenclave"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgfastpath"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

// BriefingOptions defines the parameters for generating an hourly threat briefing.
type BriefingOptions struct {
	Title                   string
	Version                 string
	HourlyWindow            time.Time
	Feed                    *intel.Feed
	K8sReport               *k8s.ManifestAuditReport
	FlakeMatches            []nix.FlakeVulnerabilityMatch
	ProbeEvents             []probe.TelemetryEvent
	StorageViolations       []storage.StorageViolation
	StorageHealth           *storage.CephHealthReport
	WireGuardViolations     []wireguard.WireGuardViolation
	WireGuardReconciliation *wireguard.ReconciliationReport
	CISViolations           []bench.CISViolation
	CISSummary              *bench.CISSummary
	GatewayViolations       []gateway.GatewayViolation
	GatewaySummary          *gateway.GatewaySummary
	AttestViolations        []attest.AttestationViolation
	AttestSummary           *attest.AttestationSummary
	FleetViolations         []fleet.FleetViolation
	FleetSummary            *fleet.FleetSummary
	SPIFFEViolations        []spiffe.SPIFFEViolation
	SPIFFESummary           *spiffe.SPIFFESummary
	SBOMViolations          []sbom.SBOMViolation
	SBOMSummary             *sbom.SBOMSummary
	SBOMDelta               []sbom.SBOMDeltaItem
	HSMViolations           []hsm.HSMViolation
	HSMSummary              *hsm.HSMSummary
	BPFViolations           []bpf.BPFViolation
	BPFSummary              *bpf.BPFSummary
	PQCViolations           []pqc.PQCViolation
	PQCSummary              *pqc.PQCSummary
	SandboxViolations       []sandbox.SandboxViolation
	SandboxSummary          *sandbox.SandboxSummary
	RemediateFindings       []remediate.RemediationFinding
	RemediatePullRequests   []remediate.GitOpsPullRequest
	RemediateSummary        *remediate.RemediationSummary
	LSMViolations           []lsm.LSMViolation
	LSMSummary              *lsm.LSMSummary
	ReplicationViolations   []replication.ReplicationViolation
	ReplicationSummary      *replication.ReplicationSummary
	FastPathViolations      []wgfastpath.WGFastPathViolation
	FastPathSummary         *wgfastpath.WGFastPathSummary
	FastPathTelemetry       []wgfastpath.FastPathTelemetry
	EnclaveViolations       []wgenclave.WGEnclaveViolation
	EnclaveSummary          *wgenclave.WGEnclaveSummary
	EnclaveReports          []wgenclave.AttestationReport
	WebhookViolations       []webhook.WebhookViolation
	WebhookSummary          *webhook.WebhookSummary
	WebhookTelemetry        *webhook.WebhookTelemetry
	OutputDir               string
	CustomFilename          string
}

// BriefingReport represents a generated Markdown briefing and its associated metadata.
type BriefingReport struct {
	Title       string
	Window      time.Time
	Telemetry   TelemetrySummary
	Content     string
	FilePath    string
	GeneratedAt time.Time
}

// GenerateBriefing synthesizes an hourly threat intelligence briefing report in Markdown.
func GenerateBriefing(opts BriefingOptions) (*BriefingReport, error) {
	now := time.Now().UTC()
	window := opts.HourlyWindow.UTC()
	if window.IsZero() {
		window = now.Truncate(time.Hour)
	}

	title := opts.Title
	if title == "" {
		title = fmt.Sprintf("Cloud-Native Threat Intelligence Briefing (%s UTC)", window.Format("2006-01-02 15:00"))
	}

	version := opts.Version
	if version == "" {
		version = "0.24.0"
	}

	telemetry := ComputeTelemetryWebhook(opts.Feed, opts.K8sReport, opts.FlakeMatches, opts.StorageViolations, opts.WireGuardViolations, opts.CISViolations, opts.GatewayViolations, opts.AttestViolations, opts.FleetViolations, opts.SPIFFEViolations, opts.SBOMViolations, opts.HSMViolations, opts.BPFViolations, opts.PQCViolations, opts.SandboxViolations, opts.RemediateFindings, opts.LSMViolations, opts.ReplicationViolations, opts.FastPathViolations, opts.EnclaveViolations, opts.WebhookViolations)

	var buf bytes.Buffer

	// 1. Header & Metadata
	buf.WriteString(fmt.Sprintf("# %s\n\n", title))
	buf.WriteString("> [!IMPORTANT]\n")
	buf.WriteString(fmt.Sprintf("> **Generated:** %s | **Window:** %s UTC | **Sentinel Engine:** v%s\n\n",
		now.Format("2006-01-02 15:04:05 UTC"),
		window.Format("2006-01-02 15:00"),
		version,
	))
	buf.WriteString("---\n\n")

	// 2. Executive Telemetry Summary
	buf.WriteString("## 📊 Executive Telemetry Matrix\n\n")
	buf.WriteString(fmt.Sprintf("This hourly threat intelligence briefing aggregates active CVE disclosures affecting **NixOS bare-metal host layers** and **Kubernetes orchestration environments**.\n\n"))

	buf.WriteString("| CVSS Severity Tier | Advisory Count | Threshold Range | Operational Action Posture |\n")
	buf.WriteString("| :--- | :---: | :---: | :--- |\n")
	buf.WriteString(fmt.Sprintf("| **CRITICAL** | **%d** | CVSS 9.0 – 10.0 | Immediate zero-day mitigation & hotfix rollout |\n", telemetry.CriticalCount))
	buf.WriteString(fmt.Sprintf("| **HIGH** | **%d** | CVSS 7.0 – 8.9 | Expedited patching within active maintenance window |\n", telemetry.HighCount))
	buf.WriteString(fmt.Sprintf("| **MEDIUM** | **%d** | CVSS 4.0 – 6.9 | Planned hardening and defense-in-depth policy |\n", telemetry.MediumCount))
	buf.WriteString(fmt.Sprintf("| **LOW** | **%d** | CVSS 0.1 – 3.9 | Routine review during scheduled sprint release |\n\n", telemetry.LowCount))

	buf.WriteString("### 🎯 Risk Exposure Breakdown\n\n")
	buf.WriteString(fmt.Sprintf("- **Total Monitored Advisories:** `%d`\n", telemetry.TotalThreats))
	buf.WriteString(fmt.Sprintf("- **Peak CVSS Score:** `%.1f / 10.0`\n", telemetry.MaxCVSS))
	buf.WriteString(fmt.Sprintf("- **Fleet Average CVSS:** `%.1f / 10.0`\n", telemetry.AverageCVSS))
	if telemetry.TotalViolations > 0 {
		buf.WriteString(fmt.Sprintf("- **Active Kubernetes Manifest Violations:** `%d`\n", telemetry.TotalViolations))
	}
	if telemetry.TotalFlakeMatches > 0 {
		buf.WriteString(fmt.Sprintf("- **Vulnerable Nix Flake Inputs:** `%d`\n", telemetry.TotalFlakeMatches))
	}
	buf.WriteString("\n")

	// Distribution Sub-tables
	if len(telemetry.TargetDistribution) > 0 {
		buf.WriteString("#### Target Architecture Distribution\n\n")
		buf.WriteString("| Target Infrastructure | Advisory Count | Share Ratio |\n")
		buf.WriteString("| :--- | :---: | :---: |\n")
		for _, target := range SortedMapKeys(telemetry.TargetDistribution) {
			count := telemetry.TargetDistribution[target]
			ratio := 0.0
			if telemetry.TotalThreats > 0 {
				ratio = float64(count) / float64(telemetry.TotalThreats) * 100
			}
			buf.WriteString(fmt.Sprintf("| `%s` | %d | %.1f%% |\n", target, count, ratio))
		}
		buf.WriteString("\n")
	}

	if len(telemetry.ComponentDistribution) > 0 {
		buf.WriteString("#### Impacted Component Radar\n\n")
		buf.WriteString("| Software Component | Advisories | Severity Vector |\n")
		buf.WriteString("| :--- | :---: | :--- |\n")
		for _, comp := range SortedMapKeys(telemetry.ComponentDistribution) {
			count := telemetry.ComponentDistribution[comp]
			buf.WriteString(fmt.Sprintf("| `%s` | %d | Monitored |\n", comp, count))
		}
		buf.WriteString("\n")
	}

	buf.WriteString("---\n\n")

	// 3. Active Threat Feed Advisories
	buf.WriteString("## 🛡️ Active Threat Intelligence Advisories\n\n")
	if opts.Feed != nil && len(opts.Feed.Items) > 0 {
		// Sort items by CVSS score descending
		sortedItems := make([]intel.ThreatItem, len(opts.Feed.Items))
		copy(sortedItems, opts.Feed.Items)
		sort.Slice(sortedItems, func(i, j int) bool {
			return sortedItems[i].CVSSScore > sortedItems[j].CVSSScore
		})

		for idx, item := range sortedItems {
			buf.WriteString(fmt.Sprintf("### %d. [%s] %s (%s)\n\n", idx+1, item.ID, item.Title, item.Severity))
			buf.WriteString(fmt.Sprintf("- **Component:** `%s` (Target: `%s`)\n", item.Component, item.Target))
			buf.WriteString(fmt.Sprintf("- **Base CVSS Score:** `%.1f` (`%s`)\n", item.CVSSScore, SeverityBadge(string(item.Severity))))
			buf.WriteString(fmt.Sprintf("- **Published At:** `%s`\n\n", item.PublishedAt.Format("2006-01-02 15:04:05 UTC")))
			buf.WriteString(fmt.Sprintf("**Threat Vector & Technical Impact:**\n%s\n\n", item.Description))
			buf.WriteString(fmt.Sprintf("**Mitigation & Hardening Playbook:**\n%s\n\n", item.Mitigation))
		}
	} else {
		buf.WriteString("_No active threat intelligence advisories loaded._\n\n")
	}

	buf.WriteString("---\n\n")

	// 4. Kubernetes Manifest Findings (if applicable)
	if opts.K8sReport != nil {
		buf.WriteString("## ☸️ Kubernetes Manifest Static Audit Findings\n\n")
		buf.WriteString(fmt.Sprintf("Scanned **%d** manifest files across **%d** declarative resources.\n\n",
			opts.K8sReport.TotalFiles, opts.K8sReport.TotalResources))

		if len(opts.K8sReport.Violations) == 0 {
			buf.WriteString("✅ **Zero security policy violations detected** in scanned Kubernetes manifests.\n\n")
		} else {
			buf.WriteString(fmt.Sprintf("⚠️ **%d security violations identified:**\n\n", len(opts.K8sReport.Violations)))
			buf.WriteString("| # | Rule ID | Severity | Target Resource | Matched CVE | Description |\n")
			buf.WriteString("| :-: | :--- | :---: | :--- | :---: | :--- |\n")
			for i, v := range opts.K8sReport.Violations {
				matched := "-"
				if v.MatchedCVE != "" {
					matched = fmt.Sprintf("`%s`", v.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| %d | `%s` | **%s** | `%s/%s` | %s | %s |\n",
					i+1, v.RuleID, v.Severity, v.ResourceKind, v.ResourceName, matched, v.Title))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 5. Nix Flake Lockfile Dependency Findings (if applicable)
	if len(opts.FlakeMatches) > 0 {
		buf.WriteString("## ❄️ NixOS Flake Input Dependency Findings\n\n")
		buf.WriteString(fmt.Sprintf("⚠️ **%d vulnerable flake input dependencies identified:**\n\n", len(opts.FlakeMatches)))
		buf.WriteString("| Input Name | Node Key | Installed Rev | Advisory ID | Severity | Mitigation |\n")
		buf.WriteString("| :--- | :--- | :--- | :--- | :---: | :--- |\n")
		for _, m := range opts.FlakeMatches {
			revShort := m.InstalledRev
			if len(revShort) > 12 {
				revShort = revShort[:12]
			}
			buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | **%s** | %s |\n",
				m.DependencyName, m.NodeKey, revShort, m.AdvisoryID, m.Severity, m.Mitigation))
		}
		buf.WriteString("\n---\n\n")
	}

	// 6. Bare-Metal eBPF Kernel Telemetry Findings (if applicable)
	if len(opts.ProbeEvents) > 0 {
		buf.WriteString("## 🔬 Bare-Metal eBPF Kernel Telemetry Findings\n\n")
		buf.WriteString(fmt.Sprintf("⚠️ **%d kernel-level runtime telemetry events captured:**\n\n", len(opts.ProbeEvents)))
		buf.WriteString("| Event ID | Node | Type | Comm | Syscall / Action | Severity | Risk | Message |\n")
		buf.WriteString("| :--- | :--- | :---: | :--- | :--- | :---: | :---: | :--- |\n")
		for _, ev := range opts.ProbeEvents {
			action := ev.EventType
			if ev.Syscall != "" {
				action = fmt.Sprintf("%s (`%s`)", ev.EventType, ev.Syscall)
			}
			buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | %s | **%s** | %.1f | %s |\n",
				ev.ID, ev.NodeName, ev.ProbeType, ev.Comm, action, ev.Severity, ev.RiskScore, ev.Message))
		}
		buf.WriteString("\n---\n\n")
	}

	// 7. Rook Ceph Distributed Storage Integrity Findings (if applicable)
	if len(opts.StorageViolations) > 0 || opts.StorageHealth != nil {
		buf.WriteString("## 🗄️ Rook Ceph Distributed Storage Integrity\n\n")
		if opts.StorageHealth != nil {
			buf.WriteString(fmt.Sprintf("**Cluster Status:** `%s` | **Mon Quorum:** %d monitors | **OSDs:** %d up / %d total | **PGs:** %d active+clean / %d total\n\n",
				opts.StorageHealth.Status, len(opts.StorageHealth.MonQuorum), opts.StorageHealth.OSDStats.Up, opts.StorageHealth.OSDStats.Total, opts.StorageHealth.PGStats.ActiveClean, opts.StorageHealth.PGStats.Total))
		}
		if len(opts.StorageViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d storage cluster integrity violations detected:**\n\n", len(opts.StorageViolations)))
			buf.WriteString("| Rule ID | Resource | Severity | CVSS | Finding & Impact | Remediation Playbook |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, sv := range opts.StorageViolations {
				cveTag := ""
				if sv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", sv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s/%s` | **%s** | %.1f | %s%s | %s |\n",
					sv.RuleID, sv.ResourceKind, sv.ResourceName, sv.Severity, sv.CVSSScore, sv.Description, cveTag, sv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 8. WireGuard Cryptographic Mesh & Peer Posture (if applicable)
	if len(opts.WireGuardViolations) > 0 || opts.WireGuardReconciliation != nil {
		buf.WriteString("## 🔐 WireGuard Cryptographic Mesh & Peer Posture\n\n")
		if opts.WireGuardReconciliation != nil {
			rec := opts.WireGuardReconciliation
			buf.WriteString(fmt.Sprintf("**Mesh Interfaces:** %d | **Declared Peers:** %d | **Runtime Peers:** %d | **Unmanaged Peers:** %d | **Stale Handshakes:** %d\n",
				rec.InterfaceCount, rec.DeclarativePeersCount, rec.RuntimePeersCount, rec.UnmanagedPeersCount, rec.StaleHandshakeCount))
			buf.WriteString(fmt.Sprintf("**Key Rotation Posture:** %d Active / %d Needs Rotation / %d Expired (Oldest Key: %d days)\n\n",
				rec.KeyRotation.ActiveKeys, rec.KeyRotation.NeedsRotationKeys, rec.KeyRotation.ExpiredKeys, rec.KeyRotation.OldestKeyAgeDays))
		}
		if len(opts.WireGuardViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d WireGuard cryptographic mesh violations detected:**\n\n", len(opts.WireGuardViolations)))
			buf.WriteString("| Rule ID | Interface / Target | Severity | CVSS | Finding & Threat Details | Remediation Playbook |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, wv := range opts.WireGuardViolations {
				cveTag := ""
				if wv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", wv.MatchedCVE)
				}
				target := wv.InterfaceName
				if wv.PeerPublicKey != "" {
					target = fmt.Sprintf("%s / `%s`", wv.InterfaceName, wv.PeerPublicKey)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | %s | **%s** | %.1f | %s%s | %s |\n",
					wv.RuleID, target, wv.Severity, wv.CVSSScore, wv.Description, cveTag, wv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 9. CIS Kubernetes Benchmark Posture (if applicable)
	if len(opts.CISViolations) > 0 || opts.CISSummary != nil {
		buf.WriteString("## 🛡️ CIS Kubernetes Benchmark Compliance Posture\n\n")
		if opts.CISSummary != nil {
			sum := opts.CISSummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Passed:** %d | **Failed:** %d | **Total Evaluated:** %d\n",
				sum.ComplianceScore, sum.PassedChecks, sum.FailedChecks, sum.TotalChecks))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.CISViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d CIS benchmark configuration violations identified:**\n\n", len(opts.CISViolations)))
			buf.WriteString("| Rule ID | Section | Component | Flag | Severity | CVSS | Current vs Expected | Remediation Action |\n")
			buf.WriteString("| :--- | :---: | :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, cv := range opts.CISViolations {
				cveTag := ""
				if cv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", cv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | `%s` | **%s** | %.1f | `%s` (want: `%s`)%s | %s |\n",
					cv.RuleID, cv.Section, cv.Component, cv.FlagName, cv.Severity, cv.CVSSScore, cv.ActualValue, cv.ExpectedValue, cveTag, cv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 10. Kubernetes Gateway API & EnvoyFilter Route Threat Radar Posture (if applicable)
	if len(opts.GatewayViolations) > 0 || opts.GatewaySummary != nil {
		buf.WriteString("## 🌐 Kubernetes Gateway API & EnvoyFilter Route Threat Radar\n\n")
		if opts.GatewaySummary != nil {
			sum := opts.GatewaySummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Passed:** %d | **Failed:** %d | **Total Evaluated:** %d\n",
				sum.ComplianceScore, sum.PassedChecks, sum.TotalChecks-sum.PassedChecks, sum.TotalChecks))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.GatewayViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d Gateway API and EnvoyFilter routing violations identified:**\n\n", len(opts.GatewayViolations)))
			buf.WriteString("| Rule ID | Resource | Namespace | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :---: | :--- | :--- |\n")
			for _, gv := range opts.GatewayViolations {
				cveTag := ""
				if gv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", gv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s/%s` | `%s` | **%s** | %.1f | %s%s | %s |\n",
					gv.RuleID, gv.ResourceKind, gv.ResourceName, gv.Namespace, gv.Severity, gv.CVSSScore, gv.Message, cveTag, gv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 11. Confidential Computing & Measured Boot Attestation Posture (if applicable)
	if len(opts.AttestViolations) > 0 || opts.AttestSummary != nil {
		buf.WriteString("## 🔒 Confidential Computing & Measured Boot Attestation Posture\n\n")
		if opts.AttestSummary != nil {
			sum := opts.AttestSummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Attested Nodes:** %d | **Verified Safe:** %d\n",
				sum.ComplianceScore, sum.NodesAttested, sum.NodesVerified))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.AttestViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d Confidential Computing & Measured Boot anomalies identified:**\n\n", len(opts.AttestViolations)))
			buf.WriteString("| Rule ID | Technology | Target | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, av := range opts.AttestViolations {
				cveTag := ""
				if av.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", av.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | **%s** | %.1f | %s%s | %s |\n",
					av.RuleID, av.Technology, av.Target, av.Severity, av.CVSSScore, av.Message, cveTag, av.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 12. Multi-Cluster Fleet Synchronization & OIDC Token Radar Posture (if applicable)
	if len(opts.FleetViolations) > 0 || opts.FleetSummary != nil {
		buf.WriteString("## 🛰️ Multi-Cluster Fleet Synchronization & OIDC Token Radar\n\n")
		if opts.FleetSummary != nil {
			sum := opts.FleetSummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Clusters Audited:** %d | **In Sync:** %d | **Drifting Apps:** %d | **OIDC Tokens Verified:** %d\n",
				sum.ComplianceScore, sum.ClustersAudited, sum.ClustersInSync, sum.DriftingApps, sum.OIDCTokensVerified))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.FleetViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d Multi-Cluster fleet and OIDC identity violations identified:**\n\n", len(opts.FleetViolations)))
			buf.WriteString("| Rule ID | Category | Resource | Cluster | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :--- |\n")
			for _, fv := range opts.FleetViolations {
				cveTag := ""
				if fv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", fv.MatchedCVE)
				}
				clusterTag := fv.ClusterID
				if clusterTag == "" {
					clusterTag = "fleet-wide"
				}
				buf.WriteString(fmt.Sprintf("| `%s` | %s | `%s/%s` | `%s` | **%s** | %.1f | %s%s | %s |\n",
					fv.RuleID, fv.Category, fv.ResourceKind, fv.ResourceName, clusterTag, fv.Severity, fv.CVSSScore, fv.Message, cveTag, fv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 13. Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation Posture (if applicable)
	if len(opts.SPIFFEViolations) > 0 || opts.SPIFFESummary != nil {
		buf.WriteString("## 🛡️ Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation\n\n")
		if opts.SPIFFESummary != nil {
			sum := opts.SPIFFESummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **SVIDs Audited:** %d | **Valid:** %d | **Expired / Near-Expiry:** %d | **Policies Synthesized:** %d\n",
				sum.ComplianceScore, sum.SVIDsAudited, sum.SVIDsValid, sum.SVIDsExpiredOrNearExpiry, sum.CiliumPoliciesSynthesized))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.SPIFFEViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d SPIFFE/SPIRE workload attestation and Cilium microsegmentation violations identified:**\n\n", len(opts.SPIFFEViolations)))
			buf.WriteString("| Rule ID | Category | Workload / Resource | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, sv := range opts.SPIFFEViolations {
				cveTag := ""
				if sv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", sv.MatchedCVE)
				}
				targetTag := sv.ResourceName
				if sv.Workload != "" {
					targetTag = sv.Workload
				}
				buf.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | **%s** | %.1f | %s%s | %s |\n",
					sv.RuleID, sv.Category, targetTag, sv.Severity, sv.CVSSScore, sv.Message, cveTag, sv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 14. Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation
	if opts.SBOMSummary != nil || len(opts.SBOMViolations) > 0 || len(opts.SBOMDelta) > 0 {
		buf.WriteString("## 📦 Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation\n\n")
		if opts.SBOMSummary != nil {
			buf.WriteString("| Evaluated Metric | Value | Security Posture Threshold |\n")
			buf.WriteString("| :--- | :---: | :--- |\n")
			buf.WriteString(fmt.Sprintf("| Total SBOM Packages Audited | **%d** | Baseline component coverage |\n", opts.SBOMSummary.TotalPackages))
			buf.WriteString(fmt.Sprintf("| Evaluated SLSA Provenance Level | **%s** | Mandatory Level 3 for production deployments |\n", opts.SBOMSummary.EvaluatedSLSALevel))
			attestStatus := "Verified"
			if !opts.SBOMSummary.AttestationVerified {
				attestStatus = "Unverified / Missing"
			}
			buf.WriteString(fmt.Sprintf("| In-Toto Envelope Signature | **%s** | Cryptographic envelope integrity |\n", attestStatus))
			buf.WriteString(fmt.Sprintf("| Drifting Packages (Version/Hash) | **%d** | Zero-drift invariant |\n", opts.SBOMSummary.DriftingPackages))
			buf.WriteString(fmt.Sprintf("| Undeclared Shadow Packages | **%d** | Zero-undeclared container invariant |\n", opts.SBOMSummary.UndeclaredPackages))
			buf.WriteString(fmt.Sprintf("| Supply Chain Compliance Score | **%.1f%%** | >= 80.0%% minimum passing grade |\n\n", opts.SBOMSummary.ComplianceScore))
		}

		if len(opts.SBOMDelta) > 0 {
			buf.WriteString("### Declarative vs. Runtime Cluster Package Delta\n\n")
			buf.WriteString("| Package Name | Declared Version | Runtime Version | Reconciliation Status | Operational Impact |\n")
			buf.WriteString("| :--- | :---: | :---: | :---: | :--- |\n")
			for _, delta := range opts.SBOMDelta {
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | **%s** | %s |\n",
					delta.PackageName, delta.DeclaredVersion, delta.RuntimeVersion, delta.Status, delta.SecurityImpact))
			}
			buf.WriteString("\n")
		}

		if len(opts.SBOMViolations) > 0 {
			buf.WriteString("### Supply Chain Security Violations\n\n")
			buf.WriteString("| Rule ID | Component / Target | Severity | Finding Description | Remediation Advisory |\n")
			buf.WriteString("| :--- | :--- | :---: | :--- | :--- |\n")
			for _, v := range opts.SBOMViolations {
				cveStr := ""
				if v.MatchedCVE != "" {
					cveStr = fmt.Sprintf(" (%s)", v.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s%s | %s |\n",
					v.RuleID, v.PackageName, SeverityBadge(string(v.Severity)), v.Description, cveStr, v.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 15. Hardware Security Module (HSM) & PKCS#11 Envelope Encryption Posture
	if opts.HSMSummary != nil || len(opts.HSMViolations) > 0 {
		buf.WriteString("## 🔐 Hardware Security Module (HSM) & PKCS#11 Envelope Encryption\n\n")
		if opts.HSMSummary != nil {
			sum := opts.HSMSummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Configs Scanned:** %d | **Keys Audited:** %d | **Status:** `%s`\n",
				sum.ComplianceScore, sum.TotalConfigsScanned, sum.TotalKeysAudited, sum.AuditStatus))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.HSMViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d HSM, PKCS#11, and KMS v2 envelope encryption violations identified:**\n\n", len(opts.HSMViolations)))
			buf.WriteString("| Rule ID | Provider / Resource | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, hv := range opts.HSMViolations {
				cveTag := ""
				if hv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", hv.MatchedCVE)
				}
				targetTag := hv.ProviderName
				if targetTag == "" {
					targetTag = filepath.Base(hv.ResourceURI)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | **%s** | %.1f | %s%s | %s |\n",
					hv.RuleID, targetTag, hv.Severity, hv.CVSSScore, hv.Description, cveTag, hv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 16. Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter Posture
	if opts.BPFSummary != nil || len(opts.BPFViolations) > 0 {
		buf.WriteString("## 🛡️ Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter\n\n")
		if opts.BPFSummary != nil {
			sum := opts.BPFSummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Profiles Scanned:** %d | **Telemetry Events:** %d | **Status:** `%s`\n",
				sum.ComplianceScore, sum.TotalProfilesScanned, sum.TotalTelemetryEvents, sum.AuditStatus))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.BPFViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d Kernel runtime threat profiling and seccomp violations identified:**\n\n", len(opts.BPFViolations)))
			buf.WriteString("| Rule ID | Workload / Resource | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, bv := range opts.BPFViolations {
				cveTag := ""
				if bv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", bv.MatchedCVE)
				}
				targetTag := bv.WorkloadName
				if targetTag == "" {
					targetTag = filepath.Base(bv.ResourceURI)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | **%s** | %.1f | %s%s | %s |\n",
					bv.RuleID, targetTag, bv.Severity, bv.CVSSScore, bv.Description, cveTag, bv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 17. Post-Quantum Cryptography (PQC) & CNSA 2.0 Cryptographic Readiness
	if len(opts.PQCViolations) > 0 || opts.PQCSummary != nil {
		buf.WriteString("## ⚛️ Post-Quantum Cryptography (PQC) & CNSA 2.0 Cryptographic Readiness\n\n")
		if opts.PQCSummary != nil {
			sum := opts.PQCSummary
			buf.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` | **Status:** `%s` | **Hybrid KEM Handshakes:** `%.1f%%` | **TLS 1.3:** `%.1f%%`\n",
				sum.CNSAComplianceScore, sum.AuditStatus, sum.HybridKEMPercentage, sum.TLS13Percentage))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.PQCViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d Post-Quantum cryptography and TLS protocol violations identified:**\n\n", len(opts.PQCViolations)))
			buf.WriteString("| Rule ID | Component | Resource | Severity | CVSS | Finding & Threat Impact | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, pv := range opts.PQCViolations {
				cveTag := ""
				if pv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", pv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | **%s** | %.1f | %s%s | %s |\n",
					pv.RuleID, pv.Component, pv.Resource, pv.Severity, pv.CVSSScore, pv.Description, cveTag, pv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 18. Ephemeral MicroVM Sandbox Detonation & Honeypot Telemetry (if applicable)
	if len(opts.SandboxViolations) > 0 || opts.SandboxSummary != nil {
		buf.WriteString("## 🔬 Ephemeral MicroVM Sandbox Detonation & Honeypot Telemetry\n\n")
		if opts.SandboxSummary != nil {
			sum := opts.SandboxSummary
			buf.WriteString(fmt.Sprintf("**Sandbox Security Score:** `%.1f%%` | **Status:** `%s` | **Detonations:** %d | **Honeypot Hits:** %d | **Quarantined:** %d\n",
				sum.SandboxSecurityScore, sum.AuditStatus, sum.TotalDetonations, sum.TotalHoneypotHits, sum.QuarantinedCount))
			buf.WriteString(fmt.Sprintf("**MicroVMs Scanned:** %d | **Clean:** %d | **Violations:** %d\n\n",
				sum.TotalMicroVMsScanned, sum.CleanCount, sum.ViolationsCount))
		}
		if len(opts.SandboxViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d Ephemeral MicroVM sandbox and honeypot detonation anomalies identified:**\n\n", len(opts.SandboxViolations)))
			buf.WriteString("| Rule ID | Target | Severity | CVSS | Title & Description | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :--- |\n")
			for _, sv := range opts.SandboxViolations {
				cveTag := ""
				if sv.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" (`%s`)", sv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | **%s** | %.1f | %s%s: %s | %s |\n",
					sv.RuleID, sv.Target, sv.Severity, sv.CVSSScore, sv.Title, cveTag, sv.Description, sv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 19. Autonomous Threat Remediation & GitOps Pull Request Posture (if applicable)
	if len(opts.RemediateFindings) > 0 || opts.RemediateSummary != nil || len(opts.RemediatePullRequests) > 0 {
		buf.WriteString("## 🤖 Autonomous Threat Remediation & GitOps Pull Request Posture\n\n")
		if opts.RemediateSummary != nil {
			sum := opts.RemediateSummary
			buf.WriteString(fmt.Sprintf("**Remediation Score:** `%.1f%%` | **Status:** `%s` | **Findings Remediated:** %d\n",
				sum.RemediationScore, sum.Status, sum.TotalFindings))
			buf.WriteString(fmt.Sprintf("**NixOS Patches:** %d | **Kustomize Overlays:** %d | **Canary Checks:** %d (Passed: %d, Failed: %d) | **PRs Synthesized:** %d\n\n",
				sum.NixOSPatchCount, sum.KustomizePatchCount, sum.CanaryChecksTotal, sum.CanaryPassedCount, sum.CanaryFailedCount, sum.PullRequestsSynthesized))
		}
		if len(opts.RemediateFindings) > 0 {
			buf.WriteString(fmt.Sprintf("🛡️ **%d Autonomous remediation opportunities identified with synthesized declarative mitigations:**\n\n", len(opts.RemediateFindings)))
			buf.WriteString("| Rule ID | Target | Resource | Severity | CVSS | Finding & Threat Impact | Canary Status | Mitigated CVE |\n")
			buf.WriteString("| :--- | :--- | :--- | :---: | :---: | :--- | :---: | :---: |\n")
			for _, rf := range opts.RemediateFindings {
				cveTag := rf.MatchedCVE
				if cveTag == "" {
					cveTag = "N/A"
				}
				resName := rf.ResourceName
				if rf.Namespace != "" {
					resName = fmt.Sprintf("%s/%s", rf.Namespace, rf.ResourceName)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s/%s` | **%s** | %.1f | %s: %s | `%s` | `%s` |\n",
					rf.RuleID, rf.Target, rf.ResourceKind, resName, rf.Severity, rf.CVSSScore, rf.Title, rf.Description, rf.CanaryStatus, cveTag))
			}
			buf.WriteString("\n")
		}
		if len(opts.RemediatePullRequests) > 0 {
			buf.WriteString(fmt.Sprintf("📦 **%d Synthesized GitOps Pull Request Bundles:**\n\n", len(opts.RemediatePullRequests)))
			buf.WriteString("| PR # | Head Branch | Base Branch | Title | Patches | Canary Status |\n")
			buf.WriteString("| :---: | :--- | :---: | :--- | :---: | :---: |\n")
			for _, pr := range opts.RemediatePullRequests {
				canaryBadge := "PASSED"
				if !pr.CanaryPassed {
					canaryBadge = "FAILED"
				}
				patchCount := len(pr.NixPatches) + len(pr.K8sPatches)
				buf.WriteString(fmt.Sprintf("| #%d | `%s` | `%s` | %s | %d | **%s** |\n",
					pr.PRNumber, pr.HeadBranch, pr.BaseBranch, pr.Title, patchCount, canaryBadge))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 20. eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control
	if len(opts.LSMViolations) > 0 || opts.LSMSummary != nil {
		buf.WriteString("## 🛡️ eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control\n\n")
		if opts.LSMSummary != nil {
			sum := opts.LSMSummary
			activeBadge := "INACTIVE"
			if sum.BPFLSMActive {
				activeBadge = "ACTIVE"
			}
			buf.WriteString(fmt.Sprintf("**LSM MAC Compliance Score:** `%.1f%%` (%s) | **eBPF LSM Kernel Status:** `%s` | **MAC Profiles:** %d | **Blocked Syscalls:** %d\n",
				sum.LSMScore, sum.Status, activeBadge, sum.MACProfileCount, sum.BlockedTelemetryCount))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.LSMViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d eBPF LSM & Kernel MAC violations identified:**\n\n", len(opts.LSMViolations)))
			buf.WriteString("| Rule ID | Resource | Severity | CVSS | Finding & Threat Details | CVE | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :---: | :--- |\n")
			for _, lv := range opts.LSMViolations {
				cveTag := "-"
				if lv.MatchedCVE != "" {
					cveTag = fmt.Sprintf("`%s`", lv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | **%s** | %.1f | %s | %s | %s |\n",
					lv.RuleID, lv.Resource, lv.Severity, lv.CVSSScore, lv.Message, cveTag, lv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 21. CephFS Snapshot & Volume Replication Disaster Recovery
	if len(opts.ReplicationViolations) > 0 || opts.ReplicationSummary != nil {
		buf.WriteString("## 🔄 CephFS Snapshot & Volume Replication Disaster Recovery Posture\n\n")
		if opts.ReplicationSummary != nil {
			sum := opts.ReplicationSummary
			splitBadge := "CLEAN"
			if sum.SplitBrainDetected {
				splitBadge = "SPLIT-BRAIN DETECTED"
			}
			buf.WriteString(fmt.Sprintf("**DR Compliance Score:** `%.1f%%` (%s) | **Split-Brain Posture:** `%s` | **Snapshot Classes:** %d | **Replicated Volumes:** %d | **Max Delta Lag:** %ds\n",
				sum.Score, sum.Status, splitBadge, sum.TotalSnapshotClasses, sum.TotalReplications, sum.MaxDeltaLagSeconds))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.ReplicationViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d CephFS snapshot & volume replication DR violations identified:**\n\n", len(opts.ReplicationViolations)))
			buf.WriteString("| Rule ID | Resource | Severity | CVSS | Finding & Threat Details | CVE | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :---: | :--- |\n")
			for _, rv := range opts.ReplicationViolations {
				cveTag := "-"
				if rv.MatchedCVE != "" {
					cveTag = fmt.Sprintf("`%s`", rv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s/%s` | **%s** | %.1f | %s | %s | %s |\n",
					rv.RuleID, rv.ResourceKind, rv.ResourceName, rv.Severity, rv.CVSSScore, rv.Description, cveTag, rv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 22. WireGuard eBPF Kernel Fast-Path & Crypto Performance Posture
	if len(opts.FastPathViolations) > 0 || opts.FastPathSummary != nil {
		buf.WriteString("## ⚡ WireGuard eBPF Kernel Fast-Path & Crypto Performance Posture\n\n")
		if opts.FastPathSummary != nil {
			sum := opts.FastPathSummary
			avxStatus := "Disabled"
			if sum.AVX512Accelerated {
				avxStatus = "Active (AVX-512)"
			} else if sum.ARMNeonAccelerated {
				avxStatus = "Active (ARM Neon)"
			}
			buf.WriteString(fmt.Sprintf("**Fast-Path Compliance Score:** `%.1f%%` | **Crypto Vector Engine:** `%s` | **Audited Interfaces:** %d | **Bottleneck Interfaces:** %d\n",
				sum.ComplianceScore, avxStatus, sum.TotalInterfacesAudited, len(sum.BottleneckInterfaces)))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.FastPathViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d WireGuard fast-path and cryptographic performance anomalies detected:**\n\n", len(opts.FastPathViolations)))
			buf.WriteString("| Rule ID | Interface | Severity | CVSS | Anomaly & Bottleneck Details | CVE | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :---: | :--- |\n")
			for _, fp := range opts.FastPathViolations {
				cveTag := "-"
				if fp.MatchedCVE != "" {
					cveTag = fmt.Sprintf("`%s`", fp.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | **%s** | %.1f | %s | %s | %s |\n",
					fp.RuleID, fp.InterfaceName, fp.Severity, fp.CVSSScore, fp.Description, cveTag, fp.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 23. Confidential VM & WireGuard Enclave Peer Attestation Posture
	if len(opts.EnclaveViolations) > 0 || opts.EnclaveSummary != nil {
		buf.WriteString("## 🔐 Confidential VM & WireGuard Enclave Peer Attestation Posture\n\n")
		if opts.EnclaveSummary != nil {
			sum := opts.EnclaveSummary
			buf.WriteString(fmt.Sprintf("**Enclave Compliance Score:** `%.1f%%` | **AMD SEV-SNP Verified:** `%t` | **Intel TDX Verified:** `%t` | **Tunnels Scanned:** %d | **Rejected:** %d | **PCR Deviations:** %d\n",
				sum.ComplianceScore, sum.SEVSNPVerified, sum.TDXVerified, sum.TotalPeersScanned, sum.RejectedPeers, sum.PCRDeviationsDetected))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.EnclaveViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d WireGuard enclave peer attestation anomalies detected:**\n\n", len(opts.EnclaveViolations)))
			buf.WriteString("| Rule ID | Interface / Peer | Severity | CVSS | Anomaly & Threat Details | CVE | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :---: | :--- |\n")
			for _, ev := range opts.EnclaveViolations {
				cveTag := "-"
				if ev.MatchedCVE != "" {
					cveTag = fmt.Sprintf("`%s`", ev.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s/%s` | **%s** | %.1f | %s | %s | %s |\n",
					ev.RuleID, ev.InterfaceName, ev.PeerName, ev.Severity, ev.CVSSScore, ev.Description, cveTag, ev.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 24. Kubernetes Dynamic Admission Webhook & Certificate Authority Rotation Radar
	if len(opts.WebhookViolations) > 0 || opts.WebhookSummary != nil {
		buf.WriteString("## 🎯 Kubernetes Dynamic Admission Webhook & CA Rotation Radar\n\n")
		if opts.WebhookSummary != nil {
			sum := opts.WebhookSummary
			buf.WriteString(fmt.Sprintf("**Webhook Compliance Score:** `%.1f%%` | **Scanned Webhooks:** %d (Validating: %d, Mutating: %d) | **Expired CAs:** %d | **Timeout Risks:** %d | **Avg P99:** `%.1fms`\n",
				sum.ComplianceScore, sum.TotalWebhooksScanned, sum.ValidatingCount, sum.MutatingCount, sum.ExpiredCACount, sum.TimeoutRiskCount, sum.AverageP99LatencyMs))
			buf.WriteString(fmt.Sprintf("**Severity Breakdown:** %d Critical | %d High | %d Medium | %d Low\n\n",
				sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount))
		}
		if len(opts.WebhookViolations) > 0 {
			buf.WriteString(fmt.Sprintf("⚠️ **%d admission webhook & CA rotation violations identified:**\n\n", len(opts.WebhookViolations)))
			buf.WriteString("| Rule ID | Webhook Name | Type | Severity | CVSS | Finding & Threat Details | CVE | Remediation Action |\n")
			buf.WriteString("| :--- | :--- | :---: | :---: | :---: | :--- | :---: | :--- |\n")
			for _, wv := range opts.WebhookViolations {
				cveTag := "-"
				if wv.MatchedCVE != "" {
					cveTag = fmt.Sprintf("`%s`", wv.MatchedCVE)
				}
				buf.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | **%s** | %.1f | %s | %s | %s |\n",
					wv.RuleID, wv.WebhookName, wv.WebhookType, wv.Severity, wv.CVSSScore, wv.Description, cveTag, wv.Remediation))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	// 25. Action Items Checklist
	buf.WriteString("## 📋 SecOps & SRE Operational Checklist\n\n")
	buf.WriteString("- [ ] Review high and critical severity advisories against production deployment manifests.\n")
	buf.WriteString("- [ ] Verify that ingress controllers enforce URI path normalization and snippet guards.\n")
	buf.WriteString("- [ ] Confirm cluster namespaces enforce default-deny ingress/egress network policies.\n")
	buf.WriteString("- [ ] Ensure NixOS systems evaluate flakes in pure mode with explicitly pinned hashes.\n")
	buf.WriteString("- [ ] Validate Ceph OSD peering, BlueStore integrity, and storage class volume protection policies.\n")
	buf.WriteString("- [ ] Enforce WireGuard 90-day cryptographic key rotation and prune dormant peer routing slots.\n")
	buf.WriteString("- [ ] Remediate unhardened CIS Kubernetes Benchmark control plane and Kubelet findings.\n")
	buf.WriteString("- [ ] Audit Kubernetes Gateway API routes against ReferenceGrants and sanitize dynamic EnvoyFilter Lua injections.\n")
	buf.WriteString("- [ ] Verify AMD SEV-SNP and Intel TDX attestation reports against golden NixOS UKI closure measurements in PCR 11.\n")
	buf.WriteString("- [ ] Reconcile multi-cluster GitOps synchronization drift and rotate federated OIDC identity tokens exceeding 24 hours.\n")
	buf.WriteString("- [ ] Validate SPIFFE/SPIRE X.509 SVID renewal windows and enforce mutual TLS with attested workload identities in CiliumNetworkPolicies.\n")
	buf.WriteString("- [ ] Ingest SPDX v3.0 / CycloneDX v1.6 SBOMs, verify In-Toto SLSA Level 3 attestations, and reconcile cluster runtime package deltas.\n")
	buf.WriteString("- [ ] Enforce hardware-backed KMS v2 envelope encryption for etcd, eliminate plaintext PKCS#11 PINs, and rotate KEKs under 90 days.\n")
	buf.WriteString("- [ ] Enforce declarative seccomp profiles, attach eBPF LSM socket_create filters, and restrict unprivileged BPF access.\n")
	buf.WriteString("- [ ] Enforce hybrid post-quantum key encapsulation (ML-KEM/Kyber) and CNSA 2.0 cipher suites across cluster control plane.\n")
	buf.WriteString("- [ ] Quarantine untrusted artifacts and isolate ephemeral microVM network egress to internal honeypot lures.\n")
	buf.WriteString("- [ ] Verify pre-flight canary test validation before applying declarative security hardening patches.\n")
	buf.WriteString("- [ ] Attach eBPF LSM mandatory access control hooks to restrict container syscalls, unprivileged BPF loading, and root privilege escalations.\n")
	buf.WriteString("- [ ] Enforce declarative VolumeSnapshotClass retention policies and verify cross-region volume replication delta sync within RPO targets.\n")
	buf.WriteString("- [ ] Profile WireGuard kernel cryptographic throughput, enable AVX-512/ARM Neon vector acceleration, and configure 100GbE NIC ring buffers to prevent packet loss under high load.\n")
	buf.WriteString("- [ ] Bind WireGuard ephemeral session keys to AMD SEV-SNP VCEK and Intel TDX attestation reports and reject peers with deviated boot PCRs.\n")
	buf.WriteString("- [ ] Enforce ValidatingWebhookConfiguration failurePolicy: Fail, timeoutSeconds <= 3s, exempt kube-system, and establish cert-manager automated CA rotation.\n")
	buf.WriteString("- [ ] Archive this briefing record into security audit ledger.\n")

	report := &BriefingReport{
		Title:       title,
		Window:      window,
		Telemetry:   telemetry,
		Content:     buf.String(),
		GeneratedAt: now,
	}

	return report, nil
}

// WriteBriefingToFile writes the briefing Markdown content to a file in the specified directory.
func WriteBriefingToFile(report *BriefingReport, dir string, customFilename string) (string, error) {
	if report == nil {
		return "", fmt.Errorf("briefing report cannot be nil")
	}

	cleanDir := filepath.Clean(dir)
	if cleanDir == "." || cleanDir == "" {
		cleanDir = "intel/briefings"
	}

	if err := os.MkdirAll(cleanDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create briefing output directory (%s): %w", cleanDir, err)
	}

	filename := customFilename
	if filename == "" {
		filename = fmt.Sprintf("briefing-%s.md", report.Window.Format("2006-01-02-1500"))
	}

	// Bounds and safety check: prevent directory traversal in custom filename
	filename = filepath.Base(filename)
	targetPath := filepath.Join(cleanDir, filename)

	if err := os.WriteFile(targetPath, []byte(report.Content), 0644); err != nil {
		return "", fmt.Errorf("failed to write briefing file (%s): %w", targetPath, err)
	}

	report.FilePath = targetPath
	return targetPath, nil
}
