package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
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
		version = "0.4.0"
	}

	telemetry := ComputeTelemetryRadar(opts.Feed, opts.K8sReport, opts.FlakeMatches, opts.StorageViolations, opts.WireGuardViolations, opts.CISViolations, opts.GatewayViolations)

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

	// 11. Action Items Checklist
	buf.WriteString("## 📋 SecOps & SRE Operational Checklist\n\n")
	buf.WriteString("- [ ] Review high and critical severity advisories against production deployment manifests.\n")
	buf.WriteString("- [ ] Verify that ingress controllers enforce URI path normalization and snippet guards.\n")
	buf.WriteString("- [ ] Confirm cluster namespaces enforce default-deny ingress/egress network policies.\n")
	buf.WriteString("- [ ] Ensure NixOS systems evaluate flakes in pure mode with explicitly pinned hashes.\n")
	buf.WriteString("- [ ] Validate Ceph OSD peering, BlueStore integrity, and storage class volume protection policies.\n")
	buf.WriteString("- [ ] Enforce WireGuard 90-day cryptographic key rotation and prune dormant peer routing slots.\n")
	buf.WriteString("- [ ] Remediate unhardened CIS Kubernetes Benchmark control plane and Kubelet findings.\n")
	buf.WriteString("- [ ] Audit Kubernetes Gateway API routes against ReferenceGrants and sanitize dynamic EnvoyFilter Lua injections.\n")
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
