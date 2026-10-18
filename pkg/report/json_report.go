package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bpf"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/hsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/impermanence"
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

// JSONAuditReport models the consolidated security audit report serialized to JSON.
type JSONAuditReport struct {
	ToolName                string                          `json:"tool_name"`
	ToolVersion             string                          `json:"tool_version"`
	GeneratedAt             time.Time                       `json:"generated_at"`
	TargetFilter            string                          `json:"target_filter,omitempty"`
	ScannedPaths            []string                        `json:"scanned_paths,omitempty"`
	Telemetry               TelemetrySummary                `json:"telemetry"`
	KubernetesReport        *k8s.ManifestAuditReport        `json:"kubernetes_report,omitempty"`
	FlakeVulnerabilities    []nix.FlakeVulnerabilityMatch  `json:"flake_vulnerabilities,omitempty"`
	ThreatAdvisories        []intel.ThreatItem              `json:"threat_advisories,omitempty"`
	ProbeEvents             []probe.TelemetryEvent          `json:"probe_events,omitempty"`
	StorageViolations       []storage.StorageViolation      `json:"storage_violations,omitempty"`
	CephHealth              *storage.CephHealthReport       `json:"ceph_health,omitempty"`
	WireGuardViolations     []wireguard.WireGuardViolation  `json:"wireguard_violations,omitempty"`
	WireGuardReconciliation *wireguard.ReconciliationReport `json:"wireguard_reconciliation,omitempty"`
	CISViolations           []bench.CISViolation            `json:"cis_violations,omitempty"`
	CISSummary              *bench.CISSummary               `json:"cis_summary,omitempty"`
	GatewayViolations       []gateway.GatewayViolation      `json:"gateway_violations,omitempty"`
	GatewaySummary          *gateway.GatewaySummary         `json:"gateway_summary,omitempty"`
	AttestViolations        []attest.AttestationViolation   `json:"attest_violations,omitempty"`
	AttestSummary           *attest.AttestationSummary      `json:"attest_summary,omitempty"`
	FleetViolations         []fleet.FleetViolation          `json:"fleet_violations,omitempty"`
	FleetSummary            *fleet.FleetSummary             `json:"fleet_summary,omitempty"`
	SPIFFEViolations        []spiffe.SPIFFEViolation        `json:"spiffe_violations,omitempty"`
	SPIFFESummary           *spiffe.SPIFFESummary           `json:"spiffe_summary,omitempty"`
	SBOMViolations          []sbom.SBOMViolation            `json:"sbom_violations,omitempty"`
	SBOMSummary             *sbom.SBOMSummary               `json:"sbom_summary,omitempty"`
	SBOMDelta               []sbom.SBOMDeltaItem            `json:"sbom_delta,omitempty"`
	HSMViolations           []hsm.HSMViolation              `json:"hsm_violations,omitempty"`
	HSMSummary              *hsm.HSMSummary                 `json:"hsm_summary,omitempty"`
	BPFViolations           []bpf.BPFViolation              `json:"bpf_violations,omitempty"`
	BPFSummary              *bpf.BPFSummary                 `json:"bpf_summary,omitempty"`
	PQCViolations           []pqc.PQCViolation              `json:"pqc_violations,omitempty"`
	PQCSummary              *pqc.PQCSummary                 `json:"pqc_summary,omitempty"`
	SandboxViolations       []sandbox.SandboxViolation      `json:"sandbox_violations,omitempty"`
	SandboxSummary          *sandbox.SandboxSummary         `json:"sandbox_summary,omitempty"`
	RemediateFindings       []remediate.RemediationFinding  `json:"remediate_findings,omitempty"`
	RemediatePullRequests   []remediate.GitOpsPullRequest   `json:"remediate_pull_requests,omitempty"`
	RemediateSummary        *remediate.RemediationSummary   `json:"remediate_summary,omitempty"`
	LSMViolations           []lsm.LSMViolation              `json:"lsm_violations,omitempty"`
	LSMSummary              *lsm.LSMSummary                 `json:"lsm_summary,omitempty"`
	ReplicationViolations   []replication.ReplicationViolation `json:"replication_violations,omitempty"`
	ReplicationSummary      *replication.ReplicationSummary `json:"replication_summary,omitempty"`
	ReplicationTelemetry    *replication.CrossRegionDRTelemetry `json:"replication_telemetry,omitempty"`
	FastPathViolations      []wgfastpath.WGFastPathViolation `json:"fastpath_violations,omitempty"`
	FastPathSummary         *wgfastpath.WGFastPathSummary   `json:"fastpath_summary,omitempty"`
	FastPathTelemetry       []wgfastpath.FastPathTelemetry  `json:"fastpath_telemetry,omitempty"`
	FastPathCrypto          []wgfastpath.CryptoBenchmarkTelemetry `json:"fastpath_crypto,omitempty"`
	EnclaveViolations       []wgenclave.WGEnclaveViolation  `json:"enclave_violations,omitempty"`
	EnclaveSummary          *wgenclave.WGEnclaveSummary     `json:"enclave_summary,omitempty"`
	EnclaveReports          []wgenclave.AttestationReport   `json:"enclave_reports,omitempty"`
	EnclavePeers            []wgenclave.PeerTunnelStatus    `json:"enclave_peers,omitempty"`
	WebhookViolations          []webhook.WebhookViolation              `json:"webhook_violations,omitempty"`
	WebhookSummary             *webhook.WebhookSummary                 `json:"webhook_summary,omitempty"`
	WebhookTelemetry           *webhook.WebhookTelemetry               `json:"webhook_telemetry,omitempty"`
	ImpermanenceViolations     []impermanence.ImpermanenceViolation   `json:"impermanence_violations,omitempty"`
	ImpermanenceSummary        *impermanence.ImpermanenceSummary       `json:"impermanence_summary,omitempty"`
	ImpermanenceTelemetry      *impermanence.EphemeralStorageTelemetry `json:"impermanence_telemetry,omitempty"`
}

// BuildJSONReport compiles the consolidated JSON audit report from provided audit data.
func BuildJSONReport(opts ReportOptions) (*JSONAuditReport, error) {
	ver := opts.Version
	if ver == "" {
		ver = "0.9.0"
	}

	scanned := make([]string, 0)
	if opts.FlakePath != "" {
		scanned = append(scanned, opts.FlakePath)
	}
	if opts.K8sPath != "" {
		scanned = append(scanned, opts.K8sPath)
	}
	if opts.StoragePath != "" {
		scanned = append(scanned, opts.StoragePath)
	}
	if opts.WireGuardPath != "" {
		scanned = append(scanned, opts.WireGuardPath)
	}
	if opts.CISPath != "" {
		scanned = append(scanned, opts.CISPath)
	}
	if opts.GatewayPath != "" {
		scanned = append(scanned, opts.GatewayPath)
	}
	if opts.AttestPath != "" {
		scanned = append(scanned, opts.AttestPath)
	}
	if opts.AttestTelemetryPath != "" {
		scanned = append(scanned, opts.AttestTelemetryPath)
	}
	if opts.FleetPath != "" {
		scanned = append(scanned, opts.FleetPath)
	}
	if opts.FleetTelemetryPath != "" {
		scanned = append(scanned, opts.FleetTelemetryPath)
	}
	if opts.SPIFFEPath != "" {
		scanned = append(scanned, opts.SPIFFEPath)
	}
	if opts.SPIFFETelemetryPath != "" {
		scanned = append(scanned, opts.SPIFFETelemetryPath)
	}
	if opts.SBOMPath != "" {
		scanned = append(scanned, opts.SBOMPath)
	}
	if opts.SBOMAttestPath != "" {
		scanned = append(scanned, opts.SBOMAttestPath)
	}
	if opts.SBOMRuntimePath != "" {
		scanned = append(scanned, opts.SBOMRuntimePath)
	}
	if opts.HSMPath != "" {
		scanned = append(scanned, opts.HSMPath)
	}
	if opts.HSMTelemetryPath != "" {
		scanned = append(scanned, opts.HSMTelemetryPath)
	}
	if opts.BPFPath != "" {
		scanned = append(scanned, opts.BPFPath)
	}
	if opts.BPFTelemetryPath != "" {
		scanned = append(scanned, opts.BPFTelemetryPath)
	}
	if opts.PQCPath != "" {
		scanned = append(scanned, opts.PQCPath)
	}
	if opts.PQCTelemetryPath != "" {
		scanned = append(scanned, opts.PQCTelemetryPath)
	}
	if opts.SandboxPath != "" {
		scanned = append(scanned, opts.SandboxPath)
	}
	if opts.SandboxTelemetryPath != "" {
		scanned = append(scanned, opts.SandboxTelemetryPath)
	}
	if opts.RemediatePath != "" {
		scanned = append(scanned, opts.RemediatePath)
	}
	if opts.RemediateOutDir != "" {
		scanned = append(scanned, opts.RemediateOutDir)
	}
	if opts.LSMPath != "" {
		scanned = append(scanned, opts.LSMPath)
	}
	if opts.LSMTelemetryPath != "" {
		scanned = append(scanned, opts.LSMTelemetryPath)
	}
	if opts.LSMSynthOut != "" {
		scanned = append(scanned, opts.LSMSynthOut)
	}
	if opts.DRManifestPath != "" {
		scanned = append(scanned, opts.DRManifestPath)
	}
	if opts.DRTelemetryPath != "" {
		scanned = append(scanned, opts.DRTelemetryPath)
	}
	if opts.DRSynthOut != "" {
		scanned = append(scanned, opts.DRSynthOut)
	}
	if opts.FastPathManifestPath != "" {
		scanned = append(scanned, opts.FastPathManifestPath)
	}
	if opts.FastPathTelemetryPath != "" {
		scanned = append(scanned, opts.FastPathTelemetryPath)
	}
	if opts.FastPathSynthOut != "" {
		scanned = append(scanned, opts.FastPathSynthOut)
	}
	if opts.EnclaveManifestPath != "" {
		scanned = append(scanned, opts.EnclaveManifestPath)
	}
	if opts.EnclaveTelemetryPath != "" {
		scanned = append(scanned, opts.EnclaveTelemetryPath)
	}
	if opts.EnclaveSynthOut != "" {
		scanned = append(scanned, opts.EnclaveSynthOut)
	}
	if opts.WebhookPath != "" {
		scanned = append(scanned, opts.WebhookPath)
	}
	if opts.WebhookTelemetryPath != "" {
		scanned = append(scanned, opts.WebhookTelemetryPath)
	}
	if opts.WebhookSynthOut != "" {
		scanned = append(scanned, opts.WebhookSynthOut)
	}
	if opts.ImpermanencePath != "" {
		scanned = append(scanned, opts.ImpermanencePath)
	}
	if opts.ImpermanenceTelemetryPath != "" {
		scanned = append(scanned, opts.ImpermanenceTelemetryPath)
	}
	if opts.ImpermanenceSynthOut != "" {
		scanned = append(scanned, opts.ImpermanenceSynthOut)
	}

	telemetry := ComputeTelemetryImpermanence(opts.Feed, opts.K8sReport, opts.FlakeMatches, opts.StorageViolations, opts.WireGuardViolations, opts.CISViolations, opts.GatewayViolations, opts.AttestViolations, opts.FleetViolations, opts.SPIFFEViolations, opts.SBOMViolations, opts.HSMViolations, opts.BPFViolations, opts.PQCViolations, opts.SandboxViolations, opts.RemediateFindings, opts.LSMViolations, opts.ReplicationViolations, opts.FastPathViolations, opts.EnclaveViolations, opts.WebhookViolations, opts.ImpermanenceViolations)

	var advisories []intel.ThreatItem
	if opts.Feed != nil {
		if opts.TargetFilter != "" {
			advisories = opts.Feed.FilterByTarget(opts.TargetFilter)
		} else {
			advisories = opts.Feed.Items
		}
	}

	rep := &JSONAuditReport{
		ToolName:                "nix-k8s-sentinel",
		ToolVersion:             ver,
		GeneratedAt:             time.Now().UTC(),
		TargetFilter:            opts.TargetFilter,
		ScannedPaths:            scanned,
		Telemetry:               telemetry,
		KubernetesReport:        opts.K8sReport,
		FlakeVulnerabilities:    opts.FlakeMatches,
		ThreatAdvisories:        advisories,
		ProbeEvents:             opts.ProbeEvents,
		StorageViolations:       opts.StorageViolations,
		CephHealth:              opts.StorageHealth,
		WireGuardViolations:     opts.WireGuardViolations,
		WireGuardReconciliation: opts.WireGuardReconciliation,
		CISViolations:           opts.CISViolations,
		CISSummary:              opts.CISSummary,
		GatewayViolations:       opts.GatewayViolations,
		GatewaySummary:          opts.GatewaySummary,
		AttestViolations:        opts.AttestViolations,
		AttestSummary:           opts.AttestSummary,
		FleetViolations:         opts.FleetViolations,
		FleetSummary:            opts.FleetSummary,
		SPIFFEViolations:        opts.SPIFFEViolations,
		SPIFFESummary:           opts.SPIFFESummary,
		SBOMViolations:          opts.SBOMViolations,
		SBOMSummary:             opts.SBOMSummary,
		SBOMDelta:               opts.SBOMDelta,
		HSMViolations:           opts.HSMViolations,
		HSMSummary:              opts.HSMSummary,
		BPFViolations:           opts.BPFViolations,
		BPFSummary:              opts.BPFSummary,
		PQCViolations:           opts.PQCViolations,
		PQCSummary:              opts.PQCSummary,
		SandboxViolations:       opts.SandboxViolations,
		SandboxSummary:          opts.SandboxSummary,
		RemediateFindings:       opts.RemediateFindings,
		RemediatePullRequests:   opts.RemediatePullRequests,
		RemediateSummary:        opts.RemediateSummary,
		LSMViolations:           opts.LSMViolations,
		LSMSummary:              opts.LSMSummary,
		ReplicationViolations:   opts.ReplicationViolations,
		ReplicationSummary:      opts.ReplicationSummary,
		ReplicationTelemetry:    opts.ReplicationTelemetry,
		FastPathViolations:      opts.FastPathViolations,
		FastPathSummary:         opts.FastPathSummary,
		FastPathTelemetry:       opts.FastPathTelemetry,
		FastPathCrypto:          opts.FastPathCrypto,
		EnclaveViolations:       opts.EnclaveViolations,
		EnclaveSummary:          opts.EnclaveSummary,
		EnclaveReports:          opts.EnclaveReports,
		EnclavePeers:            opts.EnclavePeers,
		WebhookViolations:          opts.WebhookViolations,
		WebhookSummary:             opts.WebhookSummary,
		WebhookTelemetry:           opts.WebhookTelemetry,
		ImpermanenceViolations:     opts.ImpermanenceViolations,
		ImpermanenceSummary:        opts.ImpermanenceSummary,
		ImpermanenceTelemetry:      opts.ImpermanenceTelemetry,
	}

	return rep, nil
}

// FormatJSON serializes a JSONAuditReport to raw bytes.
func FormatJSON(report *JSONAuditReport, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

// WriteJSONToFile atomically saves the JSON report to the designated path with path traversal defense.
func WriteJSONToFile(report *JSONAuditReport, destPath string, pretty bool) error {
	cleanPath := filepath.Clean(destPath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory for JSON report: %w", err)
	}

	data, err := FormatJSON(report, pretty)
	if err != nil {
		return fmt.Errorf("failed to serialize JSON audit report: %w", err)
	}

	if err := os.WriteFile(cleanPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write JSON report to %s: %w", cleanPath, err)
	}

	return nil
}
