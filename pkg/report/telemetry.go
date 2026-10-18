package report

import (
	"math"
	"sort"
	"strings"

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
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/remediate"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/replication"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sandbox"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sbom"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgenclave"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgfastpath"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

// TelemetrySummary captures aggregated vulnerability metrics across all audit domains.
type TelemetrySummary struct {
	TotalThreats               int            `json:"total_threats"`
	CriticalCount              int            `json:"critical_count"`
	HighCount                  int            `json:"high_count"`
	MediumCount                int            `json:"medium_count"`
	LowCount                   int            `json:"low_count"`
	AverageCVSS                float64        `json:"average_cvss"`
	MaxCVSS                    float64        `json:"max_cvss"`
	TargetDistribution         map[string]int `json:"target_distribution"`
	ComponentDistribution      map[string]int `json:"component_distribution"`
	TotalViolations            int            `json:"total_violations"`
	TotalFlakeMatches          int            `json:"total_flake_matches"`
	TotalStorageViolations     int            `json:"total_storage_violations"`
	TotalWireGuardViolations   int            `json:"total_wireguard_violations"`
	TotalCISViolations         int            `json:"total_cis_violations"`
	TotalGatewayViolations     int            `json:"total_gateway_violations"`
	TotalAttestViolations      int            `json:"total_attest_violations"`
	TotalFleetViolations       int            `json:"total_fleet_violations"`
	TotalSPIFFEViolations      int            `json:"total_spiffe_violations"`
	TotalSBOMViolations        int            `json:"total_sbom_violations"`
	TotalHSMViolations         int            `json:"total_hsm_violations"`
	TotalBPFViolations         int            `json:"total_bpf_violations"`
	TotalPQCViolations         int            `json:"total_pqc_violations"`
	TotalSandboxViolations     int            `json:"total_sandbox_violations"`
	TotalRemediateFindings     int            `json:"total_remediate_findings"`
	TotalLSMViolations         int            `json:"total_lsm_violations"`
	TotalReplicationViolations int            `json:"total_replication_violations"`
	TotalFastPathViolations    int            `json:"total_fastpath_violations"`
	TotalEnclaveViolations     int            `json:"total_enclave_violations"`
}

// ComputeTelemetry aggregates CVSS metrics from the threat feed, K8s violations, and Nix flake matches.
func ComputeTelemetry(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch) TelemetrySummary {
	return ComputeTelemetryExtended(feed, k8sReport, flakeMatches, nil)
}

// ComputeTelemetryExtended aggregates CVSS metrics including Rook Ceph storage violations.
func ComputeTelemetryExtended(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation) TelemetrySummary {
	return ComputeTelemetryFull(feed, k8sReport, flakeMatches, storageViolations, nil)
}

// ComputeTelemetryFull aggregates CVSS metrics across all domains including WireGuard mesh violations.
func ComputeTelemetryFull(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation) TelemetrySummary {
	return ComputeTelemetryOmni(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, nil)
}

// ComputeTelemetryOmni aggregates CVSS metrics across all domains including CIS benchmark violations.
func ComputeTelemetryOmni(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation) TelemetrySummary {
	return ComputeTelemetryRadar(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, nil)
}

// ComputeTelemetryRadar aggregates CVSS metrics across all domains including Gateway API & EnvoyFilter violations.
func ComputeTelemetryRadar(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation) TelemetrySummary {
	return ComputeTelemetryAttest(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, nil)
}

// ComputeTelemetryAttest aggregates CVSS metrics across all domains including Confidential Computing & Measured Boot violations.
func ComputeTelemetryAttest(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation) TelemetrySummary {
	return ComputeTelemetryFleet(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, nil)
}

// ComputeTelemetryFleet aggregates CVSS metrics across all domains including Multi-Cluster Fleet Synchronization & OIDC Token Radar violations.
func ComputeTelemetryFleet(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation) TelemetrySummary {
	return ComputeTelemetrySPIFFE(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, nil)
}

// ComputeTelemetrySPIFFE aggregates CVSS metrics across all domains including Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation violations.
func ComputeTelemetrySPIFFE(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation) TelemetrySummary {
	return ComputeTelemetrySBOM(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, nil)
}

// ComputeTelemetrySBOM aggregates CVSS metrics across all domains including Software Bill of Materials & In-Toto Supply Chain Attestation violations.
func ComputeTelemetrySBOM(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation) TelemetrySummary {
	return ComputeTelemetryHSM(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, nil)
}

// ComputeTelemetryHSM aggregates CVSS metrics across all domains including Hardware Security Module (HSM) & PKCS#11 Envelope Encryption violations.
func ComputeTelemetryHSM(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation) TelemetrySummary {
	return ComputeTelemetryBPF(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, nil)
}

// ComputeTelemetryBPF aggregates CVSS metrics across all domains including Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter violations.
func ComputeTelemetryBPF(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation) TelemetrySummary {
	return ComputeTelemetryPQC(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, nil)
}

// ComputeTelemetryPQC aggregates CVSS metrics across all domains including Post-Quantum Cryptography & CNSA 2.0 violations.
func ComputeTelemetryPQC(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation) TelemetrySummary {
	return ComputeTelemetrySandbox(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, pqcViolations, nil)
}

// ComputeTelemetrySandbox aggregates CVSS metrics across all domains including Ephemeral MicroVM Sandbox & Honeypot violations.
func ComputeTelemetrySandbox(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation, sandboxViolations []sandbox.SandboxViolation) TelemetrySummary {
	return ComputeTelemetryRemediate(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, pqcViolations, sandboxViolations, nil)
}

// ComputeTelemetryRemediate aggregates CVSS metrics across all domains including Autonomous Threat Remediation findings.
func ComputeTelemetryRemediate(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation, sandboxViolations []sandbox.SandboxViolation, remediateFindings []remediate.RemediationFinding) TelemetrySummary {
	return ComputeTelemetryLSM(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, pqcViolations, sandboxViolations, remediateFindings, nil)
}

// ComputeTelemetryLSM aggregates CVSS metrics across all domains including eBPF LSM and Kernel MAC violations.
func ComputeTelemetryLSM(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation, sandboxViolations []sandbox.SandboxViolation, remediateFindings []remediate.RemediationFinding, lsmViolations []lsm.LSMViolation) TelemetrySummary {
	return ComputeTelemetryReplication(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, pqcViolations, sandboxViolations, remediateFindings, lsmViolations, nil)
}

// ComputeTelemetryReplication aggregates CVSS metrics across all domains including CephFS Snapshot & Volume Replication DR findings.
func ComputeTelemetryReplication(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation, sandboxViolations []sandbox.SandboxViolation, remediateFindings []remediate.RemediationFinding, lsmViolations []lsm.LSMViolation, replicationViolations []replication.ReplicationViolation) TelemetrySummary {
	return ComputeTelemetryFastPath(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, pqcViolations, sandboxViolations, remediateFindings, lsmViolations, replicationViolations, nil)
}

// ComputeTelemetryFastPath aggregates CVSS metrics across all domains including WireGuard eBPF Fast-Path & Crypto Performance findings.
func ComputeTelemetryFastPath(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation, sandboxViolations []sandbox.SandboxViolation, remediateFindings []remediate.RemediationFinding, lsmViolations []lsm.LSMViolation, replicationViolations []replication.ReplicationViolation, fastPathViolations []wgfastpath.WGFastPathViolation) TelemetrySummary {
	summary := TelemetrySummary{
		TargetDistribution:    make(map[string]int),
		ComponentDistribution: make(map[string]int),
	}

	if feed != nil && len(feed.Items) > 0 {
		var sumScore float64
		summary.TotalThreats = len(feed.Items)

		for _, item := range feed.Items {
			// Update max CVSS
			if item.CVSSScore > summary.MaxCVSS {
				summary.MaxCVSS = item.CVSSScore
			}
			sumScore += item.CVSSScore

			// Severity bucket categorization
			sev := strings.ToUpper(string(item.Severity))
			switch {
			case sev == string(intel.SeverityCritical) || item.CVSSScore >= 9.0:
				summary.CriticalCount++
			case sev == string(intel.SeverityHigh) || (item.CVSSScore >= 7.0 && item.CVSSScore < 9.0):
				summary.HighCount++
			case sev == string(intel.SeverityMedium) || (item.CVSSScore >= 4.0 && item.CVSSScore < 7.0):
				summary.MediumCount++
			default:
				summary.LowCount++
			}

			// Target distribution
			targetKey := strings.ToLower(item.Target)
			if targetKey == "" {
				targetKey = "unassigned"
			}
			summary.TargetDistribution[targetKey]++

			// Component distribution
			compKey := strings.ToLower(item.Component)
			if compKey == "" {
				compKey = "general"
			}
			summary.ComponentDistribution[compKey]++
		}

		if summary.TotalThreats > 0 {
			summary.AverageCVSS = math.Round((sumScore/float64(summary.TotalThreats))*10) / 10
		}
	}

	if k8sReport != nil {
		summary.TotalViolations = len(k8sReport.Violations)
	}

	if len(flakeMatches) > 0 {
		summary.TotalFlakeMatches = len(flakeMatches)
	}

	if len(storageViolations) > 0 {
		summary.TotalStorageViolations = len(storageViolations)
	}

	if len(wireguardViolations) > 0 {
		summary.TotalWireGuardViolations = len(wireguardViolations)
	}

	if len(cisViolations) > 0 {
		summary.TotalCISViolations = len(cisViolations)
	}

	if len(gatewayViolations) > 0 {
		summary.TotalGatewayViolations = len(gatewayViolations)
	}

	if len(attestViolations) > 0 {
		summary.TotalAttestViolations = len(attestViolations)
	}

	if len(fleetViolations) > 0 {
		summary.TotalFleetViolations = len(fleetViolations)
	}

	if len(spiffeViolations) > 0 {
		summary.TotalSPIFFEViolations = len(spiffeViolations)
	}

	if len(sbomViolations) > 0 {
		summary.TotalSBOMViolations = len(sbomViolations)
	}

	if len(hsmViolations) > 0 {
		summary.TotalHSMViolations = len(hsmViolations)
	}

	if len(bpfViolations) > 0 {
		summary.TotalBPFViolations = len(bpfViolations)
	}

	if len(pqcViolations) > 0 {
		summary.TotalPQCViolations = len(pqcViolations)
	}

	if len(sandboxViolations) > 0 {
		summary.TotalSandboxViolations = len(sandboxViolations)
	}

	if len(remediateFindings) > 0 {
		summary.TotalRemediateFindings = len(remediateFindings)
	}

	if len(lsmViolations) > 0 {
		summary.TotalLSMViolations = len(lsmViolations)
	}

	if len(replicationViolations) > 0 {
		summary.TotalReplicationViolations = len(replicationViolations)
		for _, rv := range replicationViolations {
			summary.TotalViolations++
			summary.TargetDistribution["kubernetes"]++
			summary.ComponentDistribution["cephfs-dr"]++
			if rv.CVSSScore > summary.MaxCVSS {
				summary.MaxCVSS = rv.CVSSScore
			}
			switch rv.Severity {
			case intel.SeverityCritical:
				summary.CriticalCount++
			case intel.SeverityHigh:
				summary.HighCount++
			case intel.SeverityMedium:
				summary.MediumCount++
			default:
				summary.LowCount++
			}
		}
	}

	if len(fastPathViolations) > 0 {
		summary.TotalFastPathViolations = len(fastPathViolations)
		for _, fp := range fastPathViolations {
			summary.TotalViolations++
			summary.TargetDistribution["nixos"]++
			summary.ComponentDistribution["wireguard-fastpath"]++
			if fp.CVSSScore > summary.MaxCVSS {
				summary.MaxCVSS = fp.CVSSScore
			}
			switch fp.Severity {
			case intel.SeverityCritical:
				summary.CriticalCount++
			case intel.SeverityHigh:
				summary.HighCount++
			case intel.SeverityMedium:
				summary.MediumCount++
			default:
				summary.LowCount++
			}
		}
	}

	return summary
}

// ComputeTelemetryEnclave aggregates CVSS metrics across all domains including Confidential VM & WireGuard Enclave Peer Attestation findings.
func ComputeTelemetryEnclave(feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, flakeMatches []nix.FlakeVulnerabilityMatch, storageViolations []storage.StorageViolation, wireguardViolations []wireguard.WireGuardViolation, cisViolations []bench.CISViolation, gatewayViolations []gateway.GatewayViolation, attestViolations []attest.AttestationViolation, fleetViolations []fleet.FleetViolation, spiffeViolations []spiffe.SPIFFEViolation, sbomViolations []sbom.SBOMViolation, hsmViolations []hsm.HSMViolation, bpfViolations []bpf.BPFViolation, pqcViolations []pqc.PQCViolation, sandboxViolations []sandbox.SandboxViolation, remediateFindings []remediate.RemediationFinding, lsmViolations []lsm.LSMViolation, replicationViolations []replication.ReplicationViolation, fastPathViolations []wgfastpath.WGFastPathViolation, enclaveViolations []wgenclave.WGEnclaveViolation) TelemetrySummary {
	summary := ComputeTelemetryFastPath(feed, k8sReport, flakeMatches, storageViolations, wireguardViolations, cisViolations, gatewayViolations, attestViolations, fleetViolations, spiffeViolations, sbomViolations, hsmViolations, bpfViolations, pqcViolations, sandboxViolations, remediateFindings, lsmViolations, replicationViolations, fastPathViolations)

	if len(enclaveViolations) > 0 {
		summary.TotalEnclaveViolations = len(enclaveViolations)
		for _, ev := range enclaveViolations {
			summary.TotalViolations++
			summary.TargetDistribution["nixos"]++
			summary.ComponentDistribution["wireguard-enclave"]++
			if ev.CVSSScore > summary.MaxCVSS {
				summary.MaxCVSS = ev.CVSSScore
			}
			switch ev.Severity {
			case intel.SeverityCritical:
				summary.CriticalCount++
			case intel.SeverityHigh:
				summary.HighCount++
			case intel.SeverityMedium:
				summary.MediumCount++
			default:
				summary.LowCount++
			}
		}
	}

	return summary
}

// SortedMapKeys returns map keys sorted alphabetically for deterministic Markdown output.
func SortedMapKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SeverityBadge returns an emoji-accented indicator for a given severity string.
func SeverityBadge(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "CRITICAL [P0]"
	case "HIGH":
		return "HIGH [P1]"
	case "MEDIUM":
		return "MEDIUM [P2]"
	case "LOW":
		return "LOW [P3]"
	default:
		return "INFO"
	}
}
