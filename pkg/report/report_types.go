package report

import (
	"fmt"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bpf"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/hsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/pqc"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sbom"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

// ReportFormat designates the target serialization format for security audit findings.
type ReportFormat string

const (
	// OutputFormatConsole specifies standard human-readable terminal output.
	OutputFormatConsole ReportFormat = "console"
	// OutputFormatJSON specifies full-fidelity structured JSON audit telemetry.
	OutputFormatJSON ReportFormat = "json"
	// OutputFormatSARIF specifies OASIS SARIF v2.1.0 for GitHub Code Scanning integration.
	OutputFormatSARIF ReportFormat = "sarif"
)

// ReportOptions encapsulates all scanned domains and parameters for report synthesis.
type ReportOptions struct {
	Version                 string
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
	FlakePath               string
	K8sPath                 string
	StoragePath             string
	WireGuardPath           string
	CISPath                 string
	GatewayPath             string
	AttestPath              string
	AttestTelemetryPath     string
	FleetPath               string
	FleetTelemetryPath      string
	SPIFFEPath              string
	SPIFFETelemetryPath     string
	SBOMPath                string
	SBOMAttestPath          string
	SBOMRuntimePath         string
	HSMPath                 string
	HSMTelemetryPath        string
	BPFPath                 string
	BPFTelemetryPath        string
	PQCPath                 string
	PQCTelemetryPath        string
	TargetFilter            string
	Pretty                  bool
}

// SeverityToSARIFLevel translates CVSS severity metrics into standard SARIF v2.1.0 result levels.
// GitHub Code Scanning maps "error" -> Error, "warning" -> Warning, "note" -> Recommendation.
func SeverityToSARIFLevel(severity string, cvss float64) string {
	s := strings.ToUpper(strings.TrimSpace(severity))
	switch {
	case s == string(intel.SeverityCritical) || s == string(intel.SeverityHigh) || cvss >= 7.0:
		return "error"
	case s == string(intel.SeverityMedium) || cvss >= 4.0:
		return "warning"
	case s == string(intel.SeverityLow) || cvss > 0.0:
		return "note"
	default:
		return "note"
	}
}

// NormalizeCVSSString formats floating-point CVSS scores to standard single-decimal representation.
func NormalizeCVSSString(score float64) string {
	if score <= 0.0 {
		return "0.0"
	}
	return fmt.Sprintf("%.1f", score)
}

// FormatRuleName converts a rule ID and title into an alphanumeric PascalCase SARIF rule name.
func FormatRuleName(ruleID, title string) string {
	if title != "" {
		words := strings.Fields(title)
		var b strings.Builder
		for _, w := range words {
			clean := strings.Map(func(r rune) rune {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
					return r
				}
				return -1
			}, w)
			if len(clean) > 0 {
				b.WriteString(strings.ToUpper(clean[:1]) + strings.ToLower(clean[1:]))
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}

	cleanID := strings.ReplaceAll(ruleID, "-", "")
	cleanID = strings.ReplaceAll(cleanID, "_", "")
	return cleanID
}
