package report

import (
	"math"
	"sort"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

// TelemetrySummary captures aggregated vulnerability metrics across all audit domains.
type TelemetrySummary struct {
	TotalThreats              int            `json:"total_threats"`
	CriticalCount             int            `json:"critical_count"`
	HighCount                 int            `json:"high_count"`
	MediumCount               int            `json:"medium_count"`
	LowCount                  int            `json:"low_count"`
	AverageCVSS               float64        `json:"average_cvss"`
	MaxCVSS                   float64        `json:"max_cvss"`
	TargetDistribution        map[string]int `json:"target_distribution"`
	ComponentDistribution     map[string]int `json:"component_distribution"`
	TotalViolations           int            `json:"total_violations"`
	TotalFlakeMatches         int            `json:"total_flake_matches"`
	TotalStorageViolations    int            `json:"total_storage_violations"`
	TotalWireGuardViolations  int            `json:"total_wireguard_violations"`
	TotalCISViolations        int            `json:"total_cis_violations"`
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
