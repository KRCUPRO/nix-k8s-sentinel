package pqc

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// PQCScanner orchestrates declarative manifest audits and runtime telemetry analysis.
type PQCScanner struct {
	feed *intel.Feed
}

// NewPQCScanner initializes a new scanner instance with an optional threat intelligence feed.
func NewPQCScanner(feed *intel.Feed) *PQCScanner {
	return &PQCScanner{feed: feed}
}

// ScanPath recursively audits Kubernetes control plane manifests and NixOS cryptographic policies.
func (s *PQCScanner) ScanPath(rootPath string) (*PQCAuditReport, error) {
	cleanPath := filepath.Clean(rootPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access path %s: %w", cleanPath, err)
	}

	var allViolations []PQCViolation
	totalConfigs := 0
	totalEndpoints := 0

	walkFn := func(currentPath string, currentInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if currentInfo.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(currentPath))
		base := strings.ToLower(currentInfo.Name())

		// 1. Audit Kubernetes YAML manifests
		if ext == ".yaml" || ext == ".yml" {
			cfg, err := ParseK8sControlPlaneManifest(currentPath)
			if err == nil && cfg != nil && (len(cfg.RawArgs) > 0 || cfg.Component != "control-plane-tls") {
				totalConfigs++
				totalEndpoints++
				v := AuditControlPlaneConfig(cfg, s.feed)
				allViolations = append(allViolations, v...)
			}
		}

		// 2. Audit NixOS configuration files
		if ext == ".nix" {
			cfg, err := ParseNixOSCryptoConfig(currentPath)
			if err == nil && cfg != nil {
				totalConfigs++
				totalEndpoints++
				v := AuditNixOSCrypto(cfg, s.feed)
				allViolations = append(allViolations, v...)
			}
		}

		// 3. Audit JSON telemetry files directly if encountered in path
		if ext == ".json" && (strings.Contains(base, "telemetry") || strings.Contains(base, "pqc") || strings.Contains(base, "handshake")) {
			telemetry, err := ParsePQCTelemetryJSON(currentPath)
			if err == nil && telemetry != nil && len(telemetry.Handshakes) > 0 {
				totalConfigs++
				totalEndpoints += len(telemetry.Handshakes)
				v, _, _ := AuditTelemetry(telemetry, s.feed)
				allViolations = append(allViolations, v...)
			}
		}

		return nil
	}

	if info.IsDir() {
		if err := filepath.Walk(cleanPath, walkFn); err != nil {
			return nil, fmt.Errorf("error walking path %s: %w", cleanPath, err)
		}
	} else {
		if err := walkFn(cleanPath, info, nil); err != nil {
			return nil, err
		}
	}

	summary := ComputePQCSummary(totalConfigs, totalEndpoints, 0, allViolations, 0.0, 0.0)

	return &PQCAuditReport{
		ReportID:   fmt.Sprintf("pqc-audit-%d", time.Now().UnixNano()),
		ScannedAt:  time.Now(),
		Summary:    summary,
		Violations: allViolations,
	}, nil
}

// ScanTelemetryFile parses and evaluates a runtime TLS connection telemetry JSON file.
func (s *PQCScanner) ScanTelemetryFile(telemetryPath string) (*PQCAuditReport, error) {
	telemetry, err := ParsePQCTelemetryJSON(telemetryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan telemetry file: %w", err)
	}

	violations, hybridPct, tls13Pct := AuditTelemetry(telemetry, s.feed)
	totalEndpoints := len(telemetry.Handshakes)

	summary := ComputePQCSummary(1, totalEndpoints, totalEndpoints, violations, hybridPct, tls13Pct)

	return &PQCAuditReport{
		ReportID:   fmt.Sprintf("pqc-telemetry-audit-%d", time.Now().UnixNano()),
		ScannedAt:  time.Now(),
		Summary:    summary,
		Violations: violations,
	}, nil
}

// ComputePQCSummary computes aggregated metrics, compliance scores, and overall audit status.
func ComputePQCSummary(configsScanned, endpointsScanned, telemetryCount int, violations []PQCViolation, hybridPct, tls13Pct float64) PQCSummary {
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			critCount++
		case intel.SeverityHigh:
			highCount++
		case intel.SeverityMedium:
			medCount++
		case intel.SeverityLow:
			lowCount++
		}
	}

	// Compliance scoring model: 100.0 baseline with deductions
	score := 100.0 - (float64(critCount) * 25.0) - (float64(highCount) * 15.0) - (float64(medCount) * 8.0) - (float64(lowCount) * 3.0)
	if score < 0.0 {
		score = 0.0
	}
	score = math.Round(score*10) / 10

	status := "PASSED (CNSA 2.0 Quantum-Ready)"
	if score < 75.0 {
		status = "FAIL (Vulnerable to Harvest-Now-Decrypt-Later)"
	} else if score < 90.0 {
		status = "TRANSITIONAL (Hybrid PQC In Progress)"
	}

	return PQCSummary{
		TotalEndpointsScanned: endpointsScanned,
		TotalConfigsScanned:   configsScanned,
		TotalTelemetryEvents:  telemetryCount,
		ViolationsCount:       len(violations),
		CriticalCount:         critCount,
		HighCount:             highCount,
		MediumCount:           medCount,
		LowCount:              lowCount,
		HybridKEMPercentage:   hybridPct,
		TLS13Percentage:       tls13Pct,
		CNSAComplianceScore:   score,
		AuditStatus:           status,
	}
}
