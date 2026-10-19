package lockdown

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// LockdownScanner orchestrates directory walks, manifest parsing, telemetry correlation, and compliance evaluation.
type LockdownScanner struct{}

// NewLockdownScanner instantiates a new LockdownScanner.
func NewLockdownScanner() *LockdownScanner {
	return &LockdownScanner{}
}

// ScanLockdownTarget scans a declarative NixOS configuration path and optional runtime telemetry report.
func (s *LockdownScanner) ScanLockdownTarget(manifestPath string, telemetryPath string, feed *intel.Feed) (*LockdownAuditReport, error) {
	report := &LockdownAuditReport{
		HostName:   "localhost",
		ScannedAt:  time.Now().UTC(),
		Violations: make([]LockdownViolation, 0),
	}

	var parsedConfigs []*LockdownSecurityConfig

	if manifestPath != "" {
		cleanManifest := filepath.Clean(manifestPath)
		fileInfo, err := os.Stat(cleanManifest)
		if err != nil {
			return nil, fmt.Errorf("failed to access manifest target (%s): %w", cleanManifest, err)
		}

		if fileInfo.IsDir() {
			err = filepath.Walk(cleanManifest, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".nix") {
					cfg, parseErr := ParseLockdownConfigFile(path)
					if parseErr == nil && cfg != nil {
						parsedConfigs = append(parsedConfigs, cfg)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("error walking manifest directory: %w", err)
			}
		} else {
			cfg, parseErr := ParseLockdownConfigFile(cleanManifest)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse manifest file: %w", parseErr)
			}
			parsedConfigs = append(parsedConfigs, cfg)
		}
	}

	// Consolidate static configuration violations
	var primaryConfig *LockdownSecurityConfig
	if len(parsedConfigs) > 0 {
		primaryConfig = parsedConfigs[0]
		report.Config = primaryConfig
		if primaryConfig.HostName != "" && primaryConfig.HostName != "localhost" {
			report.HostName = primaryConfig.HostName
		}
		for _, cfg := range parsedConfigs {
			violations := AuditLockdownConfig(cfg)
			report.Violations = append(report.Violations, violations...)
		}
	}

	// Parse and audit runtime telemetry if provided
	if telemetryPath != "" {
		telReport, err := ParseLockdownTelemetryFile(telemetryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse telemetry file (%s): %w", telemetryPath, err)
		}
		report.Telemetry = telReport
		if telReport.HostName != "" && report.HostName == "localhost" {
			report.HostName = telReport.HostName
		}

		telViolations := AuditLockdownTelemetry(telReport, primaryConfig, nil)
		report.Violations = append(report.Violations, telViolations...)
	}

	// Correlate with CVE feed if provided
	if feed != nil {
		for i := range report.Violations {
			v := &report.Violations[i]
			for _, item := range feed.Items {
				if item.Component == "kernel-lockdown" || item.ID == "CVE-2026-92814" {
					if v.MatchedCVE == "" {
						v.MatchedCVE = item.ID
					}
				}
			}
		}
	}

	// Compute summary statistics
	summary := LockdownSummary{
		TotalScanned:   len(parsedConfigs),
		ViolationCount: len(report.Violations),
	}
	if summary.TotalScanned == 0 && report.Telemetry != nil {
		summary.TotalScanned = 1
	}

	for _, v := range report.Violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
		case intel.SeverityHigh:
			summary.HighCount++
		case intel.SeverityMedium:
			summary.MediumCount++
		case intel.SeverityLow:
			summary.LowCount++
		}
	}

	summary.ComplianceScore = ComputeComplianceScore(report.Violations)
	if len(report.Violations) == 0 && summary.TotalScanned > 0 {
		summary.CompliantCount = summary.TotalScanned
	}

	report.Summary = summary
	return report, nil
}
