package nixstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NixStoreScanner coordinates file scanning, streaming parsing, telemetry reconciliation, and compliance scoring.
type NixStoreScanner struct{}

// NewNixStoreScanner instantiates a new scanner for Nix Store & Binary Cache Isolation Gate.
func NewNixStoreScanner() *NixStoreScanner {
	return &NixStoreScanner{}
}

// ScanTarget inspects manifest paths (single file or recursive directory) and optional telemetry.
func (s *NixStoreScanner) ScanTarget(targetPath, telemetryPath string) (*StoreAuditReport, error) {
	report := &StoreAuditReport{
		Configs:    make([]StoreSecurityConfig, 0),
		Violations: make([]StoreViolation, 0),
		ScannedAt:  time.Now().UTC(),
	}

	// 1. Scan target manifests if provided
	if targetPath != "" {
		cleanTarget := filepath.Clean(targetPath)
		fileInfo, err := os.Stat(cleanTarget)
		if err != nil {
			return nil, fmt.Errorf("failed to access store configuration path (%s): %w", cleanTarget, err)
		}

		if fileInfo.IsDir() {
			err = filepath.Walk(cleanTarget, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".nix" || ext == ".conf" {
					cfg, parseErr := ParseNixStoreConfigFile(path)
					if parseErr == nil && cfg != nil {
						report.Configs = append(report.Configs, *cfg)
						violations := AuditStoreConfig(cfg)
						report.Violations = append(report.Violations, violations...)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to walk store configuration directory (%s): %w", cleanTarget, err)
			}
		} else {
			cfg, parseErr := ParseNixStoreConfigFile(cleanTarget)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse store configuration (%s): %w", cleanTarget, parseErr)
			}
			report.Configs = append(report.Configs, *cfg)
			violations := AuditStoreConfig(cfg)
			report.Violations = append(report.Violations, violations...)
		}
	}

	// 2. Reconcile runtime telemetry if provided
	if telemetryPath != "" {
		cleanTelemetry := filepath.Clean(telemetryPath)
		tel, telErr := ParseStoreTelemetryFile(cleanTelemetry)
		if telErr != nil {
			return nil, fmt.Errorf("failed to load nix store telemetry (%s): %w", cleanTelemetry, telErr)
		}
		report.Telemetry = tel
		telViolations := AuditStoreTelemetry(tel)
		report.Violations = append(report.Violations, telViolations...)
	}

	// 3. Compute overall compliance
	report.Summary = ComputeStoreCompliance(report.Violations, len(report.Configs), report.Telemetry)

	return report, nil
}
