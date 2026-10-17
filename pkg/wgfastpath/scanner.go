package wgfastpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// ScanFastPath scans declarative configuration manifests and telemetry to produce a complete audit report.
func ScanFastPath(
	manifestPath string,
	telemetryPath string,
	strictMode bool,
	feed *intel.Feed,
) (*WGFastPathAuditReport, error) {
	var allConfigs []WireGuardInterfaceFastPathConfig
	var allTelemetry []FastPathTelemetry
	var allCryptoTelemetry []CryptoBenchmarkTelemetry

	// 1. Scan declarative manifests if path provided
	if manifestPath != "" {
		info, err := os.Stat(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to access manifest path: %w", err)
		}

		if info.IsDir() {
			err := filepath.Walk(manifestPath, func(path string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".nix" || ext == ".yaml" || ext == ".yml" {
					cfgs, err := ParseFastPathManifest(path)
					if err == nil {
						allConfigs = append(allConfigs, cfgs...)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("directory walk failed: %w", err)
			}
		} else {
			cfgs, err := ParseFastPathManifest(manifestPath)
			if err != nil {
				return nil, fmt.Errorf("failed to parse manifest file: %w", err)
			}
			allConfigs = append(allConfigs, cfgs...)
		}
	}

	// 2. Scan telemetry if path provided
	if telemetryPath != "" {
		telemetry, cryptoTelemetry, err := ParseFastPathTelemetry(telemetryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse telemetry file: %w", err)
		}
		allTelemetry = append(allTelemetry, telemetry...)
		allCryptoTelemetry = append(allCryptoTelemetry, cryptoTelemetry...)
	}

	// 3. Audit
	violations, summary := AuditFastPath(allConfigs, allTelemetry, allCryptoTelemetry, strictMode, feed)

	report := &WGFastPathAuditReport{
		Timestamp:       time.Now().UTC(),
		Configurations:  allConfigs,
		Telemetry:       allTelemetry,
		CryptoTelemetry: allCryptoTelemetry,
		Violations:      violations,
		Summary:         summary,
	}

	return report, nil
}
