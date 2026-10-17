package lsm

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// LSMScanner orchestrates declarative manifest auditing, telemetry correlation, and compliance evaluation.
type LSMScanner struct {
	Feed       *intel.Feed
	StrictMode bool
}

// NewLSMScanner creates an initialized LSMScanner.
func NewLSMScanner(feed *intel.Feed) *LSMScanner {
	return &LSMScanner{
		Feed:       feed,
		StrictMode: false,
	}
}

// ScanManifestPath audits a single file or directory for NixOS and Kubernetes LSM security configurations.
func (s *LSMScanner) ScanManifestPath(manifestPath string) (*LSMAuditReport, error) {
	cleanPath := filepath.Clean(manifestPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect path (%s): %w", cleanPath, err)
	}

	report := &LSMAuditReport{
		Timestamp:  time.Now().UTC(),
		Configs:    make([]NixOSLSMConfig, 0),
		Profiles:   make([]ContainerMACProfile, 0),
		Telemetry:  make([]LSMTelemetryEvent, 0),
		Violations: make([]LSMViolation, 0),
	}

	if !info.IsDir() {
		if err := s.scanFile(cleanPath, report); err != nil {
			return nil, err
		}
	} else {
		err := filepath.Walk(cleanPath, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".nix" || ext == ".yaml" || ext == ".yml" {
				return s.scanFile(path, report)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to traverse directory (%s): %w", cleanPath, err)
		}
	}

	report.Summary = s.ComputeSummary(report.Violations, report.Configs, report.Profiles, report.Telemetry)
	return report, nil
}

func (s *LSMScanner) scanFile(filePath string, report *LSMAuditReport) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file (%s): %w", filePath, err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	content := string(data)

	if ext == ".nix" {
		cfg, err := ParseNixOSLSMConfig(content, filePath)
		if err != nil {
			return fmt.Errorf("failed to parse nixos lsm config: %w", err)
		}
		report.Configs = append(report.Configs, *cfg)
		v := AuditNixOSLSM(cfg, filePath, s.Feed)
		report.Violations = append(report.Violations, v...)
	} else if ext == ".yaml" || ext == ".yml" {
		profiles, err := ParseK8sMACProfile(content, filePath)
		if err != nil {
			return fmt.Errorf("failed to parse k8s mac profiles: %w", err)
		}
		report.Profiles = append(report.Profiles, profiles...)
		v := AuditMACProfiles(profiles, filePath, s.Feed)
		report.Violations = append(report.Violations, v...)
	}

	return nil
}

// ScanTelemetryPath parses and audits runtime eBPF LSM telemetry events.
func (s *LSMScanner) ScanTelemetryPath(telemetryPath string) ([]LSMTelemetryEvent, error) {
	cleanPath := filepath.Clean(telemetryPath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file (%s): %w", cleanPath, err)
	}

	events, err := ParseLSMTelemetryJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse telemetry json: %w", err)
	}

	return events, nil
}

// ComputeSummary compiles aggregate metrics and calculates deterministic compliance posture scores.
func (s *LSMScanner) ComputeSummary(violations []LSMViolation, nixConfigs []NixOSLSMConfig, profiles []ContainerMACProfile, telemetry []LSMTelemetryEvent) LSMSummary {
	sum := LSMSummary{
		TotalInspected:  len(nixConfigs) + len(profiles) + len(telemetry),
		TotalViolations: len(violations),
		MACProfileCount: len(profiles),
	}

	for _, cfg := range nixConfigs {
		if cfg.BPFLSMEnabled {
			sum.BPFLSMActive = true
			break
		}
	}

	score := 100.0
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			sum.CriticalCount++
			score -= 20.0
		case intel.SeverityHigh:
			sum.HighCount++
			score -= 10.0
		case intel.SeverityMedium:
			sum.MediumCount++
			score -= 5.0
		case intel.SeverityLow:
			sum.LowCount++
			score -= 2.0
		}
	}

	for _, t := range telemetry {
		if t.Blocked {
			sum.BlockedTelemetryCount++
		}
	}

	if score < 0.0 {
		score = 0.0
	}
	sum.LSMScore = math.Round(score*10) / 10

	switch {
	case sum.LSMScore >= 90.0:
		sum.Status = "COMPLIANT"
	case sum.LSMScore >= 70.0:
		sum.Status = "WARNING"
	default:
		sum.Status = "NON_COMPLIANT"
	}

	return sum
}
