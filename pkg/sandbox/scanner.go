package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// SandboxScanner coordinates declarative manifest parsing, directory walking, telemetry auditing, and scoring.
type SandboxScanner struct {
	feed *intel.Feed
}

// NewSandboxScanner creates a new SandboxScanner bound to an optional threat intelligence feed.
func NewSandboxScanner(feed *intel.Feed) *SandboxScanner {
	return &SandboxScanner{
		feed: feed,
	}
}

// ScanPath scans a file or directory for declarative NixOS microVM and Kubernetes detonation manifests.
func (s *SandboxScanner) ScanPath(targetPath string) (*SandboxAuditReport, error) {
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", targetPath, err)
	}

	var allConfigs []MicroVMConfig

	if info.IsDir() {
		err := filepath.Walk(targetPath, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".nix" {
				cfgs, err := ParseNixOSMicroVMConfig(p)
				if err == nil && len(cfgs) > 0 {
					allConfigs = append(allConfigs, cfgs...)
				}
			} else if ext == ".yaml" || ext == ".yml" {
				cfgs, err := ParseK8sDetonationJob(p)
				if err == nil && len(cfgs) > 0 {
					allConfigs = append(allConfigs, cfgs...)
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("directory walk failed for %s: %w", targetPath, err)
		}
	} else {
		ext := strings.ToLower(filepath.Ext(targetPath))
		if ext == ".nix" {
			cfgs, err := ParseNixOSMicroVMConfig(targetPath)
			if err != nil {
				return nil, err
			}
			allConfigs = append(allConfigs, cfgs...)
		} else if ext == ".yaml" || ext == ".yml" {
			cfgs, err := ParseK8sDetonationJob(targetPath)
			if err != nil {
				return nil, err
			}
			allConfigs = append(allConfigs, cfgs...)
		} else {
			return nil, fmt.Errorf("unsupported file extension for sandbox scan: %s", ext)
		}
	}

	var violations []SandboxViolation
	for _, cfg := range allConfigs {
		v := AuditMicroVMConfig(cfg, s.feed)
		violations = append(violations, v...)
	}

	summary := ComputeSandboxSummary(len(allConfigs), 0, 0, violations, 0, len(allConfigs))

	return &SandboxAuditReport{
		MicroVMConfigs:      allConfigs,
		Violations:          violations,
		Summary:             summary,
		ThreatFeedReference: s.feed,
	}, nil
}

// ScanTelemetryFile scans runtime detonation and honeypot interaction telemetry.
func (s *SandboxScanner) ScanTelemetryFile(telemetryPath string) (*SandboxAuditReport, error) {
	telemetries, err := ParseDetonationTelemetryJSON(telemetryPath)
	if err != nil {
		return nil, fmt.Errorf("telemetry parsing error: %w", err)
	}

	var violations []SandboxViolation
	totalHoneypotHits := 0
	quarantinedCount := 0
	cleanCount := 0

	for _, t := range telemetries {
		v := AuditDetonationTelemetry(t, s.feed)
		violations = append(violations, v...)
		totalHoneypotHits += len(t.HoneypotHits)

		if t.Status == StatusQuarantined || t.QuarantineEnforced || len(v) > 0 {
			quarantinedCount++
		} else if t.Status == StatusClean {
			cleanCount++
		}
	}

	summary := ComputeSandboxSummary(0, len(telemetries), totalHoneypotHits, violations, quarantinedCount, cleanCount)

	return &SandboxAuditReport{
		DetonationTelemetries: telemetries,
		Violations:            violations,
		Summary:               summary,
		ThreatFeedReference:   s.feed,
	}, nil
}

// ComputeSandboxSummary aggregates all summary statistics into a single SandboxSummary.
func ComputeSandboxSummary(totalVMs, totalDetonations, totalHits int, violations []SandboxViolation, quarantined, clean int) SandboxSummary {
	score, status := ComputeSandboxScore(totalVMs, totalDetonations, violations, quarantined)

	return SandboxSummary{
		TotalMicroVMsScanned: totalVMs,
		TotalDetonations:     totalDetonations,
		TotalHoneypotHits:    totalHits,
		ViolationsCount:      len(violations),
		QuarantinedCount:     quarantined,
		CleanCount:           clean,
		SandboxSecurityScore: score,
		AuditStatus:          status,
	}
}
