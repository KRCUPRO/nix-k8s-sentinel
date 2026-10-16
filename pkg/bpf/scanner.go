package bpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// BPFScanner coordinates static manifest audits, NixOS host parameter checks, and runtime telemetry profiling.
type BPFScanner struct {
	Feed *intel.Feed
}

// NewBPFScanner creates an initialized scanner bound to an optional threat intelligence feed.
func NewBPFScanner(feed *intel.Feed) *BPFScanner {
	return &BPFScanner{Feed: feed}
}

// ScanPath inspects a single manifest file or walks a directory of Kubernetes/NixOS configurations.
func (s *BPFScanner) ScanPath(targetPath string) (*BPFAuditReport, error) {
	cleanPath := filepath.Clean(targetPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access bpf scan target %s: %w", cleanPath, err)
	}

	var allViolations []BPFViolation
	scannedPaths := []string{}
	totalProfiles := 0

	if !info.IsDir() {
		v, count, err := ParseManifestFile(cleanPath)
		if err != nil {
			return nil, err
		}
		allViolations = append(allViolations, v...)
		totalProfiles += count
		scannedPaths = append(scannedPaths, cleanPath)
	} else {
		err := filepath.Walk(cleanPath, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fi.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" && ext != ".nix" && ext != ".json" {
				return nil
			}

			v, count, err := ParseManifestFile(path)
			if err != nil {
				// Continue walking on parse errors for individual files
				return nil
			}
			allViolations = append(allViolations, v...)
			totalProfiles += count
			scannedPaths = append(scannedPaths, path)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk directory %s: %w", cleanPath, err)
		}
	}

	// Correlate with threat intelligence feed
	s.correlateThreatFeed(allViolations)

	summary := ComputeBPFSummary(totalProfiles, 0, allViolations)
	return &BPFAuditReport{
		ScannedPaths: scannedPaths,
		Violations:   allViolations,
		Summary:      summary,
		GeneratedAt:  time.Now().UTC(),
	}, nil
}

// ScanTelemetryFile evaluates a standalone runtime kernel telemetry JSON file.
func (s *BPFScanner) ScanTelemetryFile(telemetryPath string) (*BPFAuditReport, error) {
	cleanPath := filepath.Clean(telemetryPath)
	violations, eventCount, err := AuditRuntimeTelemetry(cleanPath, s.Feed)
	if err != nil {
		return nil, err
	}

	s.correlateThreatFeed(violations)

	summary := ComputeBPFSummary(1, eventCount, violations)
	return &BPFAuditReport{
		ScannedPaths: []string{cleanPath},
		Violations:   violations,
		Summary:      summary,
		GeneratedAt:  time.Now().UTC(),
	}, nil
}

// correlateThreatFeed enriches discovered violations with upstream CVE metadata where applicable.
func (s *BPFScanner) correlateThreatFeed(violations []BPFViolation) {
	if s.Feed == nil || len(s.Feed.Items) == 0 {
		return
	}

	for i := range violations {
		v := &violations[i]
		if v.MatchedCVE != "" {
			continue
		}

		for _, item := range s.Feed.Items {
			// Correlate kernel BPF or socket vulnerabilities (e.g. CVE-2026-90412)
			if item.ID == "CVE-2026-90412" && (v.RuleID == "BPF-SEC-001" || v.RuleID == "BPF-SEC-004" || v.RuleID == "BPF-SEC-007" || v.RuleID == "BPF-SEC-008") {
				v.MatchedCVE = item.ID
				break
			}
		}
	}
}
