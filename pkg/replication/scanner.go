package replication

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// ReplicationScanner coordinates manifest scanning, telemetry reconciliation, and DR scoring.
type ReplicationScanner struct {
	feed *intel.Feed
}

// NewReplicationScanner constructs a new scanner instance.
func NewReplicationScanner(feed *intel.Feed) *ReplicationScanner {
	return &ReplicationScanner{feed: feed}
}

// ScanFile audits a single manifest file and returns violations and summary.
func (s *ReplicationScanner) ScanFile(filePath string) ([]ReplicationViolation, *ReplicationSummary, error) {
	manifests, err := ParseManifestFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse manifest file (%s): %w", filePath, err)
	}

	violations := AuditManifests(manifests, s.feed)
	summary := ComputeSummary(manifests, nil, violations)
	return violations, summary, nil
}

// ScanDirectory walks a directory tree and audits all YAML and JSON manifest files.
func (s *ReplicationScanner) ScanDirectory(dirPath string) (*ReplicationAuditReport, error) {
	report := &ReplicationAuditReport{}
	mergedManifests := &ParsedDRManifests{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		manifests, parseErr := ParseManifestFile(path)
		if parseErr != nil {
			// Skip non-k8s json/yaml gracefully
			return nil
		}

		report.TotalFiles++
		mergedManifests.SnapshotClasses = append(mergedManifests.SnapshotClasses, manifests.SnapshotClasses...)
		mergedManifests.SnapshotSchedules = append(mergedManifests.SnapshotSchedules, manifests.SnapshotSchedules...)
		mergedManifests.ReplicationClasses = append(mergedManifests.ReplicationClasses, manifests.ReplicationClasses...)
		mergedManifests.VolumeReplications = append(mergedManifests.VolumeReplications, manifests.VolumeReplications...)
		mergedManifests.MirrorDaemons = append(mergedManifests.MirrorDaemons, manifests.MirrorDaemons...)
		mergedManifests.ArbiterConfigs = append(mergedManifests.ArbiterConfigs, manifests.ArbiterConfigs...)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk manifest directory (%s): %w", dirPath, err)
	}

	report.Violations = AuditManifests(mergedManifests, s.feed)
	report.Summary = ComputeSummary(mergedManifests, nil, report.Violations)
	return report, nil
}

// ReconcileTelemetry parses and audits live cross-region disaster recovery telemetry.
func (s *ReplicationScanner) ReconcileTelemetry(telemetryPath string) (*CrossRegionDRTelemetry, []ReplicationViolation, error) {
	info, err := os.Stat(telemetryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat telemetry file (%s): %w", telemetryPath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, nil, fmt.Errorf("telemetry file exceeds max size ceiling (%d bytes)", info.Size())
	}

	content, err := os.ReadFile(telemetryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read telemetry file: %w", err)
	}

	telemetry, err := ParseCrossRegionDRTelemetry(content)
	if err != nil {
		return nil, nil, err
	}

	violations := AuditTelemetry(telemetry, s.feed)
	return telemetry, violations, nil
}

// AuditAll performs end-to-end audit across manifests and telemetry.
func (s *ReplicationScanner) AuditAll(manifestPath, telemetryPath string) (*ReplicationAuditReport, error) {
	report := &ReplicationAuditReport{}
	var manifests *ParsedDRManifests

	if manifestPath != "" {
		info, err := os.Stat(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect manifest path: %w", err)
		}
		if info.IsDir() {
			rep, walkErr := s.ScanDirectory(manifestPath)
			if walkErr != nil {
				return nil, walkErr
			}
			report.TotalFiles = rep.TotalFiles
			report.Violations = append(report.Violations, rep.Violations...)
		} else {
			m, pErr := ParseManifestFile(manifestPath)
			if pErr != nil {
				return nil, pErr
			}
			manifests = m
			report.TotalFiles = 1
			report.Violations = append(report.Violations, AuditManifests(manifests, s.feed)...)
		}
	}

	if telemetryPath != "" {
		telem, tViolations, tErr := s.ReconcileTelemetry(telemetryPath)
		if tErr != nil {
			return nil, tErr
		}
		report.Telemetry = telem
		report.Violations = append(report.Violations, tViolations...)
	}

	report.Summary = ComputeSummary(manifests, report.Telemetry, report.Violations)
	return report, nil
}
