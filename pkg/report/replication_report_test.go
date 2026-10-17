package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/replication"
)

func TestReplicationReportSerialization(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-10140",
				Title:     "CephFS Snapshot Desync & Volume Replication Split-Brain",
				Component: "cephfs-dr",
				Target:    "kubernetes",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.6,
			},
		},
	}

	repViolations := []replication.ReplicationViolation{
		{
			RuleID:       replication.RuleSnapshotClassDeletionPolicy,
			Title:        "VolumeSnapshotClass DeletionPolicy Set to Delete",
			ResourceKind: "VolumeSnapshotClass",
			ResourceName: "insecure-sc",
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.4,
			Description:  "Deletion policy set to Delete risking snapshot loss",
			Remediation:  "Configure deletionPolicy: Retain",
			File:         "fixtures/cephfs-dr-vulnerable.yaml",
			Line:         10,
		},
		{
			RuleID:       replication.RuleReplicationSplitBrain,
			Title:        "Cross-Region Volume Replication Split-Brain",
			ResourceKind: "VolumeReplicationStatus",
			ResourceName: "prod-db-vr",
			Namespace:    "production",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.6,
			MatchedCVE:   "CVE-2026-10140",
			Description:  "Dual Primary detected on both regions",
			Remediation:  "Demote secondary site and resynchronize",
			File:         "fixtures/cephfs-dr-telemetry.json",
			Line:         1,
		},
	}

	repSummary := &replication.ReplicationSummary{
		Score:                60.0,
		Status:               "NON_COMPLIANT",
		TotalManifests:       4,
		TotalSnapshotClasses: 1,
		TotalSchedules:       1,
		TotalReplications:    2,
		TotalViolations:      2,
		CriticalCount:        1,
		HighCount:            1,
		SplitBrainDetected:   true,
		MaxDeltaLagSeconds:   1200,
	}

	opts := ReportOptions{
		Version:               "0.22.0",
		Feed:                  feed,
		ReplicationViolations: repViolations,
		ReplicationSummary:    repSummary,
		DRManifestPath:        "fixtures/cephfs-dr-vulnerable.yaml",
		DRTelemetryPath:       "fixtures/cephfs-dr-telemetry.json",
	}

	// 1. Verify SARIF report generation
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed: %v", err)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(sarifLog.Runs))
	}
	run := sarifLog.Runs[0]
	if len(run.Results) != 2 {
		t.Errorf("expected 2 SARIF results, got %d", len(run.Results))
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "CEPH-DR-001") || !strings.Contains(string(sarifBytes), "CEPH-DR-010") {
		t.Errorf("SARIF output missing expected rule IDs")
	}

	// 2. Verify JSON report generation
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}
	if len(jsonReport.ReplicationViolations) != 2 {
		t.Errorf("expected 2 JSON replication violations, got %d", len(jsonReport.ReplicationViolations))
	}
	if jsonReport.ReplicationSummary == nil || !jsonReport.ReplicationSummary.SplitBrainDetected {
		t.Errorf("expected SplitBrainDetected in JSON report")
	}

	jsonBytes, err := json.Marshal(jsonReport)
	if err != nil {
		t.Fatalf("failed to marshal JSON report: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "CVE-2026-10140") {
		t.Errorf("JSON report missing CVE-2026-10140")
	}

	// 3. Verify Threat Briefing generation
	briefingOpts := BriefingOptions{
		Version:               "0.22.0",
		Feed:                  feed,
		ReplicationViolations: repViolations,
		ReplicationSummary:    repSummary,
		HourlyWindow:          time.Now().UTC(),
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}
	if !strings.Contains(briefing.Content, "CephFS Snapshot & Volume Replication Disaster Recovery Posture") {
		t.Errorf("Briefing missing Section 21 header")
	}
	if !strings.Contains(briefing.Content, "SPLIT-BRAIN DETECTED") {
		t.Errorf("Briefing missing split-brain alert badge")
	}
	if !strings.Contains(briefing.Content, "CEPH-DR-010") {
		t.Errorf("Briefing missing rule ID CEPH-DR-010")
	}
}
