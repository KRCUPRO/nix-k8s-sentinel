package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/lsm"
)

func TestLSMReportSerialization(t *testing.T) {
	violations := []lsm.LSMViolation{
		{
			RuleID:      "LSM-MAC-001",
			Severity:    intel.SeverityCritical,
			Resource:    "kernel.boot.params",
			File:        "fixtures/nixos-lsm-vulnerable.nix",
			Line:        5,
			Message:     "eBPF LSM is not declared in boot.kernelParams or security.lsm",
			Remediation: "Add 'bpf' to boot.kernelParams",
			MatchedCVE:  "CVE-2026-99103",
			CVSSScore:   9.8,
		},
		{
			RuleID:      "LSM-MAC-008",
			Severity:    intel.SeverityCritical,
			Resource:    "kube-system/vulnerable-privileged-daemon",
			File:        "fixtures/k8s-lsm-workload.yaml",
			Line:        1,
			Message:     "Privileged container declared without mandatory eBPF LSM MAC confinement profile",
			Remediation: "Attach a strict eBPF LSM MAC profile",
			MatchedCVE:  "CVE-2026-99103",
			CVSSScore:   9.6,
		},
	}

	summary := &lsm.LSMSummary{
		TotalInspected:       4,
		TotalViolations:      2,
		CriticalCount:        2,
		HighCount:            0,
		MediumCount:          0,
		LowCount:             0,
		LSMScore:             60.0,
		Status:               "NON_COMPLIANT",
		BPFLSMActive:         false,
		MACProfileCount:      2,
		BlockedTelemetryCount: 4,
	}

	opts := ReportOptions{
		Version:       "0.21.0",
		LSMViolations: violations,
		LSMSummary:    summary,
		LSMPath:       "fixtures/nixos-lsm-vulnerable.nix",
	}

	// 1. Verify JSON serialization
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("unexpected error building JSON report: %v", err)
	}
	if len(jsonReport.LSMViolations) != 2 {
		t.Errorf("expected 2 LSM violations in JSON report, got %d", len(jsonReport.LSMViolations))
	}
	if jsonReport.LSMSummary == nil || jsonReport.LSMSummary.LSMScore != 60.0 {
		t.Errorf("expected LSM score 60.0 in JSON report")
	}

	jsonData, err := FormatJSON(jsonReport, false)
	if err != nil {
		t.Fatalf("unexpected error formatting JSON: %v", err)
	}
	var unmarshaled JSONAuditReport
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal generated JSON: %v", err)
	}
	if len(unmarshaled.LSMViolations) != 2 {
		t.Errorf("expected 2 LSM violations after JSON roundtrip, got %d", len(unmarshaled.LSMViolations))
	}

	// 2. Verify SARIF v2.1.0 serialization
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("unexpected error building SARIF report: %v", err)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run in SARIF report")
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results in SARIF report, got %d", len(sarifLog.Runs[0].Results))
	}

	foundLSM001 := false
	foundLSM008 := false
	for _, res := range sarifLog.Runs[0].Results {
		if res.RuleID == "LSM-MAC-001" {
			foundLSM001 = true
			if res.Level != "error" {
				t.Errorf("expected error level for LSM-MAC-001, got %s", res.Level)
			}
		}
		if res.RuleID == "LSM-MAC-008" {
			foundLSM008 = true
		}
	}
	if !foundLSM001 || !foundLSM008 {
		t.Errorf("missing expected LSM rules in SARIF results")
	}

	// 3. Verify Threat Briefing Markdown serialization
	briefingOpts := BriefingOptions{
		Feed:          &intel.Feed{},
		LSMViolations: violations,
		LSMSummary:    summary,
		HourlyWindow:  time.Now().UTC(),
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("unexpected error generating briefing: %v", err)
	}
	if !strings.Contains(briefing.Content, "eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control") {
		t.Errorf("briefing markdown missing Section 20 eBPF LSM header")
	}
	if !strings.Contains(briefing.Content, "LSM-MAC-001") {
		t.Errorf("briefing markdown missing LSM-MAC-001")
	}
	if !strings.Contains(briefing.Content, "Attach eBPF LSM mandatory access control hooks") {
		t.Errorf("briefing markdown missing checklist entry")
	}
}
