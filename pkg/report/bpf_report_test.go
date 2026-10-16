package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bpf"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestBPFReportSerialization(t *testing.T) {
	vios := []bpf.BPFViolation{
		{
			RuleID:       "BPF-SEC-001",
			Title:        "Unconfined Seccomp Profile in Workload Manifest",
			Severity:     intel.SeverityHigh,
			CVSSScore:    8.2,
			Description:  "Workload unhardened-worker explicitly sets seccompProfile type: Unconfined",
			Remediation:  "Set securityContext.seccompProfile.type: RuntimeDefault",
			ResourceURI:  "fixtures/k8s-bpf-workload.yaml",
			WorkloadName: "unhardened-worker",
			Namespace:    "untrusted-apps",
			StartLine:    1,
		},
		{
			RuleID:       "BPF-SEC-007",
			Title:        "Kernel BPF Subsystem Syscall Race & Unconfined Socket Flood Attack",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.8,
			Description:  "Correlated attack signature with CVE-2026-90412: Process burst socket allocation in raw socket domain",
			Remediation:  "Enforce unprivileged_bpf_disabled=1 and attach LSM socket_create filter",
			ResourceURI:  "fixtures/bpf-runtime-telemetry.json",
			WorkloadName: "packet-sniffer-bot",
			Namespace:    "untrusted-apps",
			StartLine:    1,
			MatchedCVE:   "CVE-2026-90412",
		},
	}

	summary := &bpf.BPFSummary{
		TotalProfilesScanned: 2,
		TotalTelemetryEvents: 6,
		ViolationsCount:      2,
		CriticalCount:        1,
		HighCount:            1,
		ComplianceScore:      60.0,
		AuditStatus:          "FAIL",
	}

	opts := ReportOptions{
		Version:          "0.17.0",
		BPFViolations:    vios,
		BPFSummary:       summary,
		BPFPath:          "fixtures/k8s-bpf-workload.yaml",
		BPFTelemetryPath: "fixtures/bpf-runtime-telemetry.json",
	}

	// 1. Validate SARIF Serialization
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed for BPF findings: %v", err)
	}
	if len(sarifLog.Runs) == 0 {
		t.Fatalf("expected at least 1 SARIF run")
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Errorf("expected 2 SARIF results for BPF violations, got %d", len(sarifLog.Runs[0].Results))
	}
	rule0 := sarifLog.Runs[0].Tool.Driver.Rules[0]
	if rule0.ID != "BPF-SEC-001" && rule0.ID != "BPF-SEC-007" {
		t.Errorf("unexpected SARIF rule ID: %s", rule0.ID)
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "CVE-2026-90412") {
		t.Errorf("expected SARIF output to contain CVE-2026-90412")
	}

	// 2. Validate JSON Report Compilation
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}
	if jsonReport.Telemetry.TotalBPFViolations != 2 {
		t.Errorf("expected 2 BPF violations in telemetry summary, got %d", jsonReport.Telemetry.TotalBPFViolations)
	}
	if len(jsonReport.BPFViolations) != 2 {
		t.Errorf("expected 2 BPF violations in JSON report, got %d", len(jsonReport.BPFViolations))
	}
	if jsonReport.BPFSummary == nil || jsonReport.BPFSummary.ComplianceScore != 60.0 {
		t.Errorf("expected BPFSummary compliance score 60.0 in JSON report")
	}

	rawJSON, err := json.Marshal(jsonReport)
	if err != nil {
		t.Fatalf("failed to marshal JSON report: %v", err)
	}
	if !strings.Contains(string(rawJSON), "BPF-SEC-007") {
		t.Errorf("expected raw JSON to contain BPF-SEC-007")
	}

	// 3. Validate Threat Intelligence Briefing Report
	briefOpts := BriefingOptions{
		Version:       "0.17.0",
		BPFViolations: vios,
		BPFSummary:    summary,
	}
	briefing, err := GenerateBriefing(briefOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}
	if !strings.Contains(briefing.Content, "Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter") {
		t.Errorf("expected briefing to include BPF profiler section")
	}
	if !strings.Contains(briefing.Content, "BPF-SEC-007") {
		t.Errorf("expected briefing to include BPF-SEC-007 finding")
	}
	if !strings.Contains(briefing.Content, "CVE-2026-90412") {
		t.Errorf("expected briefing to include CVE-2026-90412 reference")
	}
}
