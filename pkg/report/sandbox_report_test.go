package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sandbox"
)

func TestSandboxReportSerialization(t *testing.T) {
	vios := []sandbox.SandboxViolation{
		{
			RuleID:      "SANDBOX-DET-002",
			Title:       "Unrestricted MicroVM Network Egress Detected",
			Severity:    "CRITICAL",
			CVSSScore:   9.2,
			Target:      "microvm/runner-01/network",
			Description: "MicroVM 'runner-01' has unrestricted egress network access enabled",
			Remediation: "Enforce strict TAP device firewall drop rules",
			MatchedCVE:  "CVE-2026-97105",
			RawContext:  "egressIsolated: false",
			LineNumber:  14,
		},
		{
			RuleID:      "SANDBOX-DET-003",
			Title:       "MicroVM Jailer Daemon and Chroot Isolation Disabled",
			Severity:    "HIGH",
			CVSSScore:   8.8,
			Target:      "microvm/runner-01",
			Description: "MicroVM 'runner-01' executed without jailer chroot",
			Remediation: "Enable Firecracker jailer daemon",
			RawContext:  "jailer: false",
			LineNumber:  10,
		},
	}

	summary := &sandbox.SandboxSummary{
		TotalMicroVMsScanned: 2,
		TotalDetonations:     3,
		TotalHoneypotHits:    4,
		ViolationsCount:      2,
		QuarantinedCount:     1,
		CleanCount:           1,
		SandboxSecurityScore: 76.0,
		AuditStatus:          "WARNING",
	}

	opts := ReportOptions{
		Version:           "0.19.0",
		SandboxViolations: vios,
		SandboxSummary:    summary,
		SandboxPath:       "fixtures/nixos-microvm-vulnerable.nix",
	}

	// 1. Verify SARIF serialization
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report: %v", err)
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(sarifLog.Runs[0].Results))
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("failed to format SARIF: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "SANDBOX-DET-002") {
		t.Errorf("SARIF report missing SANDBOX-DET-002")
	}
	if !strings.Contains(string(sarifBytes), "CVE-2026-97105") {
		t.Errorf("SARIF report missing CVE-2026-97105")
	}

	// 2. Verify JSON serialization
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}
	if len(jsonReport.SandboxViolations) != 2 {
		t.Fatalf("expected 2 sandbox violations in JSON report, got %d", len(jsonReport.SandboxViolations))
	}
	if jsonReport.SandboxSummary == nil || jsonReport.SandboxSummary.SandboxSecurityScore != 76.0 {
		t.Errorf("expected 76.0 sandbox security score in JSON report, got %+v", jsonReport.SandboxSummary)
	}

	jsonBytes, err := FormatJSON(jsonReport, true)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	var roundtrip JSONAuditReport
	if err := json.Unmarshal(jsonBytes, &roundtrip); err != nil {
		t.Fatalf("failed to unmarshal JSON roundtrip: %v", err)
	}
	if roundtrip.Telemetry.TotalSandboxViolations != 2 {
		t.Errorf("expected 2 total sandbox violations in telemetry summary, got %d", roundtrip.Telemetry.TotalSandboxViolations)
	}

	// 3. Verify Threat Briefing synthesis
	briefingOpts := BriefingOptions{
		Version:           "0.19.0",
		HourlyWindow:      time.Now(),
		SandboxViolations: vios,
		SandboxSummary:    summary,
	}

	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate threat briefing: %v", err)
	}
	if !strings.Contains(briefing.Content, "Ephemeral MicroVM Sandbox Detonation & Honeypot Telemetry") {
		t.Errorf("briefing missing sandbox detonation section")
	}
	if !strings.Contains(briefing.Content, "SANDBOX-DET-002") {
		t.Errorf("briefing missing SANDBOX-DET-002 violation")
	}
	if !strings.Contains(briefing.Content, "CVE-2026-97105") {
		t.Errorf("briefing missing CVE-2026-97105 tag")
	}
}
