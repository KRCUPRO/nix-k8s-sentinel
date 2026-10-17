package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgfastpath"
)

func TestFastPathSARIFAndJSONExport(t *testing.T) {
	violations := []wgfastpath.WGFastPathViolation{
		{
			RuleID:        "WG-FAST-003",
			InterfaceName: "wg0",
			Title:         "Kernel Fast-Path Ring Buffer Saturation Exceeds Critical Threshold",
			Severity:      intel.SeverityHigh,
			CVSSScore:     8.1,
			Description:   "Ring buffer utilization exceeds 85% on 100GbE interconnect",
			Remediation:   "Increase ring buffer to 4096 via ethtool -G rx 4096 tx 4096",
			MatchedCVE:    "CVE-2026-31049",
			FilePath:      "fixtures/nixos-wg-fastpath-vulnerable.nix",
			StartLine:     15,
		},
	}

	summary := &wgfastpath.WGFastPathSummary{
		TotalInterfacesAudited: 1,
		TotalTelemetrySamples:  2,
		ViolationsCount:        1,
		HighCount:              1,
		ComplianceScore:        85.0,
		BottleneckInterfaces:   []string{"wg0"},
	}

	opts := ReportOptions{
		Version:              "0.23.0",
		FastPathViolations:   violations,
		FastPathSummary:      summary,
		FastPathManifestPath: "fixtures/nixos-wg-fastpath-vulnerable.nix",
		Pretty:               true,
	}

	// 1. Verify SARIF
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed: %v", err)
	}

	if len(sarifLog.Runs) != 1 || len(sarifLog.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 SARIF result, got %d", len(sarifLog.Runs[0].Results))
	}

	res := sarifLog.Runs[0].Results[0]
	if res.RuleID != "WG-FAST-003" || res.Level != "error" {
		t.Errorf("unexpected SARIF result: %+v", res)
	}
	if !strings.Contains(res.Message.Text, "CVE-2026-31049") {
		t.Errorf("expected SARIF message to contain CVE-2026-31049, got %s", res.Message.Text)
	}

	// 2. Verify JSON report
	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}

	if len(jsonRep.FastPathViolations) != 1 {
		t.Fatalf("expected 1 FastPath violation in JSON report, got %d", len(jsonRep.FastPathViolations))
	}
	if jsonRep.FastPathSummary == nil || jsonRep.FastPathSummary.ComplianceScore != 85.0 {
		t.Errorf("unexpected summary in JSON report: %+v", jsonRep.FastPathSummary)
	}
	if jsonRep.Telemetry.TotalFastPathViolations != 1 {
		t.Errorf("expected TotalFastPathViolations to be 1, got %d", jsonRep.Telemetry.TotalFastPathViolations)
	}

	rawJSON, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(rawJSON, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal JSON report: %v", err)
	}
}

func TestFastPathBriefingReport(t *testing.T) {
	violations := []wgfastpath.WGFastPathViolation{
		{
			RuleID:        "WG-FAST-001",
			InterfaceName: "wg-core",
			Title:         "Kernel ChaCha20-Poly1305 Scalar Fallback",
			Severity:      intel.SeverityHigh,
			CVSSScore:     7.5,
			Description:   "Running scalar fallback lacking AVX-512 acceleration",
			Remediation:   "Enable AVX-512 in boot.kernelParams",
		},
	}

	summary := &wgfastpath.WGFastPathSummary{
		TotalInterfacesAudited: 1,
		ViolationsCount:        1,
		HighCount:              1,
		AVX512Accelerated:      false,
		ComplianceScore:        85.0,
		BottleneckInterfaces:   []string{"wg-core"},
	}

	opts := BriefingOptions{
		Version:            "0.23.0",
		HourlyWindow:       time.Date(2026, 10, 17, 23, 0, 0, 0, time.UTC),
		FastPathViolations: violations,
		FastPathSummary:    summary,
	}

	rep, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}

	if !strings.Contains(rep.Content, "WireGuard eBPF Kernel Fast-Path & Crypto Performance Posture") {
		t.Errorf("briefing missing Fast-Path section:\n%s", rep.Content)
	}
	if !strings.Contains(rep.Content, "WG-FAST-001") || !strings.Contains(rep.Content, "wg-core") {
		t.Errorf("briefing missing violation details:\n%s", rep.Content)
	}
	if !strings.Contains(rep.Content, "Profile WireGuard kernel cryptographic throughput") {
		t.Errorf("briefing missing SecOps checklist item:\n%s", rep.Content)
	}
}
