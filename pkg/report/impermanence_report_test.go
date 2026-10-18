package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/impermanence"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestImpermanenceSARIFAndJSONExport(t *testing.T) {
	violations := []impermanence.ImpermanenceViolation{
		{
			RuleID:      "IMP-ROOT-003",
			HostName:    "k8s-node-nixos-vuln-01",
			TargetPath:  "swapDevices",
			Title:       "Unencrypted Swap Partition Enabled Risking Transient Secret Leakage to Disk",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.1,
			Description: "Host enables unencrypted swap devices, risking transient secret memory leakage to disk (CVE-2026-61842)",
			Remediation: "Enable random swap encryption via swapDevices.*.randomEncryption = true",
			MatchedCVE:  "CVE-2026-61842",
			FilePath:    "fixtures/nixos-impermanence-vulnerable.nix",
			StartLine:   18,
		},
	}

	summary := &impermanence.ImpermanenceSummary{
		TotalHostsScanned:    2,
		CompliantHosts:       1,
		EphemeralRootCount:   1,
		MutableRootCount:     1,
		UnencryptedSwapCount: 1,
		CriticalCount:        1,
		ComplianceScore:      75.0,
		HighRiskHostNames:    []string{"k8s-node-nixos-vuln-01"},
	}

	opts := ReportOptions{
		Version:                "0.26.0",
		ImpermanenceViolations: violations,
		ImpermanenceSummary:    summary,
		ImpermanencePath:       "fixtures/nixos-impermanence-vulnerable.nix",
		Pretty:                 true,
	}

	// 1. Verify SARIF Generation
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed: %v", err)
	}

	if len(sarifLog.Runs) != 1 || len(sarifLog.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 SARIF result, got %d", len(sarifLog.Runs[0].Results))
	}

	res := sarifLog.Runs[0].Results[0]
	if res.RuleID != "IMP-ROOT-003" || res.Level != "error" {
		t.Errorf("unexpected SARIF result: rule=%s, level=%s", res.RuleID, res.Level)
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "IMP-ROOT-003") {
		t.Errorf("SARIF output missing IMP-ROOT-003")
	}

	// 2. Verify JSON Audit Report
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}

	if jsonReport.ToolVersion != "0.26.0" {
		t.Errorf("expected version 0.26.0, got %s", jsonReport.ToolVersion)
	}
	if len(jsonReport.ImpermanenceViolations) != 1 {
		t.Errorf("expected 1 Impermanence violation, got %d", len(jsonReport.ImpermanenceViolations))
	}
	if jsonReport.ImpermanenceSummary == nil || jsonReport.ImpermanenceSummary.ComplianceScore != 75.0 {
		t.Errorf("unexpected Impermanence summary in JSON report: %+v", jsonReport.ImpermanenceSummary)
	}

	jsonBytes, err := json.Marshal(jsonReport)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "CVE-2026-61842") {
		t.Errorf("JSON output missing CVE-2026-61842")
	}

	// 3. Verify Threat Briefing Synthesis
	briefingOpts := BriefingOptions{
		Title:                  "Test Impermanence Threat Briefing",
		Version:                "0.26.0",
		HourlyWindow:           time.Now().UTC(),
		ImpermanenceViolations: violations,
		ImpermanenceSummary:    summary,
	}

	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}

	if !strings.Contains(briefing.Content, "NixOS Immutable Root & Impermanence Ephemerality Radar") {
		t.Errorf("briefing missing Impermanence Radar section")
	}
	if !strings.Contains(briefing.Content, "IMP-ROOT-003") {
		t.Errorf("briefing missing IMP-ROOT-003 finding")
	}
	if !strings.Contains(briefing.Content, "CVE-2026-61842") {
		t.Errorf("briefing missing CVE-2026-61842")
	}
}
