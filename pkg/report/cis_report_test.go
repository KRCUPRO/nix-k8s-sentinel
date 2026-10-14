package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestBuildSARIFReport_CISViolations(t *testing.T) {
	cisViolations := []bench.CISViolation{
		{
			RuleID:        "CIS-4.2.1",
			Section:       "4.2",
			Component:     bench.ComponentKubelet,
			Title:         "Ensure that the --anonymous-auth argument is set to false",
			Description:   "Anonymous access allows unauthenticated requests to Kubelet API",
			Severity:      intel.SeverityCritical,
			CVSSScore:     9.8,
			FlagName:      "anonymous-auth",
			ActualValue:   "true",
			ExpectedValue: "false",
			Remediation:   "Set --anonymous-auth=false",
			FilePath:      "fixtures/nixos-kubernetes.nix",
			StartLine:     45,
			MatchedCVE:    "CVE-2026-38102",
		},
		{
			RuleID:        "CIS-4.2.4",
			Section:       "4.2",
			Component:     bench.ComponentKubelet,
			Title:         "Ensure that the --read-only-port argument is set to 0",
			Description:   "Port 10255 serves unauthenticated pod and node metrics",
			Severity:      intel.SeverityHigh,
			CVSSScore:     7.5,
			FlagName:      "read-only-port",
			ActualValue:   "10255",
			ExpectedValue: "0",
			Remediation:   "Set --read-only-port=0",
			FilePath:      "fixtures/nixos-kubernetes.nix",
			StartLine:     46,
		},
	}

	opts := ReportOptions{
		Version:       "0.10.0",
		CISViolations: cisViolations,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF with CIS violations: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 CIS SARIF results, got %d", len(run.Results))
	}

	for _, res := range run.Results {
		if res.Level != "error" {
			t.Errorf("expected error level for high/critical CIS violations, got %s", res.Level)
		}
	}
}

func TestBuildJSONReport_CISViolations(t *testing.T) {
	cisViolations := []bench.CISViolation{
		{
			RuleID:        "CIS-1.2.1",
			Section:       "1.2",
			Component:     bench.ComponentAPIServer,
			Title:         "Disable anonymous auth on apiserver",
			Severity:      intel.SeverityCritical,
			CVSSScore:     9.1,
			FlagName:      "anonymous-auth",
			ActualValue:   "true",
			ExpectedValue: "false",
			FilePath:      "fixtures/nixos-kubernetes.nix",
			StartLine:     18,
		},
	}

	summary := &bench.CISSummary{
		TotalChecks:     20,
		PassedChecks:    19,
		FailedChecks:    1,
		ComplianceScore: 95.0,
		CriticalCount:   1,
	}

	opts := ReportOptions{
		Version:       "0.10.0",
		CISViolations: cisViolations,
		CISSummary:    summary,
		CISPath:       "fixtures/nixos-kubernetes.nix",
		Pretty:        true,
	}

	rep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report with CIS violations: %v", err)
	}

	if len(rep.CISViolations) != 1 {
		t.Errorf("expected 1 CIS violation, got %d", len(rep.CISViolations))
	}
	if rep.CISSummary == nil || rep.CISSummary.ComplianceScore != 95.0 {
		t.Errorf("expected 95.0%% compliance score, got %+v", rep.CISSummary)
	}
	if rep.Telemetry.TotalCISViolations != 1 {
		t.Errorf("expected 1 TotalCISViolations in telemetry, got %d", rep.Telemetry.TotalCISViolations)
	}

	data, err := FormatJSON(rep, true)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse formatted JSON: %v", err)
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "cis-audit.json")
	if err := WriteJSONToFile(rep, outPath, true); err != nil {
		t.Fatalf("failed to write JSON report to file: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("expected output file to exist: %v", err)
	}
}
