package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
)

func TestBuildJSONReport_Comprehensive(t *testing.T) {
	feed := &intel.Feed{
		UpdatedAt: time.Now().UTC(),
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-21801",
				Title:       "Ingress-Nginx Lua Directive Injection",
				Component:   "ingress-nginx",
				Target:      "kubernetes",
				Severity:    intel.SeverityCritical,
				CVSSScore:   9.8,
				Description: "Arbitrary code execution via lua snippets",
				Mitigation:  "Upgrade to v1.12.0+",
			},
			{
				ID:          "CVE-2026-19402",
				Title:       "Nix Daemon Sandbox Egress",
				Component:   "nix",
				Target:      "nixos",
				Severity:    intel.SeverityHigh,
				CVSSScore:   8.5,
				Description: "Pure eval escape",
				Mitigation:  "Apply pure evaluation sandbox patch",
			},
		},
	}

	k8sReport := &k8s.ManifestAuditReport{
		TotalFiles:     1,
		TotalResources: 1,
		Violations: []k8s.Violation{
			{
				RuleID:       "K8S-ING-001",
				Title:        "Ingress Snippet Injection",
				ResourceKind: "Ingress",
				ResourceName: "demo",
				Namespace:    "default",
				Severity:     intel.SeverityCritical,
				CVSSScore:    9.8,
				Description:  "Dangerous configuration-snippet annotation",
				Remediation:  "Disable snippets",
			},
		},
	}

	flakeMatches := []nix.FlakeVulnerabilityMatch{
		{
			AdvisoryID:     "CVE-2026-19402",
			DependencyName: "nixpkgs",
			NodeKey:        "nixpkgs_unstable",
			InstalledRev:   "9a8b7c6d",
			Severity:       intel.SeverityHigh,
			CVSSScore:      8.5,
			Title:          "Nix Daemon Sandbox Egress",
			Mitigation:     "Upgrade input",
		},
	}

	opts := ReportOptions{
		Version:      "0.6.0",
		Feed:         feed,
		K8sReport:    k8sReport,
		FlakeMatches: flakeMatches,
		FlakePath:    "fixtures/flake.lock",
		K8sPath:      "fixtures/k8s-ingress-vulnerable.yaml",
		TargetFilter: "kubernetes",
		Pretty:       true,
	}

	rep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}

	if rep.ToolName != "nix-k8s-sentinel" {
		t.Errorf("expected tool_name nix-k8s-sentinel, got %s", rep.ToolName)
	}
	if rep.ToolVersion != "0.6.0" {
		t.Errorf("expected tool_version 0.6.0, got %s", rep.ToolVersion)
	}
	if rep.Telemetry.TotalThreats != 2 {
		t.Errorf("expected 2 total threats in telemetry, got %d", rep.Telemetry.TotalThreats)
	}
	if rep.Telemetry.TotalViolations != 1 {
		t.Errorf("expected 1 violation in telemetry, got %d", rep.Telemetry.TotalViolations)
	}
	if rep.Telemetry.TotalFlakeMatches != 1 {
		t.Errorf("expected 1 flake match in telemetry, got %d", rep.Telemetry.TotalFlakeMatches)
	}
	if len(rep.ScannedPaths) != 2 {
		t.Errorf("expected 2 scanned paths, got %d", len(rep.ScannedPaths))
	}
	// Filtered by target "kubernetes": 1 advisory
	if len(rep.ThreatAdvisories) != 1 {
		t.Errorf("expected 1 advisory matching 'kubernetes', got %d", len(rep.ThreatAdvisories))
	}
}

func TestFormatJSON_And_WriteJSONToFile(t *testing.T) {
	opts := ReportOptions{
		Version: "0.6.0",
	}

	rep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}

	// 1. Test Pretty Formatting
	prettyData, err := FormatJSON(rep, true)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}

	var parsed JSONAuditReport
	if err := json.Unmarshal(prettyData, &parsed); err != nil {
		t.Fatalf("invalid json produced: %v", err)
	}
	if parsed.ToolName != "nix-k8s-sentinel" {
		t.Errorf("expected tool_name nix-k8s-sentinel, got %s", parsed.ToolName)
	}

	// 2. Test Compact Formatting
	compactData, err := FormatJSON(rep, false)
	if err != nil {
		t.Fatalf("failed to format compact JSON: %v", err)
	}
	if len(compactData) >= len(prettyData) {
		t.Errorf("expected compact JSON length (%d) to be smaller than pretty (%d)", len(compactData), len(prettyData))
	}

	// 3. Test Disk Persistence
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "audit-out", "audit.json")

	if err := WriteJSONToFile(rep, outPath, true); err != nil {
		t.Fatalf("failed to write JSON file: %v", err)
	}

	readBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed reading written file: %v", err)
	}
	if len(readBytes) == 0 {
		t.Error("written JSON file was empty")
	}
}
