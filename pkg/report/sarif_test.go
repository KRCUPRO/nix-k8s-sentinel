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
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
)

func TestBuildSARIFReport_EmptyFindings(t *testing.T) {
	opts := ReportOptions{
		Version: "0.6.0",
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("unexpected error building empty SARIF report: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if log.Schema != SARIFSchemaURI {
		t.Errorf("expected schema %s, got %s", SARIFSchemaURI, log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "nix-k8s-sentinel" {
		t.Errorf("expected driver name nix-k8s-sentinel, got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.6.0" {
		t.Errorf("expected driver version 0.6.0, got %s", run.Tool.Driver.Version)
	}
	if run.Results == nil {
		t.Error("expected non-nil results slice")
	}
	if len(run.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(run.Results))
	}
}

func TestBuildSARIFReport_K8sViolations(t *testing.T) {
	k8sReport := &k8s.ManifestAuditReport{
		TotalFiles:     1,
		TotalResources: 2,
		Violations: []k8s.Violation{
			{
				RuleID:       "K8S-ING-001",
				Title:        "Ingress Configuration Snippet Injection",
				ResourceKind: "Ingress",
				ResourceName: "web-gateway",
				Namespace:    "prod",
				Severity:     intel.SeverityCritical,
				CVSSScore:    9.8,
				Description:  "Dangerous configuration-snippet annotation detected",
				Remediation:  "Disable allow-snippet-annotations in controller ConfigMap",
				MatchedCVE:   "CVE-2023-5044",
				FilePath:     "manifests/ingress.yaml",
				StartLine:    14,
			},
			{
				RuleID:       "K8S-CNI-002",
				Title:        "Global Unrestricted Egress to 0.0.0.0/0",
				ResourceKind: "NetworkPolicy",
				ResourceName: "allow-all-egress",
				Namespace:    "default",
				Severity:     intel.SeverityHigh,
				CVSSScore:    8.2,
				Description:  "Egress rule permits outbound traffic to entire IPv4 address space",
				Remediation:  "Restrict egress CIDRs to authorized subnets",
				FilePath:     "manifests/netpol.yaml",
				StartLine:    8,
			},
			{
				RuleID:       "K8S-ING-005",
				Title:        "Ingress Plaintext HTTP Insecure Transport",
				ResourceKind: "Ingress",
				ResourceName: "public-api",
				Namespace:    "default",
				Severity:     intel.SeverityMedium,
				CVSSScore:    5.0,
				Description:  "SSL redirect is disabled",
				Remediation:  "Set ssl-redirect: 'true'",
				FilePath:     "manifests/api.yaml",
				StartLine:    1,
			},
		},
	}

	opts := ReportOptions{
		Version:   "0.6.0",
		K8sReport: k8sReport,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("expected 3 distinct rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Verify Rule 0 (Critical -> error)
	r0 := run.Results[0]
	if r0.RuleID != "K8S-ING-001" {
		t.Errorf("expected rule K8S-ING-001, got %s", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("expected level 'error' for critical severity, got %s", r0.Level)
	}
	if len(r0.Locations) == 0 || r0.Locations[0].PhysicalLocation == nil {
		t.Fatal("missing physical location for result 0")
	}
	loc0 := r0.Locations[0].PhysicalLocation
	if loc0.ArtifactLocation.URI != "manifests/ingress.yaml" {
		t.Errorf("expected URI manifests/ingress.yaml, got %s", loc0.ArtifactLocation.URI)
	}
	if loc0.Region.StartLine != 14 {
		t.Errorf("expected startLine 14, got %d", loc0.Region.StartLine)
	}

	// Verify Rule 2 (Medium -> warning)
	r2 := run.Results[2]
	if r2.RuleID != "K8S-ING-005" {
		t.Errorf("expected rule K8S-ING-005, got %s", r2.RuleID)
	}
	if r2.Level != "warning" {
		t.Errorf("expected level 'warning' for medium severity, got %s", r2.Level)
	}

	// Verify Driver Rule Properties
	ruleDef0 := run.Tool.Driver.Rules[0]
	if ruleDef0.Properties["security-severity"] != "9.8" {
		t.Errorf("expected security-severity '9.8', got %v", ruleDef0.Properties["security-severity"])
	}
	if ruleDef0.DefaultConfiguration.Level != "error" {
		t.Errorf("expected default level 'error', got %s", ruleDef0.DefaultConfiguration.Level)
	}
}

func TestBuildSARIFReport_FlakeMatches(t *testing.T) {
	flakeMatches := []nix.FlakeVulnerabilityMatch{
		{
			AdvisoryID:     "CVE-2026-19402",
			DependencyName: "nixpkgs",
			NodeKey:        "nixpkgs_unstable",
			InstalledRev:   "9a8b7c6d5e4f3a2b1c0d",
			Severity:       intel.SeverityHigh,
			CVSSScore:      8.5,
			Title:          "Nix Daemon Pure Evaluation Sandbox Egress Bypass",
			Mitigation:     "Update flake input to nixpkgs rev with pure-eval sandboxing patch",
			FilePath:       "flake.lock",
			StartLine:      1,
		},
	}

	opts := ReportOptions{
		Version:      "0.6.0",
		FlakeMatches: flakeMatches,
		FlakePath:    "flake.lock",
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report with flake matches: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != "CVE-2026-19402" {
		t.Errorf("expected rule ID CVE-2026-19402, got %s", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected level error for CVSS 8.5, got %s", res.Level)
	}
	if res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "flake.lock" {
		t.Errorf("expected URI flake.lock, got %s", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestBuildSARIFReport_StandaloneFeed(t *testing.T) {
	feed := &intel.Feed{
		UpdatedAt: time.Now().UTC(),
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-21801",
				Title:       "Ingress-Nginx OpenResty Directive Injection",
				Component:   "ingress-nginx",
				Target:      "kubernetes",
				Severity:    intel.SeverityCritical,
				CVSSScore:   9.8,
				Description: "Lua directive injection allows remote code execution",
				Mitigation:  "Upgrade ingress-nginx to v1.12.0+",
			},
		},
	}

	opts := ReportOptions{
		Version: "0.6.0",
		Feed:    feed,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build standalone feed SARIF report: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	if run.Results[0].RuleID != "CVE-2026-21801" {
		t.Errorf("expected CVE-2026-21801, got %s", run.Results[0].RuleID)
	}
}

func TestFormatSARIF_And_WriteSARIFToFile(t *testing.T) {
	opts := ReportOptions{
		Version: "0.6.0",
	}
	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF: %v", err)
	}

	// 1. Test Formatting
	data, err := FormatSARIF(log, true)
	if err != nil {
		t.Fatalf("failed to format SARIF: %v", err)
	}

	var parsed SARIFLog
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("formatted SARIF is invalid JSON: %v", err)
	}
	if parsed.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", parsed.Version)
	}

	// 2. Test Disk Persistence
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "reports", "audit-results.sarif")

	if err := WriteSARIFToFile(log, outPath, true); err != nil {
		t.Fatalf("failed to write SARIF file: %v", err)
	}

	readBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read persisted SARIF file: %v", err)
	}

	if len(readBytes) == 0 {
		t.Error("persisted SARIF file is empty")
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity string
		cvss     float64
		expected string
	}{
		{"CRITICAL", 9.8, "error"},
		{"HIGH", 8.2, "error"},
		{"MEDIUM", 5.5, "warning"},
		{"LOW", 2.1, "note"},
		{"INFO", 0.0, "note"},
		{"UNKNOWN", 7.5, "error"},
		{"UNKNOWN", 4.2, "warning"},
		{"UNKNOWN", 1.0, "note"},
	}

	for _, tc := range tests {
		got := SeverityToSARIFLevel(tc.severity, tc.cvss)
		if got != tc.expected {
			t.Errorf("SeverityToSARIFLevel(%s, %.1f) = %s; want %s", tc.severity, tc.cvss, got, tc.expected)
		}
	}
}

func TestFormatRuleName(t *testing.T) {
	tests := []struct {
		ruleID   string
		title    string
		expected string
	}{
		{"K8S-ING-001", "Ingress Snippet Injection", "IngressSnippetInjection"},
		{"K8S-CNI-002", "Global 0.0.0.0/0 Egress", "Global00000Egress"},
		{"CVE-2026-19402", "", "CVE202619402"},
	}

	for _, tc := range tests {
		got := FormatRuleName(tc.ruleID, tc.title)
		if got != tc.expected {
			t.Errorf("FormatRuleName(%s, %s) = %s; want %s", tc.ruleID, tc.title, got, tc.expected)
		}
	}
}

func TestBuildSARIFReport_ProbeTelemetry(t *testing.T) {
	probeEvents := []probe.TelemetryEvent{
		{
			ID:         "EVT-01",
			ProbeType:  probe.ProbeTypeSocket,
			NodeName:   "nixos-worker-01",
			Comm:       "sh",
			EventType:  "SOCKET_CONNECT",
			Severity:   "CRITICAL",
			RiskScore:  9.2,
			Message:    "Reverse shell outbound connection",
			ThreatTags: []string{"REVERSE_SHELL_ATTEMPT"},
		},
		{
			ID:         "EVT-02",
			ProbeType:  probe.ProbeTypeStorage,
			NodeName:   "nixos-control-01",
			Comm:       "mod-tool",
			EventType:  "STORE_TAMPER_ATTEMPT",
			Severity:   "HIGH",
			RiskScore:  8.8,
			Message:    "Unauthorized write to /nix/store",
			ThreatTags: []string{"IMMUTABLE_STORE_TAMPERING"},
		},
		{
			ID:        "EVT-03",
			ProbeType: probe.ProbeTypeSocket,
			NodeName:  "nixos-control-01",
			Comm:      "kubelet",
			EventType: "SOCKET_CONNECT",
			Severity:  "INFO",
			RiskScore: 1.0,
			Message:   "Normal health check",
		},
	}

	opts := ReportOptions{
		Version:     "0.7.0",
		ProbeEvents: probeEvents,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF with probe events: %v", err)
	}

	run := log.Runs[0]
	// Low risk/info event EVT-03 (score 1.0) is filtered out; 2 high/critical events remain
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 high/critical SARIF results, got %d", len(run.Results))
	}
	if run.Results[0].RuleID != "REVERSE_SHELL_ATTEMPT" {
		t.Errorf("expected first rule ID REVERSE_SHELL_ATTEMPT, got %s", run.Results[0].RuleID)
	}
	if run.Results[0].Level != "error" {
		t.Errorf("expected error level for critical probe event, got %s", run.Results[0].Level)
	}
}

