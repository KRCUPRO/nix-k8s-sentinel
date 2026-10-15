package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestBuildSARIFReport_GatewayViolations(t *testing.T) {
	gwViolations := []gateway.GatewayViolation{
		{
			RuleID:       "GW-RADAR-001",
			Title:        "Unrestricted Cross-Namespace Backend Reference (Missing ReferenceGrant)",
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.8,
			Category:     "CrossNamespaceAuthorization",
			ResourceKind: "HTTPRoute",
			ResourceName: "tenant-route",
			Namespace:    "tenant-a",
			FilePath:     "fixtures/gateway-api-routes.yaml",
			StartLine:    45,
			Message:      "Route references backend in payment-backend without ReferenceGrant",
			Remediation:  "Define a declarative ReferenceGrant",
			MatchedCVE:   "CVE-2026-44219",
		},
		{
			RuleID:       "GW-RADAR-002",
			Title:        "Unsafe EnvoyFilter Inline Lua Script Injection",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.3,
			Category:     "CodeInjection",
			ResourceKind: "EnvoyFilter",
			ResourceName: "unsafe-lua",
			Namespace:    "istio-system",
			FilePath:     "fixtures/gateway-api-routes.yaml",
			StartLine:    88,
			Message:      "EnvoyFilter executes io.popen inside proxy sidecar",
			Remediation:  "Disallow dynamic Lua script injection",
		},
	}

	opts := ReportOptions{
		Version:           "0.11.0",
		GatewayViolations: gwViolations,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF with Gateway violations: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 Gateway SARIF results, got %d", len(run.Results))
	}

	for _, res := range run.Results {
		if res.Level != "error" {
			t.Errorf("expected error level for high/critical Gateway violations, got %s", res.Level)
		}
	}
}

func TestBuildJSONReport_GatewayViolations(t *testing.T) {
	gwViolations := []gateway.GatewayViolation{
		{
			RuleID:       "GW-RADAR-003",
			Title:        "EnvoyFilter Filter Chain Order Bypass",
			Severity:     intel.SeverityHigh,
			CVSSScore:    8.2,
			Category:     "FilterOrdering",
			ResourceKind: "EnvoyFilter",
			ResourceName: "bypass-auth",
			Namespace:    "istio-system",
			FilePath:     "fixtures/gateway-api-routes.yaml",
			StartLine:    120,
			Message:      "INSERT_BEFORE relative to jwt_authn enables authn bypass",
			Remediation:  "Place custom filters after authn",
		},
	}

	summary := &gateway.GatewaySummary{
		TotalChecks:     25,
		PassedChecks:    24,
		ComplianceScore: 96.0,
		HighCount:       1,
	}

	opts := ReportOptions{
		Version:           "0.11.0",
		GatewayViolations: gwViolations,
		GatewaySummary:    summary,
		GatewayPath:       "fixtures/gateway-api-routes.yaml",
		Pretty:            true,
	}

	rep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report with Gateway violations: %v", err)
	}

	if len(rep.GatewayViolations) != 1 {
		t.Errorf("expected 1 Gateway violation, got %d", len(rep.GatewayViolations))
	}
	if rep.GatewaySummary == nil || rep.GatewaySummary.ComplianceScore != 96.0 {
		t.Errorf("expected 96.0%% compliance score, got %+v", rep.GatewaySummary)
	}
	if rep.Telemetry.TotalGatewayViolations != 1 {
		t.Errorf("expected 1 TotalGatewayViolations in telemetry, got %d", rep.Telemetry.TotalGatewayViolations)
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
	outPath := filepath.Join(tmpDir, "gateway-audit.json")
	if err := WriteJSONToFile(rep, outPath, true); err != nil {
		t.Fatalf("failed to write JSON report to file: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("expected output file to exist: %v", err)
	}
}
