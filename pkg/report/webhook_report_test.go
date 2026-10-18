package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/webhook"
)

func TestWebhookSARIFAndJSONExport(t *testing.T) {
	violations := []webhook.WebhookViolation{
		{
			RuleID:      "WH-RADAR-001",
			WebhookName: "bypass.security.gatekeeper.sh",
			WebhookType: webhook.WebhookTypeValidating,
			Title:       "Security-Critical Admission Webhook Configured with failurePolicy: Ignore",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.2,
			Description: "Webhook operates with failurePolicy: Ignore, permitting total admission bypass during webhook failures",
			Remediation: "Configure failurePolicy: Fail for security-critical webhooks and ensure multi-replica high availability",
			MatchedCVE:  "CVE-2026-52194",
			FilePath:    "fixtures/k8s-admission-webhook-vulnerable.yaml",
			StartLine:   7,
		},
	}

	summary := &webhook.WebhookSummary{
		TotalWebhooksScanned: 2,
		ValidatingCount:      1,
		MutatingCount:        1,
		CompliantWebhooks:    1,
		CriticalCount:        1,
		BypassRiskCount:      1,
		ComplianceScore:      75.0,
		HighRiskWebhookNames: []string{"bypass.security.gatekeeper.sh"},
	}

	opts := ReportOptions{
		Version:           "0.25.0",
		WebhookViolations: violations,
		WebhookSummary:    summary,
		WebhookPath:       "fixtures/k8s-admission-webhook-vulnerable.yaml",
		Pretty:            true,
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
	if res.RuleID != "WH-RADAR-001" || res.Level != "error" {
		t.Errorf("unexpected SARIF result: %+v", res)
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "WH-RADAR-001") {
		t.Errorf("expected SARIF JSON to contain WH-RADAR-001")
	}

	// 2. Verify JSON
	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}
	if len(jsonRep.WebhookViolations) != 1 {
		t.Fatalf("expected 1 JSON webhook violation, got %d", len(jsonRep.WebhookViolations))
	}

	jsonBytes, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal generated JSON failed: %v", err)
	}
	if parsed["tool_version"] != "0.25.0" {
		t.Errorf("expected tool_version 0.25.0, got %v", parsed["tool_version"])
	}

	// 3. Verify Briefing Generation
	briefingOpts := BriefingOptions{
		Title:             "Admission Webhook Test Briefing",
		Version:           "0.25.0",
		HourlyWindow:      time.Now().UTC(),
		WebhookViolations: violations,
		WebhookSummary:    summary,
	}

	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}

	if !strings.Contains(briefing.Content, "Kubernetes Dynamic Admission Webhook & CA Rotation Radar") {
		t.Errorf("expected briefing markdown to contain webhook section")
	}
	if !strings.Contains(briefing.Content, "WH-RADAR-001") {
		t.Errorf("expected briefing markdown to contain WH-RADAR-001")
	}
	if !strings.Contains(briefing.Content, "CVE-2026-52194") {
		t.Errorf("expected briefing markdown to contain CVE-2026-52194")
	}
}
