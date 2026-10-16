package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/hsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestHSMReportSerialization(t *testing.T) {
	vios := []hsm.HSMViolation{
		{
			RuleID:        "HSM-ENC-001",
			Title:         "Insecure etcd Encryption-At-Rest Configuration",
			Severity:      intel.SeverityCritical,
			CVSSScore:     9.5,
			Description:   "Plaintext identity provider configured first.",
			Remediation:   "Place KMS v2 provider at top of chain.",
			ResourceURI:   "k8s-encryption-config.yaml",
			ProviderName:  "identity",
			ActualValue:   "primary_provider=identity",
			ExpectedValue: "primary_provider=kms (v2)",
		},
		{
			RuleID:        "HSM-ENC-007",
			Title:         "Nitro Enclave / HSM Session Leakage or Unsealed Attestation",
			Severity:      intel.SeverityCritical,
			CVSSScore:     9.4,
			Description:   "Nitro enclave session leakage detected.",
			Remediation:   "Re-bind enclave session to measured boot PCR0.",
			ResourceURI:   "telemetry://prod-cluster/node-01",
			ProviderName:  "NitroEnclave",
			MatchedCVE:    "CVE-2026-83190",
			ActualValue:   "nitro_enclave_ok=false",
			ExpectedValue: "nitro_enclave_ok=true",
		},
	}

	summary := &hsm.HSMSummary{
		TotalConfigsScanned: 2,
		TotalKeysAudited:    8,
		ViolationsCount:     2,
		CriticalCount:       2,
		ComplianceScore:     50.0,
		AuditStatus:         "CRITICAL_DEFECTS_DETECTED",
	}

	opts := ReportOptions{
		Version:          "0.16.0",
		HSMViolations:    vios,
		HSMSummary:       summary,
		HSMPath:          "k8s-encryption-config.yaml",
		HSMTelemetryPath: "hsm-telemetry.json",
	}

	// 1. Validate SARIF Serialization
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed: %v", err)
	}
	if sarifLog == nil {
		t.Fatalf("BuildSARIFReport returned nil")
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(sarifLog.Runs))
	}
	run := sarifLog.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(run.Results))
	}

	foundCVE := false
	for _, res := range run.Results {
		if res.RuleID == "HSM-ENC-007" && strings.Contains(res.Message.Text, "CVE-2026-83190") {
			foundCVE = true
		}
	}
	if !foundCVE {
		t.Errorf("SARIF results missing CVE-2026-83190 tag in HSM-ENC-007")
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	var parsedSARIF map[string]interface{}
	if err := json.Unmarshal(sarifBytes, &parsedSARIF); err != nil {
		t.Fatalf("invalid SARIF JSON output: %v", err)
	}

	// 2. Validate JSON Report Serialization
	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}
	if jsonRep.Telemetry.TotalHSMViolations != 2 {
		t.Errorf("expected 2 TotalHSMViolations in JSON telemetry, got %d", jsonRep.Telemetry.TotalHSMViolations)
	}
	if len(jsonRep.HSMViolations) != 2 {
		t.Errorf("expected 2 HSMViolations in JSON report, got %d", len(jsonRep.HSMViolations))
	}

	jsonBytes, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	var parsedJSON map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsedJSON); err != nil {
		t.Fatalf("invalid JSON report output: %v", err)
	}

	// 3. Validate Threat Intelligence Briefing Markdown
	briefingOpts := BriefingOptions{
		Title:         "Hourly Threat Briefing with HSM & KMS v2",
		Version:       "0.16.0",
		HourlyWindow:  time.Now().UTC(),
		HSMViolations: vios,
		HSMSummary:    summary,
	}
	briefingRep, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}
	if !strings.Contains(briefingRep.Content, "Hardware Security Module (HSM) & PKCS#11 Envelope Encryption") {
		t.Errorf("briefing markdown missing Section 15 HSM title")
	}
	if !strings.Contains(briefingRep.Content, "CVE-2026-83190") {
		t.Errorf("briefing markdown missing CVE-2026-83190 reference")
	}
	if !strings.Contains(briefingRep.Content, "HSM-ENC-001") {
		t.Errorf("briefing markdown missing HSM-ENC-001 rule ID")
	}
}
