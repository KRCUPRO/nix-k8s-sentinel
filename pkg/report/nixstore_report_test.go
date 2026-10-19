package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nixstore"
)

func TestNixStoreSARIFAndJSONExport(t *testing.T) {
	violations := []nixstore.StoreViolation{
		{
			RuleID:       "NIX-STORE-001",
			Title:        "Unsigned Binary Cache Substitution Allowed",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.4,
			Description:  "Nix daemon allows unsigned binary cache substitutes (require-sigs = false), permitting unauthenticated substitutes to poison the shared multi-tenant /nix/store.",
			ConfigTarget: "fixtures/nixos-store-vulnerable.nix",
			FilePath:     "fixtures/nixos-store-vulnerable.nix",
			StartLine:    6,
			Remediation:  "Set `nix.settings.require-sigs = true;` in NixOS configuration.",
			MatchedCVE:   "CVE-2026-81930",
		},
		{
			RuleID:       "NIX-STORE-003",
			Title:        "Insecure Plaintext HTTP Binary Cache Substituter",
			Severity:     intel.SeverityHigh,
			CVSSScore:    8.2,
			Description:  "Substituter 'http://untrusted-cache.internal' uses insecure plaintext HTTP transport.",
			ConfigTarget: "fixtures/nixos-store-vulnerable.nix",
			FilePath:     "fixtures/nixos-store-vulnerable.nix",
			StartLine:    11,
			Remediation:  "Enforce TLS encryption on all substituters (`https://...`).",
		},
	}

	summary := &nixstore.StoreSummary{
		TotalConfigs:       1,
		TotalViolations:    2,
		CriticalCount:      1,
		HighCount:          1,
		ComplianceScore:    77.0,
		SandboxingEnforced: true,
		SignaturesEnforced: false,
	}

	telemetry := &nixstore.NixStoreTelemetryReport{
		HostName:                    "prod-builder-01",
		CollectedAt:                 time.Now().UTC(),
		StorePathCount:              95000,
		StoreUsedBytes:              400 * 1024 * 1024 * 1024,
		StoreCapacityBytes:          1000 * 1024 * 1024 * 1024,
		StoreUsagePercent:           40.0,
		SignatureVerificationsTotal: 500,
		SignatureRejectionsCount:    10,
		SignatureRejectionRate:      2.0,
		NARChecksumFailuresCount:    0,
		DownloadP95LatencyMs:        450.0,
		ActiveSubstituters: []nixstore.SubstituterTelemetry{
			{
				URL:                 "https://cache.nixos.org",
				DownloadsTotal:      490,
				SignaturesVerified:  485,
				SignaturesRejected:  5,
				P95LatencyMs:        420.0,
				Healthy:             true,
			},
		},
	}

	opts := ReportOptions{
		Version:         "0.28.0",
		StoreViolations: violations,
		StoreSummary:    summary,
		StoreTelemetry:  telemetry,
		StorePath:       "fixtures/nixos-store-vulnerable.nix",
	}

	// 1. Validate SARIF report generation
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report: %v", err)
	}
	if len(sarifLog.Runs) == 0 {
		t.Fatalf("SARIF log contains zero runs")
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results in SARIF, got %d", len(sarifLog.Runs[0].Results))
	}
	if sarifLog.Runs[0].Results[0].RuleID != "NIX-STORE-001" {
		t.Errorf("expected NIX-STORE-001 rule ID, got %s", sarifLog.Runs[0].Results[0].RuleID)
	}

	// 2. Validate JSON report generation
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}
	if len(jsonReport.StoreViolations) != 2 {
		t.Fatalf("expected 2 store violations in JSON, got %d", len(jsonReport.StoreViolations))
	}
	if jsonReport.StoreSummary == nil || jsonReport.StoreSummary.ComplianceScore != 77.0 {
		t.Errorf("expected 77.0 compliance score in JSON summary")
	}
	if jsonReport.StoreTelemetry == nil || jsonReport.StoreTelemetry.HostName != "prod-builder-01" {
		t.Errorf("expected telemetry host prod-builder-01 in JSON")
	}

	jsonBytes, err := json.Marshal(jsonReport)
	if err != nil {
		t.Fatalf("failed to serialize JSON report: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "NIX-STORE-001") {
		t.Errorf("serialized JSON missing NIX-STORE-001")
	}

	// 3. Validate Threat Briefing generation
	briefingOpts := BriefingOptions{
		Version:         "0.28.0",
		StoreViolations: violations,
		StoreSummary:    summary,
		StoreTelemetry:  telemetry,
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate threat briefing: %v", err)
	}
	if !strings.Contains(briefing.Content, "Nix Store Signature & Binary Cache Isolation Gate") {
		t.Errorf("briefing markdown missing Nix Store Signature section")
	}
	if !strings.Contains(briefing.Content, "NIX-STORE-001") {
		t.Errorf("briefing markdown missing NIX-STORE-001 rule")
	}
	if !strings.Contains(briefing.Content, "CVE-2026-81930") {
		t.Errorf("briefing markdown missing CVE-2026-81930 tag")
	}
}
