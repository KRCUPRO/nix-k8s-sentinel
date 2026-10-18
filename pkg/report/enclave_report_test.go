package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgenclave"
)

func TestEnclaveSARIFAndJSONExport(t *testing.T) {
	violations := []wgenclave.WGEnclaveViolation{
		{
			RuleID:        "WG-ENC-005",
			PeerName:      "vulnerable-enclave-peer",
			InterfaceName: "wg0",
			Platform:      wgenclave.PlatformSEVSNP,
			Title:         "WireGuard Ephemeral Session Key Missing Enclave REPORT_DATA Binding",
			Severity:      intel.SeverityCritical,
			CVSSScore:     9.4,
			Description:   "Active session key hash not cryptographically bound to enclave attestation REPORT_DATA",
			Remediation:   "Enforce cryptographic session key binding in NixOS enclave peer config",
			MatchedCVE:    "CVE-2026-40291",
			FilePath:      "fixtures/nixos-wg-enclave-vulnerable.nix",
			StartLine:     20,
		},
	}

	summary := &wgenclave.WGEnclaveSummary{
		TotalPeersScanned:     2,
		CompliantPeers:        1,
		RejectedPeers:         1,
		CriticalCount:         1,
		SEVSNPVerified:        true,
		TDXVerified:           false,
		PCRDeviationsDetected: 1,
		ComplianceScore:       75.0,
		RejectedPeerIDs:       []string{"vulnerable-enclave-peer"},
	}

	opts := ReportOptions{
		Version:             "0.24.0",
		EnclaveViolations:   violations,
		EnclaveSummary:      summary,
		EnclaveManifestPath: "fixtures/nixos-wg-enclave-vulnerable.nix",
		Pretty:              true,
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
	if res.RuleID != "WG-ENC-005" || res.Level != "error" {
		t.Errorf("unexpected SARIF result: %+v", res)
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "WG-ENC-005") {
		t.Errorf("expected SARIF JSON to contain WG-ENC-005")
	}

	// 2. Verify JSON
	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}
	if len(jsonRep.EnclaveViolations) != 1 {
		t.Fatalf("expected 1 JSON enclave violation, got %d", len(jsonRep.EnclaveViolations))
	}

	jsonBytes, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal generated JSON failed: %v", err)
	}
	if parsed["tool_version"] != "0.24.0" {
		t.Errorf("expected tool_version 0.24.0, got %v", parsed["tool_version"])
	}

	// 3. Verify Briefing Generation
	briefingOpts := BriefingOptions{
		Title:             "Enclave Test Briefing",
		Version:           "0.24.0",
		HourlyWindow:      time.Now().UTC(),
		EnclaveViolations: violations,
		EnclaveSummary:    summary,
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}
	if !strings.Contains(briefing.Content, "Confidential VM & WireGuard Enclave Peer Attestation Posture") {
		t.Errorf("expected Briefing to contain Section 23 header")
	}
	if !strings.Contains(briefing.Content, "WG-ENC-005") {
		t.Errorf("expected Briefing to contain WG-ENC-005 violation")
	}
}
