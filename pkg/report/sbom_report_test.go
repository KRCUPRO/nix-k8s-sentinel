package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sbom"
)

func TestSBOMReportSerialization(t *testing.T) {
	vios := []sbom.SBOMViolation{
		{
			ID:          "VIO-SBOM-CHAIN-004-test-bin",
			RuleID:      "SBOM-CHAIN-004",
			Title:       "Tampered or Mismatched Subject Digest / Cryptographic Checksum",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.8,
			ResourceURI: "build/out/test-bin",
			PackageName: "test-bin",
			LineNumber:  1,
			Description: "Artifact digest mismatch detected.",
			Remediation: "Quarantine artifact and re-verify attestation.",
			MatchedCVE:  "CVE-2026-71044",
		},
		{
			ID:          "VIO-SBOM-CHAIN-008-shadow-agent",
			RuleID:      "SBOM-CHAIN-008",
			Title:       "Runtime Undeclared Package / Shadow Binary Injection",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.4,
			ResourceURI: "cluster/runtime",
			PackageName: "shadow-agent",
			LineNumber:  1,
			Description: "Undeclared runtime package active in cluster.",
			Remediation: "Evict pod and investigate image build.",
		},
	}

	deltaItems := []sbom.SBOMDeltaItem{
		{
			PackageName:     "nginx",
			DeclaredVersion: "1.25.4",
			RuntimeVersion:  "1.25.4",
			Status:          sbom.DeltaMatch,
			Severity:        intel.SeverityLow,
			Message:         "Package verified against declarative SBOM.",
		},
		{
			PackageName:    "shadow-agent",
			RuntimeVersion: "1.0.0",
			Status:         sbom.DeltaUndeclaredRuntime,
			Severity:       intel.SeverityCritical,
			Message:        "Undeclared package running in cluster.",
			SecurityImpact: "Potential supply chain backdoor.",
		},
	}

	summary := &sbom.SBOMSummary{
		TotalPackages:       120,
		TotalDocuments:      1,
		TotalViolations:     2,
		CriticalCount:       2,
		HighCount:           0,
		MediumCount:         0,
		LowCount:            0,
		AttestationVerified: true,
		EvaluatedSLSALevel:  sbom.SLSALevel3,
		DriftingPackages:    0,
		UndeclaredPackages:  1,
		ComplianceScore:     70.0,
	}

	opts := ReportOptions{
		Version:        "0.15.0",
		SBOMPath:       "fixtures/spdx-v3-sbom.json",
		SBOMViolations: vios,
		SBOMSummary:    summary,
		SBOMDelta:      deltaItems,
	}

	// 1. Verify JSON report export
	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}
	if len(jsonRep.SBOMViolations) != 2 {
		t.Errorf("expected 2 SBOM violations in JSON report, got %d", len(jsonRep.SBOMViolations))
	}
	if len(jsonRep.SBOMDelta) != 2 {
		t.Errorf("expected 2 SBOM delta items in JSON report, got %d", len(jsonRep.SBOMDelta))
	}
	if jsonRep.Telemetry.TotalSBOMViolations != 2 {
		t.Errorf("expected 2 TotalSBOMViolations in telemetry, got %d", jsonRep.Telemetry.TotalSBOMViolations)
	}

	jsonData, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(jsonData, &roundtrip); err != nil {
		t.Fatalf("failed to unmarshal JSON roundtrip: %v", err)
	}

	// 2. Verify SARIF v2.1.0 report export
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report: %v", err)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run in SARIF log, got %d", len(sarifLog.Runs))
	}
	run := sarifLog.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results in SARIF run, got %d", len(run.Results))
	}
	found004 := false
	for _, res := range run.Results {
		if res.RuleID == "SBOM-CHAIN-004" {
			found004 = true
		}
	}
	if !found004 {
		t.Errorf("expected SBOM-CHAIN-004 in SARIF results")
	}

	// 3. Verify Threat Intelligence Markdown Briefing export
	briefingOpts := BriefingOptions{
		Title:          "Cloud-Native Threat Intelligence Briefing",
		Version:        "0.15.0",
		HourlyWindow:   time.Now().UTC(),
		SBOMViolations: vios,
		SBOMSummary:    summary,
		SBOMDelta:      deltaItems,
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate briefing: %v", err)
	}
	if !strings.Contains(briefing.Content, "Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation") {
		t.Errorf("expected Section 14 in briefing markdown")
	}
	if !strings.Contains(briefing.Content, "SLSA_LEVEL_3") {
		t.Errorf("expected SLSA_LEVEL_3 in briefing table")
	}
	if !strings.Contains(briefing.Content, "shadow-agent") {
		t.Errorf("expected shadow-agent mentioned in delta/violations table")
	}
}
