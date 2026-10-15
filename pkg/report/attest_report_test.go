package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestBuildSARIFReport_AttestViolations(t *testing.T) {
	attestViolations := []attest.AttestationViolation{
		{
			RuleID:      "ATTEST-BOOT-001",
			Title:       "AMD SEV-SNP Memory Encryption Disabled or Unconfigured",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.2,
			Category:    "ConfidentialComputing",
			Technology:  "AMD SEV-SNP",
			Target:      "worker-sev-01",
			FilePath:    "fixtures/nixos-measured-boot.nix",
			StartLine:   35,
			Message:     "AMD SEV-SNP memory encryption kernel parameters missing in host configuration",
			Remediation: "Ensure mem_encrypt=on kvm_amd.sev=1 is configured in boot.kernelParams",
			MatchedCVE:  "CVE-2026-51204",
		},
		{
			RuleID:      "ATTEST-BOOT-004",
			Title:       "TPM 2.0 PCR 11 Unified Kernel Image (UKI) / NixOS System Closure Digest Desync",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.7,
			Category:    "MeasuredBoot",
			Technology:  "Bare-Metal TPM2",
			Target:      "worker-node-02",
			FilePath:    "fixtures/attestation-telemetry.json",
			StartLine:   1,
			Message:     "TPM PCR 11 measurement mismatch",
			Remediation: "Regenerate signed NixOS Unified Kernel Images using Lanzaboote",
		},
	}

	opts := ReportOptions{
		Version:          "0.12.0",
		AttestViolations: attestViolations,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF with Attestation violations: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 Attestation SARIF results, got %d", len(run.Results))
	}

	for _, res := range run.Results {
		if res.Level != "error" {
			t.Errorf("expected error level for high/critical Attestation violations, got %s", res.Level)
		}
	}
}

func TestBuildJSONReport_AttestViolations(t *testing.T) {
	attestViolations := []attest.AttestationViolation{
		{
			RuleID:      "ATTEST-BOOT-005",
			Title:       "Confidential Computing Firmware Debug Mode Permitted in Remote Quote",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.4,
			Category:    "EnclaveIntegrity",
			Technology:  "Generic Attestation",
			Target:      "worker-tdx-03",
			FilePath:    "fixtures/attestation-telemetry.json",
			StartLine:   1,
			Message:     "Node is operating in unsealed debug mode",
			Remediation: "Deploy confidential VM instances with debug mode explicitly disabled",
		},
	}

	summary := &attest.AttestationSummary{
		TotalChecks:     15,
		PassedChecks:    14,
		ComplianceScore: 93.3,
		CriticalCount:   1,
		NodesAttested:   3,
		NodesVerified:   2,
	}

	opts := ReportOptions{
		Version:          "0.12.0",
		AttestViolations: attestViolations,
		AttestSummary:    summary,
		AttestPath:       "fixtures/nixos-measured-boot.nix",
		Pretty:           true,
	}

	rep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report with Attestation violations: %v", err)
	}

	if len(rep.AttestViolations) != 1 {
		t.Errorf("expected 1 Attest violation, got %d", len(rep.AttestViolations))
	}
	if rep.AttestSummary == nil || rep.AttestSummary.ComplianceScore != 93.3 {
		t.Errorf("expected 93.3%% compliance score, got %+v", rep.AttestSummary)
	}
	if rep.Telemetry.TotalAttestViolations != 1 {
		t.Errorf("expected 1 TotalAttestViolations in telemetry, got %d", rep.Telemetry.TotalAttestViolations)
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
	outPath := filepath.Join(tmpDir, "attest-audit.json")
	if err := WriteJSONToFile(rep, outPath, true); err != nil {
		t.Fatalf("failed to write JSON report to file: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("expected output file to exist: %v", err)
	}
}
