package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalAttestationRules(t *testing.T) {
	if len(CanonicalAttestationRules) < 12 {
		t.Errorf("expected at least 12 canonical attestation rules, got %d", len(CanonicalAttestationRules))
	}

	rule1 := GetAttestationRule("ATTEST-BOOT-001")
	if rule1.Severity != intel.SeverityCritical || rule1.CVSSScore < 9.0 {
		t.Errorf("expected critical rule for ATTEST-BOOT-001, got %+v", rule1)
	}

	fallback := GetAttestationRule("NON-EXISTENT-RULE")
	if fallback.ID != "NON-EXISTENT-RULE" || fallback.Category != "GeneralAttestation" {
		t.Errorf("expected fallback rule for non-existent ID, got %+v", fallback)
	}
}

func TestAttestationScanner_CompliantConfig(t *testing.T) {
	compliantNix := `
{ config, pkgs, ... }:
{
  boot.loader.systemd-boot.enable = true;
  boot.initrd.systemd.enable = true;
  boot.lanzaboote.enable = true;

  security.tpm2.enable = true;
  security.tpm2.pkcs11.enable = true;

  nix.settings.trusted-public-keys = [
    "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
  ];

  boot.kernelParams = [
    "mem_encrypt=on"
    "kvm_amd.sev=1"
    "amd_iommu=on"
  ];
}
`
	tmpDir := t.TempDir()
	nixFile := filepath.Join(tmpDir, "compliant.nix")
	if err := os.WriteFile(nixFile, []byte(compliantNix), 0644); err != nil {
		t.Fatalf("failed to write test nix file: %v", err)
	}

	scanner := NewAttestationScanner(nil)
	rep, err := scanner.ScanFile(nixFile)
	if err != nil {
		t.Fatalf("unexpected scanner failure: %v", err)
	}

	if len(rep.Violations) != 0 {
		t.Errorf("expected 0 violations for compliant nix config, got %d: %+v", len(rep.Violations), rep.Violations)
	}
	if rep.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score, got %.1f", rep.Summary.ComplianceScore)
	}
}

func TestAttestationScanner_VulnerableConfig(t *testing.T) {
	vulnerableNix := `
{ config, pkgs, ... }:
{
  boot.loader.systemd-boot.enable = false;
  security.tpm2.enable = false;

  boot.kernelParams = [
    "kvm_amd.sev=0"
    "nokaslr"
  ];
}
`
	tmpDir := t.TempDir()
	nixFile := filepath.Join(tmpDir, "vulnerable.nix")
	if err := os.WriteFile(nixFile, []byte(vulnerableNix), 0644); err != nil {
		t.Fatalf("failed to write test nix file: %v", err)
	}

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-51204",
				Title:     "AMD SEV-SNP Firmware Measurement Replay",
				Severity:  intel.SeverityCritical,
				Component: "amd-sev",
			},
		},
	}

	scanner := NewAttestationScanner(feed)
	rep, err := scanner.ScanFile(nixFile)
	if err != nil {
		t.Fatalf("unexpected scanner failure: %v", err)
	}

	if len(rep.Violations) == 0 {
		t.Fatal("expected violations for unhardened nix configuration, got 0")
	}

	hasSevViolation := false
	hasNokaslrViolation := false
	for _, v := range rep.Violations {
		if v.RuleID == "ATTEST-BOOT-001" {
			hasSevViolation = true
			if v.MatchedCVE != "CVE-2026-51204" {
				t.Errorf("expected CVE-2026-51204 matched, got '%s'", v.MatchedCVE)
			}
		}
		if v.RuleID == "ATTEST-BOOT-010" {
			hasNokaslrViolation = true
		}
	}

	if !hasSevViolation {
		t.Error("expected ATTEST-BOOT-001 violation for disabled SEV")
	}
	if !hasNokaslrViolation {
		t.Error("expected ATTEST-BOOT-010 violation for nokaslr")
	}
}

func TestAttestationVerifier_CompliantNode(t *testing.T) {
	now := time.Now().UTC()
	node := NodeAttestationReport{
		NodeName:                   "worker-sev-01",
		Platform:                   PlatformAmdSEVSNP,
		AttestationEnclave:         "AMD-SEV-SNP-v2",
		AttestedAt:                 now.Add(-10 * time.Minute),
		TokenExpired:               false,
		DebugMode:                  false,
		MemoryEncryptionEnabled:    true,
		StorePathSignature:         "sha256-abcdef1234567890",
		ExpectedStorePathSignature: "sha256-abcdef1234567890",
		TCBVersion:                 "0800102b",
		MinRequiredTCB:             "08001000",
		Quotes: []PCRQuote{
			{
				Index:           7,
				DigestAlgorithm: "sha256",
				ExpectedDigest:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				ActualDigest:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Description:     "Secure Boot Policy",
				Valid:           true,
			},
			{
				Index:           11,
				DigestAlgorithm: "sha256",
				ExpectedDigest:  "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
				ActualDigest:    "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
				Description:     "Unified Kernel Image System Closure",
				Valid:           true,
			},
		},
	}

	verifier := NewAttestationVerifier(nil)
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("failed to serialize test node: %v", err)
	}

	rep, err := verifier.VerifyTelemetryBytes(data, "test-telemetry.json")
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	if len(rep.Violations) != 0 {
		t.Errorf("expected 0 violations for verified compliant node, got %d: %+v", len(rep.Violations), rep.Violations)
	}
	if rep.Summary.NodesVerified != 1 {
		t.Errorf("expected 1 verified node, got %d", rep.Summary.NodesVerified)
	}
	if rep.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score, got %.1f", rep.Summary.ComplianceScore)
	}
}

func TestAttestationVerifier_VulnerableNode(t *testing.T) {
	node := NodeAttestationReport{
		NodeName:                   "worker-tdx-compromised",
		Platform:                   PlatformIntelTDX,
		AttestationEnclave:         "Intel-TDX-QVE",
		AttestedAt:                 time.Now().UTC().Add(-48 * time.Hour), // Expired
		TokenExpired:               true,
		DebugMode:                  true,  // Critical
		MemoryEncryptionEnabled:    false, // Critical
		StorePathSignature:         "sha256-untrusted",
		ExpectedStorePathSignature: "sha256-golden",
		Quotes: []PCRQuote{
			{
				Index:           11,
				DigestAlgorithm: "sha256",
				ExpectedDigest:  "sha256-golden-pcr11",
				ActualDigest:    "sha256-tampered-pcr11",
				Description:     "NixOS UKI Digest",
				Valid:           false,
			},
		},
	}

	verifier := NewAttestationVerifier(nil)
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("failed to serialize test node: %v", err)
	}

	rep, err := verifier.VerifyTelemetryBytes(data, "test-compromised.json")
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	if len(rep.Violations) < 4 {
		t.Errorf("expected at least 4 violations (expired, debug, memory encryption, pcr11), got %d", len(rep.Violations))
	}
	if rep.Summary.NodesVerified != 0 {
		t.Errorf("expected 0 verified nodes, got %d", rep.Summary.NodesVerified)
	}
	if rep.Summary.CriticalCount < 2 {
		t.Errorf("expected at least 2 critical violations (debug, memory encryption), got %d", rep.Summary.CriticalCount)
	}
}

func TestAttestationVerifier_DirectoryScan(t *testing.T) {
	tmpDir := t.TempDir()
	nix1 := filepath.Join(tmpDir, "node1.nix")
	nix2 := filepath.Join(tmpDir, "node2.nix")

	code1 := `
{
  boot.loader.systemd-boot.enable = true;
  boot.initrd.systemd.enable = true;
  boot.lanzaboote.enable = true;
  security.tpm2.enable = true;
  nix.settings.trusted-public-keys = [ "key1" ];
  boot.kernelParams = [ "mem_encrypt=on" "kvm_amd.sev=1" ];
}
`
	code2 := `
{
  boot.loader.systemd-boot.enable = false;
  security.tpm2.enable = false;
}
`
	if err := os.WriteFile(nix1, []byte(code1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nix2, []byte(code2), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewAttestationScanner(nil)
	dirRep, err := scanner.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("failed to scan directory: %v", err)
	}

	if dirRep.TotalFiles != 2 {
		t.Errorf("expected 2 files scanned, got %d", dirRep.TotalFiles)
	}
	if len(dirRep.Violations) == 0 {
		t.Error("expected violations from node2.nix")
	}
}

func TestAttestation_BoundsAndSafety(t *testing.T) {
	verifier := NewAttestationVerifier(nil)
	_, err := verifier.VerifyTelemetryBytes([]byte{}, "empty.json")
	if err == nil {
		t.Error("expected error on empty payload")
	}

	_, err = verifier.VerifyTelemetryBytes([]byte(`{ "invalid": "json"`), "bad.json")
	if err == nil {
		t.Error("expected error on malformed json")
	}
}
