package nixstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleCatalogIntegrity(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical rules in catalog, got %d", len(rules))
	}

	for i := 1; i <= 12; i++ {
		id := strings.TrimSpace(AllRules()[i-1].ID)
		rule, ok := LookupRule(id)
		if !ok {
			t.Errorf("failed to lookup canonical rule: %s", id)
		}
		if rule.Name == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has incomplete metadata", id)
		}
		if rule.CVSSScore <= 0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", id, rule.CVSSScore)
		}
	}
}

func TestValidateEd25519PublicKey(t *testing.T) {
	// Valid key (cache.nixos.org-1)
	validKey := "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
	name, key, ok := ValidateEd25519PublicKey(validKey)
	if !ok || name != "cache.nixos.org-1" || key == "" {
		t.Errorf("expected valid Ed25519 key for %s, got ok=%v", validKey, ok)
	}

	// Invalid format: missing colon
	_, _, ok = ValidateEd25519PublicKey("cache.nixos.org-16NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=")
	if ok {
		t.Errorf("expected invalid format for key missing colon")
	}

	// Invalid format: non-base64
	_, _, ok = ValidateEd25519PublicKey("cache.nixos.org-1:!!!not-base64!!!")
	if ok {
		t.Errorf("expected invalid format for non-base64 key")
	}

	// Invalid format: not 32 bytes (only 4 bytes)
	_, _, ok = ValidateEd25519PublicKey("short-key:AAAA")
	if ok {
		t.Errorf("expected invalid format for key with length != 32 bytes")
	}
}

func TestParseCompliantNixConfig(t *testing.T) {
	nixContent := `
{ config, pkgs, ... }:
{
  networking.hostName = "prod-builder-01";
  nix.settings = {
    require-sigs = true;
    trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
    ];
    substituters = [
      "https://cache.nixos.org"
      "https://nix-community.cachix.org"
    ];
    trusted-users = [ "root" ];
    sandbox = true;
    sandbox-fallback = false;
    pure-eval = true;
    accept-flake-config = false;
    build-users-group = "nixbld";
    nr-build-users = 32;
  };
  nix.gc.automatic = true;
}
`
	cfg, err := ParseNixStoreConfig([]byte(nixContent), "test-compliant.nix")
	if err != nil {
		t.Fatalf("failed to parse compliant Nix config: %v", err)
	}

	if cfg.HostName != "prod-builder-01" {
		t.Errorf("expected hostName prod-builder-01, got %s", cfg.HostName)
	}
	if cfg.RequireSigs == nil || !*cfg.RequireSigs {
		t.Errorf("expected require-sigs true")
	}
	if len(cfg.TrustedPublicKeys) != 2 {
		t.Errorf("expected 2 trusted public keys, got %d", len(cfg.TrustedPublicKeys))
	}
	if len(cfg.Substituters) != 2 {
		t.Errorf("expected 2 substituters, got %d", len(cfg.Substituters))
	}
	if cfg.Sandbox == nil || !*cfg.Sandbox {
		t.Errorf("expected sandbox true")
	}
	if cfg.SandboxFallback == nil || *cfg.SandboxFallback {
		t.Errorf("expected sandbox-fallback false")
	}
	if cfg.PureEval == nil || !*cfg.PureEval {
		t.Errorf("expected pure-eval true")
	}
	if cfg.BuildUsersGroup != "nixbld" {
		t.Errorf("expected build-users-group nixbld, got %s", cfg.BuildUsersGroup)
	}

	violations := AuditStoreConfig(cfg)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for compliant config, got %d: %+v", len(violations), violations)
	}

	summary := ComputeStoreCompliance(violations, 1, nil)
	if summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score, got %.1f", summary.ComplianceScore)
	}
	if !summary.SandboxingEnforced || !summary.SignaturesEnforced {
		t.Errorf("expected sandboxing and signatures enforced")
	}
}

func TestParseVulnerableNixConfig(t *testing.T) {
	vulnerableContent := `
{ config, pkgs, ... }:
{
  networking.hostName = "vulnerable-node";
  nix.settings = {
    require-sigs = false;
    trusted-public-keys = [
      "invalid-key-format"
    ];
    substituters = [
      "http://untrusted-cache.internal"
    ];
    trusted-users = [ "*" ];
    sandbox = false;
    sandbox-fallback = true;
    pure-eval = false;
    accept-flake-config = true;
    netrc-file = "/nix/store/12345-netrc";
  };
  nix.gc.automatic = false;
}
`
	cfg, err := ParseNixStoreConfig([]byte(vulnerableContent), "test-vulnerable.nix")
	if err != nil {
		t.Fatalf("failed to parse vulnerable Nix config: %v", err)
	}

	violations := AuditStoreConfig(cfg)
	if len(violations) < 7 {
		t.Fatalf("expected at least 7 violations for vulnerable config, got %d", len(violations))
	}

	hasRule := func(id string) bool {
		for _, v := range violations {
			if v.RuleID == id {
				return true
			}
		}
		return false
	}

	if !hasRule("NIX-STORE-001") {
		t.Errorf("expected NIX-STORE-001 violation for require-sigs = false")
	}
	if !hasRule("NIX-STORE-002") {
		t.Errorf("expected NIX-STORE-002 violation for invalid public key")
	}
	if !hasRule("NIX-STORE-003") {
		t.Errorf("expected NIX-STORE-003 violation for http:// substituter")
	}
	if !hasRule("NIX-STORE-004") {
		t.Errorf("expected NIX-STORE-004 violation for trusted-users = *")
	}
	if !hasRule("NIX-STORE-005") {
		t.Errorf("expected NIX-STORE-005 violation for sandbox = false")
	}
	if !hasRule("NIX-STORE-006") {
		t.Errorf("expected NIX-STORE-006 violation for pure-eval = false")
	}
	if !hasRule("NIX-STORE-008") {
		t.Errorf("expected NIX-STORE-008 violation for /nix/store netrc path")
	}
	if !hasRule("NIX-STORE-012") {
		t.Errorf("expected NIX-STORE-012 violation for gc.automatic = false")
	}

	summary := ComputeStoreCompliance(violations, 1, nil)
	if summary.ComplianceScore > 50.0 {
		t.Errorf("expected low compliance score for vulnerable config, got %.1f", summary.ComplianceScore)
	}
	if summary.SandboxingEnforced || summary.SignaturesEnforced {
		t.Errorf("expected sandboxing and signatures not enforced")
	}
}

func TestParseNixConfFormat(t *testing.T) {
	nixConf := `
# /etc/nix/nix.conf
require-sigs = true
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
substituters = https://cache.nixos.org
trusted-users = root
sandbox = true
sandbox-fallback = false
pure-eval = true
accept-flake-config = false
build-users-group = nixbld
nr-build-users = 32
`
	cfg, err := ParseNixStoreConfig([]byte(nixConf), "/etc/nix/nix.conf")
	if err != nil {
		t.Fatalf("failed to parse nix.conf: %v", err)
	}

	if cfg.RequireSigs == nil || !*cfg.RequireSigs {
		t.Errorf("expected require-sigs true")
	}
	if len(cfg.TrustedPublicKeys) != 1 {
		t.Errorf("expected 1 trusted public key, got %d", len(cfg.TrustedPublicKeys))
	}
	if cfg.BuildUsersGroup != "nixbld" {
		t.Errorf("expected build-users-group nixbld, got %s", cfg.BuildUsersGroup)
	}

	violations := AuditStoreConfig(cfg)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for clean nix.conf, got %d", len(violations))
	}
}

func TestTelemetryAuditor(t *testing.T) {
	telemetryJSON := `{
		"host_name": "worker-node-42",
		"collected_at": "2026-10-19T10:00:00Z",
		"store_path_count": 145000,
		"store_used_bytes": 950000000000,
		"store_capacity_bytes": 1000000000000,
		"store_usage_percent": 95.0,
		"signature_verifications_total": 1000,
		"signature_rejections_count": 80,
		"signature_rejection_rate": 8.0,
		"nar_checksum_failures_count": 2,
		"download_p95_latency_ms": 18500.0,
		"unauthorized_elevation_attempts": 3,
		"active_substituters": [
			{
				"url": "https://cache.nixos.org",
				"downloads_total": 900,
				"signatures_verified": 890,
				"signatures_rejected": 10,
				"p95_latency_ms": 450.0,
				"healthy": true
			}
		]
	}`

	tel, err := ParseStoreTelemetryJSON([]byte(telemetryJSON))
	if err != nil {
		t.Fatalf("failed to parse telemetry JSON: %v", err)
	}

	violations := AuditStoreTelemetry(tel)
	if len(violations) < 4 {
		t.Fatalf("expected at least 4 violations from telemetry, got %d", len(violations))
	}

	hasRule := func(id string) bool {
		for _, v := range violations {
			if v.RuleID == id {
				return true
			}
		}
		return false
	}

	if !hasRule("NIX-STORE-009") {
		t.Errorf("expected NIX-STORE-009 for high signature rejection rate (8.0%%)")
	}
	if !hasRule("NIX-STORE-010") {
		t.Errorf("expected NIX-STORE-010 for NAR checksum failures (2)")
	}
	if !hasRule("NIX-STORE-011") {
		t.Errorf("expected NIX-STORE-011 for high latency (18500ms)")
	}
	if !hasRule("NIX-STORE-012") {
		t.Errorf("expected NIX-STORE-012 for high disk utilization (95%%)")
	}
	if !hasRule("NIX-STORE-004") {
		t.Errorf("expected NIX-STORE-004 for unauthorized elevation attempts")
	}
}

func TestPolicySynthesis(t *testing.T) {
	tmpDir := t.TempDir()

	trustedKeys := []string{"cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="}
	substituters := []string{"https://cache.nixos.org"}
	trustedUsers := []string{"root"}

	written, err := WriteSynthesizedPolicies(tmpDir, trustedKeys, substituters, trustedUsers)
	if err != nil {
		t.Fatalf("failed to write synthesized policies: %v", err)
	}

	if len(written) != 3 {
		t.Fatalf("expected 3 files written, got %d", len(written))
	}

	// Verify nixos-store-hardened.nix
	moduleBytes, err := os.ReadFile(written[0])
	if err != nil {
		t.Fatalf("failed to read synthesized module: %v", err)
	}
	if !strings.Contains(string(moduleBytes), "require-sigs = true;") {
		t.Errorf("synthesized module missing require-sigs")
	}
	if !strings.Contains(string(moduleBytes), "sandbox = true;") {
		t.Errorf("synthesized module missing sandbox")
	}

	// Verify nix.conf
	confBytes, err := os.ReadFile(written[1])
	if err != nil {
		t.Fatalf("failed to read synthesized nix.conf: %v", err)
	}
	if !strings.Contains(string(confBytes), "require-sigs = true") {
		t.Errorf("synthesized nix.conf missing require-sigs")
	}

	// Verify Prometheus alerts
	alertsBytes, err := os.ReadFile(written[2])
	if err != nil {
		t.Fatalf("failed to read synthesized alerts: %v", err)
	}
	if !strings.Contains(string(alertsBytes), "NixStoreSignatureRejectionsHigh") {
		t.Errorf("synthesized alerts missing NixStoreSignatureRejectionsHigh")
	}
}

func TestScannerDirectoryTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	cleanNix := `
{ ... }:
{
  nix.settings = {
    require-sigs = true;
    trusted-public-keys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
    substituters = [ "https://cache.nixos.org" ];
    trusted-users = [ "root" ];
    sandbox = true;
    sandbox-fallback = false;
    pure-eval = true;
    accept-flake-config = false;
    build-users-group = "nixbld";
  };
  nix.gc.automatic = true;
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "node1.nix"), []byte(cleanNix), 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	scanner := NewNixStoreScanner()
	report, err := scanner.ScanTarget(tmpDir, "")
	if err != nil {
		t.Fatalf("scanner failed: %v", err)
	}

	if len(report.Configs) != 1 {
		t.Errorf("expected 1 config scanned, got %d", len(report.Configs))
	}
	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(report.Violations))
	}
	if report.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 score, got %.1f", report.Summary.ComplianceScore)
	}
}

func TestMemoryBoundsLimits(t *testing.T) {
	// Payload > MaxManifestBytes
	oversized := make([]byte, MaxManifestBytes+100)
	_, err := ParseNixStoreConfig(oversized, "huge.nix")
	if err == nil {
		t.Errorf("expected error for oversized manifest, got nil")
	}

	// Telemetry > MaxTelemetryBytes
	oversizedTel := make([]byte, MaxTelemetryBytes+100)
	_, err = ParseStoreTelemetryJSON(oversizedTel)
	if err == nil {
		t.Errorf("expected error for oversized telemetry, got nil")
	}
}
