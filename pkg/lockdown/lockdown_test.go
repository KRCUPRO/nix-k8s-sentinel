package lockdown

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalRulesCatalog(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical rules, got %d", len(rules))
	}

	seen := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" || seen[r.ID] {
			t.Errorf("duplicate or empty rule ID: %s", r.ID)
		}
		seen[r.ID] = true
		if r.Name == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s is missing name, description, or remediation", r.ID)
		}
		if r.CVSSScore <= 0.0 || r.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", r.ID, r.CVSSScore)
		}
		if r.Severity == "" {
			t.Errorf("rule %s has empty severity", r.ID)
		}
	}

	r := GetRuleByID("LOCKDOWN-001")
	if r == nil || r.ID != "LOCKDOWN-001" {
		t.Errorf("failed to retrieve LOCKDOWN-001 by ID")
	}
	if GetRuleByID("NON_EXISTENT") != nil {
		t.Errorf("expected nil for non-existent rule")
	}
}

func TestSHA256Validator(t *testing.T) {
	valid := "c026859345ee3a652cc596fc7c4ab59f77e20b33c16262bf6a992e5954a1be2e"
	if !ValidateSHA256Hash(valid) {
		t.Errorf("expected valid SHA-256 hash to pass")
	}

	invalidShort := "c026859345ee3a652cc596fc7c4ab59f77e20b33c16262bf6a992e5954a1be"
	if ValidateSHA256Hash(invalidShort) {
		t.Errorf("expected short hash to fail")
	}

	invalidChars := "z026859345ee3a652cc596fc7c4ab59f77e20b33c16262bf6a992e5954a1be2e"
	if ValidateSHA256Hash(invalidChars) {
		t.Errorf("expected invalid hex character to fail")
	}
}

func TestParseLiveLockdownSysfs(t *testing.T) {
	tests := []struct {
		input    string
		expected LockdownMode
	}{
		{"none integrity [confidentiality]", LockdownModeConfidentiality},
		{"none [integrity] confidentiality", LockdownModeIntegrity},
		{"[none] integrity confidentiality", LockdownModeNone},
		{"confidentiality", LockdownModeConfidentiality},
		{"integrity", LockdownModeIntegrity},
		{"", LockdownModeNone},
		{"unknown", LockdownModeNone},
	}

	for _, tc := range tests {
		res := ParseLiveLockdownSysfs(tc.input)
		if res != tc.expected {
			t.Errorf("ParseLiveLockdownSysfs(%q) = %s, expected %s", tc.input, res, tc.expected)
		}
	}
}

func TestParseLockdownConfigCompliant(t *testing.T) {
	content := []byte(`
{ config, pkgs, ... }:
{
  networking.hostName = "prod-node-01";
  security.lockdown = "confidentiality";
  security.protectKernelImage = true;

  boot.kernelParams = [
    "lockdown=confidentiality"
    "module.sig_enforce=1"
  ];

  boot.kernel.sysctl = {
    "kernel.modules_disabled" = 1;
    "dev.mem.restricted" = 1;
  };

  boot.lanzaboote.enable = true;
  security.secureBoot.enable = true;
  security.kexec.requireSignature = true;
}
`)

	cfg, err := ParseLockdownConfig(content, "test-compliant.nix")
	if err != nil {
		t.Fatalf("unexpected error parsing compliant config: %v", err)
	}

	if cfg.HostName != "prod-node-01" {
		t.Errorf("expected hostname prod-node-01, got %s", cfg.HostName)
	}
	if cfg.LockdownParam != LockdownModeConfidentiality {
		t.Errorf("expected LockdownParam confidentiality, got %s", cfg.LockdownParam)
	}
	if cfg.SecurityLockdown != LockdownModeConfidentiality {
		t.Errorf("expected SecurityLockdown confidentiality, got %s", cfg.SecurityLockdown)
	}
	if cfg.ProtectKernelImage == nil || !*cfg.ProtectKernelImage {
		t.Errorf("expected ProtectKernelImage = true")
	}
	if cfg.ModulesDisabled == nil || !*cfg.ModulesDisabled {
		t.Errorf("expected ModulesDisabled = true")
	}
	if cfg.ModuleSigEnforce == nil || !*cfg.ModuleSigEnforce {
		t.Errorf("expected ModuleSigEnforce = true")
	}
	if cfg.LanzabooteEnabled == nil || !*cfg.LanzabooteEnabled {
		t.Errorf("expected LanzabooteEnabled = true")
	}

	violations := AuditLockdownConfig(cfg)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for compliant config, got %d", len(violations))
	}
	score := ComputeComplianceScore(violations)
	if score != 100.0 {
		t.Errorf("expected compliance score 100.0, got %f", score)
	}
}

func TestParseLockdownConfigVulnerable(t *testing.T) {
	content := []byte(`
{ config, pkgs, ... }:
{
  networking.hostName = "vuln-node-01";
  security.lockdown = "none";
  security.protectKernelImage = false;

  boot.kernelParams = [
    "lockdown=none"
    "module.sig_enforce=0"
  ];

  boot.kernel.sysctl = {
    "kernel.modules_disabled" = 0;
  };

  boot.loader.secureboot.enable = false;
  boot.lanzaboote.enable = false;
}
`)

	cfg, err := ParseLockdownConfig(content, "test-vuln.nix")
	if err != nil {
		t.Fatalf("unexpected error parsing vulnerable config: %v", err)
	}

	violations := AuditLockdownConfig(cfg)
	if len(violations) == 0 {
		t.Fatalf("expected multiple violations for vulnerable config, got 0")
	}

	ruleHits := make(map[string]bool)
	for _, v := range violations {
		ruleHits[v.RuleID] = true
	}

	expectedRules := []string{"LOCKDOWN-001", "LOCKDOWN-003", "LOCKDOWN-004", "LOCKDOWN-007", "LOCKDOWN-008", "LOCKDOWN-009"}
	for _, expected := range expectedRules {
		if !ruleHits[expected] {
			t.Errorf("expected violation %s not triggered", expected)
		}
	}

	score := ComputeComplianceScore(violations)
	if score >= 50.0 {
		t.Errorf("expected low compliance score for vulnerable config, got %f", score)
	}
}

func TestAuditIntegrityOnlyMode(t *testing.T) {
	content := []byte(`
{ config, pkgs, ... }:
{
  networking.hostName = "integrity-node";
  security.lockdown = "integrity";
  boot.kernelParams = [ "lockdown=integrity" "module.sig_enforce=1" ];
  boot.kernel.sysctl."kernel.modules_disabled" = 1;
  security.protectKernelImage = true;
  boot.lanzaboote.enable = true;
  security.kexec.requireSignature = true;
}
`)

	cfg, err := ParseLockdownConfig(content, "integrity.nix")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	violations := AuditLockdownConfig(cfg)
	foundIntegrityViolation := false
	for _, v := range violations {
		if v.RuleID == "LOCKDOWN-002" {
			foundIntegrityViolation = true
		}
	}
	if !foundIntegrityViolation {
		t.Errorf("expected LOCKDOWN-002 for integrity-only lockdown mode")
	}
}

func TestTelemetryAuditor(t *testing.T) {
	telemetryJSON := []byte(`{
		"host_name": "worker-baremetal-04",
		"collected_at": "2026-10-19T10:00:00Z",
		"live_lockdown_mode": "none [integrity] confidentiality",
		"module_signature_enforced": true,
		"secure_boot_status": "disabled",
		"setup_mode_active": true,
		"dbx_version": "UEFI-DBX-2024-01",
		"dbx_release_date": "2024-01-01T00:00:00Z",
		"dbx_total_revocations": 30,
		"dbx_age_days": 180,
		"active_bootloader_path": "/boot/EFI/BOOT/shimx64.efi",
		"active_bootloader_sha256": "c026859345ee3a652cc596fc7c4ab59f77e20b33c16262bf6a992e5954a1be2e",
		"active_bootloader_revoked": true,
		"mok_list_x_revocations_count": 2,
		"unsigned_module_load_denials": 5,
		"direct_dev_mem_denials": 2,
		"kexec_denials": 0,
		"events": [
			{
				"timestamp": "2026-10-19T09:55:00Z",
				"event_type": "UNSIGNED_MODULE_DENIED",
				"syscall": "finit_module",
				"process": "insmod",
				"details": "Denied attempt to load unsigned rootkit.ko"
			}
		]
	}`)

	report, err := ParseLockdownTelemetryJSON(telemetryJSON)
	if err != nil {
		t.Fatalf("unexpected error parsing telemetry JSON: %v", err)
	}

	if report.HostName != "worker-baremetal-04" {
		t.Errorf("expected host worker-baremetal-04, got %s", report.HostName)
	}
	if report.LiveLockdownMode != LockdownModeIntegrity {
		t.Errorf("expected live lockdown mode integrity, got %s", report.LiveLockdownMode)
	}
	if len(report.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(report.Events))
	}

	cfg := &LockdownSecurityConfig{
		LockdownParam: LockdownModeConfidentiality,
	}

	violations := AuditLockdownTelemetry(report, cfg, nil)
	ruleHits := make(map[string]bool)
	for _, v := range violations {
		ruleHits[v.RuleID] = true
	}

	if !ruleHits["LOCKDOWN-004"] {
		t.Errorf("expected LOCKDOWN-004 for disabled secure boot / setup mode")
	}
	if !ruleHits["LOCKDOWN-005"] {
		t.Errorf("expected LOCKDOWN-005 for outdated DBX (> 60 days)")
	}
	if !ruleHits["LOCKDOWN-006"] {
		t.Errorf("expected LOCKDOWN-006 for revoked bootloader SHA-256")
	}
	if !ruleHits["LOCKDOWN-010"] {
		t.Errorf("expected LOCKDOWN-010 for unsigned module load denials")
	}
}

func TestMemoryBoundsLimits(t *testing.T) {
	giantManifest := make([]byte, MaxManifestBytes+1024)
	_, err := ParseLockdownConfig(giantManifest, "giant.nix")
	if err == nil {
		t.Errorf("expected error for manifest exceeding MaxManifestBytes ceiling")
	}

	giantTelemetry := make([]byte, MaxTelemetryBytes+1024)
	_, err = ParseLockdownTelemetryJSON(giantTelemetry)
	if err == nil {
		t.Errorf("expected error for telemetry exceeding MaxTelemetryBytes ceiling")
	}
}

func TestSynthesizers(t *testing.T) {
	cfg := &LockdownSecurityConfig{
		HostName: "test-node",
	}

	module := SynthesizeHardenedLockdownModule(cfg)
	if !strings.Contains(module, "security.lockdown = \"confidentiality\"") {
		t.Errorf("hardened module missing security.lockdown")
	}
	if !strings.Contains(module, "boot.lanzaboote = {") {
		t.Errorf("hardened module missing lanzaboote configuration")
	}

	service := SynthesizeDBXUpdateService()
	if !strings.Contains(service, "fwupdtool security --force") {
		t.Errorf("dbx service missing fwupd invocation")
	}

	alerts := SynthesizeLockdownAlertRules()
	if !strings.Contains(alerts, "alert: KernelLockdownDisabled") {
		t.Errorf("alerts missing KernelLockdownDisabled")
	}
	if !strings.Contains(alerts, "alert: RevokedBootloaderBinaryDetected") {
		t.Errorf("alerts missing RevokedBootloaderBinaryDetected")
	}

	tempDir, err := os.MkdirTemp("", "lockdown-synth-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	written, err := WriteSynthesizedPolicies(tempDir, cfg)
	if err != nil {
		t.Fatalf("failed to write synthesized policies: %v", err)
	}
	if len(written) != 3 {
		t.Errorf("expected 3 files written, got %d", len(written))
	}
	for _, f := range written {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected synthesized file %s to exist on disk", f)
		}
	}
}

func TestLockdownScannerEndToEnd(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lockdown-scan-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manifestPath := filepath.Join(tempDir, "configuration.nix")
	manifestContent := `
{ config, pkgs, ... }:
{
  networking.hostName = "k8s-worker-01";
  security.lockdown = "none";
  security.protectKernelImage = false;
  boot.lanzaboote.enable = false;
}
`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	telemetryPath := filepath.Join(tempDir, "telemetry.json")
	telReport := LockdownTelemetryReport{
		HostName:                 "k8s-worker-01",
		CollectedAt:              time.Now().UTC(),
		LiveLockdownMode:         LockdownModeNone,
		SecureBootStatus:         SecureBootEnabled,
		DBXVersion:               "2026.10-release",
		DBXTotalRevocations:      250,
		ActiveBootloaderPath:     "/boot/EFI/systemd/systemd-bootx64.efi",
		ActiveBootloaderSHA256:   "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
		ActiveBootloaderRevoked:  false,
		UnsignedModuleLoadDenials: 0,
	}
	telBytes, _ := json.Marshal(telReport)
	if err := os.WriteFile(telemetryPath, telBytes, 0o644); err != nil {
		t.Fatalf("failed to write telemetry: %v", err)
	}

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-92814",
				Component: "kernel-lockdown",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.4,
			},
		},
	}

	scanner := NewLockdownScanner()
	report, err := scanner.ScanLockdownTarget(manifestPath, telemetryPath, feed)
	if err != nil {
		t.Fatalf("scanner failed: %v", err)
	}

	if report.HostName != "k8s-worker-01" {
		t.Errorf("expected host k8s-worker-01, got %s", report.HostName)
	}
	if len(report.Violations) == 0 {
		t.Fatalf("expected violations for vulnerable configuration")
	}
	if report.Summary.ViolationCount == 0 {
		t.Errorf("expected summary violation count > 0")
	}
	if report.Summary.ComplianceScore >= 100.0 {
		t.Errorf("expected degraded compliance score, got %f", report.Summary.ComplianceScore)
	}
}
