package hsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestHSMRulesCatalog(t *testing.T) {
	rules := GetAllRules()
	if len(rules) < 12 {
		t.Fatalf("expected at least 12 canonical HSM rules, got %d", len(rules))
	}

	expectedRules := []string{
		"HSM-ENC-001", "HSM-ENC-002", "HSM-ENC-003", "HSM-ENC-004",
		"HSM-ENC-005", "HSM-ENC-006", "HSM-ENC-007", "HSM-ENC-008",
		"HSM-ENC-009", "HSM-ENC-010", "HSM-ENC-011", "HSM-ENC-012",
	}

	for _, ruleID := range expectedRules {
		r, ok := GetRule(ruleID)
		if !ok {
			t.Errorf("missing expected rule %s", ruleID)
		}
		if r.Title == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s has incomplete metadata", ruleID)
		}
		if r.DefaultCVSS <= 0.0 || r.DefaultCVSS > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", ruleID, r.DefaultCVSS)
		}
	}
}

func TestParseK8sEncryptionConfig_Compliant(t *testing.T) {
	manifest := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - kms:
          apiVersion: v2
          name: pkcs11-hsm-provider
          endpoint: unix:///var/run/kmsplugin/socket.sock
          timeout: 3s
          cachesize: 1000
      - kms:
          apiVersion: v2
          name: backup-nitro-provider
          endpoint: unix:///var/run/kmsplugin/backup.sock
          timeout: 3s
          cachesize: 500
      - identity: {}
`
	cfg, err := ParseK8sEncryptionConfig(strings.NewReader(manifest), "k8s-test.yaml")
	if err != nil {
		t.Fatalf("unexpected error parsing compliant manifest: %v", err)
	}

	if !cfg.IsKMSv2 {
		t.Errorf("expected IsKMSv2 to be true")
	}
	if cfg.PrimaryProviderType != "kms" {
		t.Errorf("expected PrimaryProviderType 'kms', got '%s'", cfg.PrimaryProviderType)
	}
	if len(cfg.KMSProviders) != 2 {
		t.Fatalf("expected 2 KMS providers, got %d", len(cfg.KMSProviders))
	}
	if !cfg.KMSProviders[0].IsUnixSocket {
		t.Errorf("expected provider 0 to be unix socket")
	}
	if !cfg.HasIdentityFallback {
		t.Errorf("expected HasIdentityFallback to be true")
	}

	violations := AuditEncryptionConfig(cfg, nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for compliant config, got %d", len(violations))
	}
}

func TestParseK8sEncryptionConfig_Vulnerable(t *testing.T) {
	manifest := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - identity: {}
      - kms:
          apiVersion: v1
          name: legacy-kms-provider
          endpoint: tcp://10.0.0.5:5000
          timeout: 10s
`
	cfg, err := ParseK8sEncryptionConfig(strings.NewReader(manifest), "k8s-vuln.yaml")
	if err != nil {
		t.Fatalf("unexpected error parsing vulnerable manifest: %v", err)
	}

	if cfg.IsKMSv2 {
		t.Errorf("expected IsKMSv2 to be false for v1beta1")
	}
	if cfg.PrimaryProviderType != "identity" {
		t.Errorf("expected PrimaryProviderType 'identity', got '%s'", cfg.PrimaryProviderType)
	}

	violations := AuditEncryptionConfig(cfg, nil)
	if len(violations) < 3 {
		t.Fatalf("expected at least 3 violations (ENC-001, ENC-002, ENC-008), got %d", len(violations))
	}

	hasEnc001 := false
	hasEnc002 := false
	hasEnc008 := false
	for _, v := range violations {
		if v.RuleID == "HSM-ENC-001" {
			hasEnc001 = true
		}
		if v.RuleID == "HSM-ENC-002" {
			hasEnc002 = true
		}
		if v.RuleID == "HSM-ENC-008" {
			hasEnc008 = true
		}
	}

	if !hasEnc001 {
		t.Errorf("expected violation HSM-ENC-001 for identity provider first")
	}
	if !hasEnc002 {
		t.Errorf("expected violation HSM-ENC-002 for KMS v1 apiVersion")
	}
	if !hasEnc008 {
		t.Errorf("expected violation HSM-ENC-008 for non-unix socket endpoint")
	}
}

func TestParsePKCS11URI_AndSanitizePIN(t *testing.T) {
	rawURI := "pkcs11:model=NitroHSM;token=k8s-root;object=master-kek;cipher=3DES;pin-value=SuperSecretPassword123"
	decl, err := ParsePKCS11URI(rawURI, "hsm.nix", 42)
	if err != nil {
		t.Fatalf("unexpected error parsing PKCS#11 URI: %v", err)
	}

	if !decl.HasPlaintextPIN {
		t.Errorf("expected HasPlaintextPIN to be true")
	}
	if decl.CipherSuite != Cipher3DES {
		t.Errorf("expected CipherSuite 3DES, got %s", decl.CipherSuite)
	}

	sanitized := SanitizePIN(rawURI)
	if strings.Contains(sanitized, "SuperSecretPassword123") {
		t.Errorf("expected plaintext PIN to be redacted in '%s'", sanitized)
	}
	if !strings.Contains(sanitized, "pin-value=[REDACTED]") {
		t.Errorf("expected [REDACTED] in sanitized URI: '%s'", sanitized)
	}

	violations := AuditPKCS11(decl, nil)
	hasEnc003 := false
	hasEnc004 := false
	hasEnc012 := false
	for _, v := range violations {
		if v.RuleID == "HSM-ENC-003" {
			hasEnc003 = true
		}
		if v.RuleID == "HSM-ENC-004" {
			hasEnc004 = true
		}
		if v.RuleID == "HSM-ENC-012" {
			hasEnc012 = true
		}
	}
	if !hasEnc003 || !hasEnc004 || !hasEnc012 {
		t.Errorf("expected ENC-003, ENC-004, and ENC-012, got: %+v", violations)
	}
}

func TestAuditTelemetry_OfflineAndOverdueRotation(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:       "CVE-2026-83190",
				Title:    "Kubernetes KMS v2 Provider PKCS#11 Session Leakage & Unrotated DEK Envelope Attack",
				Severity: intel.SeverityCritical,
			},
		},
	}

	telemetry := &HSMRuntimeTelemetry{
		ClusterID:        "prod-eu-central",
		NodeName:         "worker-baremetal-01",
		ProviderType:     ProviderPKCS11,
		PluginStatus:     PluginStatusOffline,
		NitroEnclaveOK:   false,
		AverageLatencyMs: 145.5,
		ActiveKeys: []HSMKeyTelemetry{
			{
				KeyID:        "kek-2025-01",
				KeyLabel:     "etcd-envelope-master",
				ProviderType: "PKCS11",
				AgeDays:      195.0,
			},
			{
				KeyID:        "kek-2026-02",
				KeyLabel:     "etcd-envelope-secondary",
				ProviderType: "PKCS11",
				AgeDays:      45.0,
			},
		},
	}

	violations := AuditTelemetry(telemetry, feed)
	if len(violations) < 4 {
		t.Fatalf("expected at least 4 violations (ENC-005, ENC-006, ENC-007, ENC-010), got %d", len(violations))
	}

	hasEnc005 := false
	hasEnc006 := false
	hasEnc007 := false
	hasEnc010 := false
	matchedCVE := false

	for _, v := range violations {
		if v.RuleID == "HSM-ENC-005" {
			hasEnc005 = true
		}
		if v.RuleID == "HSM-ENC-006" {
			hasEnc006 = true
		}
		if v.RuleID == "HSM-ENC-007" {
			hasEnc007 = true
			if v.MatchedCVE == "CVE-2026-83190" {
				matchedCVE = true
			}
		}
		if v.RuleID == "HSM-ENC-010" {
			hasEnc010 = true
		}
	}

	if !hasEnc005 {
		t.Errorf("missing HSM-ENC-005 for offline plugin")
	}
	if !hasEnc006 {
		t.Errorf("missing HSM-ENC-006 for unrotated key (>180 days)")
	}
	if !hasEnc007 || !matchedCVE {
		t.Errorf("missing HSM-ENC-007 or CVE-2026-83190 correlation")
	}
	if !hasEnc010 {
		t.Errorf("missing HSM-ENC-010 for latency > 100ms")
	}
}

func TestHSMScanner_FileAndTelemetryScan(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hsm-scanner-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "encryption-config.yaml")
	manifestContent := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          apiVersion: v2
          name: primary-kms
          endpoint: unix:///var/run/kms.sock
          timeout: 2s
          cachesize: 1000
      - identity: {}
`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0600); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	telemetryPath := filepath.Join(tmpDir, "telemetry.json")
	telemetryContent := `[
  {
    "cluster_id": "test-cluster",
    "node_name": "node-1",
    "provider_type": "PKCS11",
    "plugin_status": "HEALTHY",
    "nitro_enclave_ok": true,
    "average_latency_ms": 12.4,
    "active_keys": [
      {
        "key_id": "kek-primary",
        "key_label": "master",
        "age_days": 20.0
      }
    ]
  }
]`
	if err := os.WriteFile(telemetryPath, []byte(telemetryContent), 0600); err != nil {
		t.Fatalf("failed to write telemetry: %v", err)
	}

	scanner := NewHSMScanner(nil)

	// Scan manifest
	rep1, err := scanner.ScanPath(manifestPath)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}
	if rep1.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score for clean manifest, got %f", rep1.Summary.ComplianceScore)
	}

	// Scan telemetry
	rep2, err := scanner.ScanTelemetryFile(telemetryPath)
	if err != nil {
		t.Fatalf("ScanTelemetryFile failed: %v", err)
	}
	if rep2.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score for healthy telemetry, got %f", rep2.Summary.ComplianceScore)
	}
}

func TestNixOSHSMHost_DisabledDaemon(t *testing.T) {
	nixConfig := `
{ config, pkgs, ... }:
{
  services.p11-kit.enable = false;
  hardware.nitro-enclaves.enable = false;
  environment.systemPackages = [ pkgs.opensc ];
}
`
	p11s, nitros, p11On, nitroOn, err := ParseNixOSHSMConfig(strings.NewReader(nixConfig), "configuration.nix")
	if err != nil {
		t.Fatalf("unexpected error parsing nix config: %v", err)
	}
	if p11On || nitroOn {
		t.Errorf("expected daemons to be disabled")
	}

	violations := AuditNixOSHost(p11s, nitros, p11On, nitroOn, "hsm-host.nix")
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation for disabled HSM daemons, got %d", len(violations))
	}
	if violations[0].RuleID != "HSM-ENC-011" {
		t.Errorf("expected rule HSM-ENC-011, got %s", violations[0].RuleID)
	}
}
