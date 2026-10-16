package pqc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestRulesCatalog(t *testing.T) {
	rules := GetRulesCatalog()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical PQC rules, got %d", len(rules))
	}

	for _, r := range rules {
		if !strings.HasPrefix(r.RuleID, "PQC-TLS-") {
			t.Errorf("rule %s missing standard PQC-TLS prefix", r.RuleID)
		}
		if r.Title == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s has empty metadata fields", r.RuleID)
		}
		if r.CVSSScore <= 0.0 || r.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %.1f", r.RuleID, r.CVSSScore)
		}
		if r.Severity != intel.SeverityCritical && r.Severity != intel.SeverityHigh && r.Severity != intel.SeverityMedium && r.Severity != intel.SeverityLow {
			t.Errorf("rule %s has invalid severity: %s", r.RuleID, r.Severity)
		}
	}

	// Test LookupRule
	r, found := LookupRule("PQC-TLS-002")
	if !found {
		t.Fatalf("failed to lookup PQC-TLS-002")
	}
	if r.MatchedCVE != "CVE-2026-94301" {
		t.Errorf("expected PQC-TLS-002 to map to CVE-2026-94301, got %s", r.MatchedCVE)
	}

	_, notFound := LookupRule("PQC-TLS-999")
	if notFound {
		t.Errorf("expected PQC-TLS-999 to not be found")
	}
}

func TestK8sControlPlaneVulnerable(t *testing.T) {
	tmpDir := t.TempDir()
	vulnManifest := filepath.Join(tmpDir, "kube-apiserver-vuln.yaml")
	content := `
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --tls-min-version=VersionTLS12
    - --tls-cipher-suites=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
`
	if err := os.WriteFile(vulnManifest, []byte(content), 0644); err != nil {
		t.Fatalf("failed writing test manifest: %v", err)
	}

	cfg, err := ParseK8sControlPlaneManifest(vulnManifest)
	if err != nil {
		t.Fatalf("failed parsing vulnerable manifest: %v", err)
	}

	if cfg.Component != "kube-apiserver" {
		t.Errorf("expected component 'kube-apiserver', got '%s'", cfg.Component)
	}
	if cfg.TLSMinVersion != "VersionTLS12" {
		t.Errorf("expected TLSMinVersion 'VersionTLS12', got '%s'", cfg.TLSMinVersion)
	}

	violations := AuditControlPlaneConfig(cfg, nil)
	if len(violations) == 0 {
		t.Fatalf("expected multiple violations on vulnerable manifest, got 0")
	}

	ruleIDs := make(map[string]bool)
	for _, v := range violations {
		ruleIDs[v.RuleID] = true
	}

	if !ruleIDs["PQC-TLS-001"] {
		t.Errorf("expected PQC-TLS-001 (insecure TLS version) violation")
	}
	if !ruleIDs["PQC-TLS-002"] {
		t.Errorf("expected PQC-TLS-002 (missing hybrid PQC) violation")
	}
	if !ruleIDs["PQC-TLS-003"] {
		t.Errorf("expected PQC-TLS-003 (deprecated weak cipher) violation")
	}
}

func TestK8sControlPlaneHardened(t *testing.T) {
	tmpDir := t.TempDir()
	hardenedManifest := filepath.Join(tmpDir, "kube-apiserver-hardened.yaml")
	content := `
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --tls-min-version=VersionTLS13
    - --tls-cipher-suites=TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256
    - --tls-key-exchange-groups=X25519MLKEM768,SecP384r1MLKEM1024
`
	if err := os.WriteFile(hardenedManifest, []byte(content), 0644); err != nil {
		t.Fatalf("failed writing test manifest: %v", err)
	}

	cfg, err := ParseK8sControlPlaneManifest(hardenedManifest)
	if err != nil {
		t.Fatalf("failed parsing hardened manifest: %v", err)
	}

	violations := AuditControlPlaneConfig(cfg, nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations on hardened manifest, got %d: %+v", len(violations), violations)
	}
}

func TestNixOSCryptoAudit(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Vulnerable NixOS Config
	vulnNix := filepath.Join(tmpDir, "crypto-vuln.nix")
	vulnContent := `
{ config, pkgs, ... }:
{
  environment.etc."ssl/openssl.cnf".text = ''
    providers = [ "default" ]
    Groups = "X25519:P-256";
    MinProtocol = "TLSv1.2";
  '';
  networking.gnutls.priority = "@SYSTEM:!VERS-ALL:+VERS-TLS1.2";
}
`
	if err := os.WriteFile(vulnNix, []byte(vulnContent), 0644); err != nil {
		t.Fatalf("failed writing vulnerable nix: %v", err)
	}

	cfgVuln, err := ParseNixOSCryptoConfig(vulnNix)
	if err != nil {
		t.Fatalf("failed parsing vulnerable nix config: %v", err)
	}

	vulnViolations := AuditNixOSCrypto(cfgVuln, nil)
	if len(vulnViolations) == 0 {
		t.Fatalf("expected violations for vulnerable NixOS config, got 0")
	}

	ruleIDs := make(map[string]bool)
	for _, v := range vulnViolations {
		ruleIDs[v.RuleID] = true
	}
	if !ruleIDs["PQC-TLS-007"] {
		t.Errorf("expected PQC-TLS-007 (missing oqsprovider)")
	}
	if !ruleIDs["PQC-TLS-002"] {
		t.Errorf("expected PQC-TLS-002 (missing hybrid groups)")
	}
	if !ruleIDs["PQC-TLS-001"] {
		t.Errorf("expected PQC-TLS-001 (MinProtocol TLSv1.2)")
	}

	// 2. Hardened NixOS Config
	hardenedNix := filepath.Join(tmpDir, "crypto-hardened.nix")
	hardenedContent := `
{ config, pkgs, ... }:
{
  environment.etc."ssl/openssl.cnf".text = ''
    providers = [ "default" "oqsprovider" ]
    Groups = "X25519MLKEM768:SecP384r1MLKEM1024";
    MinProtocol = "TLSv1.3";
  '';
  networking.gnutls.priority = "@SYSTEM:!VERS-ALL:+VERS-TLS1.3:+GROUP-X25519-KYBER768";
}
`
	if err := os.WriteFile(hardenedNix, []byte(hardenedContent), 0644); err != nil {
		t.Fatalf("failed writing hardened nix: %v", err)
	}

	cfgHardened, err := ParseNixOSCryptoConfig(hardenedNix)
	if err != nil {
		t.Fatalf("failed parsing hardened nix config: %v", err)
	}

	hardenedViolations := AuditNixOSCrypto(cfgHardened, nil)
	if len(hardenedViolations) != 0 {
		t.Errorf("expected 0 violations for hardened NixOS config, got %d: %+v", len(hardenedViolations), hardenedViolations)
	}
}

func TestTelemetryAudit(t *testing.T) {
	telemetry := &PQCRuntimeTelemetry{
		ClusterID:  "sentinel-cluster-01",
		CapturedAt: time.Now(),
		Handshakes: []PQCHandshakeTelemetry{
			{
				Endpoint:           "10.244.0.1:6443",
				Component:          "kube-apiserver",
				ProtocolVersion:    "TLSv1.3",
				CipherSuite:        "TLS_AES_256_GCM_SHA384",
				KeyExchangeGroup:   "X25519MLKEM768",
				SignatureAlgorithm: "ml-dsa-65",
				IsHybridPQC:        true,
				HandshakeLatencyMs: 12.4,
			},
			{
				Endpoint:           "10.244.0.2:2379",
				Component:          "etcd",
				ProtocolVersion:    "TLSv1.2",
				CipherSuite:        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				KeyExchangeGroup:   "X25519",
				SignatureAlgorithm: "rsa_pkcs1_sha256",
				IsHybridPQC:        false,
				HandshakeLatencyMs: 8.2,
			},
		},
	}

	violations, hybridPct, tls13Pct := AuditTelemetry(telemetry, nil)
	if len(violations) == 0 {
		t.Fatalf("expected violations for mixed telemetry, got 0")
	}

	if hybridPct != 50.0 {
		t.Errorf("expected hybridPct 50.0, got %.1f", hybridPct)
	}
	if tls13Pct != 50.0 {
		t.Errorf("expected tls13Pct 50.0, got %.1f", tls13Pct)
	}

	summary := ComputePQCSummary(1, 2, 2, violations, hybridPct, tls13Pct)
	if summary.ViolationsCount != len(violations) {
		t.Errorf("summary violation count mismatch: %d vs %d", summary.ViolationsCount, len(violations))
	}
}

func TestEvaluateCNSACompliance(t *testing.T) {
	// CNSA 2.0 2033 Compliant
	res33 := EvaluateCNSACompliance(
		[]string{"TLS_AES_256_GCM_SHA384"},
		[]string{"SecP384r1MLKEM1024"},
		"VersionTLS13",
	)
	if res33 != CNSACompliant2033 {
		t.Errorf("expected CNSACompliant2033, got %s", res33)
	}

	// CNSA 2.0 2030 Compliant
	res30 := EvaluateCNSACompliance(
		[]string{"TLS_AES_256_GCM_SHA384"},
		[]string{"X25519MLKEM768"},
		"VersionTLS13",
	)
	if res30 != CNSACompliant2030 {
		t.Errorf("expected CNSACompliant2030, got %s", res30)
	}

	// Non-compliant: TLS 1.2
	resNon := EvaluateCNSACompliance(
		[]string{"TLS_AES_256_GCM_SHA384"},
		[]string{"X25519MLKEM768"},
		"VersionTLS12",
	)
	if resNon != CNSANonCompliant {
		t.Errorf("expected CNSANonCompliant, got %s", resNon)
	}
}

func TestPolicySynthesis(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "policies")

	written, err := WriteSynthesizedPQCConfig(outDir)
	if err != nil {
		t.Fatalf("failed synthesizing PQC policies: %v", err)
	}

	if len(written) != 3 {
		t.Fatalf("expected 3 files written, got %d", len(written))
	}

	nixPath := written["nixos-module"]
	data, err := os.ReadFile(nixPath)
	if err != nil {
		t.Fatalf("failed reading synthesized nix module: %v", err)
	}
	if !strings.Contains(string(data), "oqsprovider") {
		t.Errorf("synthesized nix module missing oqsprovider")
	}
}

func TestScannerDirectoryWalk(t *testing.T) {
	tmpDir := t.TempDir()

	// Write 1 k8s manifest and 1 nix file
	k8sFile := filepath.Join(tmpDir, "apiserver.yaml")
	_ = os.WriteFile(k8sFile, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --tls-min-version=VersionTLS13
    - --tls-cipher-suites=TLS_AES_256_GCM_SHA384
    - --tls-key-exchange-groups=X25519MLKEM768
`), 0644)

	scanner := NewPQCScanner(nil)
	report, err := scanner.ScanPath(tmpDir)
	if err != nil {
		t.Fatalf("scanner failed on directory walk: %v", err)
	}

	if report.Summary.TotalConfigsScanned == 0 {
		t.Errorf("expected at least 1 config scanned, got 0")
	}
}

func TestBoundsAndSafety(t *testing.T) {
	tmpDir := t.TempDir()

	// Non-existent path
	scanner := NewPQCScanner(nil)
	_, err := scanner.ScanPath(filepath.Join(tmpDir, "non-existent"))
	if err == nil {
		t.Errorf("expected error scanning non-existent path")
	}

	// Nil inputs
	if v := AuditControlPlaneConfig(nil, nil); len(v) != 0 {
		t.Errorf("expected 0 violations for nil config")
	}
	if v := AuditNixOSCrypto(nil, nil); len(v) != 0 {
		t.Errorf("expected 0 violations for nil nixos config")
	}
	if v, h, tls := AuditTelemetry(nil, nil); len(v) != 0 || h != 0 || tls != 0 {
		t.Errorf("expected 0 violations for nil telemetry")
	}
}
