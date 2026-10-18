package webhook

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Helper to generate a real synthetic self-signed X.509 CA certificate in base64.
func generateTestCACertBase64(t *testing.T, validDays int) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(time.Duration(validDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName:   "sentinel-test-ca",
			Organization: []string{"Sentinel Security PKI"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return base64.StdEncoding.EncodeToString(pemBytes)
}

func TestRulesCatalog(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical webhook rules, got %d", len(rules))
	}

	requiredIDs := []string{
		"WH-RADAR-001", "WH-RADAR-002", "WH-RADAR-003", "WH-RADAR-004",
		"WH-RADAR-005", "WH-RADAR-006", "WH-RADAR-007", "WH-RADAR-008",
		"WH-RADAR-009", "WH-RADAR-010", "WH-RADAR-011", "WH-RADAR-012",
	}

	for _, id := range requiredIDs {
		rule, ok := GetRule(id)
		if !ok {
			t.Errorf("missing rule %s in rules catalog", id)
		}
		if rule.Title == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has empty metadata fields", id)
		}
		if rule.CVSSScore <= 0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", id, rule.CVSSScore)
		}
	}
}

func TestParseAdmissionWebhooks(t *testing.T) {
	validCA := generateTestCACertBase64(t, 90)

	yamlContent := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: gatekeeper-validating-webhook-configuration
webhooks:
  - name: validation.gatekeeper.sh
    admissionReviewVersions:
      - v1
    clientConfig:
      caBundle: ` + validCA + `
      service:
        name: gatekeeper-webhook-service
        namespace: gatekeeper-system
        path: /v1/admit
        port: 443
    failurePolicy: Fail
    timeoutSeconds: 3
    sideEffects: None
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system"]
`

	configs, err := ParseAdmissionWebhooks(yamlContent, "test-gatekeeper.yaml")
	if err != nil {
		t.Fatalf("unexpected error parsing webhooks: %v", err)
	}

	if len(configs) != 1 {
		t.Fatalf("expected 1 webhook config, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.Name != "validation.gatekeeper.sh" {
		t.Errorf("expected webhook name validation.gatekeeper.sh, got %q", cfg.Name)
	}
	if cfg.FailurePolicy != FailurePolicyFail {
		t.Errorf("expected failurePolicy Fail, got %v", cfg.FailurePolicy)
	}
	if cfg.TimeoutSeconds != 3 {
		t.Errorf("expected timeoutSeconds 3, got %d", cfg.TimeoutSeconds)
	}
	if !cfg.ExemptsKubeSystem {
		t.Errorf("expected ExemptsKubeSystem to be true")
	}
	if !cfg.CAValid || cfg.CAExpired {
		t.Errorf("expected valid non-expired CA, valid=%v, expired=%v", cfg.CAValid, cfg.CAExpired)
	}
	if cfg.CADaysRemaining < 80 {
		t.Errorf("expected ~90 days remaining, got %d", cfg.CADaysRemaining)
	}
}

func TestAuditVulnerableWebhook(t *testing.T) {
	expiredCA := generateTestCACertBase64(t, -5) // expired 5 days ago

	yamlContent := `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: vulnerable-mutating-webhook
webhooks:
  - name: policy.security.cluster.local
    admissionReviewVersions:
      - v1beta1
    clientConfig:
      caBundle: ` + expiredCA + `
      url: http://192.168.1.100:8080/mutate
    failurePolicy: Ignore
    timeoutSeconds: 15
    sideEffects: Some
    reinvocationPolicy: Never
`

	configs, err := ParseAdmissionWebhooks(yamlContent, "vuln-webhook.yaml")
	if err != nil {
		t.Fatalf("failed to parse vulnerable webhook: %v", err)
	}

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-52194",
				Component: "admission-webhook",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.2,
			},
		},
	}

	violations := AuditWebhookConfig(configs[0], feed)
	if len(violations) == 0 {
		t.Fatalf("expected multiple violations for vulnerable webhook, got 0")
	}

	violationMap := make(map[string]WebhookViolation)
	for _, v := range violations {
		violationMap[v.RuleID] = v
	}

	expectedRules := []string{
		"WH-RADAR-001", // failurePolicy: Ignore on security webhook
		"WH-RADAR-003", // expired CA
		"WH-RADAR-005", // timeout > 3s
		"WH-RADAR-007", // v1beta1
		"WH-RADAR-008", // missing reinvocationPolicy: IfNeeded
		"WH-RADAR-009", // sideEffects: Some
		"WH-RADAR-012", // plaintext HTTP URL
	}

	for _, ruleID := range expectedRules {
		if _, found := violationMap[ruleID]; !found {
			t.Errorf("expected rule %s violation to be reported", ruleID)
		}
	}
}

func TestAuditWebhookTelemetry(t *testing.T) {
	configs := []WebhookConfig{
		{
			Name: "sentinel-validator",
			Type: WebhookTypeValidating,
		},
	}

	telJSON := []byte(`{
		"timestamp": "2026-10-18T12:00:00Z",
		"cluster_id": "k8s-prod-us-east-1",
		"metrics": [
			{
				"webhook_name": "sentinel-validator",
				"p50_ms": 12.5,
				"p95_ms": 280.0,
				"p99_ms": 650.0,
				"request_count": 12500,
				"error_rate_percent": 8.5,
				"timeout_count": 42,
				"stall_warning": true
			}
		],
		"ca_certificates": [
			{
				"cert_name": "sentinel-ca-cert",
				"issuer": "cert-manager",
				"subject": "sentinel-root",
				"not_before": "2026-01-01T00:00:00Z",
				"not_after": "2026-10-25T00:00:00Z",
				"days_remaining": 7,
				"is_expired": false,
				"auto_rotation_enabled": false
			}
		]
	}`)

	tel, err := ParseWebhookTelemetryJSON(telJSON)
	if err != nil {
		t.Fatalf("failed to parse telemetry JSON: %v", err)
	}

	violations := AuditWebhookTelemetry(tel, configs)
	if len(violations) == 0 {
		t.Fatalf("expected telemetry violations, got 0")
	}

	foundP99 := false
	foundErrorRate := false
	foundExpiringCA := false

	for _, v := range violations {
		if v.RuleID == "WH-RADAR-010" {
			foundP99 = true
		}
		if v.RuleID == "WH-RADAR-011" {
			foundErrorRate = true
		}
		if v.RuleID == "WH-RADAR-004" {
			foundExpiringCA = true
		}
	}

	if !foundP99 {
		t.Errorf("expected WH-RADAR-010 (p99 latency stall) violation")
	}
	if !foundErrorRate {
		t.Errorf("expected WH-RADAR-011 (elevated error rate) violation")
	}
	if !foundExpiringCA {
		t.Errorf("expected WH-RADAR-004 (expiring CA in 7 days) violation")
	}
}

func TestSynthesizers(t *testing.T) {
	// 1. Hardened Validating Webhook
	hardenedYAML := SynthesizeHardenedValidatingWebhook("sentinel-admit", "sentinel-svc", "sentinel-system", "/validate", 443)
	if !strings.Contains(hardenedYAML, "failurePolicy: Fail") {
		t.Errorf("expected failurePolicy: Fail in synthesized webhook")
	}
	if !strings.Contains(hardenedYAML, "timeoutSeconds: 3") {
		t.Errorf("expected timeoutSeconds: 3 in synthesized webhook")
	}
	if !strings.Contains(hardenedYAML, "kube-system") {
		t.Errorf("expected kube-system exemption in synthesized webhook")
	}
	if !strings.Contains(hardenedYAML, "cert-manager.io/inject-ca-from") {
		t.Errorf("expected cert-manager injection annotation in synthesized webhook")
	}

	// 2. cert-manager CA refresher
	certYAML := SynthesizeCertManagerCABundleRefresher("sentinel-admit", "sentinel-system", "sentinel-ca-issuer")
	if !strings.Contains(certYAML, "isCA: true") {
		t.Errorf("expected isCA: true in synthesized cert")
	}
	if !strings.Contains(certYAML, "renewBefore: 720h") {
		t.Errorf("expected 30-day renewal buffer in synthesized cert")
	}

	// 3. PrometheusRule Alert Policy
	alertYAML := SynthesizeWebhookAPIServerAlertRule("sentinel", "sentinel-admit", "monitoring")
	if !strings.Contains(alertYAML, "AdmissionWebhookLatencyStall") {
		t.Errorf("expected AdmissionWebhookLatencyStall alert in PrometheusRule")
	}
	if !strings.Contains(alertYAML, "AdmissionWebhookCAExpiringSoon") {
		t.Errorf("expected AdmissionWebhookCAExpiringSoon alert in PrometheusRule")
	}
}

func TestScanner(t *testing.T) {
	tempDir := t.TempDir()
	validCA := generateTestCACertBase64(t, 90)

	manifestPath := filepath.Join(tempDir, "webhook-hardened.yaml")
	manifestContent := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-sentinel-validating
webhooks:
  - name: validate.sentinel.io
    admissionReviewVersions: ["v1"]
    clientConfig:
      caBundle: ` + validCA + `
      service:
        name: sentinel-service
        namespace: sentinel-system
        path: /validate
        port: 443
    failurePolicy: Fail
    timeoutSeconds: 3
    sideEffects: None
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system"]
`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write test manifest: %v", err)
	}

	scanner := NewWebhookScanner()
	report, err := scanner.ScanAll(tempDir, "", nil)
	if err != nil {
		t.Fatalf("scanner.ScanAll failed: %v", err)
	}

	if report.Summary.TotalWebhooksScanned != 1 {
		t.Errorf("expected 1 webhook scanned, got %d", report.Summary.TotalWebhooksScanned)
	}
	if report.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score for compliant webhook, got %.1f", report.Summary.ComplianceScore)
	}
}

func TestGenerateProductionFixtures(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "fixtures")
	if _, err := os.Stat(fixturesDir); os.IsNotExist(err) {
		return // not running from repo root
	}

	validCA := generateTestCACertBase64(t, 180)
	expiredCA := generateTestCACertBase64(t, -20)

	hardenedContent := `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: sentinel-validating-webhook
  annotations:
    cert-manager.io/inject-ca-from: sentinel-system/sentinel-ca
    sentinel.defense.io/hardened-by: nix-k8s-sentinel
webhooks:
  - name: validation.sentinel.io
    admissionReviewVersions: ["v1"]
    clientConfig:
      caBundle: ` + validCA + `
      service:
        name: sentinel-webhook-svc
        namespace: sentinel-system
        path: /validate
        port: 443
    failurePolicy: Fail
    timeoutSeconds: 3
    sideEffects: None
    matchPolicy: Equivalent
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system", "kube-node-lease", "kube-public"]
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: ["*"]
        apiVersions: ["v1"]
        resources: ["pods", "deployments", "daemonsets"]
        scope: Namespaced
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: sentinel-mutating-webhook
  annotations:
    cert-manager.io/inject-ca-from: sentinel-system/sentinel-ca
webhooks:
  - name: mutation.sentinel.io
    admissionReviewVersions: ["v1"]
    clientConfig:
      caBundle: ` + validCA + `
      service:
        name: sentinel-mutator-svc
        namespace: sentinel-system
        path: /mutate
        port: 443
    failurePolicy: Fail
    timeoutSeconds: 3
    reinvocationPolicy: IfNeeded
    sideEffects: None
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system"]
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        scope: Namespaced
`
	_ = os.WriteFile(filepath.Join(fixturesDir, "k8s-admission-webhook.yaml"), []byte(hardenedContent), 0644)

	vulnerableContent := `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: vulnerable-policy-gatekeeper
webhooks:
  - name: bypass.security.gatekeeper.sh
    admissionReviewVersions: ["v1beta1"]
    clientConfig:
      caBundle: ` + expiredCA + `
      service:
        name: gatekeeper-broken-svc
        namespace: default
        path: /v1/admit
        port: 8080
    failurePolicy: Ignore
    timeoutSeconds: 20
    sideEffects: Some
    rules:
      - operations: ["*"]
        apiGroups: ["*"]
        apiVersions: ["*"]
        resources: ["*"]
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: unauthenticated-external-mutator
webhooks:
  - name: external.insecure.mutator.net
    admissionReviewVersions: ["v1beta1"]
    clientConfig:
      insecureSkipTLSVerify: true
      url: http://192.168.100.50:9090/mutate
    failurePolicy: Ignore
    timeoutSeconds: 15
    reinvocationPolicy: Never
    sideEffects: Some
`
	_ = os.WriteFile(filepath.Join(fixturesDir, "k8s-admission-webhook-vulnerable.yaml"), []byte(vulnerableContent), 0644)

	telemetryContent := `{
  "timestamp": "2026-10-18T12:00:00Z",
  "cluster_id": "k8s-baremetal-prod-01",
  "metrics": [
    {
      "webhook_name": "validation.sentinel.io",
      "p50_ms": 5.2,
      "p95_ms": 32.0,
      "p99_ms": 88.0,
      "request_count": 145000,
      "error_rate_percent": 0.01,
      "timeout_count": 0,
      "stall_warning": false
    },
    {
      "webhook_name": "bypass.security.gatekeeper.sh",
      "p50_ms": 140.0,
      "p95_ms": 490.0,
      "p99_ms": 820.0,
      "request_count": 28400,
      "error_rate_percent": 8.4,
      "timeout_count": 48,
      "stall_warning": true
    },
    {
      "webhook_name": "external.insecure.mutator.net",
      "p50_ms": 210.0,
      "p95_ms": 680.0,
      "p99_ms": 1150.0,
      "request_count": 12000,
      "error_rate_percent": 12.1,
      "timeout_count": 95,
      "stall_warning": true
    }
  ],
  "ca_certificates": [
    {
      "cert_name": "sentinel-ca",
      "issuer": "cert-manager",
      "subject": "sentinel-root-ca",
      "not_before": "2026-09-01T00:00:00Z",
      "not_after": "2027-03-01T00:00:00Z",
      "days_remaining": 133,
      "is_expired": false,
      "auto_rotation_enabled": true
    },
    {
      "cert_name": "legacy-cluster-ca",
      "issuer": "internal-vault",
      "subject": "cluster-legacy-ca",
      "not_before": "2025-10-18T00:00:00Z",
      "not_after": "2026-10-28T00:00:00Z",
      "days_remaining": 10,
      "is_expired": false,
      "auto_rotation_enabled": false
    },
    {
      "cert_name": "expired-gatekeeper-ca",
      "issuer": "manual-selfsigned",
      "subject": "gatekeeper-ca",
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2026-09-15T00:00:00Z",
      "days_remaining": -33,
      "is_expired": true,
      "auto_rotation_enabled": false
    }
  ]
}
`
	_ = os.WriteFile(filepath.Join(fixturesDir, "webhook-telemetry.json"), []byte(telemetryContent), 0644)
}

