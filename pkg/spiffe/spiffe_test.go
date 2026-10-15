package spiffe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestRuleCatalogCompleteness(t *testing.T) {
	if len(CanonicalRules) != 12 {
		t.Fatalf("expected 12 canonical SPIFFE rules, found %d", len(CanonicalRules))
	}

	for _, rule := range CanonicalRules {
		if rule.RuleID == "" {
			t.Errorf("empty rule ID found")
		}
		if rule.Title == "" {
			t.Errorf("empty title for rule %s", rule.RuleID)
		}
		if rule.BaseCVSS <= 0 || rule.BaseCVSS > 10.0 {
			t.Errorf("invalid CVSS score %.1f for rule %s", rule.BaseCVSS, rule.RuleID)
		}
		if rule.Remediation == "" {
			t.Errorf("missing remediation for rule %s", rule.RuleID)
		}
	}

	if _, exists := GetRule("SPIFFE-SVID-001"); !exists {
		t.Errorf("SPIFFE-SVID-001 not found in RuleMap")
	}
	if _, exists := GetRule("SPIFFE-SVID-012"); !exists {
		t.Errorf("SPIFFE-SVID-012 not found in RuleMap")
	}
}

func TestParseSPIFFEID(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantTD     string
		wantPath   string
		shouldFail bool
	}{
		{
			name:       "valid standard workload ID",
			raw:        "spiffe://cluster.local/ns/prod/sa/payment-service",
			wantTD:     "cluster.local",
			wantPath:   "/ns/prod/sa/payment-service",
			shouldFail: false,
		},
		{
			name:       "valid federated ID",
			raw:        "spiffe://partner-mesh.internal/workload/order-processor",
			wantTD:     "partner-mesh.internal",
			wantPath:   "/workload/order-processor",
			shouldFail: false,
		},
		{
			name:       "missing scheme",
			raw:        "cluster.local/ns/prod/sa/payment",
			shouldFail: true,
		},
		{
			name:       "wrong scheme",
			raw:        "https://cluster.local/ns/prod/sa/payment",
			shouldFail: true,
		},
		{
			name:       "missing path",
			raw:        "spiffe://cluster.local",
			shouldFail: true,
		},
		{
			name:       "empty ID",
			raw:        "",
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td, path, err := ParseSPIFFEID(tt.raw)
			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected failure for %s, but got nil", tt.raw)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tt.raw, err)
				}
				if td != tt.wantTD {
					t.Errorf("trust domain mismatch: got %s, want %s", td, tt.wantTD)
				}
				if path != tt.wantPath {
					t.Errorf("path mismatch: got %s, want %s", path, tt.wantPath)
				}
			}
		})
	}
}

func TestAuditSVID(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	primaryTD := "cluster.local"
	federated := []string{"partner-mesh.internal"}

	t.Run("Compliant SVID", func(t *testing.T) {
		record := SVIDRecord{
			SPIFFEID:       "spiffe://cluster.local/ns/production/sa/api-gateway",
			TrustDomain:    "cluster.local",
			Namespace:      "production",
			WorkloadID:     "api-gateway",
			IssuedAt:       now.Add(-2 * time.Hour),
			ExpiresAt:      now.Add(10 * time.Hour), // 12h lifespan total
			KeyType:        "ECDSA-P256",
			KeyBits:        256,
			ActiveNode:     "worker-01",
		}

		violations := AuditSVID(record, primaryTD, federated, now)
		if len(violations) != 0 {
			t.Fatalf("expected 0 violations for compliant SVID, got %d: %+v", len(violations), violations)
		}
	})

	t.Run("Untrusted Foreign Trust Domain", func(t *testing.T) {
		record := SVIDRecord{
			SPIFFEID:       "spiffe://rogue-cloud.org/ns/default/sa/injected-pod",
			TrustDomain:    "rogue-cloud.org",
			WorkloadID:     "injected-pod",
			IssuedAt:       now.Add(-1 * time.Hour),
			ExpiresAt:      now.Add(5 * time.Hour),
			KeyType:        "ECDSA-P256",
		}

		violations := AuditSVID(record, primaryTD, federated, now)
		found := false
		for _, v := range violations {
			if v.RuleID == "SPIFFE-SVID-001" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPIFFE-SVID-001 for foreign trust domain, got %+v", violations)
		}
	})

	t.Run("Excessive Lifespan (> 24 Hours)", func(t *testing.T) {
		record := SVIDRecord{
			SPIFFEID:       "spiffe://cluster.local/ns/default/sa/long-lived",
			WorkloadID:     "long-lived",
			IssuedAt:       now.Add(-2 * time.Hour),
			ExpiresAt:      now.Add(70 * time.Hour), // 72 hours
			KeyType:        "ECDSA-P256",
		}

		violations := AuditSVID(record, primaryTD, federated, now)
		found := false
		for _, v := range violations {
			if v.RuleID == "SPIFFE-SVID-002" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPIFFE-SVID-002 for excessive lifespan, got %+v", violations)
		}
	})

	t.Run("Near Expiry (< 15 Minutes Remaining)", func(t *testing.T) {
		record := SVIDRecord{
			SPIFFEID:       "spiffe://cluster.local/ns/default/sa/expiring-soon",
			WorkloadID:     "expiring-soon",
			IssuedAt:       now.Add(-11 * time.Hour),
			ExpiresAt:      now.Add(8 * time.Minute), // 8 mins left
			KeyType:        "ECDSA-P256",
		}

		violations := AuditSVID(record, primaryTD, federated, now)
		found := false
		for _, v := range violations {
			if v.RuleID == "SPIFFE-SVID-003" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPIFFE-SVID-003 for expiring SVID, got %+v", violations)
		}
	})

	t.Run("Weak Cryptographic Key (RSA 1024)", func(t *testing.T) {
		record := SVIDRecord{
			SPIFFEID:       "spiffe://cluster.local/ns/default/sa/weak-key-app",
			WorkloadID:     "weak-key-app",
			IssuedAt:       now.Add(-1 * time.Hour),
			ExpiresAt:      now.Add(10 * time.Hour),
			KeyType:        "RSA-1024",
			KeyBits:        1024,
		}

		violations := AuditSVID(record, primaryTD, federated, now)
		found := false
		for _, v := range violations {
			if v.RuleID == "SPIFFE-SVID-009" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPIFFE-SVID-009 for weak key, got %+v", violations)
		}
	})
}

func TestAuditRegistrationEntry(t *testing.T) {
	primaryTD := "cluster.local"
	federated := []string{"partner-mesh.internal"}

	t.Run("Permissive Wildcard Selector", func(t *testing.T) {
		entry := WorkloadIdentity{
			Name:        "wildcard-service",
			Namespace:   "default",
			SPIFFEID:    "spiffe://cluster.local/ns/default/sa/wildcard",
			TrustDomain: "cluster.local",
			Selectors: map[string]string{
				"k8s:ns": "*",
			},
		}

		violations := AuditRegistrationEntry(entry, primaryTD, federated)
		found := false
		for _, v := range violations {
			if v.RuleID == "SPIFFE-SVID-004" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPIFFE-SVID-004 for wildcard selector, got %+v", violations)
		}
	})

	t.Run("Unfederated Cross-Cluster Trust Domain", func(t *testing.T) {
		entry := WorkloadIdentity{
			Name:        "cross-cluster-app",
			Namespace:   "default",
			SPIFFEID:    "spiffe://external.io/workload/app",
			TrustDomain: "external.io",
			Selectors: map[string]string{
				"k8s:ns": "default",
				"k8s:sa": "app",
			},
		}

		violations := AuditRegistrationEntry(entry, primaryTD, federated)
		found := false
		for _, v := range violations {
			if v.RuleID == "SPIFFE-SVID-008" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPIFFE-SVID-008 for unfederated cross-cluster entry, got %+v", violations)
		}
	})
}

func TestCiliumPolicySynthesis(t *testing.T) {
	workloads := []WorkloadIdentity{
		{
			Name:        "payment-backend",
			Namespace:   "finance",
			SPIFFEID:    "spiffe://cluster.local/ns/finance/sa/payment-backend",
			Attested:    true,
		},
	}

	yamlOutput := SynthesizeCiliumPoliciesForWorkloads(workloads)
	if !strings.Contains(yamlOutput, "kind: CiliumNetworkPolicy") {
		t.Errorf("missing CiliumNetworkPolicy in synthesized output")
	}
	if !strings.Contains(yamlOutput, "default-deny-spiffe-microsegmentation") {
		t.Errorf("missing default-deny baseline policy in synthesized output")
	}
	if !strings.Contains(yamlOutput, "io.spiffe.id") {
		t.Errorf("missing io.spiffe.id selector in synthesized policy")
	}
	if !strings.Contains(yamlOutput, "mode: required") {
		t.Errorf("missing mutual TLS authentication mode required in synthesized policy")
	}

	// Test persistence
	tmpDir := t.TempDir()
	outPath, err := WriteCiliumPoliciesToDir(yamlOutput, tmpDir)
	if err != nil {
		t.Fatalf("failed to write policies to dir: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read persisted policy file: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("empty persisted policy file")
	}
}

func TestSPIFFEScanner_ManifestAndTelemetry(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-67210",
				Title:     "SPIFFE/SPIRE Workload Attestation SVID Expiration Desync",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.3,
			},
		},
	}

	scanner := NewSPIFFEScanner(feed)
	scanner.SetTrustDomains("cluster.local", []string{"partner-mesh.internal"})

	// Create test manifest file
	tmpDir := t.TempDir()
	manifestFile := filepath.Join(tmpDir, "spire-entry.yaml")
	manifestContent := `apiVersion: spire.spiffe.io/v1alpha1
kind: SpireRegistrationEntry
metadata:
  name: payment-entry
  namespace: prod
spec:
  spiffe_id: "spiffe://cluster.local/ns/prod/sa/payment"
  selectors:
    - k8s:ns:*
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: unhardened-ingress
  namespace: prod
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
`
	if err := os.WriteFile(manifestFile, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to create test manifest: %v", err)
	}

	report, err := scanner.ScanFile(manifestFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(report.Violations) < 2 {
		t.Errorf("expected at least 2 violations (wildcard selector & missing mTLS), got %d", len(report.Violations))
	}

	// Test Directory scan
	dirReport, err := scanner.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}
	if dirReport.TotalFiles != 1 {
		t.Errorf("expected 1 file scanned, got %d", dirReport.TotalFiles)
	}

	// Test Telemetry Reconciliation
	telemetryFile := filepath.Join(tmpDir, "telemetry.json")
	now := time.Now().UTC()
	telemetryData := `{
		"cluster_id": "nixos-k8s-prod-us-east",
		"primary_trust_domain": "cluster.local",
		"captured_at": "` + now.Format(time.RFC3339) + `",
		"svids": [
			{
				"spiffe_id": "spiffe://cluster.local/ns/prod/sa/vault",
				"workload_id": "vault-0",
				"namespace": "prod",
				"issued_at": "` + now.Add(-2*time.Hour).Format(time.RFC3339) + `",
				"expires_at": "` + now.Add(5*time.Minute).Format(time.RFC3339) + `",
				"key_type": "ECDSA-P256",
				"key_bits": 256,
				"active_node": "worker-01"
			}
		],
		"agent_admin_sockets": [
			"/var/run/spire/sockets/spire-agent.sock (0777 world-writable)"
		]
	}`
	if err := os.WriteFile(telemetryFile, []byte(telemetryData), 0644); err != nil {
		t.Fatalf("failed to write telemetry fixture: %v", err)
	}

	telemReport, err := scanner.ReconcileTelemetryFile(telemetryFile)
	if err != nil {
		t.Fatalf("ReconcileTelemetryFile failed: %v", err)
	}

	if len(telemReport.Violations) < 2 {
		t.Errorf("expected at least 2 violations (near expiry & insecure socket), got %d: %+v", len(telemReport.Violations), telemReport.Violations)
	}

	// Check CVE correlation
	foundCVE := false
	for _, v := range telemReport.Violations {
		if v.MatchedCVE == "CVE-2026-67210" {
			foundCVE = true
			break
		}
	}
	if !foundCVE {
		t.Errorf("expected CVE-2026-67210 correlation on near-expiry SVID")
	}
}
