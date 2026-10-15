package fleet_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestFleetRulesCatalog(t *testing.T) {
	expectedRules := []string{
		"FLEET-RBAC-001",
		"FLEET-RBAC-002",
		"FLEET-RBAC-003",
		"FLEET-RBAC-004",
		"FLEET-RBAC-005",
		"FLEET-OIDC-001",
		"FLEET-OIDC-002",
		"FLEET-OIDC-003",
		"FLEET-OIDC-004",
		"FLEET-GITOPS-001",
		"FLEET-GITOPS-002",
		"FLEET-GITOPS-003",
		"FLEET-GITOPS-004",
		"FLEET-DRIFT-001",
	}

	for _, ruleID := range expectedRules {
		rule, ok := fleet.LookupFleetRule(ruleID)
		if !ok {
			t.Errorf("Expected rule %s to exist in catalog, but was not found", ruleID)
		}
		if rule.ID != ruleID {
			t.Errorf("Rule ID mismatch: expected %s, got %s", ruleID, rule.ID)
		}
		if rule.Title == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("Rule %s has empty description or remediation", ruleID)
		}
		if rule.CVSSScore <= 0.0 {
			t.Errorf("Rule %s has invalid CVSS score: %.1f", ruleID, rule.CVSSScore)
		}
	}
}

func TestRBACWildcardAndPrivilegeEscalation(t *testing.T) {
	auditor := fleet.NewRBACOIDCAuditor(nil)

	// Vulnerable ClusterRole with wildcard permissions, escalate, and impersonation
	lines := []string{
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRole",
		"metadata:",
		"  name: cluster-operator",
		"rules:",
		"- apiGroups: ['*']",
		"  resources: ['*']",
		"  verbs: ['*']",
		"- apiGroups: ['rbac.authorization.k8s.io']",
		"  resources: ['clusterroles']",
		"  verbs: ['bind', 'escalate']",
		"- apiGroups: ['']",
		"  resources: ['users', 'groups']",
		"  verbs: ['impersonate']",
		"- apiGroups: ['']",
		"  resources: ['secrets']",
		"  verbs: ['get', 'list', 'watch']",
	}

	violations := auditor.AuditRBACDocument(lines, 1, "test-role.yaml", "ClusterRole", "cluster-operator", "")
	if len(violations) < 4 {
		t.Fatalf("Expected at least 4 RBAC violations, got %d", len(violations))
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["FLEET-RBAC-001"] {
		t.Errorf("Expected FLEET-RBAC-001 (wildcard verb/resource) violation")
	}
	if !ruleMap["FLEET-RBAC-002"] {
		t.Errorf("Expected FLEET-RBAC-002 (bind/escalate) violation")
	}
	if !ruleMap["FLEET-RBAC-004"] {
		t.Errorf("Expected FLEET-RBAC-004 (impersonate) violation")
	}
	if !ruleMap["FLEET-RBAC-005"] {
		t.Errorf("Expected FLEET-RBAC-005 (cluster-wide secret access) violation")
	}
}

func TestRBACClusterAdminBroadBinding(t *testing.T) {
	auditor := fleet.NewRBACOIDCAuditor(nil)

	lines := []string{
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRoleBinding",
		"metadata:",
		"  name: all-authenticated-admins",
		"subjects:",
		"- kind: Group",
		"  name: system:authenticated",
		"  apiGroup: rbac.authorization.k8s.io",
		"roleRef:",
		"  kind: ClusterRole",
		"  name: cluster-admin",
		"  apiGroup: rbac.authorization.k8s.io",
	}

	violations := auditor.AuditRBACDocument(lines, 1, "test-binding.yaml", "ClusterRoleBinding", "all-authenticated-admins", "")
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation for broad cluster-admin binding, got %d", len(violations))
	}
	if violations[0].RuleID != "FLEET-RBAC-003" {
		t.Errorf("Expected FLEET-RBAC-003, got %s", violations[0].RuleID)
	}
}

func TestOIDCTokenAudits(t *testing.T) {
	auditor := fleet.NewRBACOIDCAuditor(nil)

	// Insecure Token: none algorithm, excessive TTL (48 hours), missing audience, stale key
	badToken := fleet.OIDCTokenDeclaration{
		TokenID:         "tok-insecure-001",
		ClusterID:       "cluster-prod-01",
		Issuer:          "https://oidc.example.com/auth",
		ClientID:        "k8s-cluster",
		Audience:        "", // missing audience
		SigningAlg:      "none",
		IssuedAt:        time.Now().Add(-48 * time.Hour),
		ExpiresAt:       time.Now(),
		TTLSeconds:      172800, // 48 hours
		KeyRotationDays: 120,    // > 90 days
	}

	violations := auditor.AuditOIDCToken(badToken, "cluster-prod-01")
	if len(violations) < 4 {
		t.Fatalf("Expected 4 OIDC violations for bad token, got %d", len(violations))
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["FLEET-OIDC-001"] {
		t.Errorf("Expected FLEET-OIDC-001 (insecure alg 'none')")
	}
	if !ruleMap["FLEET-OIDC-002"] {
		t.Errorf("Expected FLEET-OIDC-002 (excessive TTL)")
	}
	if !ruleMap["FLEET-OIDC-003"] {
		t.Errorf("Expected FLEET-OIDC-003 (missing audience)")
	}
	if !ruleMap["FLEET-OIDC-004"] {
		t.Errorf("Expected FLEET-OIDC-004 (stale rotation key)")
	}

	// Valid Token: RS256, 1-hour TTL, valid audience, rotated 15 days ago
	goodToken := fleet.OIDCTokenDeclaration{
		TokenID:         "tok-secure-002",
		ClusterID:       "cluster-prod-01",
		Issuer:          "https://oidc.example.com/auth",
		ClientID:        "k8s-cluster",
		Audience:        "k8s-fleet-prod",
		SigningAlg:      "RS256",
		IssuedAt:        time.Now().Add(-30 * time.Minute),
		ExpiresAt:       time.Now().Add(30 * time.Minute),
		TTLSeconds:      3600,
		KeyRotationDays: 15,
	}

	cleanViolations := auditor.AuditOIDCToken(goodToken, "cluster-prod-01")
	if len(cleanViolations) != 0 {
		t.Errorf("Expected 0 violations for clean token, got %d", len(cleanViolations))
	}
}

func TestGitOpsAudits(t *testing.T) {
	auditor := fleet.NewGitOpsAuditor(nil)

	// Vulnerable ArgoCD Application: floating branch, disabled selfHeal, wildcard server
	lines := []string{
		"apiVersion: argoproj.io/v1alpha1",
		"kind: Application",
		"metadata:",
		"  name: payment-service",
		"spec:",
		"  source:",
		"    repoURL: https://github.com/org/payments.git",
		"    targetRevision: main",
		"  destination:",
		"    server: '*'",
		"  syncPolicy:",
		"    automated:",
		"      selfHeal: false",
	}

	violations := auditor.AuditGitOpsDocument(lines, 1, "argo-app.yaml", "Application", "payment-service", "argocd")
	if len(violations) != 3 {
		t.Fatalf("Expected 3 GitOps violations, got %d", len(violations))
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["FLEET-GITOPS-001"] {
		t.Errorf("Expected FLEET-GITOPS-001 (selfHeal disabled)")
	}
	if !ruleMap["FLEET-GITOPS-002"] {
		t.Errorf("Expected FLEET-GITOPS-002 (floating targetRevision 'main')")
	}
	if !ruleMap["FLEET-GITOPS-004"] {
		t.Errorf("Expected FLEET-GITOPS-004 (wildcard server '*')")
	}
}

func TestGitOpsRuntimeSyncDrift(t *testing.T) {
	auditor := fleet.NewGitOpsAuditor(nil)

	status := fleet.GitOpsSyncStatus{
		AppName:           "order-api",
		TargetCluster:     "eu-west-prod",
		Namespace:         "production",
		Engine:            "ArgoCD",
		SourceRepo:        "https://github.com/org/orders.git",
		TargetRevision:    "v2.14.0",
		CurrentRevision:   "v2.13.9",
		SyncStatus:        "OutOfSync",
		HealthStatus:      "Degraded",
		AutomatedSelfHeal: false,
		DriftDetails:      "ConfigMap 'order-config' has drifted keys",
	}

	violations := auditor.AuditSyncStatus(status)
	if len(violations) < 2 {
		t.Fatalf("Expected at least 2 violations for drifted app, got %d", len(violations))
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["FLEET-DRIFT-001"] {
		t.Errorf("Expected FLEET-DRIFT-001 (out-of-sync or degraded)")
	}
	if !ruleMap["FLEET-GITOPS-001"] {
		t.Errorf("Expected FLEET-GITOPS-001 (selfHeal false)")
	}
}

func TestFleetScannerFileAndTelemetry(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-60114",
				Title:       "Multi-Cluster GitOps Reconciliation Drift & OIDC Token Replay",
				Severity:    intel.SeverityCritical,
				CVSSScore:   9.4,
				Description: "ArgoCD and Kubernetes RBAC OIDC token replay vulnerability",
				Component:   "rbac",
			},
		},
	}

	scanner := fleet.NewFleetScanner(feed)
	tmpDir := t.TempDir()

	// 1. Create temporary manifest file
	manifestContent := `---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-wildcard
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: drift-app
spec:
  source:
    repoURL: https://github.com/org/infra.git
    targetRevision: HEAD
  destination:
    server: https://kubernetes.default.svc
  syncPolicy:
    automated:
      selfHeal: false
`
	manifestFile := filepath.Join(tmpDir, "fleet-sample.yaml")
	if err := os.WriteFile(manifestFile, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("Failed to write manifest file: %v", err)
	}

	rep, err := scanner.ScanFile(manifestFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(rep.Violations) < 3 {
		t.Errorf("Expected at least 3 violations from scan, got %d", len(rep.Violations))
	}

	// 2. Create temporary telemetry JSON
	telemetryContent := `{
  "timestamp": "2026-10-15T10:00:00Z",
  "fleet_id": "global-k8s-mesh",
  "clusters": [
    {
      "cluster_id": "us-east-prod",
      "region": "us-east-1",
      "provider": "aws",
      "k8s_version": "v1.31.2",
      "connected": true,
      "rbac_admin_roles": 2,
      "active_oidc_tokens": 12
    },
    {
      "cluster_id": "ap-southeast-dr",
      "region": "ap-southeast-1",
      "provider": "baremetal",
      "k8s_version": "v1.31.2",
      "connected": false,
      "rbac_admin_roles": 8,
      "active_oidc_tokens": 1
    }
  ],
  "gitops_apps": [
    {
      "app_name": "checkout-svc",
      "target_cluster": "us-east-prod",
      "namespace": "ecommerce",
      "engine": "ArgoCD",
      "source_repo": "https://github.com/org/checkout.git",
      "target_revision": "v1.5.0",
      "current_revision": "v1.5.0",
      "sync_status": "Synced",
      "health_status": "Healthy",
      "automated_self_heal": true
    }
  ],
  "oidc_tokens": [
    {
      "token_id": "tok-ap-01",
      "cluster_id": "ap-southeast-dr",
      "issuer": "https://identity.org/auth",
      "client_id": "ap-dr-k8s",
      "audience": "k8s-cluster",
      "signing_alg": "HS256",
      "issued_at": "2026-10-14T08:00:00Z",
      "expires_at": "2026-10-16T08:00:00Z",
      "ttl_seconds": 172800,
      "key_rotation_days": 110
    }
  ]
}`
	telemetryFile := filepath.Join(tmpDir, "fleet-telemetry.json")
	if err := os.WriteFile(telemetryFile, []byte(telemetryContent), 0644); err != nil {
		t.Fatalf("Failed to write telemetry file: %v", err)
	}

	telemetryRep, err := scanner.ReconcileTelemetryFile(telemetryFile)
	if err != nil {
		t.Fatalf("ReconcileTelemetryFile failed: %v", err)
	}

	if telemetryRep.Summary.ClustersAudited != 2 {
		t.Errorf("Expected 2 clusters audited, got %d", telemetryRep.Summary.ClustersAudited)
	}
	if len(telemetryRep.Violations) < 3 {
		t.Errorf("Expected at least 3 violations from telemetry, got %d", len(telemetryRep.Violations))
	}
}
