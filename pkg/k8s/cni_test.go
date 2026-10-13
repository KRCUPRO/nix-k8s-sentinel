package k8s

import (
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCNIAnalyzer_UnrestrictedEgress(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: wide-open-egress
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	analyzer := NewCNIAnalyzer()
	violations := analyzer.AuditNetworkPolicy(resources[0])

	foundEgress := false
	for _, v := range violations {
		if v.RuleID == "K8S-CNI-002" {
			foundEgress = true
			if v.Severity != intel.SeverityHigh {
				t.Errorf("expected HIGH severity, got %v", v.Severity)
			}
		}
	}

	if !foundEgress {
		t.Errorf("expected K8S-CNI-002 violation for 0.0.0.0/0 egress")
	}
}

func TestCNIAnalyzer_SensitivePortExposure(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: expose-etcd
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      component: etcd
  ingress:
  - ports:
    - port: 2379
      protocol: TCP
    - port: 10250
      protocol: TCP
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	analyzer := NewCNIAnalyzer()
	violations := analyzer.AuditNetworkPolicy(resources[0])

	exposedPorts := make(map[string]bool)
	for _, v := range violations {
		if v.RuleID == "K8S-CNI-003" {
			exposedPorts[v.Description] = true
		}
	}

	if len(exposedPorts) < 2 {
		t.Errorf("expected at least 2 sensitive port violations (2379 and 10250), got %d", len(exposedPorts))
	}
}

func TestCNIAnalyzer_DefaultDenyPosture(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: isolated-ns
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: custom-app-policy
  namespace: unisolated-ns
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - ports:
    - port: 8080
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	analyzer := NewCNIAnalyzer()
	violations := analyzer.AuditDefaultDenyPostures(resources)

	isolatedMissing := false
	unisolatedMissing := false

	for _, v := range violations {
		if v.RuleID == "K8S-CNI-001" {
			if v.Namespace == "isolated-ns" {
				isolatedMissing = true
			}
			if v.Namespace == "unisolated-ns" {
				unisolatedMissing = true
			}
		}
	}

	if isolatedMissing {
		t.Errorf("isolated-ns has default deny, should not be flagged")
	}
	if !unisolatedMissing {
		t.Errorf("unisolated-ns lacks default deny, must be flagged")
	}
}

func TestCNIAnalyzer_CiliumL7Wildcard(t *testing.T) {
	manifest := `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cilium-api-filter
  namespace: prod
spec:
  endpointSelector:
    matchLabels:
      app: api-gateway
  ingress:
  - toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: "*"
          path: "/.*"
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	analyzer := NewCNIAnalyzer()
	violations := analyzer.AuditNetworkPolicy(resources[0])

	foundL7Bypass := false
	for _, v := range violations {
		if v.RuleID == "K8S-CNI-005" {
			foundL7Bypass = true
		}
	}

	if !foundL7Bypass {
		t.Errorf("expected K8S-CNI-005 violation for Cilium wildcard HTTP method")
	}
}

func TestCNIAnalyzer_CalicoUntracked(t *testing.T) {
	manifest := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: calico-fastpath
spec:
  selector: all()
  doNotTrack: true
  applyOnForward: true
  ingress:
  - action: Allow
`
	resources, err := ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	analyzer := NewCNIAnalyzer()
	violations := analyzer.AuditNetworkPolicy(resources[0])

	foundUntracked := false
	for _, v := range violations {
		if v.RuleID == "K8S-CNI-006" {
			foundUntracked = true
		}
	}

	if !foundUntracked {
		t.Errorf("expected K8S-CNI-006 violation for Calico doNotTrack policy")
	}
}
