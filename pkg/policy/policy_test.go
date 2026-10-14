package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

func sampleFeed() *intel.Feed {
	return &intel.Feed{
		Version:   "1.0.0",
		UpdatedAt: time.Now().UTC(),
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-21801",
				Title:       "Kubernetes Ingress-Nginx Path Traversal Vulnerability",
				Component:   "ingress-nginx",
				Target:      "kubernetes",
				Severity:    intel.SeverityHigh,
				CVSSScore:   8.4,
				Description: "Specially crafted request URI paths allow bypassing URL rewriting rules.",
				Mitigation:  "Upgrade to v1.11.0.",
			},
			{
				ID:          "CVE-2026-20914",
				Title:       "Containerd Cgroup v2 Memory Limit Enforcement Race",
				Component:   "containerd",
				Target:      "kubernetes",
				Severity:    intel.SeverityHigh,
				CVSSScore:   7.8,
				Description: "Cgroup memory limits may fail to attach prior to container entrypoint.",
				Mitigation:  "Enable synchronous cgroup driver attachment.",
			},
			{
				ID:          "CVE-2026-19402",
				Title:       "NixOS Flake Lock Input Evaluation Hijack",
				Component:   "nix",
				Target:      "nixos",
				Severity:    intel.SeverityMedium,
				CVSSScore:   6.1,
				Description: "Recursive flake evaluations in untrusted git inputs trigger remote fetches.",
				Mitigation:  "Enable pure-eval mode.",
			},
			{
				ID:          "CVE-2026-15509",
				Title:       "Ceph OSD BlueStore Metadata Desync on Kernel 6.12",
				Component:   "ceph",
				Target:      "nixos",
				Severity:    intel.SeverityMedium,
				CVSSScore:   5.5,
				Description: "Direct I/O async flushes on NVMe trigger transient OSD peering heartbeats timeouts.",
				Mitigation:  "Tune bluestore_default_buffered_write.",
			},
		},
	}
}

func sampleViolations() []k8s.Violation {
	return []k8s.Violation{
		{
			RuleID:       "K8S-ING-001",
			Title:        "Custom Configuration Snippet Injection Detected",
			ResourceKind: "Ingress",
			ResourceName: "vulnerable-ingress",
			Namespace:    "production",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.8,
			Description:  "Ingress contains dangerous configuration-snippet annotation.",
			Remediation:  "Remove custom snippet annotation.",
			MatchedCVE:   "CVE-2023-5044",
		},
		{
			RuleID:       "K8S-CNI-002",
			Title:        "Unrestricted Global Egress to 0.0.0.0/0",
			ResourceKind: "NetworkPolicy",
			ResourceName: "allow-all-egress",
			Namespace:    "default",
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.5,
			Description:  "NetworkPolicy allows egress to 0.0.0.0/0.",
			Remediation:  "Restrict egress CIDRs to required subnets.",
		},
		{
			RuleID:       "K8S-CNI-003",
			Title:        "Sensitive Infrastructure Port Exposure Detected",
			ResourceKind: "NetworkPolicy",
			ResourceName: "expose-etcd",
			Namespace:    "kube-system",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.1,
			Description:  "NetworkPolicy permits traffic to etcd port 2379.",
			Remediation:  "Isolate etcd ports.",
		},
	}
}

func TestSynthesizeFalcoFromThreat(t *testing.T) {
	feed := sampleFeed()

	// 1. Ingress CVE
	rule1 := SynthesizeFalcoFromThreat(feed.Items[0], []string{"custom-cluster"})
	if rule1 == nil || !strings.Contains(rule1.Rule, "Ingress Controller Shell Spawn") {
		t.Fatalf("expected Ingress Falco rule, got: %+v", rule1)
	}
	if rule1.Priority != FalcoPriorityError {
		t.Errorf("expected priority %s, got %s", FalcoPriorityError, rule1.Priority)
	}
	if !strings.Contains(rule1.Condition, "ingress-nginx") {
		t.Errorf("expected condition to reference ingress-nginx: %s", rule1.Condition)
	}

	// 2. Containerd Cgroup CVE
	rule2 := SynthesizeFalcoFromThreat(feed.Items[1], nil)
	if rule2 == nil || rule2.Priority != FalcoPriorityCritical {
		t.Fatalf("expected Critical containerd cgroup rule, got: %+v", rule2)
	}

	// 3. Nix Flake CVE
	rule3 := SynthesizeFalcoFromThreat(feed.Items[2], nil)
	if rule3 == nil || !strings.Contains(rule3.Condition, "nix-daemon") {
		t.Fatalf("expected Nix evaluation egress rule, got: %+v", rule3)
	}

	// 4. Ceph OSD CVE
	rule4 := SynthesizeFalcoFromThreat(feed.Items[3], nil)
	if rule4 == nil || !strings.Contains(rule4.Condition, "ceph-osd") {
		t.Fatalf("expected Ceph OSD crash rule, got: %+v", rule4)
	}

	// 5. Generic Threat Item
	genericItem := intel.ThreatItem{
		ID:        "CVE-2026-99999",
		Title:     "Generic Kernel Flaw",
		Component: "kernel",
		Severity:  intel.SeverityLow,
	}
	genericRule := SynthesizeFalcoFromThreat(genericItem, nil)
	if genericRule == nil || genericRule.Priority != FalcoPriorityNotice {
		t.Fatalf("expected Low severity to map to NOTICE: %+v", genericRule)
	}
}

func TestSynthesizeFalcoFromViolation(t *testing.T) {
	violations := sampleViolations()

	r1 := SynthesizeFalcoFromViolation(violations[0], nil)
	if r1 == nil || !strings.Contains(r1.Rule, "K8S-ING-001") {
		t.Fatalf("expected K8S-ING-001 rule: %+v", r1)
	}

	r2 := SynthesizeFalcoFromViolation(violations[1], nil)
	if r2 == nil || !strings.Contains(r2.Rule, "K8S-CNI-002") {
		t.Fatalf("expected K8S-CNI-002 rule: %+v", r2)
	}

	r3 := SynthesizeFalcoFromViolation(violations[2], nil)
	if r3 == nil || !strings.Contains(r3.Rule, "K8S-CNI-003") {
		t.Fatalf("expected K8S-CNI-003 rule: %+v", r3)
	}

	// Unknown violation rule ID returns nil
	unknown := k8s.Violation{RuleID: "K8S-UNKNOWN-999"}
	if rUnknown := SynthesizeFalcoFromViolation(unknown, nil); rUnknown != nil {
		t.Errorf("expected nil for unknown violation, got: %+v", rUnknown)
	}
}

func TestBuildFalcoRuleSetAndFormatYAML(t *testing.T) {
	feed := sampleFeed()
	violations := sampleViolations()

	rules := BuildFalcoRuleSet(feed, violations, []string{"unit-test"})
	if len(rules) < 6 {
		t.Fatalf("expected at least 6 combined rules, got %d", len(rules))
	}

	yamlOutput := FormatFalcoYAML(rules, true)
	if !strings.Contains(yamlOutput, "CNCF Falco Runtime Threat Mitigation Ruleset") {
		t.Errorf("missing header comment in Falco YAML")
	}
	if !strings.Contains(yamlOutput, "- rule:") {
		t.Errorf("missing '- rule:' list items in Falco YAML")
	}
	if !strings.Contains(yamlOutput, "condition: >-") {
		t.Errorf("missing multiline condition block in Falco YAML")
	}
}

func TestSynthesizeGatekeeperPolicies(t *testing.T) {
	feed := sampleFeed()
	violations := sampleViolations()

	opts := DefaultSynthesisOptions()
	opts.EnforcementAction = EnforceWarn
	opts.NamespaceFilter = []string{"prod", "staging"}

	templates, constraints := SynthesizeGatekeeperPolicies(feed, violations, opts)
	if len(templates) < 5 {
		t.Fatalf("expected at least 5 constraint templates, got %d", len(templates))
	}
	if len(constraints) < 5 {
		t.Fatalf("expected at least 5 constraints, got %d", len(constraints))
	}

	// Verify all constraints inherit the enforcementAction and namespaces
	for _, c := range constraints {
		if c.Spec.EnforcementAction != EnforceWarn {
			t.Errorf("expected enforcementAction %s, got %s", EnforceWarn, c.Spec.EnforcementAction)
		}
		if len(c.Spec.Match.Namespaces) != 2 {
			t.Errorf("expected 2 namespaces, got %d", len(c.Spec.Match.Namespaces))
		}
	}

	// Test rule exclusion
	optsExcluded := DefaultSynthesisOptions()
	optsExcluded.ExcludedRuleIDs = []string{"K8S-ING-001"}
	tFiltered, cFiltered := SynthesizeGatekeeperPolicies(feed, violations, optsExcluded)
	if len(tFiltered) != len(templates)-1 {
		t.Errorf("expected %d templates after excluding K8S-ING-001, got %d", len(templates)-1, len(tFiltered))
	}
	for _, tf := range tFiltered {
		if tf.Metadata.Name == "k8sdenycustomsnippets" {
			t.Errorf("k8sdenycustomsnippets should have been excluded")
		}
	}
	_ = cFiltered
}

func TestFormatGatekeeperYAML(t *testing.T) {
	feed := sampleFeed()
	violations := sampleViolations()

	templates, constraints := SynthesizeGatekeeperPolicies(feed, violations, DefaultSynthesisOptions())
	yamlOutput := FormatGatekeeperYAML(templates, constraints, true)

	if !strings.Contains(yamlOutput, "apiVersion: templates.gatekeeper.sh/v1beta1") {
		t.Errorf("missing Gatekeeper template apiVersion in output")
	}
	if !strings.Contains(yamlOutput, "apiVersion: constraints.gatekeeper.sh/v1beta1") {
		t.Errorf("missing Gatekeeper constraint apiVersion in output")
	}
	if !strings.Contains(yamlOutput, "---") {
		t.Errorf("missing multi-document separator '---' in output")
	}
	if !strings.Contains(yamlOutput, "package k8sdenycustomsnippets") {
		t.Errorf("missing rego package declaration in output")
	}
}

func TestSynthesizePoliciesFullPipelineAndDiskWrite(t *testing.T) {
	feed := sampleFeed()
	violations := sampleViolations()

	opts := DefaultSynthesisOptions()
	policySet, err := SynthesizePolicies(feed, violations, opts)
	if err != nil {
		t.Fatalf("SynthesizePolicies failed: %v", err)
	}

	if policySet.TotalFalcoRules == 0 || policySet.TotalOPAConstraintTemplates == 0 {
		t.Fatalf("expected non-zero policy counts: Falco=%d, Gatekeeper=%d",
			policySet.TotalFalcoRules, policySet.TotalOPAConstraintTemplates)
	}

	tmpDir, err := os.MkdirTemp("", "sentinel-policy-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	files, err := WritePoliciesToDir(policySet, tmpDir)
	if err != nil {
		t.Fatalf("WritePoliciesToDir failed: %v", err)
	}

	falcoFile, hasFalco := files[EngineFalco]
	if !hasFalco {
		t.Fatalf("expected falco output path in written files map")
	}
	falcoData, err := os.ReadFile(falcoFile)
	if err != nil || len(falcoData) == 0 {
		t.Fatalf("failed to read written falco policy file: %v", err)
	}

	opaFile, hasOPA := files[EngineGatekeeper]
	if !hasOPA {
		t.Fatalf("expected gatekeeper output path in written files map")
	}
	opaData, err := os.ReadFile(opaFile)
	if err != nil || len(opaData) == 0 {
		t.Fatalf("failed to read written gatekeeper policy file: %v", err)
	}
}

func TestSchemaFixtureValidation(t *testing.T) {
	// Verify Falco schema fixture
	falcoFixturePath := filepath.Join("..", "..", "fixtures", "policies", "falco-rules-fixture.yaml")
	data, err := os.ReadFile(falcoFixturePath)
	if err != nil {
		t.Fatalf("failed to read falco fixture (%s): %v", falcoFixturePath, err)
	}
	content := string(data)
	if !strings.Contains(content, "- rule:") || !strings.Contains(content, "condition: >-") {
		t.Errorf("falco fixture lacks standard rule schema properties")
	}

	// Verify Gatekeeper schema fixture
	opaFixturePath := filepath.Join("..", "..", "fixtures", "policies", "opa-gatekeeper-fixture.yaml")
	opaData, err := os.ReadFile(opaFixturePath)
	if err != nil {
		t.Fatalf("failed to read opa fixture (%s): %v", opaFixturePath, err)
	}
	opaContent := string(opaData)
	if !strings.Contains(opaContent, "apiVersion: templates.gatekeeper.sh/v1beta1") ||
		!strings.Contains(opaContent, "kind: ConstraintTemplate") ||
		!strings.Contains(opaContent, "apiVersion: constraints.gatekeeper.sh/v1beta1") {
		t.Errorf("gatekeeper fixture lacks standard ConstraintTemplate / Constraint structure")
	}
}
