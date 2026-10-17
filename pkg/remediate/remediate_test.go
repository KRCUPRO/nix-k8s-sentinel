package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestRuleCatalog(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical remediation rules, got %d", len(rules))
	}

	seenIDs := make(map[string]bool)
	for _, r := range rules {
		if seenIDs[r.ID] {
			t.Errorf("duplicate rule ID: %s", r.ID)
		}
		seenIDs[r.ID] = true

		if r.Title == "" {
			t.Errorf("rule %s has empty title", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty description", r.ID)
		}
		if r.SuggestedRemediation == "" {
			t.Errorf("rule %s has empty suggested remediation", r.ID)
		}
		if r.CVSSScore <= 0.0 || r.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %.1f", r.ID, r.CVSSScore)
		}
		if r.Target != "nixos" && r.Target != "kubernetes" {
			t.Errorf("rule %s has unknown target: %s", r.ID, r.Target)
		}
	}

	// Test GetRuleByID
	rule, found := GetRuleByID("REMEDIATE-AUTO-002")
	if !found {
		t.Fatalf("expected to find REMEDIATE-AUTO-002")
	}
	if rule.ID != "REMEDIATE-AUTO-002" || rule.MatchedCVE != "CVE-2026-20914" {
		t.Errorf("unexpected rule retrieved: %+v", rule)
	}

	_, notFound := GetRuleByID("NON-EXISTENT-999")
	if notFound {
		t.Errorf("expected false for NON-EXISTENT-999")
	}
}

func TestSynthesizeNixOSPatch(t *testing.T) {
	rule, _ := GetRuleByID("REMEDIATE-AUTO-006")
	patch := SynthesizeNixOSPatch(rule, "hardware.nix", "networking.wireguard.interfaces.wg0.privateKeyFile", "\"/nix/store/key\"", "\"/run/secrets/wg.key\"", "")

	if patch.TargetModule != "hardware.nix" {
		t.Errorf("expected target module hardware.nix, got %s", patch.TargetModule)
	}
	if patch.OptionPath != "networking.wireguard.interfaces.wg0.privateKeyFile" {
		t.Errorf("unexpected option path: %s", patch.OptionPath)
	}
	if !strings.Contains(patch.DiffContent, "--- a/hardware.nix") {
		t.Errorf("diff missing header: %s", patch.DiffContent)
	}
	if !strings.Contains(patch.DiffContent, "-   networking.wireguard.interfaces.wg0.privateKeyFile = \"/nix/store/key\";") {
		t.Errorf("diff missing old value removal: %s", patch.DiffContent)
	}
	if !strings.Contains(patch.DiffContent, "+   networking.wireguard.interfaces.wg0.privateKeyFile = \"/run/secrets/wg.key\";") {
		t.Errorf("diff missing new value addition: %s", patch.DiffContent)
	}
}

func TestSynthesizeKustomizePatches(t *testing.T) {
	rule, _ := GetRuleByID("REMEDIATE-AUTO-002")
	patchBody := "spec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n"
	kp := SynthesizeKustomizeStrategicMerge(rule, "apps/v1", "Deployment", "payment-api", "prod", patchBody)

	if kp.PatchType != "strategic-merge" {
		t.Errorf("expected strategic-merge, got %s", kp.PatchType)
	}
	if !strings.Contains(kp.PatchYAML, "apiVersion: apps/v1") {
		t.Errorf("patch YAML missing apiVersion: %s", kp.PatchYAML)
	}
	if !strings.Contains(kp.PatchYAML, "name: payment-api") {
		t.Errorf("patch YAML missing name: %s", kp.PatchYAML)
	}
	if !strings.Contains(kp.PatchYAML, "runAsNonRoot: true") {
		t.Errorf("patch YAML missing runAsNonRoot: %s", kp.PatchYAML)
	}

	// Test JSONPatch
	rule3, _ := GetRuleByID("REMEDIATE-AUTO-003")
	jp := SynthesizeKustomizeJSONPatch(rule3, "networking.k8s.io/v1", "Ingress", "public-gw", "ingress", "remove", "/metadata/annotations/snippet", "")
	if jp.PatchType != "json6902" {
		t.Errorf("expected json6902, got %s", jp.PatchType)
	}
	if !strings.Contains(jp.PatchYAML, "- op: remove") {
		t.Errorf("JSONPatch missing op: %s", jp.PatchYAML)
	}

	// Test FormatKustomizationFile
	kustFile := FormatKustomizationFile([]KustomizePatch{kp, jp})
	if !strings.Contains(kustFile, "kind: Kustomization") {
		t.Errorf("kustomization missing kind: %s", kustFile)
	}
	if !strings.Contains(kustFile, kp.TargetFile) || !strings.Contains(kustFile, jp.TargetFile) {
		t.Errorf("kustomization missing patch paths: %s", kustFile)
	}
}

func TestCanaryValidator(t *testing.T) {
	validator := NewCanaryValidator(true)

	// Valid NixOS patch
	rule, _ := GetRuleByID("REMEDIATE-AUTO-005")
	validNix := SynthesizeNixOSPatch(rule, "ceph.nix", "services.ceph.requireMsgr2", "false", "true", "")
	checkNix := validator.ValidateNixOSPatch(&validNix)
	if checkNix.Status != CanaryPassed {
		t.Errorf("expected valid NixOS patch to pass canary, got %s: %s", checkNix.Status, checkNix.Error)
	}

	// Invalid NixOS patch: Unbalanced braces
	badNix := validNix
	badNix.DiffContent = "{\n  services.ceph.requireMsgr2 = true;\n" // Missing closing brace
	badCheck := validator.ValidateNixOSPatch(&badNix)
	if badCheck.Status != CanaryFailed {
		t.Errorf("expected unbalanced braces to fail canary, got %s", badCheck.Status)
	}

	// Invalid NixOS patch: Prohibited command injection
	injectNix := validNix
	injectNix.DiffContent = "{\n  services.ceph.requireMsgr2 = true; builtins.exec [ \"rm\" \"-rf\" ];\n}"
	injectCheck := validator.ValidateNixOSPatch(&injectNix)
	if injectCheck.Status != CanaryFailed || !strings.Contains(injectCheck.Error, "prohibited unsafe construct") {
		t.Errorf("expected command injection to fail canary, got %s (%s)", injectCheck.Status, injectCheck.Error)
	}

	// Valid Kustomize patch
	rule2, _ := GetRuleByID("REMEDIATE-AUTO-002")
	validK8s := SynthesizeKustomizeStrategicMerge(rule2, "apps/v1", "Deployment", "test-deploy", "default", "spec:\n  replicas: 3\n")
	checkK8s := validator.ValidateKustomizePatch(&validK8s)
	if checkK8s.Status != CanaryPassed {
		t.Errorf("expected valid Kustomize patch to pass canary, got %s: %s", checkK8s.Status, checkK8s.Error)
	}

	// Invalid Kustomize patch: Tab character
	tabK8s := validK8s
	tabK8s.PatchYAML = "apiVersion: apps/v1\nkind: Deployment\n\tspec:\n\t  replicas: 3\n"
	tabCheck := validator.ValidateKustomizePatch(&tabK8s)
	if tabCheck.Status != CanaryFailed || !strings.Contains(tabCheck.Error, "prohibited tab character") {
		t.Errorf("expected tab character to fail canary, got %s (%s)", tabCheck.Status, tabCheck.Error)
	}

	// Valid GitOps PR
	pr := SynthesizeGitOpsPR("fix(security): apply mitigations", "remediation/patch-123", "main", []NixOSPatch{validNix}, []KustomizePatch{validK8s}, validator)
	if !pr.CanaryPassed {
		t.Errorf("expected PR canary to pass, but failed")
	}

	// Invalid GitOps PR: Invalid branch name
	badBranchPR := SynthesizeGitOpsPR("fix(security): apply mitigations", "feature/unauthorized_branch", "main", []NixOSPatch{validNix}, []KustomizePatch{validK8s}, validator)
	if badBranchPR.CanaryPassed {
		t.Errorf("expected PR with invalid branch to fail canary")
	}
}

func TestRemediationScannerAndReport(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a vulnerable NixOS module
	nixContent := `
{ config, pkgs, ... }:
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.0.0.1/24" ];
    privateKey = "unencrypted-store-key";
  };
  services.ceph.enable = true;
}
`
	nixFile := filepath.Join(tempDir, "vulnerable.nix")
	if err := os.WriteFile(nixFile, []byte(nixContent), 0644); err != nil {
		t.Fatalf("failed to write test nix file: %v", err)
	}

	// 2. Create a vulnerable Kubernetes manifest
	k8sContent := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-workload
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vulnerable-ingress
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: "proxy_set_header X-Custom $uri;"
spec:
  rules:
    - host: example.com
`
	k8sFile := filepath.Join(tempDir, "vulnerable.yaml")
	if err := os.WriteFile(k8sFile, []byte(k8sContent), 0644); err != nil {
		t.Fatalf("failed to write test k8s file: %v", err)
	}

	feed := &intel.Feed{}
	scanner := NewRemediationScanner(feed)

	report, err := scanner.ScanManifestPath(tempDir)
	if err != nil {
		t.Fatalf("ScanManifestPath failed: %v", err)
	}

	if len(report.Findings) < 4 {
		t.Errorf("expected at least 4 findings, got %d", len(report.Findings))
	}
	if len(report.PullRequests) != 1 {
		t.Fatalf("expected 1 synthesized GitOps PR, got %d", len(report.PullRequests))
	}

	pr := report.PullRequests[0]
	if !pr.CanaryPassed {
		t.Errorf("expected PR canary validation to pass, but failed")
	}
	if len(pr.NixPatches) == 0 || len(pr.K8sPatches) == 0 {
		t.Errorf("expected both NixOS and K8s patches, got %d nix, %d k8s", len(pr.NixPatches), len(pr.K8sPatches))
	}

	if report.Summary.RemediationScore < 85.0 {
		t.Errorf("expected RemediationScore >= 85.0, got %.1f", report.Summary.RemediationScore)
	}
	if report.Summary.Status != "PASSED" {
		t.Errorf("expected Status PASSED, got %s", report.Summary.Status)
	}
}

func TestWriteRemediationArtifacts(t *testing.T) {
	tempDir := t.TempDir()
	outDir := filepath.Join(tempDir, "artifacts")

	rule, _ := GetRuleByID("REMEDIATE-AUTO-002")
	k8sPatch := SynthesizeKustomizeStrategicMerge(rule, "apps/v1", "Deployment", "test-app", "default", "spec:\n  replicas: 2\n")

	ruleNix, _ := GetRuleByID("REMEDIATE-AUTO-005")
	nixPatch := SynthesizeNixOSPatch(ruleNix, "storage.nix", "services.ceph.requireMsgr2", "false", "true", "")

	validator := NewCanaryValidator(true)
	pr := SynthesizeGitOpsPR("fix(security): declarative fixes", "remediation/auto-patch", "main", []NixOSPatch{nixPatch}, []KustomizePatch{k8sPatch}, validator)

	written, err := WriteRemediationArtifacts(outDir, pr)
	if err != nil {
		t.Fatalf("WriteRemediationArtifacts failed: %v", err)
	}

	if len(written) < 4 {
		t.Errorf("expected at least 4 written files, got %d: %+v", len(written), written)
	}

	for key, path := range written {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("written artifact %s at %s does not exist: %v", key, path, err)
		}
	}
}
