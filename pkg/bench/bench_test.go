package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func sampleFeed() *intel.Feed {
	return &intel.Feed{
		Version: "1.0.0",
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-38102",
				Title:     "Kubernetes Kubelet Unauthenticated Remote Execution",
				Component: "kubelet",
				Target:    "kubernetes",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.8,
			},
		},
	}
}

func TestAllCISRules(t *testing.T) {
	rules := AllCISRules()
	if len(rules) < 15 {
		t.Fatalf("expected at least 15 CIS benchmark rules, got %d", len(rules))
	}

	seen := make(map[string]bool)
	for _, r := range rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID found: %s", r.ID)
		}
		seen[r.ID] = true

		if r.Title == "" || r.Description == "" || r.FlagName == "" {
			t.Errorf("rule %s has empty required fields", r.ID)
		}
		if r.CVSSScore <= 0.0 || r.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", r.ID, r.CVSSScore)
		}
	}
}

func TestGetRuleByID(t *testing.T) {
	r := GetRuleByID("CIS-1.2.1")
	if r == nil {
		t.Fatal("expected rule CIS-1.2.1 to be found")
	}
	if r.Component != ComponentAPIServer {
		t.Errorf("expected component apiserver, got %s", r.Component)
	}

	missing := GetRuleByID("NON-EXISTENT")
	if missing != nil {
		t.Errorf("expected nil for non-existent rule, got %+v", missing)
	}
}

func TestGetRulesByComponent(t *testing.T) {
	kubeletRules := GetRulesByComponent(ComponentKubelet)
	if len(kubeletRules) == 0 {
		t.Fatal("expected non-empty rules for Kubelet")
	}
	for _, r := range kubeletRules {
		if r.Component != ComponentKubelet {
			t.Errorf("expected Kubelet component, got %s", r.Component)
		}
	}
}

func TestScanNixOSConfigVulnerable(t *testing.T) {
	nixContent := `
{ config, pkgs, ... }:
{
  services.kubernetes = {
    roles = [ "master" "node" ];
    apiserver = {
      enable = true;
      anonymousAuth = true; # VIOLATION: CIS-1.2.1
      authorizationMode = [ "AlwaysAllow" ]; # VIOLATION: CIS-1.2.6
      extraOpts = "--profiling=true --bind-address=0.0.0.0";
    };
    kubelet = {
      enable = true;
      extraOpts = "--anonymous-auth=true --read-only-port=10255 --authorization-mode=AlwaysAllow";
    };
  };
}
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "nixos-k8s.nix")
	if err := os.WriteFile(filePath, []byte(nixContent), 0644); err != nil {
		t.Fatalf("failed to write test nix file: %v", err)
	}

	scanner := NewCISScanner(sampleFeed())
	report, err := scanner.ScanFile(filePath)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if len(report.Violations) == 0 {
		t.Fatal("expected violations in vulnerable NixOS config, got 0")
	}

	// Verify specific violations
	hasAnonAuth := false
	hasReadOnlyPort := false
	hasKubeletCVE := false

	for _, v := range report.Violations {
		if v.RuleID == "CIS-1.2.1" || v.RuleID == "CIS-4.2.1" {
			hasAnonAuth = true
		}
		if v.RuleID == "CIS-4.2.4" {
			hasReadOnlyPort = true
		}
		if v.RuleID == "CIS-4.2.1" && v.MatchedCVE == "CVE-2026-38102" {
			hasKubeletCVE = true
		}
	}

	if !hasAnonAuth {
		t.Error("expected violation for anonymous-auth")
	}
	if !hasReadOnlyPort {
		t.Error("expected violation for read-only-port")
	}
	if !hasKubeletCVE {
		t.Error("expected CVE-2026-38102 to correlate with CIS-4.2.1")
	}

	if report.Summary.ComplianceScore >= 100.0 {
		t.Errorf("expected compliance score < 100%%, got %.1f%%", report.Summary.ComplianceScore)
	}
}

func TestScanYAMLKubeletConfig(t *testing.T) {
	yamlContent := `
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
rotateCertificates: true
tlsCipherSuites:
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "kubelet-config.yaml")
	if err := os.WriteFile(filePath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	scanner := NewCISScanner(sampleFeed())
	report, err := scanner.ScanFile(filePath)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	// Check Kubelet component rules: CIS-4.2.1, CIS-4.2.2, CIS-4.2.4, CIS-4.2.6 should pass
	for _, v := range report.Violations {
		if v.Component == ComponentKubelet {
			switch v.RuleID {
			case "CIS-4.2.1":
				t.Errorf("CIS-4.2.1 should have passed, but got violation: %+v", v)
			case "CIS-4.2.2":
				t.Errorf("CIS-4.2.2 should have passed, but got violation: %+v", v)
			case "CIS-4.2.4":
				t.Errorf("CIS-4.2.4 should have passed, but got violation: %+v", v)
			case "CIS-4.2.6":
				t.Errorf("CIS-4.2.6 should have passed, but got violation: %+v", v)
			}
		}
	}
}

func TestRemediationSynthesis(t *testing.T) {
	violations := []CISViolation{
		{
			RuleID:         "CIS-1.2.1",
			Component:      ComponentAPIServer,
			Title:          "Disable anonymous auth",
			Severity:       intel.SeverityCritical,
			RemediationNix: "services.kubernetes.apiserver.anonymousAuth = false;",
			FlagName:       "anonymous-auth",
			ActualValue:    "true",
			ExpectedValue:  "false",
		},
		{
			RuleID:         "CIS-4.2.4",
			Component:      ComponentKubelet,
			Title:          "Disable read-only port",
			Severity:       intel.SeverityHigh,
			RemediationNix: "services.kubernetes.kubelet.extraOpts = \"--read-only-port=0\";",
			FlagName:       "read-only-port",
			ActualValue:    "10255",
			ExpectedValue:  "0",
		},
	}

	nixPatch := SynthesizeNixOSRemediation(violations)
	if !strings.Contains(nixPatch, "services.kubernetes.apiserver.anonymousAuth = false;") {
		t.Errorf("expected synthesized nixos patch to contain apiserver fix, got:\n%s", nixPatch)
	}
	if !strings.Contains(nixPatch, "services.kubernetes.kubelet.extraOpts = \"--read-only-port=0\";") {
		t.Errorf("expected synthesized nixos patch to contain kubelet fix, got:\n%s", nixPatch)
	}

	yamlPatch := SynthesizeKubeletConfigRemediation(violations)
	if !strings.Contains(yamlPatch, "readOnlyPort: 0") {
		t.Errorf("expected synthesized yaml patch to contain readOnlyPort: 0, got:\n%s", yamlPatch)
	}

	report := &CISAuditReport{Violations: violations}
	summary := FormatRemediationSummary(report)
	if !strings.Contains(summary, "CIS BENCHMARK REMEDIATION PLAN") {
		t.Errorf("expected summary header, got: %s", summary)
	}
}

func TestDefensiveBounds(t *testing.T) {
	scanner := NewCISScanner(nil)
	tmpDir := t.TempDir()
	oversizedPath := filepath.Join(tmpDir, "huge.nix")

	// Create 11MB file to trigger bounds check
	f, err := os.Create(oversizedPath)
	if err != nil {
		t.Fatalf("failed to create oversized file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 1024*1024) // 1MB buffer
	for i := 0; i < 11; i++ {
		if _, err := f.Write(buf); err != nil {
			t.Fatalf("failed to write to file: %v", err)
		}
	}
	f.Close()

	_, err = scanner.ScanFile(oversizedPath)
	if err == nil {
		t.Fatal("expected error scanning oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum benchmark size limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}
