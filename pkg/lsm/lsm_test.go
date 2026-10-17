package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalLSMRules(t *testing.T) {
	rules := CanonicalLSMRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical LSM rules, got %d", len(rules))
	}

	for _, r := range rules {
		if r.ID == "" || r.Name == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s has incomplete fields", r.ID)
		}
		if r.CVSSScore <= 0.0 || r.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", r.ID, r.CVSSScore)
		}
		lookedUp, ok := LookupLSMRule(r.ID)
		if !ok || lookedUp.ID != r.ID {
			t.Errorf("failed to lookup rule %s", r.ID)
		}
	}
}

func TestParseAndAuditNixOSLSM(t *testing.T) {
	compliantNix := `
{
  boot.kernelParams = [
    "lsm=lockdown,yama,bpf,apparmor"
  ];
  security.lsm = [ "lockdown" "yama" "bpf" "apparmor" ];
  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 1;
  };
  systemd.services.ebpf-lsm-mac = {
    description = "eBPF LSM Daemon";
  };
}
`
	cfg, err := ParseNixOSLSMConfig(compliantNix, "test-compliant.nix")
	if err != nil {
		t.Fatalf("unexpected error parsing compliant nix config: %v", err)
	}
	if !cfg.BPFLSMEnabled {
		t.Errorf("expected BPFLSMEnabled to be true")
	}
	if !cfg.UnprivilegedBPFDisabled {
		t.Errorf("expected UnprivilegedBPFDisabled to be true")
	}

	violations := AuditNixOSLSM(cfg, "test-compliant.nix", nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for compliant nixos config, got %d", len(violations))
	}

	vulnerableNix := `
{
  boot.kernelParams = [
    "lsm=lockdown,yama"
  ];
  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 0;
  };
}
`
	vulnCfg, err := ParseNixOSLSMConfig(vulnerableNix, "test-vuln.nix")
	if err != nil {
		t.Fatalf("unexpected error parsing vulnerable nix config: %v", err)
	}
	if vulnCfg.BPFLSMEnabled {
		t.Errorf("expected BPFLSMEnabled to be false")
	}

	vulnViolations := AuditNixOSLSM(vulnCfg, "test-vuln.nix", nil)
	if len(vulnViolations) < 2 {
		t.Fatalf("expected at least 2 violations for vulnerable config, got %d", len(vulnViolations))
	}

	hasLSM001 := false
	hasLSM006 := false
	for _, v := range vulnViolations {
		if v.RuleID == "LSM-MAC-001" {
			hasLSM001 = true
		}
		if v.RuleID == "LSM-MAC-006" {
			hasLSM006 = true
		}
	}
	if !hasLSM001 {
		t.Errorf("expected LSM-MAC-001 violation for missing bpf in LSM")
	}
	if !hasLSM006 {
		t.Errorf("expected LSM-MAC-006 violation for enabled unprivileged BPF")
	}
}

func TestParseAndAuditK8sMACProfile(t *testing.T) {
	k8sYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-workload
  namespace: prod
spec:
  hostPID: true
  containers:
  - name: agent
    image: alpine:latest
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
        - NET_RAW
---
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
  namespace: prod
  annotations:
    lsm.security.alpha.kubernetes.io/profile: "strict"
spec:
  containers:
  - name: app
    image: nginx:alpine
`

	profiles, err := ParseK8sMACProfile(k8sYAML, "workloads.yaml")
	if err != nil {
		t.Fatalf("unexpected error parsing k8s profiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}

	if !profiles[0].Privileged || !profiles[0].HostPID {
		t.Errorf("expected first profile to be privileged with hostPID")
	}
	if !profiles[1].MACEnforced {
		t.Errorf("expected second profile to have MACEnforced=true")
	}

	violations := AuditMACProfiles(profiles, "workloads.yaml", nil)
	if len(violations) < 3 {
		t.Fatalf("expected multiple violations for privileged workload, got %d", len(violations))
	}

	hasPriv := false
	hasHostPID := false
	hasCap := false
	hasRaw := false

	for _, v := range violations {
		if v.RuleID == "LSM-MAC-008" {
			hasPriv = true
		}
		if v.RuleID == "LSM-MAC-009" {
			hasHostPID = true
		}
		if v.RuleID == "LSM-MAC-010" {
			hasCap = true
		}
		if v.RuleID == "LSM-MAC-004" {
			hasRaw = true
		}
	}

	if !hasPriv {
		t.Errorf("expected LSM-MAC-008 for privileged container")
	}
	if !hasHostPID {
		t.Errorf("expected LSM-MAC-009 for hostPID")
	}
	if !hasCap {
		t.Errorf("expected LSM-MAC-010 for CAP_SYS_ADMIN")
	}
	if !hasRaw {
		t.Errorf("expected LSM-MAC-004 for CAP_NET_RAW")
	}
}

func TestTelemetryParsingAndAudit(t *testing.T) {
	telemetryJSON := `[
  {
    "timestamp": "2026-10-17T11:30:00Z",
    "node": "nixos-worker-01",
    "container_id": "container-xyz",
    "cgroup": "kubepods.slice/pod-123",
    "hook": "bprm_check_security",
    "syscall": "execve",
    "comm": "curl_payload",
    "target_path": "/tmp/reverse_shell.sh",
    "return_code": -1,
    "blocked": true,
    "action": "DENY"
  },
  {
    "timestamp": "2026-10-17T11:32:00Z",
    "node": "nixos-worker-02",
    "container_id": "container-abc",
    "cgroup": "kubepods.slice/pod-456",
    "hook": "socket_create",
    "syscall": "socket",
    "comm": "packet_crafter",
    "target_path": "AF_PACKET",
    "return_code": -1,
    "blocked": true,
    "action": "DENY"
  }
]`

	events, err := ParseLSMTelemetryJSON([]byte(telemetryJSON))
	if err != nil {
		t.Fatalf("unexpected error parsing telemetry json: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 telemetry events, got %d", len(events))
	}

	violations := AuditTelemetry(events, "telemetry.json", nil)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations from blocked telemetry, got %d", len(violations))
	}

	hasLSM011 := false
	hasLSM012 := false
	for _, v := range violations {
		if v.RuleID == "LSM-MAC-011" {
			hasLSM011 = true
		}
		if v.RuleID == "LSM-MAC-012" {
			hasLSM012 = true
		}
	}
	if !hasLSM011 {
		t.Errorf("expected LSM-MAC-011 for blocked execution in /tmp")
	}
	if !hasLSM012 {
		t.Errorf("expected LSM-MAC-012 for blocked socket_create")
	}
}

func TestPolicySynthesis(t *testing.T) {
	profile := &ContainerMACProfile{
		WorkloadName: "sentinel-agent",
		Namespace:    "monitoring",
	}

	nixMod := SynthesizeNixOSLSMModule([]ContainerMACProfile{*profile})
	if !strings.Contains(nixMod, "lsm=lockdown,yama,bpf,apparmor") {
		t.Errorf("synthesized nix module missing bpf in kernelParams")
	}
	if !strings.Contains(nixMod, "ebpf-lsm-mac") {
		t.Errorf("synthesized nix module missing systemd service")
	}

	bpfCode := SynthesizeBPFLSMCode(profile)
	if !strings.Contains(bpfCode, "SEC(\"lsm/bprm_check_security\")") {
		t.Errorf("synthesized BPF program missing bprm hook")
	}
	if !strings.Contains(bpfCode, "SEC(\"lsm/socket_create\")") {
		t.Errorf("synthesized BPF program missing socket hook")
	}

	k8sPolicy := SynthesizeK8sMACPolicy(profile)
	if !strings.Contains(k8sPolicy, "ContainerMACProfile") {
		t.Errorf("synthesized k8s policy missing CRD kind")
	}

	tmpDir := t.TempDir()
	written, err := WriteLSMArtifacts(tmpDir, nixMod, bpfCode, k8sPolicy)
	if err != nil {
		t.Fatalf("unexpected error writing lsm artifacts: %v", err)
	}
	if len(written) != 3 {
		t.Errorf("expected 3 written artifacts, got %d", len(written))
	}
	for name, path := range written {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("artifact %s not written to %s", name, path)
		}
	}
}

func TestLSMScannerAndLimits(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-99103",
				CVSSScore: 9.8,
			},
		},
	}
	scanner := NewLSMScanner(feed)

	tmpDir := t.TempDir()
	nixFile := filepath.Join(tmpDir, "host.nix")
	if err := os.WriteFile(nixFile, []byte("boot.kernelParams = [ \"lsm=bpf\" ];"), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := scanner.ScanManifestPath(tmpDir)
	if err != nil {
		t.Fatalf("unexpected scanner error: %v", err)
	}
	if len(report.Configs) != 1 {
		t.Errorf("expected 1 config scanned, got %d", len(report.Configs))
	}

	// Test memory limit defense
	hugeContent := strings.Repeat("A", MaxManifestBytes+10)
	_, err = ParseNixOSLSMConfig(hugeContent, "huge.nix")
	if err == nil {
		t.Errorf("expected error for manifest exceeding MaxManifestBytes")
	}

	_, err = ParseLSMTelemetryJSON([]byte(hugeContent))
	if err == nil {
		t.Errorf("expected error for telemetry exceeding MaxTelemetryBytes")
	}
}
