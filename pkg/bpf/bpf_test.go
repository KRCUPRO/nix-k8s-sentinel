package bpf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalBPFRules(t *testing.T) {
	if len(CanonicalBPFRules) != 12 {
		t.Fatalf("expected 12 canonical BPF rules, got %d", len(CanonicalBPFRules))
	}

	for _, rule := range CanonicalBPFRules {
		if rule.RuleID == "" {
			t.Errorf("rule missing RuleID")
		}
		if rule.Title == "" {
			t.Errorf("rule %s missing Title", rule.RuleID)
		}
		if rule.Severity == "" {
			t.Errorf("rule %s missing Severity", rule.RuleID)
		}
		if rule.CVSSScore <= 0.0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s invalid CVSS score: %f", rule.RuleID, rule.CVSSScore)
		}
		if rule.Description == "" {
			t.Errorf("rule %s missing Description", rule.RuleID)
		}
		if rule.Remediation == "" {
			t.Errorf("rule %s missing Remediation", rule.RuleID)
		}

		fetched, err := LookupBPFRule(rule.RuleID)
		if err != nil {
			t.Errorf("LookupBPFRule(%s) failed: %v", rule.RuleID, err)
		}
		if fetched.RuleID != rule.RuleID {
			t.Errorf("LookupBPFRule returned mismatch rule: got %s, want %s", fetched.RuleID, rule.RuleID)
		}
	}

	_, err := LookupBPFRule("BPF-SEC-999")
	if err == nil {
		t.Errorf("expected error for non-existent rule BPF-SEC-999")
	}
}

func TestParseK8sManifest(t *testing.T) {
	vulnerableYAML := `apiVersion: v1
kind: Pod
metadata:
  name: unhardened-worker
  namespace: prod-apps
spec:
  hostPID: true
  hostIPC: true
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
    - name: app
      image: alpine:latest
      securityContext:
        capabilities:
          add:
            - NET_RAW
            - SYS_ADMIN
            - SYS_MODULE
---
apiVersion: v1
kind: Pod
metadata:
  name: hardened-worker
  namespace: prod-apps
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: alpine:latest
      securityContext:
        capabilities:
          drop:
            - ALL
`
	tmpDir := t.TempDir()
	vulnPath := filepath.Join(tmpDir, "k8s-workload.yaml")
	if err := os.WriteFile(vulnPath, []byte(vulnerableYAML), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	violations, count, err := ParseManifestFile(vulnPath)
	if err != nil {
		t.Fatalf("ParseManifestFile failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 workloads scanned, got %d", count)
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	expectedRules := []string{"BPF-SEC-001", "BPF-SEC-002", "BPF-SEC-003", "BPF-SEC-006", "BPF-SEC-010"}
	for _, r := range expectedRules {
		if !ruleMap[r] {
			t.Errorf("expected violation %s not found in manifest scan", r)
		}
	}
}

func TestParseNixOSConfig(t *testing.T) {
	vulnNix := `{ config, lib, pkgs, ... }:
{
  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 0;
  };
  security.lsm = [ "lockdown" "apparmor" ];
  systemd.services.legacy-daemon = {
    serviceConfig = {
      ExecStart = "/usr/bin/daemon";
    };
  };
}
`
	tmpDir := t.TempDir()
	nixPath := filepath.Join(tmpDir, "nixos.nix")
	if err := os.WriteFile(nixPath, []byte(vulnNix), 0o644); err != nil {
		t.Fatalf("failed to write nix fixture: %v", err)
	}

	violations, count, err := ParseManifestFile(nixPath)
	if err != nil {
		t.Fatalf("ParseManifestFile failed for nix: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 config scanned, got %d", count)
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["BPF-SEC-008"] {
		t.Errorf("expected BPF-SEC-008 for unprivileged_bpf_disabled=0")
	}
	if !ruleMap["BPF-SEC-005"] {
		t.Errorf("expected BPF-SEC-005 for missing bpf in security.lsm")
	}
	if !ruleMap["BPF-SEC-011"] {
		t.Errorf("expected BPF-SEC-011 for systemd unit missing SystemCallFilter")
	}
}

func TestParseJSONSeccompProfile(t *testing.T) {
	insecureProfile := SeccompProfile{
		DefaultAction: ActionAllow,
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscallRule{
			{
				Names:  []string{"ptrace", "process_vm_writev"},
				Action: ActionAllow,
			},
			{
				Names:  []string{"init_module"},
				Action: ActionAllow,
			},
			{
				Names:  []string{"bpf"},
				Action: ActionAllow,
			},
		},
	}

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "seccomp.json")
	data, _ := json.Marshal(insecureProfile)
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		t.Fatalf("failed to write seccomp json: %v", err)
	}

	violations, count, err := ParseManifestFile(jsonPath)
	if err != nil {
		t.Fatalf("ParseManifestFile failed on json profile: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 profile scanned, got %d", count)
	}

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["BPF-SEC-009"] {
		t.Errorf("expected BPF-SEC-009 for defaultAction SCMP_ACT_ALLOW")
	}
	if !ruleMap["BPF-SEC-002"] {
		t.Errorf("expected BPF-SEC-002 for ptrace allow")
	}
	if !ruleMap["BPF-SEC-010"] {
		t.Errorf("expected BPF-SEC-010 for init_module allow")
	}
	if !ruleMap["BPF-SEC-008"] {
		t.Errorf("expected BPF-SEC-008 for bpf allow")
	}
}

func TestAuditRuntimeTelemetry(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-90412",
				Title:     "Kernel BPF Syscall Race",
				Component: "kernel-bpf",
				Target:    "nixos",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.8,
			},
		},
	}

	telem := BPFRuntimeTelemetry{
		ClusterID:   "cluster-prod-01",
		NodeName:    "worker-node-alpha",
		GeneratedAt: time.Now().UTC(),
		ActiveLSMHooks: []string{
			"lsm/bprm_check_security",
		},
		SocketEvents: []SocketTelemetryItem{
			{
				PID:          4092,
				ProcessName:  "scanner-bot",
				Namespace:    "default",
				PodName:      "test-pod",
				Domain:       "AF_PACKET",
				Type:         "SOCK_RAW",
				Protocol:     0,
				CreationRate: 480.0, // Exceeds MaxSocketRateThreshold (250)
				AnomalyFlag:  true,
				Timestamp:    time.Now().UTC(),
			},
		},
		SyscallEvents: []SyscallTelemetryEvent{
			{
				PID:          4092,
				ProcessName:  "scanner-bot",
				Namespace:    "default",
				PodName:      "test-pod",
				SyscallName:  "ptrace",
				CallCount:    15,
				FailureCount: 2,
				IsPrivileged: true,
				BlockedByLSM: true,
				Timestamp:    time.Now().UTC(),
			},
		},
	}

	tmpDir := t.TempDir()
	telemPath := filepath.Join(tmpDir, "bpf-telemetry.json")
	data, _ := json.Marshal(telem)
	if err := os.WriteFile(telemPath, data, 0o644); err != nil {
		t.Fatalf("failed to write telemetry file: %v", err)
	}

	violations, events, err := AuditRuntimeTelemetry(telemPath, feed)
	if err != nil {
		t.Fatalf("AuditRuntimeTelemetry failed: %v", err)
	}
	if events != 2 {
		t.Errorf("expected 2 telemetry events, got %d", events)
	}

	ruleMap := make(map[string]bool)
	hasCVE := false
	for _, v := range violations {
		ruleMap[v.RuleID] = true
		if v.MatchedCVE == "CVE-2026-90412" {
			hasCVE = true
		}
	}

	if !ruleMap["BPF-SEC-005"] {
		t.Errorf("expected BPF-SEC-005 for missing socket_create hook")
	}
	if !ruleMap["BPF-SEC-003"] {
		t.Errorf("expected BPF-SEC-003 for SOCK_RAW")
	}
	if !ruleMap["BPF-SEC-004"] {
		t.Errorf("expected BPF-SEC-004 for burst creation rate (480/s)")
	}
	if !ruleMap["BPF-SEC-007"] {
		t.Errorf("expected BPF-SEC-007 for CVE-2026-90412 correlation")
	}
	if !ruleMap["BPF-SEC-012"] {
		t.Errorf("expected BPF-SEC-012 for BlockedByLSM syscall")
	}
	if !hasCVE {
		t.Errorf("expected MatchedCVE to be populated with CVE-2026-90412")
	}

	summary := ComputeBPFSummary(1, events, violations)
	if summary.AuditStatus != "FAIL" {
		t.Errorf("expected AuditStatus FAIL, got %s", summary.AuditStatus)
	}
}

func TestPolicySynthesis(t *testing.T) {
	// 1. Seccomp Profile
	profile := SynthesizeHardenedSeccompProfile()
	if profile.DefaultAction != ActionErrno {
		t.Errorf("expected DefaultAction SCMP_ACT_ERRNO, got %s", profile.DefaultAction)
	}
	if len(profile.Syscalls) == 0 || len(profile.Syscalls[0].Names) < 50 {
		t.Errorf("expected at least 50 safe syscalls in synthesized profile")
	}

	// 2. NixOS Module
	nixMod := SynthesizeNixOSSeccompModule("custom-service")
	if !strings.Contains(nixMod, "systemd.services.\"custom-service\".serviceConfig") {
		t.Errorf("expected custom-service declaration in NixOS module")
	}
	if !strings.Contains(nixMod, "kernel.unprivileged_bpf_disabled") {
		t.Errorf("expected kernel.unprivileged_bpf_disabled setting in NixOS module")
	}

	// 3. eBPF LSM Policy
	lsmPol := SynthesizeEBPFLSMDropPolicy()
	if !strings.Contains(lsmPol, "kind: EBPFLSMPolicy") {
		t.Errorf("expected kind: EBPFLSMPolicy in synthesized YAML")
	}

	// 4. Disk writing
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "policies")
	written, err := WriteSynthesizedPolicies(outDir, "test-svc")
	if err != nil {
		t.Fatalf("WriteSynthesizedPolicies failed: %v", err)
	}
	if len(written) != 3 {
		t.Errorf("expected 3 files written, got %d", len(written))
	}
	for key, path := range written {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("written file %s (%s) does not exist: %v", key, path, err)
		}
	}
}

func TestBPFScanner_DirectoryWalk(t *testing.T) {
	tmpDir := t.TempDir()
	k8sFile := filepath.Join(tmpDir, "pod.yaml")
	os.WriteFile(k8sFile, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
`), 0o644)

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-90412",
				Title:     "Kernel BPF Syscall Race",
				Component: "kernel-bpf",
				Target:    "nixos",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.8,
			},
		},
	}

	scanner := NewBPFScanner(feed)
	rep, err := scanner.ScanPath(tmpDir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}
	if len(rep.ScannedPaths) != 1 {
		t.Errorf("expected 1 scanned path, got %d", len(rep.ScannedPaths))
	}
	if rep.Summary.ComplianceScore < 90.0 {
		t.Errorf("expected high compliance score for hardened pod, got %.1f", rep.Summary.ComplianceScore)
	}
}

func TestBoundsAndLimits(t *testing.T) {
	tmpDir := t.TempDir()
	hugeFile := filepath.Join(tmpDir, "huge.yaml")
	f, err := os.Create(hugeFile)
	if err != nil {
		t.Fatalf("failed to create huge file: %v", err)
	}
	defer f.Close()
	f.Truncate(MaxManifestBytes + 1024)

	_, _, err = ParseManifestFile(hugeFile)
	if err == nil {
		t.Errorf("expected error for file exceeding MaxManifestBytes")
	}
}
