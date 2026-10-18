package impermanence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesCatalogIntegrity(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical rules, got %d", len(rules))
	}

	expectedIDs := []string{
		"IMP-ROOT-001", "IMP-ROOT-002", "IMP-ROOT-003", "IMP-ROOT-004",
		"IMP-ROOT-005", "IMP-ROOT-006", "IMP-ROOT-007", "IMP-ROOT-008",
		"IMP-ROOT-009", "IMP-ROOT-010", "IMP-ROOT-011", "IMP-ROOT-012",
	}

	for _, id := range expectedIDs {
		rule := GetRule(id)
		if rule == nil {
			t.Errorf("rule %s missing from catalog", id)
			continue
		}
		if rule.ID != id {
			t.Errorf("rule ID mismatch: expected %s, got %s", id, rule.ID)
		}
		if rule.Title == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has empty metadata", id)
		}
		if rule.CVSSScore <= 0.0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", id, rule.CVSSScore)
		}
	}

	// Verify CVE-2026-61842 mapping
	rule3 := GetRule("IMP-ROOT-003")
	if rule3.MatchedCVE != "CVE-2026-61842" {
		t.Errorf("expected IMP-ROOT-003 to map to CVE-2026-61842, got %s", rule3.MatchedCVE)
	}
}

func TestParseCompliantNixOSImpermanence(t *testing.T) {
	config := `
{ config, pkgs, lib, ... }:

{
  networking.hostName = "worker-nixos-01";

  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "defaults" "size=8G" "mode=755" ];
  };

  fileSystems."/persist" = {
    device = "/dev/mapper/enc-persist";
    fsType = "ext4";
    neededForBoot = true;
  };

  boot.kernelParams = [
    "init_on_alloc=1"
    "init_on_free=1"
    "page_poison=1"
  ];

  swapDevices = [
    {
      device = "/dev/disk/by-partlabel/swap";
      randomEncryption = true;
    }
  ];

  environment.persistence."/persist" = {
    hideMounts = true;
    directories = [
      "/var/log"
      { directory = "/var/lib/kubelet"; mode = "0700"; }
      { directory = "/var/lib/containerd"; mode = "0711"; }
    ];
    files = [
      "/etc/machine-id"
      { file = "/etc/ssh/ssh_host_ed25519_key"; mode = "0600"; }
    ];
  };
}
`
	host, err := ParseNixOSImpermanence(config, "/etc/nixos/configuration.nix")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if host.HostName != "worker-nixos-01" {
		t.Errorf("expected hostName 'worker-nixos-01', got '%s'", host.HostName)
	}
	if host.Mode != ModeTmpfsRoot {
		t.Errorf("expected mode ModeTmpfsRoot, got %s", host.Mode)
	}
	if !host.StorageEncrypted {
		t.Errorf("expected StorageEncrypted = true")
	}
	if host.HasUnencryptedSwap {
		t.Errorf("expected HasUnencryptedSwap = false")
	}
	if !host.MachineIDPersisted {
		t.Errorf("expected MachineIDPersisted = true")
	}
	if !host.KubeletPKIPersisted {
		t.Errorf("expected KubeletPKIPersisted = true")
	}
	if !host.ContainerdPersisted {
		t.Errorf("expected ContainerdPersisted = true")
	}
	if host.ContainerdOnTmpfs {
		t.Errorf("expected ContainerdOnTmpfs = false")
	}
	if !host.KernelMemoryWiping {
		t.Errorf("expected KernelMemoryWiping = true")
	}

	auditor := NewAuditor()
	violations := auditor.AuditHost(host)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for compliant host, got %d: %+v", len(violations), violations)
	}
}

func TestParseVulnerableNixOSImpermanence(t *testing.T) {
	vulnerableConfig := `
{ config, pkgs, lib, ... }:

{
  networking.hostName = "vulnerable-node";

  fileSystems."/" = {
    device = "/dev/sda1";
    fsType = "ext4";
  };

  fileSystems."/persist" = {
    device = "/dev/sdb1";
    fsType = "ext4";
  };

  swapDevices = [
    {
      device = "/dev/sda2";
    }
  ];

  environment.persistence."/persist" = {
    directories = [
      "/var/log"
      { directory = "/var/lib/kubelet"; mode = "0777"; }
    ];
    files = [
      { file = "/etc/ssh/ssh_host_ed25519_key"; mode = "0666"; }
    ];
  };
}
`
	host, err := ParseNixOSImpermanence(vulnerableConfig, "/etc/nixos/vulnerable.nix")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if host.Mode != ModeMutableDisk {
		t.Errorf("expected ModeMutableDisk, got %s", host.Mode)
	}
	if !host.HasUnencryptedSwap {
		t.Errorf("expected HasUnencryptedSwap = true")
	}
	if host.MachineIDPersisted {
		t.Errorf("expected MachineIDPersisted = false")
	}
	if host.KernelMemoryWiping {
		t.Errorf("expected KernelMemoryWiping = false")
	}

	auditor := NewAuditor()
	violations := auditor.AuditHost(host)

	// Expect violations:
	// IMP-ROOT-001 (mutable root)
	// IMP-ROOT-003 (unencrypted swap)
	// IMP-ROOT-005 (unencrypted persist storage)
	// IMP-ROOT-006 (permissive modes on kubelet and ssh key)
	// IMP-ROOT-012 (missing kernel memory wiping)
	found001 := false
	found003 := false
	found005 := false
	found006 := false
	found012 := false

	for _, v := range violations {
		switch v.RuleID {
		case "IMP-ROOT-001":
			found001 = true
		case "IMP-ROOT-003":
			found003 = true
		case "IMP-ROOT-005":
			found005 = true
		case "IMP-ROOT-006":
			found006 = true
		case "IMP-ROOT-012":
			found012 = true
		}
	}

	if !found001 {
		t.Errorf("expected IMP-ROOT-001 violation for mutable root")
	}
	if !found003 {
		t.Errorf("expected IMP-ROOT-003 violation for unencrypted swap")
	}
	if !found005 {
		t.Errorf("expected IMP-ROOT-005 violation for unencrypted persistence storage")
	}
	if !found006 {
		t.Errorf("expected IMP-ROOT-006 violation for loose permissions")
	}
	if !found012 {
		t.Errorf("expected IMP-ROOT-012 violation for missing memory scrubbing")
	}

	summary := ComputeSummary([]ImpermanenceHostConfig{*host}, violations)
	if summary.ComplianceScore >= 50.0 {
		t.Errorf("expected low compliance score for highly vulnerable host, got %f", summary.ComplianceScore)
	}
	if summary.CriticalCount < 2 {
		t.Errorf("expected at least 2 critical violations, got %d", summary.CriticalCount)
	}
}

func TestClusterMountCollisions(t *testing.T) {
	hostConfig := `
{ config, pkgs, ... }:
{
  networking.hostName = "k8s-stateless-worker";
  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
  };
  environment.persistence."/persist" = {
    directories = [ "/var/lib/kubelet" ];
  };
}
`
	host, err := ParseNixOSImpermanence(hostConfig, "nixos.nix")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	k8sManifest := `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: logging-agent
  namespace: kube-system
spec:
  template:
    spec:
      volumes:
      - name: ephemeral-data
        hostPath:
          path: /var/log/app-data
      - name: persisted-data
        hostPath:
          path: /persist/log
`
	mounts, err := ParseK8sStorageMounts(k8sManifest, "daemonset.yaml")
	if err != nil {
		t.Fatalf("mount parse error: %v", err)
	}

	if len(mounts) != 2 {
		t.Fatalf("expected 2 mount references, got %d", len(mounts))
	}

	auditor := NewAuditor()
	violations := auditor.AuditClusterMountCollisions(host, mounts)

	// /var/log/app-data is on ephemeral root outside /persist, so it should trigger IMP-ROOT-010
	found010 := false
	for _, v := range violations {
		if v.RuleID == "IMP-ROOT-010" && strings.Contains(v.TargetPath, "/var/log/app-data") {
			found010 = true
		}
	}

	if !found010 {
		t.Errorf("expected IMP-ROOT-010 violation for ephemeral hostPath mount")
	}
}

func TestTelemetryAuditor(t *testing.T) {
	telemetryJSON := `
{
  "timestamp": "2026-10-18T18:00:00Z",
  "cluster_id": "prod-fleet",
  "nodes": [
    {
      "node_name": "worker-nixos-01",
      "root_mount": "none (tmpfs)",
      "total_ram_bytes": 68719476736,
      "used_ram_bytes": 21474836480,
      "root_total_bytes": 17179869184,
      "root_used_bytes": 15461882265,
      "root_usage_percent": 90.0,
      "orphaned_inodes": 1500,
      "swap_used_bytes": 524288000,
      "swap_encrypted": false,
      "wipe_on_reboot_active": true,
      "shutdown_memory_zeroed": true
    }
  ]
}
`
	telemetry, err := ParseImpermanenceTelemetryJSON([]byte(telemetryJSON))
	if err != nil {
		t.Fatalf("telemetry parse error: %v", err)
	}

	if len(telemetry.Nodes) != 1 {
		t.Fatalf("expected 1 node telemetry, got %d", len(telemetry.Nodes))
	}

	auditor := NewAuditor()
	host := &ImpermanenceHostConfig{HostName: "worker-nixos-01"}
	violations := auditor.AuditTelemetry(host, &telemetry.Nodes[0])

	found011 := false
	found003 := false
	for _, v := range violations {
		if v.RuleID == "IMP-ROOT-011" {
			found011 = true
		}
		if v.RuleID == "IMP-ROOT-003" {
			found003 = true
		}
	}

	if !found011 {
		t.Errorf("expected IMP-ROOT-011 for root tmpfs usage >= 85%%")
	}
	if !found003 {
		t.Errorf("expected IMP-ROOT-003 for unencrypted active swap")
	}
}

func TestPolicySynthesizer(t *testing.T) {
	synth := NewSynthesizer()

	nixosMod := synth.SynthesizeHardenedNixOSModule("edge-node-01", "/persist")
	if !strings.Contains(nixosMod, "fsType = \"tmpfs\";") {
		t.Errorf("synthesized NixOS module missing tmpfs root")
	}
	if !strings.Contains(nixosMod, "randomEncryption = true;") {
		t.Errorf("synthesized NixOS module missing encrypted swap")
	}
	if !strings.Contains(nixosMod, "init_on_free=1") {
		t.Errorf("synthesized NixOS module missing memory scrubbing")
	}

	zfsHook := synth.SynthesizeWipeOnRebootHook("zfs", "rpool/root@blank")
	if !strings.Contains(zfsHook, "zfs rollback -r rpool/root@blank") {
		t.Errorf("synthesized ZFS hook missing rollback command")
	}

	btrfsHook := synth.SynthesizeWipeOnRebootHook("btrfs", "/dev/mapper/enc-root")
	if !strings.Contains(btrfsHook, "btrfs subvolume snapshot") {
		t.Errorf("synthesized Btrfs hook missing subvolume snapshot")
	}

	alerts := synth.SynthesizePrometheusAlerts()
	if !strings.Contains(alerts, "TmpfsRootStorageFillingUp") {
		t.Errorf("synthesized Prometheus alerts missing TmpfsRootStorageFillingUp")
	}

	// Test writing to temporary directory
	tmpDir, err := os.MkdirTemp("", "impermanence-synth-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := synth.WriteSynthesizedPolicies(tmpDir, "test-node", "/persist"); err != nil {
		t.Fatalf("failed to write synthesized policies: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "impermanence-hardened.nix")); err != nil {
		t.Errorf("impermanence-hardened.nix was not written")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "wipe-on-reboot-zfs.nix")); err != nil {
		t.Errorf("wipe-on-reboot-zfs.nix was not written")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "impermanence-alerts.yaml")); err != nil {
		t.Errorf("impermanence-alerts.yaml was not written")
	}
}

func TestDefensiveBounds(t *testing.T) {
	oversized := make([]byte, MaxManifestBytes+1024)
	_, err := ParseNixOSImpermanence(string(oversized), "huge.nix")
	if err == nil {
		t.Errorf("expected error for oversized NixOS config")
	}

	oversizedTele := make([]byte, MaxTelemetryBytes+1024)
	_, err = ParseImpermanenceTelemetryJSON(oversizedTele)
	if err == nil {
		t.Errorf("expected error for oversized telemetry JSON")
	}
}

func TestScannerEndToEnd(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "impermanence-scan-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	nixContent := `
{ config, pkgs, ... }:
{
  networking.hostName = "scanner-test-node";
  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
  };
  environment.persistence."/persist" = {
    directories = [ "/var/lib/kubelet" ];
    files = [ "/etc/machine-id" ];
  };
  swapDevices = [
    {
      device = "/dev/sda2";
      randomEncryption = true;
    }
  ];
  boot.kernelParams = [ "page_poison=1" ];
}
`
	nixFile := filepath.Join(tmpDir, "configuration.nix")
	if err := os.WriteFile(nixFile, []byte(nixContent), 0644); err != nil {
		t.Fatalf("failed to write test nix file: %v", err)
	}

	scanner := NewScanner()
	report, err := scanner.Scan(tmpDir, "", "")
	if err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	if len(report.Hosts) != 1 {
		t.Fatalf("expected 1 host scanned, got %d", len(report.Hosts))
	}
	if report.Summary.EphemeralRootCount != 1 {
		t.Errorf("expected 1 ephemeral root count, got %d", report.Summary.EphemeralRootCount)
	}
}
