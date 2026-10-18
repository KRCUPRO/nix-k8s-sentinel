# Vulnerable NixOS Configuration with Mutable Root & Insecure Impermanence
# Used for nix-k8s-sentinel security audit verification

{ config, pkgs, lib, ... }:

{
  networking.hostName = "k8s-node-nixos-vuln-01";

  # 1. Insecure Mutable Root Filesystem on Persistent Ext4 Disk (Triggers IMP-ROOT-001)
  fileSystems."/" = {
    device = "/dev/sda1";
    fsType = "ext4";
  };

  # 2. Persistence on Unencrypted Storage Volume (Triggers IMP-ROOT-005)
  fileSystems."/persist" = {
    device = "/dev/sdb1";
    fsType = "ext4";
  };

  # 3. Unencrypted Swap Partition Active (Triggers IMP-ROOT-003 / CVE-2026-61842)
  swapDevices = [
    {
      device = "/dev/sda2";
    }
  ];

  # 4. Insecure Persistence Declarations with Loose Modes & Missing Machine-ID
  # (Triggers IMP-ROOT-004, IMP-ROOT-006, IMP-ROOT-008, IMP-ROOT-009)
  environment.persistence."/persist" = {
    hideMounts = false;
    directories = [
      "/var/log"
      {
        directory = "/var/lib/kubelet";
        mode = "0777";
      }
    ];
    files = [
      {
        file = "/etc/ssh/ssh_host_ed25519_key";
        mode = "0666";
      }
    ];
  };

  # 5. Missing Memory Scrubbing Boot Parameters (Triggers IMP-ROOT-012)
  boot.kernelParams = [ ];
}
