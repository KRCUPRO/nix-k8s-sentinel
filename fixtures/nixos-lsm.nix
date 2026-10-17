# Hardened NixOS Host Configuration with active eBPF LSM and Kernel MAC
{ config, pkgs, ... }:

{
  boot.kernelParams = [
    "lsm=lockdown,yama,bpf,apparmor"
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
  ];

  security.lsm = [ "lockdown" "yama" "bpf" "apparmor" ];

  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
    "fs.protected_regular" = 2;
    "fs.protected_fifos" = 2;
  };

  systemd.services.ebpf-lsm-mac = {
    description = "eBPF LSM Container Mandatory Access Control Daemon";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" "cgroup.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.sentinel-lsm-loader}/bin/sentinel-lsm-loader --cgroup-root=/sys/fs/cgroup/kubepods.slice";
      Restart = "always";
      RestartSec = 3;
      ProtectSystem = "strict";
      ProtectHome = true;
      CapabilityBoundingSet = [ "CAP_SYS_ADMIN" "CAP_BPF" "CAP_DAC_READ_SEARCH" ];
    };
  };
}
