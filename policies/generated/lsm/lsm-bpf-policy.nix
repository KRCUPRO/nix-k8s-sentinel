# Automatically synthesized by nix-k8s-sentinel (v0.21.0)
# Declarative eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control
{
  boot.kernelParams = [
    "lsm=lockdown,yama,bpf,apparmor"
  ];

  security.lsm = [ "lockdown" "yama" "bpf" "apparmor" ];

  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
  };

  # Systemd eBPF LSM Mandatory Access Control Manager
  systemd.services.ebpf-lsm-mac = {
    description = "eBPF LSM Container Mandatory Access Control Daemon";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" "cgroup.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "/run/current-system/sw/bin/sentinel-lsm-loader --cgroup-root=/sys/fs/cgroup/kubepods.slice";
      Restart = "always";
      RestartSec = 3;
      ProtectSystem = "strict";
      ProtectHome = true;
      CapabilityBoundingSet = [ "CAP_SYS_ADMIN" "CAP_BPF" "CAP_DAC_READ_SEARCH" ];
    };
  };
}
