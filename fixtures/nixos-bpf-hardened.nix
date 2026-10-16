# Production NixOS host configuration with hardened kernel parameters, eBPF LSM, and systemd seccomp
{ config, lib, pkgs, ... }:

{
  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.kptr_restrict" = 2;
  };

  # Active eBPF LSM attached in security.lsm
  security.lsm = [ "lockdown" "yama" "bpf" "apparmor" ];

  systemd.services.hardened-node-agent = {
    description = "Hardened Sentinel Node Agent";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      SystemCallFilter = [
        "@system-service"
        "~@privileged"
        "~@resources"
        "~@reboot"
        "~@module"
        "~@raw-io"
      ];
      SystemCallArchitectures = "native";
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
    };
  };
}
