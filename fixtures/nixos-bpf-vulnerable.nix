# Production NixOS host configuration with unhardened kernel parameters and missing BPF LSM
{ config, lib, pkgs, ... }:

{
  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 0;
    "net.ipv4.ip_forward" = 1;
  };

  # Missing "bpf" in LSM chain
  security.lsm = [ "lockdown" "yama" "apparmor" ];

  systemd.services.legacy-node-agent = {
    description = "Legacy Unconfined Node Agent";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      # Missing SystemCallFilter and SystemCallArchitectures
    };
  };
}
