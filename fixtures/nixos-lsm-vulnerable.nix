# Vulnerable NixOS Host Configuration missing eBPF LSM and unconfined BPF
{ config, pkgs, ... }:

{
  boot.kernelParams = [
    "lsm=lockdown,yama"
  ];

  # Missing "bpf" in security.lsm
  security.lsm = [ "lockdown" "yama" ];

  # Insecure unprivileged BPF enabled
  boot.kernel.sysctl = {
    "kernel.unprivileged_bpf_disabled" = 0;
  };
}
