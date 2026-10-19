# Hardened NixOS Host Configuration with Kernel Lockdown & Lanzaboote UEFI Secure Boot
{ config, lib, pkgs, ... }:

{
  networking.hostName = "nixos-k8s-hardened-node-01";

  # 1. Mandatory Kernel Lockdown Mode (Confidentiality)
  # Blocks unsigned modules, kexec payloads, raw I/O, and unprivileged kernel memory inspection
  security.lockdown = "confidentiality";
  security.protectKernelImage = true;

  # 2. Kernel Command Line Parameters
  boot.kernelParams = [
    "lockdown=confidentiality"
    "module.sig_enforce=1"
    "page_poison=1"
    "init_on_free=1"
    "slab_nomerge"
    "slub_debug=FZP"
  ];

  # 3. Restrict Dynamic Modules and Kernel Access
  boot.kernel.sysctl = {
    "kernel.modules_disabled" = 1;
    "kernel.kexec_load_disabled" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.core.bpf_jit_harden" = 2;
    "dev.mem.restricted" = 1;
  };

  # 4. Lanzaboote UEFI Secure Boot (Unified Kernel Image)
  boot.loader.systemd-boot.enable = lib.mkForce false;
  boot.lanzaboote = {
    enable = true;
    pkiBundle = "/etc/secureboot";
  };
  security.secureBoot.enable = true;
  security.kexec.requireSignature = true;

  environment.systemPackages = with pkgs; [
    sbctl
    mokutil
    efibootmgr
    fwupd
  ];
}
