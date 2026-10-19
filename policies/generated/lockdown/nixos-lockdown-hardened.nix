# Hardened Linux Kernel Lockdown & Lanzaboote UEFI Secure Boot Module
# Generated automatically by nix-k8s-sentinel security synthesizer.
{
  config,
  lib,
  pkgs,
  ...
}:

{
  # 1. Enforce Kernel Lockdown Mode (Confidentiality)
  # Restricts both ring 0 code modification and unprivileged physical/kernel memory extraction.
  security.lockdown = "confidentiality";
  security.protectKernelImage = true;

  # 2. Strict Kernel Boot Command Line Parameters
  boot.kernelParams = [
    "lockdown=confidentiality"
    "module.sig_enforce=1"
    "page_poison=1"
    "init_on_free=1"
    "slab_nomerge"
    "slub_debug=FZP"
  ];

  # 3. Kernel Sysctl Runtime Confinement
  # Disable dynamic module loading and block unsigned kexec payloads after boot initialization.
  boot.kernel.sysctl = {
    "kernel.modules_disabled" = 1;
    "kernel.kexec_load_disabled" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.core.bpf_jit_harden" = 2;
    "dev.mem.restricted" = 1;
  };

  # 4. Lanzaboote UEFI Secure Boot with Unified Kernel Image (UKI)
  # Signs both kernel, initrd, and bootloader into an atomic cryptographic artifact.
  boot.loader.systemd-boot.enable = lib.mkForce false;
  boot.lanzaboote = {
    enable = true;
    pkiBundle = "/etc/secureboot";
  };

  # 5. Security Auditing & DBX Sync Tools
  environment.systemPackages = with pkgs; [
    sbctl
    mokutil
    efibootmgr
    fwupd
  ];
}
