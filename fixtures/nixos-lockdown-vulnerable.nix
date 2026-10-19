# Vulnerable NixOS Host Configuration Missing Kernel Lockdown & Secure Boot
{ config, lib, pkgs, ... }:

{
  networking.hostName = "nixos-k8s-vulnerable-node-02";

  # VULNERABILITY 1: Kernel Lockdown Mode explicitly disabled
  security.lockdown = "none";
  security.protectKernelImage = false;

  # VULNERABILITY 2: Unsigned modules permitted in boot params
  boot.kernelParams = [
    "lockdown=none"
    "module.sig_enforce=0"
  ];

  # VULNERABILITY 3: Dynamic module loading enabled and devmem unconfined
  boot.kernel.sysctl = {
    "kernel.modules_disabled" = 0;
  };

  # VULNERABILITY 4: Insecure legacy bootloader without Lanzaboote or Secure Boot
  boot.loader.grub = {
    enable = true;
    efiSupport = true;
    device = "nodev";
  };
  boot.loader.secureboot.enable = false;
  boot.lanzaboote.enable = false;

  # Declared outdated bootloader binary
  bootloader.efi = "/boot/EFI/BOOT/shimx64.efi c026859345ee3a652cc596fc7c4ab59f77e20b33c16262bf6a992e5954a1be2e";
}
