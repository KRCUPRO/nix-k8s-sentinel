# NixOS Measured Boot & Confidential Computing Configuration Sample Fixture
# Demonstrates production-hardened AMD SEV-SNP, Intel TDX, TPM 2.0, and UKI settings.
{ config, pkgs, lib, ... }:

{
  # 1. Systemd-Boot & Measured Bootloader Integration
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.initrd.systemd.enable = true;

  # 2. Lanzaboote Secure Boot & Unified Kernel Image (UKI)
  boot.lanzaboote = {
    enable = true;
    pkiBundle = "/etc/secureboot";
  };

  # 3. Hardware TPM 2.0 Security Module & PKCS#11 Provider
  security.tpm2 = {
    enable = true;
    pkcs11.enable = true;
    tctiEnvironment.enable = true;
  };

  # 4. Strict Binary Cache Signing Public Keys
  nix.settings.trusted-public-keys = [
    "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    "sentinel-cluster-attest:9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B="
  ];

  # 5. Confidential Computing Hardware Enclave Kernel Parameters
  boot.kernelParams = [
    # AMD SEV-SNP Memory Encryption & IOMMU Protection
    "mem_encrypt=on"
    "kvm_amd.sev=1"
    "amd_iommu=on"

    # Intel Trust Domain Extensions (TDX)
    "intel_iommu=on"
    "kvm_intel.tdx=1"

    # Kernel Self-Protection & ASLR immutability
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
    "page_alloc.shuffle=1"
  ];
}
