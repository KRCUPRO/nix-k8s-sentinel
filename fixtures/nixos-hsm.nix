# NixOS Hardware Security Module (HSM) & AWS Nitro Enclaves Host Configuration
{ config, pkgs, ... }:

{
  # 1. PKCS#11 Provider & Cryptographic Tooling
  services.p11-kit.enable = true;
  security.pam.p11.enable = true;

  environment.systemPackages = with pkgs; [
    opensc
    p11-kit
    gnutls
    aws-nitro-enclaves-cli
  ];

  # 2. AWS Nitro Enclaves Isolation & Daemon Configuration
  hardware.nitro-enclaves = {
    enable = true;
    allocator = {
      enable = true;
      memoryMiB = 4096;
      cpuCount = 2;
    };
  };

  # 3. Dedicated KMS v2 Plugin Unix Domain Socket Directory
  systemd.tmpfiles.rules = [
    "d /var/run/kmsplugin 0750 root root -"
  ];

  # 4. Declarative Master Key URI Reference (Secured with pin-source file)
  environment.etc."kubernetes/kms/pkcs11-uri.conf".text = ''
    pkcs11:model=HSM3000;manufacturer=NitroSec;token=k8s-root;object=kek-master;cipher=AES-GCM-256;pin-source=/etc/kubernetes/kms/pin.secret
  '';
}
