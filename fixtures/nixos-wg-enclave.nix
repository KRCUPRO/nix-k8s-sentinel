# Declarative Hardened NixOS WireGuard Enclave Peer Configuration
# Production reference for Confidential VM attestation in AMD SEV-SNP and Intel TDX
{ config, pkgs, lib, ... }:

{
  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.100.0.1/24" ];
    listenPort = 51820;

    peers = [
      {
        # peer: worker-sev-snp-01
        publicKey = "K3vL8zP8sY4w8Qv8K3vL8zP8sY4w8Qv8K3vL8zP8sY4=";
        endpoint = "192.168.10.101:51820";
        allowedIPs = [ "10.100.0.101/32" ];
        persistentKeepalive = 25;

        enclave = {
          platform = "AMD_SEV_SNP";
          minTcbSvn = 4;
          requireHardwareRoot = true;
          requireSessionKeyBinding = true;
          allowDebug = false;
          maxAttestationAgeSec = 3600;
          goldenImageDigest = "sha256:4a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b";
          pcrs."0" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
          pcrs."2" = "c24f6e4a8b1c9d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e";
          pcrs."4" = "b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
          pcrs."7" = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5";
        };
      },
      {
        # peer: worker-tdx-02
        publicKey = "TDXk8zP8sY4w8Qv8K3vL8zP8sY4w8Qv8K3vL8zP8sTD=";
        endpoint = "192.168.10.102:51820";
        allowedIPs = [ "10.100.0.102/32" ];
        persistentKeepalive = 25;

        enclave = {
          platform = "INTEL_TDX";
          minTcbSvn = 5;
          requireHardwareRoot = true;
          requireSessionKeyBinding = true;
          allowDebug = false;
          maxAttestationAgeSec = 3600;
          goldenImageDigest = "sha256:7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a";
          pcrs."0" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
          pcrs."2" = "c24f6e4a8b1c9d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e";
          pcrs."4" = "b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
          pcrs."7" = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5";
          rtmrs."0" = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
          rtmrs."1" = "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2";
        };
      }
    ];
  };
}
