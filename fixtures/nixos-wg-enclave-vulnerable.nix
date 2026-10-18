# Vulnerable NixOS WireGuard Configuration
# Violates WG-ENC-001, WG-ENC-004, WG-ENC-005, WG-ENC-006, WG-ENC-010
{ config, pkgs, lib, ... }:

{
  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.100.0.1/24" ];
    listenPort = 51820;

    peers = [
      {
        # peer: unverified-plain-peer
        publicKey = "VU5WRVJJRklFRFBMQUlOVEVYVFdJUkVHVUFSRFBFRVI=";
        endpoint = "192.168.10.200:51820";
        allowedIPs = [ "10.100.0.200/32" ];
        # Missing enclave attestation configuration (WG-ENC-001)
      },
      {
        # peer: debug-enabled-sev-peer
        publicKey = "REVJVTNFTlZNT0RFREVCR0FMTFBPV0VETk9ERTEyM0E=";
        endpoint = "192.168.10.201:51820";
        allowedIPs = [ "10.100.0.201/32" ];

        enclave = {
          platform = "AMD_SEV_SNP";
          minTcbSvn = 1; # Outdated TCB SVN (WG-ENC-010)
          requireHardwareRoot = true;
          requireSessionKeyBinding = false; # Missing session key binding (WG-ENC-005)
          allowDebug = true; # Hypervisor memory debug enabled (WG-ENC-006)
          # Missing declarative golden PCR reference values (WG-ENC-004)
        };
      }
    ];
  };
}
