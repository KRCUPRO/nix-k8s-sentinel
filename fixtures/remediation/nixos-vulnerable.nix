# Production sample fixture representing an unhardened NixOS system configuration
# with unpinned flake dependencies, plaintext wireguard keys, and missing storage crypto.
{ config, lib, pkgs, ... }:

{
  # 1. Unpinned flake input without immutable narHash
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # 2. Plaintext WireGuard interface credentials in /nix/store (CVE-2026-31048)
  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.100.0.1/24" ];
    listenPort = 51820;
    privateKey = "4Kx9...PLAINTEXT_PRIVATE_KEY_EXPOSURE...8dY=";
    peers = [
      {
        publicKey = "xT39...PUBLIC_KEY_PEER...1aQ=";
        allowedIPs = [ "10.100.0.2/32" ];
        endpoint = "192.168.1.10:51820";
      }
    ];
  };

  # 3. Distributed storage without msgr2 cryptographic framing (CVE-2026-15509)
  services.ceph = {
    enable = true;
    monHosts = [ "192.168.1.20" ];
  };

  # 4. Detonation sandbox without Firecracker jailer confinement (CVE-2026-97105)
  microvm.vms.detonation = {
    vcpu = 4;
    mem = 4096;
    jailer.enable = false;
  };
}
