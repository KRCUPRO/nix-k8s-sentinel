# Production-like NixOS Declarative WireGuard Mesh Configuration
# Audited by nix-k8s-sentinel (Rules WG-MESH-001..012)
{ config, pkgs, ... }:

{
  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.100.0.1/24" ];
    listenPort = 51820;
    # Secure runtime private key reference
    privateKeyFile = "/run/keys/wg0.key";
    mtu = 1420;

    peers = [
      # Peer 1: Control-plane primary peer (Fully compliant with PSK and strict CIDR)
      {
        publicKey = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
        presharedKeyFile = "/run/keys/wg0-control-01.psk";
        allowedIPs = [ "10.100.0.10/32" ];
        endpoint = "198.51.100.10:51820";
        persistentKeepalive = 25;
      }
      # Peer 2: Worker node with missing PSK and permissive allowedIPs
      {
        publicKey = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
        allowedIPs = [ "0.0.0.0/0" "10.100.0.20/32" ];
        endpoint = "198.51.100.20:51820";
        persistentKeepalive = 25;
      }
      # Peer 3: Insecure peer hardcoding plaintext pre-shared key
      {
        publicKey = "MDExMjIzMzQ0NTU2Njc3ODg5OWFhYmJjY2RkZWVmZmc=";
        presharedKey = "unencrypted-psk-token-leaking-in-nix-store";
        allowedIPs = [ "10.100.0.30/32" ];
        endpoint = "198.51.100.30:51820";
        persistentKeepalive = 25;
      }
    ];
  };

  # Legacy unhardened interface demonstrating world-readable private key
  networking.wireguard.interfaces.wg-legacy = {
    ips = [ "10.200.0.1/24" ];
    listenPort = 51821;
    privateKey = "super-secret-unencrypted-private-key-in-store";
    mtu = 1500; # Sub-optimal MTU triggering PMTUD fragmentation

    peers = [
      {
        publicKey = "WFlaMDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg=";
        allowedIPs = [ "10.200.0.10/32" ];
        endpoint = "203.0.113.50:51821";
      }
    ];
  };
}
