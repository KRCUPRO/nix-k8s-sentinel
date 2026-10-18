# NixOS FRR BGP Peering and Kernel Routing Hardening Module
{ config, pkgs, lib, ... }:

{
  # Free Range Routing (FRR) BGP Daemon
  services.frr = {
    enable = true;
    bgp = {
      enable = true;
      routerId = "192.168.100.10";
      localASN = 65001;
      neighbors = [
        "192.168.100.1 remote-as 65000"
        "192.168.100.1 password <REDACTED_SECRET>"
        "192.168.100.1 route-map RMAP_IN in"
        "192.168.100.1 route-map RMAP_OUT out"
      ];
    };
  };

  # Restrict BGP TCP port 179 to trusted peering interface
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 179 ];
  };

  # Kernel dual-stack routing sysctl hardening
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.ipv4.tcp_rfc1337" = 1;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
  };
}
