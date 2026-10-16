# Hardened NixOS MicroVM Module Specification (Production Reference)
{ config, pkgs, lib, ... }:

{
  microvm.vms.detonation-sandbox-01 = {
    hypervisor = "firecracker";
    vcpu = 2;
    mem = 2048;
    kvmDevice = "/dev/kvm";
    kernelPath = "${pkgs.linuxPackages_latest.kernel}/vmlinux";
    rootfsPath = "/var/lib/microvms/detonation-sandbox-01/rootfs.ext4";
    readOnly = true;
    isolateEgress = true;

    jailer = {
      enable = true;
      user = "firecracker";
      group = "firecracker";
      chrootPath = "/srv/jailer/firecracker/detonation-sandbox-01";
      cgroups = {
        cpu_weight = 50;
        memory_max = "2147483648"; # 2GiB hard ceiling
      };
    };

    interfaces = [
      {
        type = "tap";
        id = "vm-detonate0";
        mac = "02:fc:00:00:00:01";
        isolateEgress = true;
      }
    ];

    shares = [
      {
        tag = "nix-store-ro";
        source = "/nix/store";
        mountPoint = "/nix/store";
        readOnly = true;
      }
    ];
  };
}
