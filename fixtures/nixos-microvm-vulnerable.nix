# Vulnerable NixOS MicroVM Module Specification (Test Fixture)
{ config, pkgs, lib, ... }:

{
  microvm.vms.unhardened-sandbox-01 = {
    hypervisor = "firecracker";
    vcpu = 4;
    mem = 4096;
    kvmDevice = "none"; # Missing hardware KVM acceleration
    kernelPath = "/boot/vmlinux";
    rootfsPath = "/var/lib/microvms/unhardened/rootfs.ext4";
    readOnly = false;   # Writable rootfs - vulnerable to tampering
    isolateEgress = false; # Unisolated network egress - vulnerable to C2

    jailer = {
      enable = false;  # Missing jailer isolation
    };

    interfaces = [
      {
        type = "tap";
        id = "vm-public0";
        mac = "02:fc:00:00:00:99";
        isolateEgress = false;
      }
    ];
  };
}
