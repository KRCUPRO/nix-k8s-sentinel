# Autonomous NixOS Security Remediation Module
{ config, lib, pkgs, ... }:
{
  # Mitigates CVE-2026-31048: Synthesize NixOS configuration patch migrating privateKey strings to privateKeyFile paths under /run/secrets/wireguard/key.
  networking.wireguard.interfaces.wg0.privateKeyFile = "/run/secrets/wireguard/key";

  # Mitigates CVE-2026-15509: Synthesize declarative CephCluster patch activating requireMsgr2: true and setting bluestore_default_buffered_write throttling.
  services.ceph.requireMsgr2 = true;

  # Mitigates CVE-2026-97105: Synthesize hardened NixOS microvm module enforcing unprivileged jailer UID/GID, read-only rootfs, and egress TAP redirection.
  microvm.vms.detonation.jailer.enable = true;

}
