# Declarative Automated UEFI Secure Boot DBX Revocation Sync Service
# Generated automatically by nix-k8s-sentinel security synthesizer.
{
  config,
  lib,
  pkgs,
  ...
}:

{
  systemd.services.uefi-dbx-sync = {
    description = "Automated UEFI Secure Boot DBX Revocation Sync";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.fwupd}/bin/fwupdtool security --force";
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      NoNewPrivileges = true;
    };
  };

  systemd.timers.uefi-dbx-sync = {
    description = "Weekly UEFI Secure Boot DBX Revocation Sync Timer";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "weekly";
      Persistent = true;
    };
  };
}
