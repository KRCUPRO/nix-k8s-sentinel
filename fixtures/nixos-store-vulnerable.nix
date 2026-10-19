{ config, lib, pkgs, ... }:

{
  # Insecure / Vulnerable NixOS Nix Store Configuration
  # Demonstrates anti-patterns exposing multi-tenant clusters to CVE-2026-81930
  nix.settings = {
    # VIOLATION NIX-STORE-001: Allows unsigned substitutes
    require-sigs = false;

    # VIOLATION NIX-STORE-002: Malformed or unverified public key format
    trusted-public-keys = [
      "invalid-key-format-without-base64"
    ];

    # VIOLATION NIX-STORE-003: Plaintext HTTP substituters vulnerable to MITM
    substituters = [
      "http://untrusted-mirror.local:8080"
    ];

    # VIOLATION NIX-STORE-004: Wildcard trusted-users allows any local tenant to inject substituters
    trusted-users = [ "*" ];

    # VIOLATION NIX-STORE-005: Sandboxing disabled and fallback enabled
    sandbox = false;
    sandbox-fallback = true;

    # VIOLATION NIX-STORE-006: Impure evaluation and accept untrusted flake configs
    pure-eval = false;
    accept-flake-config = true;

    # VIOLATION NIX-STORE-008: Leaking credentials in world-readable store path
    netrc-file = "/nix/store/abc123-credentials/netrc";
  };

  # VIOLATION NIX-STORE-012: GC explicitly disabled
  nix.gc = {
    automatic = false;
  };
}
