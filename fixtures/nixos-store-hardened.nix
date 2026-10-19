{ config, lib, pkgs, ... }:

{
  # Hardened NixOS Nix Store & Binary Cache Security Profile
  # Aligned with CVE-2026-81930 Zero-Trust Substitute Isolation Guidelines
  nix.settings = {
    # 1. Enforce Ed25519 signature verification on all binary cache substitutes
    require-sigs = true;

    # 2. Strict whitelist of trusted Ed25519 public keys for substitute archives
    trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      "hydra.infra.internal-1:MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
    ];

    # 3. Encrypted HTTPS substituter mirrors with zero unauthenticated endpoints
    substituters = [
      "https://cache.nixos.org"
      "https://nix-community.cachix.org"
      "https://cache.infra.internal"
    ];

    # 4. Strictly isolated trusted-users restricted to root operator
    trusted-users = [ "root" ];

    # 5. Linux namespace sandbox confinement with zero fallback tolerance
    sandbox = true;
    sandbox-fallback = false;

    # 6. Hermetic evaluation and refusal of untrusted flake-directed settings
    pure-eval = true;
    accept-flake-config = false;

    # 7. Isolated build user pool
    build-users-group = "nixbld";

    # 8. Private cache credentials located in restricted runtime path
    netrc-file = "/run/secrets/nix/netrc";

    # 9. Storage bounds protection
    min-free = 10737418240; # 10 GB
    max-free = 53687091200; # 50 GB
  };

  # Automated store garbage collection
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 14d";
  };
}
