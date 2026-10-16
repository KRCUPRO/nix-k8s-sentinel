# Production-like NixOS Legacy Cryptographic Configuration Lacking PQC
{ config, pkgs, lib, ... }:

{
  security.pki.certificateFiles = [ ];

  # Insecure OpenSSL configuration without OQS provider and with TLS 1.2
  environment.etc."ssl/openssl.cnf".text = ''
    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect
    ssl_conf = ssl_module

    [provider_sect]
    default = default_sect

    [default_sect]
    activate = 1

    [ssl_module]
    system_default = ssl_configuration

    [ssl_configuration]
    MinProtocol = TLSv1.2
    CipherSuites = TLS_AES_128_GCM_SHA256
    Groups = X25519:P-256
  '';

  # Legacy GnuTLS priority string
  networking.gnutls.priority = "@SYSTEM:!VERS-ALL:+VERS-TLS1.2";
}
