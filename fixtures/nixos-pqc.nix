# Production-like NixOS Post-Quantum Cryptography & CNSA 2.0 Hardened Configuration
{ config, pkgs, lib, ... }:

{
  security.pki.certificateFiles = [ ];

  # System-wide OpenSSL 3.4+ Post-Quantum Configuration
  environment.etc."ssl/openssl.cnf".text = ''
    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect
    ssl_conf = ssl_module

    [provider_sect]
    default = default_sect
    oqsprovider = oqsprovider_sect

    [default_sect]
    activate = 1

    [oqsprovider_sect]
    activate = 1

    [ssl_module]
    system_default = ssl_configuration

    [ssl_configuration]
    MinProtocol = TLSv1.3
    CipherSuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    Groups = X25519MLKEM768:SecP384r1MLKEM1024
  '';

  # System-wide GnuTLS Quantum-Safe Configuration
  networking.gnutls.priority = "@SYSTEM:!VERS-ALL:+VERS-TLS1.3:+GROUP-X25519-KYBER768:+GROUP-SECP384R1-MLKEM1024";
}
