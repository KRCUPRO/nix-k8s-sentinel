<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <strong>🇩🇪 Deutsch</strong> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Deklarativer Schwachstellenscanner & Echtzeit-Bedrohungsaufklärungsradar für NixOS & Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Überblick

`nix-k8s-sentinel` ist eine deklarative Schwachstellenanalyse-, autonome Behebungs- und kontinuierliche Bedrohungsaufklärungs-Engine, die speziell für Bare-Metal-NixOS-Cluster und Kubernetes-Produktionsinfrastrukturen entwickelt wurde.

Im Gegensatz zu herkömmlichen Scannern, die ephemere Containerschichten erst nach dem Deployment passiv prüfen, auditiert `nix-k8s-sentinel` die zugrunde liegenden deklarativen Definitionen vor dem Workload-Scheduling und korreliert Manifeste sowie Kernel-Telemetrie in Echtzeit mit normalisierten CVSS-Bedrohungs-Feeds.

### 🎯 Fünf zentrale Verteidigungssäulen

1. **Bare-Metal- & Kernel-Härtung**: Linux-Kernel-Lockdown, UEFI-DBX-Widerrufsprüfung, Mandatory Access Control (MAC) mit eBPF LSM und gemessener Systemstart mit hardwarebasierter Vertrauensanker (Root of Trust).
2. **Cluster-Netzwerk & Service-Mesh-Verteidigung**: Erkennung von DNS-Exfiltration und eBPF-Socket-Flows mittels Shannon-Entropie, Cilium Dual-Stack-BGP-Peering, WireGuard-Kernel-Fast-Path und Gateway-API-Routensicherheit.
3. **Kryptografie & Confidential Computing**: Post-Quanten-Kryptografie (NSA CNSA 2.0), SPIFFE/SPIRE-Workload-Attestierung, vertrauliche VM-Remote-Attestierung (AMD SEV-SNP / Intel TDX) und HSM/KMS v2-Umschlagverschlüsselung.
4. **Deklarative Lieferkette & Unveränderlicher Speicher**: In-Toto SLSA Level 3 SBOM-Herkunftsnachweise, Ed25519-Signaturen für den Nix-Store und zustandslose NixOS-Root-Validierung mit Impermanence.
5. **Dynamische Admission & Autonome Behebung**: Fail-Closed Admission-Webhooks, MicroVM-Köder-Detonation in ephemeren Sandboxes und automatisierte GitOps-PR-Synthese mit Canary-Validierung.

---

## 🏛️ Kernfunktionen

### 1. 🛡️ Kernel-Sicherheit & Host-Härtung

- **Linux-Kernel-Lockdown & UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *Audits*: Lockdown-Modi (`integrity`/`confidentiality`), unsignierte Kernelmodule (`module.sig_enforce`), `/dev/mem`-Zugriffe und Lanzaboote-Deklarationen.
  - *Mitigations*: Verhindert willkürliche Ring-0-Rechteausweitungen (`CVE-2026-92814`) und blockiert widerrufene Bootloader aus der UEFI-DBX-Datenbank (`CVE-2023-40547`).
  - *Synthese*: Gehärtete NixOS-Module (`nixos-lockdown-hardened.nix`), systemd-DBX-Aktualisierungsdienste und Prometheus-Alerts (`--lockdown`).
- **eBPF LSM-Sicherheitsmodul & Mandatory Access Control (MAC)**
  - *Audits*: Kernel-LSM-Parameter (`security.lsm = ["bpf"]`) und Container-Sicherheitskontexte (`bprm_check_security`, `file_open`, `socket_create`).
  - *Mitigations*: Blockiert privilegierte Container-Ausbrüche unter Umgehung von seccomp (`CVE-2026-99103`) und unbefugte Manipulationen an BPF-Maps.
  - *Synthese*: Deklarative NixOS-Module, verifizierbare C-eBPF-Programme und Kubernetes-CRDs `ContainerMACProfile` (`--lsm`).
- **Dynamischer Kernel-Bedrohungsprofiler & Syscall-BPF-Filter**
  - *Audits*: Deklarative Seccomp-Profile, unbeschränkte Container und kritische administrative Systemaufrufe (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *Mitigations*: Erkennt Socket-Stürme (> 250 Sockets/s) und Raw-Socket-Allokationen im Zusammenhang mit `CVE-2026-90412`.
  - *Synthese*: Least-Privilege-Seccomp-Profile und systemd-Isolationsmodule für NixOS (`--bpf`).
- **CIS-Kubernetes-Benchmark & Bare-Metal-Sonden**
  - *Audits*: Parameter der Control-Plane-systemd-Units, Kubelet-Optionen und Worker-Knoten-Socket/Syscall-Telemetrie.
  - *Synthese*: Automatisierte Behebungspatches für NixOS-Hosts und knotenübergreifende Sondensynchronisation (`--cis`, `--probe`).

### 2. 🌐 Cluster-Netzwerk & Service-Mesh-Verteidigung

- **eBPF-Netzwerkfluss-Profiler & DNS-Exfiltrationsradar (`FLOW-RADAR-001..012`)**
  - *Audits*: `CiliumNetworkPolicy`-Manifeste, NixOS-Host-Profiler und eBPF-Telemetrie von Socket-Verbindungen und DNS-Abfragen.
  - *Mitigations*: Fängt uneingeschränkten ausgehenden Datenverkehr auf Port 53 ab (`CVE-2026-10392`), blockiert DNS-Tunnel mit hoher Shannon-Entropie ($H > 4.2$), DGA-Bursts und Verbindungsspitzen (> 500 Verb./s).
  - *Synthese*: Gehärtete `CiliumNetworkPolicy`-Ressourcen (L7-DNS-Proxy mit FQDN-Regex) und Prometheus-Alerting-Regeln (`--flow`).
- **Cilium BGP-Peering & Dual-Stack IPv6-Radar (`BGP-RADAR-001..012`)**
  - *Audits*: Cilium-BGP-Peering-Richtlinien, LoadBalancer-IP-Pools und NixOS-FRR-BGP-Konfigurationen.
  - *Mitigations*: Erkennt fehlende TCP-MD5- / RFC 2385-Authentifizierung (`CVE-2026-70192`), Route-Leaks und Prefix-Flapping.
  - *Synthese*: Gehärtete Cilium-BGP-Manifeste, NixOS-FRR-Module und Prometheus-Regeln (`--bgp`).
- **WireGuard-Kernel-Fast-Path mit eBPF & Krypto-Beschleunigung (`WG-FAST-001..012`)**
  - *Audits*: SIMD-Vektorbeschleunigung für ChaCha20-Poly1305 (AVX-512, ARM Neon), native eBPF/XDP-Hooks und 100GbE-Overlays.
  - *Mitigations*: Erkennt Rückfall auf skalare Krypto-Routinen, SoftIRQ-Sättigung (> 70%) und Ringpuffer-Überläufe (`CVE-2026-31049`).
  - *Synthese*: Gehärtete NixOS-Fast-Path-Module und verifizierte eBPF-XDP-C-Programme (`--wg-fastpath`).
- **Bedrohungsradar für Kubernetes Ingress, Gateway API & EnvoyFilter**
  - *Audits*: `Gateway`-, `HTTPRoute`-, `GRPCRoute`-, `ReferenceGrant`-Ressourcen und Istio-`EnvoyFilter`-Regeln.
  - *Mitigations*: Blockiert Snippet-Injektionen (`CVE-2023-5044`), namespace-übergreifendes Routing-Hijacking (`CVE-2026-44219`), willkürliche Lua-Skripte und Path-Traversal-Angriffe (`--gw`, `--k8s`).

### 3. 🔐 Kryptografie, Confidential Computing & Identitätsverwaltung

- **Post-Quanten-Kryptografie (PQC) & NSA CNSA 2.0-Übergang**
  - *Audits*: Control-Plane-TLS-Parameter, Aktivierung des NixOS-OpenSSL-Providers `oqsprovider` und GnuTLS-Prioritäten.
  - *Mitigations*: Schützt vor rückwirkenden Entschlüsselungsangriffen (Harvest Now, Decrypt Later - HNDL) (`CVE-2026-94301`).
  - *Synthese*: Hybride ML-KEM/Kyber-TLS-Deklarationen und Einhaltung der CNSA 2.0-Meilensteine (`--pqc`).
- **Attestierung vertraulicher virtueller Maschinen für WireGuard (`WG-ENC-001..012`)**
  - *Audits*: AMD SEV-SNP VCEK-Zertifikatsketten, Intel TDX-Quotes und gemessene Boot-PCR-Digests.
  - *Mitigations*: Bindet ephemere Sitzungsschlüssel an Enklavenberichte und weist manipulierte oder unbestätigte Tunnel ab (`CVE-2026-40291`).
  - *Synthese*: Gehärtete NixOS-Module und Pre-Handshake-Validierungsskripte (`--wg-enclave`).
- **Zero-Trust-Mikrosegmentierung & SPIFFE/SPIRE-Attestierung**
  - *Audits*: RFC-konforme SPIFFE-IDs, obligatorischer Cilium-mTLS-Modus und SVID-Gültigkeitszeitfenster.
  - *Mitigations*: Beseitigt gefährliche Wildcard-Selektoren (`k8s:ns:*`) und verhindert Ausfälle durch Zertifikatsdesynchronisation (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **Hardware-Sicherheitsmodule (HSM) & PKCS#11-Umschlagverschlüsselung**
  - *Audits*: `EncryptionConfiguration`-Dateien für etcd, KMS v2-Plugins und AWS Nitro Enclaves (`CVE-2026-83190`) (`--hsm`).
- **Multi-Cluster-Flottensynchronisation & OIDC-Token-Radar**
  - *Audits*: Mandantenfähige RBAC-Berechtigungen, föderierte OIDC-Signaturalgorithmen und GitOps-Drifts mit ArgoCD/Flux (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 Deklarative Lieferkette & Unveränderlicher Speicher

- **Mandantenfähige Nix-Store-Isolation & Binärcache-Sicherheit (`NIX-STORE-001..012`)**
  - *Audits*: Nix-Daemon-Parameter (`nix.settings.*`, `nix.conf`), Ed25519-Signaturprüfungen und Substituter-Telemetrie.
  - *Mitigations*: Verhindert Cache-Poisoning durch unsignierte Substitute (`CVE-2026-81930`), unverschlüsselte HTTP-Streams und Sandbox-Ausbrüche.
  - *Synthese*: Gehärtete NixOS-Module, `/etc/nix/nix.conf`-Vorlagen und Prometheus-Alerts (`--nixstore`).
- **Unveränderliche NixOS-Root & Impermanence-Ephemerspeicher (`IMP-ROOT-001..012`)**
  - *Audits*: Impermanence-Deklarationen (`environment.persistence`) und `hostPath`-Cluster-Mounts.
  - *Mitigations*: Erzwingt eine `tmpfs`-Root im Arbeitsspeicher, erkennt hostPath-Lecks ins flüchtige Dateisystem (`CVE-2026-61842`) und blockiert unverschlüsseltes Swap.
  - *Synthese*: Gehärtete Impermanence-Module, initrd-Bereinigungshooks beim Systemstart und Speicherplatzüberwachung (`--impermanence`).
- **Software-Stücklisten (SBOM) & In-Toto SLSA Level 3-Attestierung**
  - *Audits*: SPDX v3.0- und CycloneDX v1.6-Dokumente sowie Nix-Closures abgeglichen mit kryptografischen In-Toto-Attestierungen.
  - *Mitigations*: Erkennt Manipulationen an Artefakten (`CVE-2026-71044`) und deckt Versionsabweichungen in Produktions-Deployments auf (`--sbom`).

### 5. 🤖 Workload-Admission, Notfallwiederherstellung & Autonome Behebung

- **Radar für dynamische Admission-Webhooks & CA-Rotation (`WH-RADAR-001..012`)**
  - *Audits*: `ValidatingWebhookConfiguration`-, `MutatingWebhookConfiguration`-Manifeste und Ablaufdaten von X.509-CA-Zertifikaten.
  - *Mitigations*: Verhindert riskante `failurePolicy: Ignore`-Bypass-Konfigurationen (`CVE-2026-52194`), Timeout-Verzögerungen (> 3s) und Boot-Deadlocks.
  - *Synthese*: Ausfallsichere Webhooks, automatisierte cert-manager-Ressourcen und Latenz-Monitoring (`--webhook`).
- **CephFS-Snapshot-Orchestrierung & Georedundante Disaster Recovery (`CEPH-DR-001..012`)**
  - *Audits*: CephFS-Snapshot-Zeitpläne, CSI-Volume-Replikationsklassen und regionenübergreifende Delta-Synchronisation.
  - *Mitigations*: Blockiert zerstörerische Löschrichtlinien für das RPO (`deletionPolicy: Delete`) und Split-Brain-Zustände (`CVE-2026-10140`).
  - *Synthese*: Gehärtete Snapshot-Klassen, verschlüsselte Replikation und Anti-Affinitätsregeln für Mirror-Daemons (`--dr`).
- **Ephemere MicroVM-Sandbox & Honeypot-Köderdetonation**
  - *Audits*: Firecracker-MicroVM-Isolation, Jailer-Parameter und simulierte Kubelet/etcd-Täuschungsziele.
  - *Mitigations*: Isoliert verdächtige Container in Quarantäne und erkennt MMIO-Hypervisor-Ausbrüche (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **Autonome Behebung & GitOps-Pull-Request-Generator**
  - *Funktionsweise*: Vorabprüfung durch Canary-Validierung (`pkg/remediate/canary.go`), reine Nix-Flake-Evaluation und Dry-Run-Tests via `kubectl kustomize`.
  - *Artefakte*: Atomare, unterbrechungsfreie PRs (`remediation/*`), strategische Kustomize-Patches und RFC 6902 JSONPatches (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 Schnellstart

### Voraussetzungen
- Lokale Go 1.22+-Installation.

### Kompilierung und Ausführung
```bash
# Repository klonen
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Tests ausführen
go test ./...

# Live-Bedrohungsfeed prüfen
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# flake.lock-Abhängigkeiten auf Sicherheitshinweise prüfen
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Kubernetes-Manifeste auf Ingress- und CNI-Fehlkonfigurationen prüfen
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# CiliumNetworkPolicy und NixOS-eBPF-Flussprofiler prüfen
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# eBPF-Flusstelemetrie abgleichen und gehärtete Richtlinien generieren
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Linux-Kernel-Lockdown und UEFI Secure Boot DBX auditieren
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# Nix-Store-Isolation und Binärcaches auditieren
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# Unveränderliche NixOS-Root und hostPath-Mounts auditieren
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Dynamische Kubernetes-Admission-Webhooks auditieren
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# Vertrauliche VM-WireGuard-Attestierung (SEV-SNP / TDX) auditieren
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# WireGuard-Kernel-Fast-Path und kryptografische Vektorisierung auditieren
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Cilium BGP-Peering-Richtlinien und FRR-Deklarationen auditieren
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# Bare-Metal-eBPF-Telemetrieanalyse über das gesamte Cluster ausführen
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# Ergebnisse im OASIS SARIF v2.1.0-Format für GitHub Code Scanning exportieren
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Vollständigen Audit-Bericht im JSON-Format generieren
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Automatisiertes stündliches Sicherheits-Briefing erstellen
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ Roadmap & Kontinuierliche Weiterentwicklung

Weitere Details zur aktiven Roadmap und anstehenden Entwicklungsmeilensteinen finden Sie in [ROADMAP.md](../../ROADMAP.md).

---

## 🔒 Sicherheitsrichtlinie

Informationen zur Meldung von Sicherheitslücken und unseren Sicherheitsrichtlinien finden Sie in [SECURITY.md](../../SECURITY.md).
