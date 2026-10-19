<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <strong>🇫🇷 Français</strong> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Scanner de vulnérabilités déclaratif et radar de renseignement sur les menaces en temps réel pour NixOS & Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Vue d'Ensemble

`nix-k8s-sentinel` est un moteur d'analyse déclarative des vulnérabilités, de remédiation autonome et de synchronisation continue du renseignement sur les menaces, conçu spécifiquement pour les clusters bare-metal NixOS et les infrastructures de production Kubernetes.

Contrairement aux scanners traditionnels qui inspectent passivement les couches éphémères de conteneurs après déploiement, `nix-k8s-sentinel` audite les définitions déclaratives sous-jacentes avant l'ordonnancement des charges de travail, en corrélant les manifestes et la télémétrie du noyau avec des flux de menaces CVSS normalisés en temps réel.

### 🎯 Cinq Piliers de Défense Fondamentaux

1. **Durcissement Bare-Metal & Noyau**: Verrouillage du noyau Linux (Lockdown), vérification de la révocation UEFI DBX, contrôle d'accès obligatoire (MAC) avec eBPF LSM et démarrage mesuré avec racine de confiance matérielle.
2. **Réseau de Cluster & Maillage de Services**: Détection d'exfiltration DNS et de flux de sockets eBPF par entropie de Shannon, peering Cilium BGP double pile, fast-path noyau WireGuard et sécurité des routes Gateway API.
3. **Cryptographie & Informatique Confidentielle**: Cryptographie post-quantique (NSA CNSA 2.0), attestation de charge de travail SPIFFE/SPIRE, citations distantes sur VM confidentielles (AMD SEV-SNP / Intel TDX) et chiffrement d'enveloppe HSM/KMS v2.
4. **Chaîne d'Approvisionnement & Stockage Immuable**: Vérification de provenance SBOM In-Toto SLSA Niveau 3, signatures Ed25519 pour le magasin Nix et validation de la racine sans état NixOS avec impermanence.
5. **Admission Dynamique & Remédiation Autonome**: Webhooks d'admission à fermeture sécurisée (Fail-Closed), détonation de leurres en MicroVM éphémères et synthèse automatisée de PR GitOps avec validation canary.

---

## 🏛️ Fonctionnalités Principales

### 1. 🛡️ Sécurité du Noyau & Durcissement de l'Hôte

- **Verrouillage du Noyau Linux (Lockdown) et UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *Audits*: Modes de verrouillage (`integrity`/`confidentiality`), modules non signés (`module.sig_enforce`), accès à `/dev/mem` et déclarations Lanzaboote.
  - *Mitigations*: Prévient toute élévation ring-0 arbitraire (`CVE-2026-92814`) et bloque les chargeurs révoqués listés dans UEFI DBX (`CVE-2023-40547`).
  - *Synthèse*: Módules NixOS durcis (`nixos-lockdown-hardened.nix`), services systemd de mise à jour DBX et alertes Prometheus (`--lockdown`).
- **Module de Sécurité eBPF LSM et Contrôle d'Accès Obligatoire (MAC)**
  - *Audits*: Paramètres LSM du noyau (`security.lsm = ["bpf"]`) et contextes de sécurité des conteneurs (`bprm_check_security`, `file_open`, `socket_create`).
  - *Mitigations*: Bloque les évasions de conteneurs privilégiés contournant seccomp (`CVE-2026-99103`) et les manipulations illicites de tables BPF.
  - *Synthèse*: Modules NixOS déclaratifs, programmes C eBPF vérifiables et CRDs Kubernetes `ContainerMACProfile` (`--lsm`).
- **Profileur Dynamique des Menaces du Noyau et Filtre BPF de Syscalls**
  - *Audits*: Profils seccomp déclaratifs, conteneurs sans restriction et appels système administratifs critiques (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *Mitigations*: Détecte les tempêtes de sockets (> 250 sockets/s) et l'allocation de raw sockets associées à `CVE-2026-90412`.
  - *Synthèse*: Profils Seccomp de moindre privilège et modules d'isolation systemd pour NixOS (`--bpf`).
- **Benchmark CIS Kubernetes et Sondes Bare-Metal**
  - *Audits*: Paramètres des unités systemd du plan de contrôle, options Kubelet et télémétrie des sockets/syscalls sur les nœuds de travail.
  - *Synthèse*: Patchs de remédiation automatisés pour hôtes NixOS et agrégation de sondes multi-nœuds (`--cis`, `--probe`).

### 2. 🌐 Réseau de Cluster & Défense du Maillage de Services

- **Profileur de Flux Réseau eBPF et d'Exfiltration DNS (`FLOW-RADAR-001..012`)**
  - *Audits*: Manifestes `CiliumNetworkPolicy`, profileurs d'hôte NixOS et télémétrie eBPF des connexions sockets et requêtes DNS.
  - *Mitigations*: Intercepte le trafic sortant non restreint sur le port 53 (`CVE-2026-10392`), les tunnels DNS à haute entropie de Shannon ($H > 4.2$), les rafales DGA et les pics de connexion (> 500 conn/s).
  - *Synthèse*: Politiques `CiliumNetworkPolicy` renforcées (proxy DNS L7 avec regex FQDN) et alertes Prometheus associées (`--flow`).
- **Radar de Peering BGP Cilium et IPv6 Double Pile (`BGP-RADAR-001..012`)**
  - *Audits*: Politiques de peering BGP Cilium, pools IP d'équilibrage de charge et configurations BGP NixOS FRR.
  - *Mitigations*: Identifie l'absence d'authentification TCP MD5 / RFC 2385 (`CVE-2026-70192`), les fuites d'exportation de routes et le flapping de préfixes.
  - *Synthèse*: Manifestes Cilium BGP durcis, modules NixOS FRR et règles d'alerte Prometheus (`--bgp`).
- **Fast-Path Noyau WireGuard avec eBPF et Accélération Cryptographique (`WG-FAST-001..012`)**
  - *Audits*: Accélération vectorielle SIMD ChaCha20-Poly1305 (AVX-512, ARM Neon), points d'attache natifs eBPF/XDP et overlays 100GbE.
  - *Mitigations*: Détecte le repli vers la cryptographie scalaire, la saturation de softIRQ (> 70%) et le débordement de tampon (`CVE-2026-31049`).
  - *Synthèse*: Modules NixOS fast-path durcis et programmes C eBPF XDP vérifiés (`--wg-fastpath`).
- **Radar de Menaces sur Kubernetes Ingress, Gateway API et EnvoyFilter**
  - *Audits*: Ressources `Gateway`, `HTTPRoute`, `GRPCRoute`, `ReferenceGrant` et règles Istio `EnvoyFilter`.
  - *Mitigations*: Bloque les injections de snippets (`CVE-2023-5044`), le détournement de routes inter-namespaces (`CVE-2026-44219`), les scripts Lua arbitraires et les traversées de chemin (`--gw`, `--k8s`).

### 3. 🔐 Cryptographie, Informatique Confidentielle & Gestion des Identités

- **Cryptographie Post-Quantique (PQC) et Transition NSA CNSA 2.0**
  - *Audits*: Paramètres TLS du plan de contrôle, activation du fournisseur OpenSSL `oqsprovider` sous NixOS et priorités GnuTLS.
  - *Mitigations*: Protège contre les attaques de déchiffrement rétroactif post-quantique (HNDL) (`CVE-2026-94301`).
  - *Synthèse*: Déclarations TLS hybrides ML-KEM/Kyber et conformité aux jalons CNSA 2.0 (`--pqc`).
- **Attestation de VM Confidentielles pour WireGuard (`WG-ENC-001..012`)**
  - *Audits*: Chaînes de certificats AMD SEV-SNP VCEK, citations Intel TDX et digests PCR de démarrage mesuré.
  - *Mitigations*: Lie les clés de session éphémères aux rapports d'enclave, rejetant les tunnels modifiés ou non vérifiés (`CVE-2026-40291`).
  - *Synthèse*: Modules NixOS durcis et scripts de vérification en amont du handshake (`--wg-enclave`).
- **Microsegmentation Zero-Trust et Attestation SPIFFE/SPIRE**
  - *Audits*: Identifiants SPIFFE conformes RFC, mode mTLS obligatoire sous Cilium et fenêtres de validité des SVIDs.
  - *Mitigations*: Supprime les sélecteurs génériques dangereux (`k8s:ns:*`) et prévient les déconnexions dues à la désynchronisation des certificats (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **Module de Sécurité Matériel (HSM) et Chiffrement d'Enveloppe PKCS#11**
  - *Audits*: Fichiers `EncryptionConfiguration` pour etcd, plugins KMS v2 et AWS Nitro Enclaves (`CVE-2026-83190`) (`--hsm`).
- **Synchronisation de Flotte Multi-Cluster et Radar de Jetons OIDC**
  - *Audits*: Permissions RBAC multi-locataires, algorithmes de signature OIDC fédérés et dérives GitOps avec ArgoCD/Flux (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 Chaîne d'Approvisionnement Déclarative & Stockage Immuable

- **Isolation du Magasin Nix Multi-Locataire et Cache Binaire (`NIX-STORE-001..012`)**
  - *Audits*: Paramètres du démon Nix (`nix.settings.*`, `nix.conf`), contrôle des signatures Ed25519 et télémétrie des substituts.
  - *Mitigations*: Empêche l'empoisonnement du cache par des substituts non signés (`CVE-2026-81930`), les flux HTTP et le contournement de bac à sable.
  - *Synthèse*: Modules NixOS durcis, configurations `/etc/nix/nix.conf` et alertes Prometheus (`--nixstore`).
- **Racine Immuable NixOS et Stockage Éphémère Impermanence (`IMP-ROOT-001..012`)**
  - *Audits*: Déclarations d'impermanence (`environment.persistence`) et montages `hostPath` sur le cluster.
  - *Mitigations*: Impose une racine `tmpfs` en mémoire RAM, détecte les fuites hostPath vers la racine éphémère (`CVE-2026-61842`) et bloque le swap non chiffré.
  - *Synthèse*: Modules d'impermanence renforcés, hooks initrd de purge au redémarrage et surveillance de l'espace disque (`--impermanence`).
- **Nomenclature Logicielle (SBOM) et Attestation In-Toto SLSA Niveau 3**
  - *Audits*: Documents SPDX v3.0, CycloneDX v1.6 et fermetures Nix confrontés aux déclarations cryptographiques In-Toto.
  - *Mitigations*: Détecte toute altération d'artéfact (`CVE-2026-71044`) et identifie les dérives de versions en production (`--sbom`).

### 5. 🤖 Admission des Charges, Plan de Continuité & Remédiation Autonome

- **Radar des Webhooks d'Admission Dynamique et Rotation des AC (`WH-RADAR-001..012`)**
  - *Audits*: Manifestes `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration` et expiration des certificats d'AC X.509.
  - *Mitigations*: Supprime les contournements dangereux `failurePolicy: Ignore` (`CVE-2026-52194`), les délais excessifs (> 3s) et les blocages de démarrage.
  - *Synthèse*: Webhooks sécurisés, ressources automatisées cert-manager et surveillance de latence (`--webhook`).
- **Planification des Snapshots CephFS et Réplication Inter-Régionale (`CEPH-DR-001..012`)**
  - *Audits*: Calendriers de snapshots CephFS, classes de réplication de volumes CSI et synchronisation delta entre régions.
  - *Mitigations*: Bloque les règles de suppression destructrices pour le RPO (`deletionPolicy: Delete`) et les états split-brain (`CVE-2026-10140`).
  - *Synthèse*: Classes de snapshots durcies, réplication chiffrée et anti-affinité des démons miroirs (`--dr`).
- **Sandbox Éphémère en MicroVM et Détonation de Leurres Honeypot**
  - *Audits*: Confinement des microVMs Firecracker, paramètres de geôlier (jailer) et leurres virtuels simulant Kubelet/etcd.
  - *Mitigations*: Met en quarantaine les conteneurs suspects et détecte les évasions d'hyperviseur MMIO (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **Remédiation Autonome et Générateur de Pull Requests GitOps**
  - *Fonctionnement*: Validation préalable par canaris (`pkg/remediate/canary.go`), évaluation pure sous Nix Flake et tests à blanc avec `kubectl kustomize`.
  - *Livrables*: PRs atomiques non perturbatrices (`remediation/*`), patchs stratégiques Kustomize et RFC 6902 JSONPatches (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 Démarrage Rapide

### Prérequis
- Go 1.22+ installé localement.

### Compilation et Exécution
```bash
# Cloner le dépôt
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Exécuter les tests
go test ./...

# Examiner le flux de menaces en direct
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Auditer le fichier flake.lock par rapport aux avis de sécurité
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Auditer les manifestes Kubernetes pour détecter les failles Ingress et CNI
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Auditer les politiques CiliumNetworkPolicy et profileurs eBPF NixOS
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# Réconcilier la télémétrie des flux eBPF et générer des politiques renforcées
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Auditer le verrouillage du noyau Linux et la base UEFI Secure Boot DBX
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# Auditer l'isolation du magasin Nix et les caches binaires
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# Auditer l'impermanence de la racine NixOS et les montages hostPath
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Auditer les webhooks d'admission Kubernetes (ValidatingWebhookConfiguration)
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# Auditer l'attestation des pairs WireGuard sur VM confidentielles (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# Auditer le fast-path WireGuard eBPF et les performances cryptographiques
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Auditer les politiques de peering Cilium BGP et déclarations NixOS FRR
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# Exécuter l'analyse de télémétrie eBPF bare-metal sur l'ensemble du cluster
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# Exporter les résultats au format OASIS SARIF v2.1.0 pour GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Générer un rapport d'audit complet au format JSON
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Générer un briefing horaire automatisé sur l'état de sécurité
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ Feuille de Route et Évolution

Consultez [ROADMAP.md](../../ROADMAP.md) pour découvrir la feuille de route active et les prochaines étapes de développement.

---

## 🔒 Politique de Sécurité

Pour signaler une vulnérabilité et consulter nos principes directeurs de sécurité, référez-vous à [SECURITY.md](../../SECURITY.md).
