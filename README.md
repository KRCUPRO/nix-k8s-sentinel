<div align="center">

<p align="center">
  <strong>🇺🇸 English</strong> ·
  <a href="./docs/translations/README.ko.md">🇰🇷 한국어</a> ·
  <a href="./docs/translations/README.ja.md">🇯🇵 日本語</a> ·
  <a href="./docs/translations/README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./docs/translations/README.es.md">🇪🇸 Español</a><br />
  <a href="./docs/translations/README.fr.md">🇫🇷 Français</a> ·
  <a href="./docs/translations/README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./docs/translations/README.ru.md">🇷🇺 Русский</a> ·
  <a href="./docs/translations/README.pt.md">🇧🇷 Português</a> ·
  <a href="./docs/translations/README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Automated Threat Intelligence & Declarative Vulnerability Scanner for NixOS & Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.31.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Overview

`nix-k8s-sentinel` is a high-performance declarative vulnerability scanner, autonomous threat remediation engine, and continuous threat intelligence system engineered specifically for bare-metal NixOS clusters and Kubernetes production environments.

Unlike traditional runtime scanners that passively inspect ephemeral container layers post-deployment, `nix-k8s-sentinel` audits the underlying declarative definitions before workloads are scheduled. It correlates static manifests and runtime kernel telemetry against normalized, high-fidelity CVSS threat intelligence feeds.

### 🎯 Five Core Defense Pillars

1. **Bare-Metal & Kernel Hardening**: Linux Kernel Lockdown enforcement, UEFI DBX revocation verification, eBPF LSM mandatory access control, and hardware root-of-trust measured boot.
2. **Cluster Networking & Service Mesh**: eBPF socket flow & Shannon entropy DNS exfiltration profiling, dual-stack Cilium BGP peering, WireGuard kernel fast-path, and Gateway API routing security.
3. **Cryptography & Confidential Computing**: Post-Quantum Cryptography (NSA CNSA 2.0), SPIFFE/SPIRE workload attestation, Confidential VM remote quotes (AMD SEV-SNP / Intel TDX), and HSM/KMS v2 envelope encryption.
4. **Supply Chain & Storage Ephemerality**: In-Toto SLSA Level 3 SBOM provenance verification, Ed25519 Nix store signature enforcement, and NixOS stateless root with impermanence validation.
5. **Dynamic Admission & Autonomous Remediation**: Fail-closed admission webhooks, ephemeral MicroVM honeypot detonation, and automated GitOps PR synthesis with pre-flight canary checks.

---

## 🏛️ Core Capabilities

### 1. 🛡️ Kernel Security & Host Hardening

- **Linux Kernel Lockdown & UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *Audits*: Kernel lockdown mode (`integrity`/`confidentiality`), unsigned kernel modules (`module.sig_enforce`), `/dev/mem` access, and Lanzaboote declarations.
  - *Mitigations*: Prevents arbitrary ring-0 compromise (`CVE-2026-92814`) and bootloaders matching revoked UEFI DBX digests (`CVE-2023-40547`).
  - *Synthesis*: Hardened NixOS lockdown modules (`nixos-lockdown-hardened.nix`), automated DBX updater services, and Prometheus alert rules (`--lockdown`).
- **eBPF LSM Security Module & Kernel Mandatory Access Control**
  - *Audits*: Host kernel LSM parameters (`security.lsm = ["bpf"]`) and container security contexts (`bprm_check_security`, `file_open`, `socket_create`).
  - *Mitigations*: Blocks privileged container escapes bypassing seccomp (`CVE-2026-99103`) and unauthorized BPF map manipulations.
  - *Synthesis*: Declarative NixOS LSM modules, verifiable eBPF C programs, and Kubernetes `ContainerMACProfile` CRDs (`--lsm`).
- **Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter**
  - *Audits*: Declarative seccomp profiles, unconfined containers, and administrative syscall allocations (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *Mitigations*: Flags abnormal socket storms (> 250 sockets/s) and raw socket allocations linked to `CVE-2026-90412`.
  - *Synthesis*: Hardened Kubernetes Seccomp profiles and systemd sandboxing drop-ins (`--bpf`).
- **CIS Kubernetes Benchmark & Bare-Metal Probes**
  - *Audits*: Control plane systemd unit flags, Kubelet parameters, and kernel socket/syscall events across cluster worker nodes.
  - *Synthesis*: Automated NixOS host remediation patches and multi-node probe telemetry reconciliation (`--cis`, `--probe`).

### 2. 🌐 Cluster Networking & Service Mesh Defense

- **Multi-Tenant Cilium ClusterMesh & Global Service Discovery Auditor (`MESH-RADAR-001..012`)**
  - *Audits*: Cilium ClusterMesh Helm values, ConfigMaps, Global Services (`io.cilium/global-service`), `ServiceExport`/`ServiceImport` CRDs, and live etcd peering telemetry.
  - *Mitigations*: Prevents unencrypted cross-cluster tunnels (`CVE-2026-11483`), cluster-id collisions/0, etcd TLS disablement, ServiceExport collisions, and multi-tenant routing leaks.
  - *Synthesis*: Hardened Cilium Helm values (WireGuard transit encryption, strict heartbeat timers), tenant boundary `CiliumClusterwideNetworkPolicy`, and Prometheus alert rules (`--clustermesh`).
- **Cluster-Wide eBPF Network Flow & DNS Exfiltration Profiler (`FLOW-RADAR-001..012`)**
  - *Audits*: Kubernetes `CiliumNetworkPolicy` manifests, NixOS host flow profilers, and live eBPF kernel socket/DNS telemetry.
  - *Mitigations*: Intercepts unrestricted port 53 egress (`CVE-2026-10392`), high Shannon entropy DNS tunnels ($H > 4.2$), DGA bursts (> 15 q/min), and socket connect spikes (> 500 conn/s).
  - *Synthesis*: Hardened `CiliumNetworkPolicy` (L7 DNS proxy with FQDN regexes), NixOS profiler modules, and Prometheus alert rules (`--flow`).
- **Dual-Stack IPv6 & Cilium BGP Peering Radar (`BGP-RADAR-001..012`)**
  - *Audits*: Cilium BGP peering policies, load balancer IP pools, and NixOS FRR BGP host configurations.
  - *Mitigations*: Detects missing TCP MD5 / RFC 2385 authentication (`CVE-2026-70192`), route export leaks, and prefix churn.
  - *Synthesis*: Hardened Cilium BGP manifests, NixOS FRR modules, and BGP alerting rules (`--bgp`).
- **WireGuard eBPF Kernel Fast-Path & Crypto Performance (`WG-FAST-001..012`)**
  - *Audits*: ChaCha20-Poly1305 SIMD vector acceleration (AVX-512, ARM Neon), native eBPF/XDP hooks, and 100GbE overlays.
  - *Mitigations*: Detects scalar crypto fallback, softIRQ starvation (> 70%), and ring buffer saturation (`CVE-2026-31049`).
  - *Synthesis*: Hardened NixOS fast-path modules and verified eBPF XDP C steering programs (`--wg-fastpath`).
- **Kubernetes Ingress, Gateway API & EnvoyFilter Route Threat Radar**
  - *Audits*: `Gateway`, `HTTPRoute`, `GRPCRoute`, `ReferenceGrant`, and Istio `EnvoyFilter` declarations.
  - *Mitigations*: Blocks snippet injection (`CVE-2023-5044`), cross-namespace route hijacking (`CVE-2026-44219`), inline Lua script injections, and unanchored path traversals (`--gw`, `--k8s`).

### 3. 🔐 Cryptography, Confidential Computing & Identity

- **Post-Quantum Cryptography (PQC) & NSA CNSA 2.0 Transition**
  - *Audits*: Kube-apiserver, etcd, and Kubelet TLS flags, NixOS OpenSSL `oqsprovider` activation, and GnuTLS priority strings.
  - *Mitigations*: Defends against Harvest-Now-Decrypt-Later (HNDL) quantum cryptanalysis threats (`CVE-2026-94301`).
  - *Synthesis*: Quantum-hardened ML-KEM/Kyber hybrid TLS declarations and CNSA 2.0 readiness milestones (`--pqc`).
- **Confidential VM & Secure Enclave WireGuard Attestation (`WG-ENC-001..012`)**
  - *Audits*: AMD SEV-SNP VCEK certificate chains, Intel TDX quotes, and runtime measured boot PCR digests.
  - *Mitigations*: Binds ephemeral session keys to enclave reports, rejecting unverified or tampered peer tunnels (`CVE-2026-40291`).
  - *Synthesis*: Hardened NixOS enclave modules and pre-handshake kernel gatekeeper scripts (`--wg-enclave`).
- **Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation**
  - *Audits*: RFC-compliant SPIFFE IDs, Cilium mandatory mTLS (`authentication.mode: required`), and short-lived SVID windows.
  - *Mitigations*: Eliminates wildcard selectors (`k8s:ns:*`) and prevents SVID renewal desync dropouts (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **Hardware Security Module (HSM) & PKCS#11 Envelope Encryption**
  - *Audits*: Kubernetes etcd `EncryptionConfiguration`, KMS v2 plugins, and AWS Nitro Enclaves (`CVE-2026-83190`) (`--hsm`).
- **Multi-Cluster Fleet Synchronization & OIDC Token Radar**
  - *Audits*: Multi-tenant RBAC permissions, federated OIDC signing algorithms, and ArgoCD/Flux GitOps state drift (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 Declarative Supply Chain & Immutable Storage

- **Multi-Tenant Nix Store Signature & Binary Cache Isolation (`NIX-STORE-001..012`)**
  - *Audits*: Nix daemon settings (`nix.settings.*`, `nix.conf`), Ed25519 signature enforcement, and runtime substitute telemetry.
  - *Mitigations*: Blocks unsigned substitute cache poisoning (`CVE-2026-81930`), HTTP substituters, and sandbox bypasses.
  - *Synthesis*: Hardened NixOS store modules, `/etc/nix/nix.conf`, and Prometheus alert rules (`--nixstore`).
- **NixOS Immutable Root & Impermanence Storage Ephemerality (`IMP-ROOT-001..012`)**
  - *Audits*: NixOS impermanence configurations (`environment.persistence`) and Kubernetes `hostPath` cluster mounts.
  - *Mitigations*: Enforces RAM-backed `tmpfs` root, catches hostPath root escapes (`CVE-2026-61842`), and blocks unencrypted swap.
  - *Synthesis*: Hardened impermanence modules, wipe-on-reboot initrd hooks, and storage headroom alerts (`--impermanence`).
- **Software Bill of Materials (SBOM) & In-Toto SLSA Level 3 Supply Chain Attestation**
  - *Audits*: SPDX v3.0, CycloneDX v1.6, and Nix store closures against cryptographic In-Toto statements.
  - *Mitigations*: Detects artifact tampering (`CVE-2026-71044`) and version drift between declarations and cluster runtime (`--sbom`).

### 5. 🤖 Workload Admission, Disaster Recovery & Autonomous Remediation

- **Kubernetes Dynamic Admission Webhook & CA Rotation Radar (`WH-RADAR-001..012`)**
  - *Audits*: `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`, and X.509 CA certificate expiration.
  - *Mitigations*: Prevents insecure `failurePolicy: Ignore` bypasses (`CVE-2026-52194`), excessive timeouts (> 3s), and cluster deadlocks.
  - *Synthesis*: Hardened ValidatingWebhooks, cert-manager automated CA resources, and latency alerts (`--webhook`).
- **CephFS Snapshot Scheduling & Cross-Region Volume Replication Disaster Recovery (`CEPH-DR-001..012`)**
  - *Audits*: CephFS snapshot schedules, CSI volume replication classes, and replication delta synchronization.
  - *Mitigations*: Blocks RPO-destroying `deletionPolicy: Delete` and split-brain dual-primary states (`CVE-2026-10140`).
  - *Synthesis*: Hardened VolumeSnapshotClasses, encrypted replication transports, and mirror daemons (`--dr`).
- **Ephemeral MicroVM Sandbox & Honeypot Detonation Dispatch**
  - *Audits*: Firecracker microVM confinement, jailer parameters, and fake Kubelet/etcd decoy honeypots.
  - *Mitigations*: Quarantines malicious container images and catches hypervisor MMIO escapes (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **Autonomous Threat Remediation & GitOps Pull Request Synthesizer**
  - *Mechanism*: Pre-flight canary validation (`pkg/remediate/canary.go`) with pure Nix flake evaluation and `kubectl kustomize` dry-runs.
  - *Output*: Non-breaking atomic PRs (`remediation/*`), Kustomize strategic merge patches, and RFC 6902 JSONPatches (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 Quick Start

### Prerequisites
- Go 1.22+ installed locally.

### Build and Run
```bash
# Clone the repository
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Run test suite
go test ./...

# Inspect live threat feed
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Audit NixOS flake.lock against known security advisories
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Audit Kubernetes manifests for Ingress and CNI policy violations
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Audit Kubernetes CiliumNetworkPolicy & NixOS eBPF flow profiler manifests
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# Audit Cilium ClusterMesh Helm values, Global Services & cross-cluster policies
go run cmd/sentinel/main.go --clustermesh=fixtures/cilium-clustermesh-vulnerable.yaml --clustermesh-telemetry=fixtures/clustermesh-telemetry.json --clustermesh-synth-out=policies/generated/clustermesh

# Reconcile runtime eBPF socket connect flows & synthesize hardened policies
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Audit Linux Kernel Lockdown & Lanzaboote UEFI Secure Boot DBX configurations
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# Audit Multi-Tenant Nix Store & Binary Cache isolation settings
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# Audit NixOS impermanence configuration & cluster storage hostPath mounts
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Audit Kubernetes admission webhooks (ValidatingWebhookConfiguration)
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# Audit Confidential VM WireGuard peer attestation manifests (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# Audit WireGuard eBPF kernel fast-path & cryptographic throughput configurations
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Audit Cilium BGP peering policies & NixOS FRR BGP manifests
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# Run bare-metal eBPF kernel telemetry audit across multi-node cluster
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# Export audit findings to OASIS SARIF v2.1.0 for GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Export comprehensive JSON telemetry audit report
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Generate automated hourly threat intelligence briefing
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ Roadmap & Continuous Evolution

Please refer to [ROADMAP.md](./ROADMAP.md) for the active engineering roadmap, milestone history, and planned features.

---

## 🔒 Security Policy

For vulnerability reporting procedures, disclosure guidelines, and cryptographic invariants, consult [SECURITY.md](./SECURITY.md).
