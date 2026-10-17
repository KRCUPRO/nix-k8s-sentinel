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
[![Version](https://img.shields.io/badge/Release-v0.22.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Overview

`nix-k8s-sentinel` is a high-performance declarative vulnerability scanner, autonomous threat remediation engine, and continuous threat intelligence system designed specifically for bare-metal NixOS clusters and Kubernetes infrastructure.

Unlike ephemeral container scanners, `nix-k8s-sentinel` audits declarative configuration matrices (NixOS Flakes, Kubernetes CNI policies, Ingress controllers, Gateway API routes, Istio EnvoyFilters, Rook Ceph storage clusters, WireGuard mesh networks, CIS Kubernetes Benchmarks, Confidential Computing measured boot chains, Multi-Cluster GitOps fleet topologies, SPIFFE/SPIRE Zero-Trust microsegmentation, Software Bill of Materials with In-Toto SLSA Level 3 supply chain attestations, Hardware Security Module envelope encryption, Dynamic Kernel Threat Profiling with Syscall BPF Filters, Post-Quantum Cryptography with NSA CNSA 2.0 TLS audit engine, Ephemeral MicroVM Sandbox with Honeypot Detonation Dispatch, Autonomous Threat Remediation with GitOps Pull Request Synthesis & Canary Validation, eBPF LSM Security Module & Kernel Mandatory Access Control, and CephFS Snapshot Scheduling & Cross-Region Volume Replication Disaster Recovery) against real-time normalized CVSS threat intelligence feeds, enabling automated mitigation before workloads are scheduled.

---

## 🏛️ Core Capabilities

- **🔍 Declarative Infrastructure Auditing**: Pattern matching and input tracking for NixOS Flake inputs, Kubernetes manifests, and CNI policies.
- **🔄 CephFS Snapshot Scheduling & Cross-Region Volume Replication Disaster Recovery**: Comprehensive disaster recovery auditing engine inspecting CephFS snapshot schedules, CSI volume replication classes, cross-region replication states, and runtime delta synchronization across multi-cluster Kubernetes deployments. Detects VolumeSnapshotClasses with deletionPolicy `Delete` risking catastrophic recovery point destruction upon volume churn (`CEPH-DR-001`), missing or excessive snapshot schedules (> 24h) violating RPO SLAs (`CEPH-DR-002`), inadequate snapshot retention < 3 (`CEPH-DR-003`), unencrypted WAN replication transport (`CEPH-DR-004`), excessive replication intervals (`CEPH-DR-005`), unmanaged replication CRDs (`CEPH-DR-006`), single-replica mirror daemons lacking anti-affinity (`CEPH-DR-007`), stretched clusters missing 3rd-zone Arbiter monitors (`CEPH-DR-008`), replication delta lag exceeding 900s (`CEPH-DR-009`), cross-region split-brain dual-primary assertions (`CVE-2026-10140`), degraded/error states (`CEPH-DR-011`), and unverified standby DR failover readiness (`CEPH-DR-012`). Autonomously synthesizes hardened `VolumeSnapshotClass` (Retain), `CephFilesystemSubVolumeGroup` snapshot schedules, `VolumeReplicationClass` with encrypted transport, and primary/secondary `VolumeReplication` pairs (`--dr-manifests`, `--dr`, `--dr-telemetry`, `--dr-synth-out`, `--dr-rpo-max`, `--dr-strict`).
- **🛡️ eBPF LSM Security Module & Kernel Mandatory Access Control**: Kernel-level mandatory access control (MAC) and declarative eBPF Linux Security Module (LSM) security engine for NixOS container hosts and Kubernetes workloads. Audits declarative host kernel parameters (`boot.kernelParams`, `security.lsm = [ ... "bpf" ... ]`), container security contexts, and eBPF LSM telemetry hooks (`bprm_check_security`, `file_open`, `socket_create`, `task_alloc`, `bpf`). Detects privileged container escapes bypassing seccomp (CVE-2026-99103), unconfined syscall invocations, unauthorized BPF map interactions, and missing kernel MAC profiles. Reconciles live eBPF denial telemetry and autonomously synthesizes hardened declarative NixOS modules (`lsm-bpf-policy.nix`), verifiable eBPF C programs (`lsm_container_mac.bpf.c`), and Kubernetes `ContainerMACProfile` CRDs (`--lsm`, `--lsm-mac`, `--lsm-telemetry`, `--lsm-synth-out`).
- **🤖 Autonomous Threat Remediation & GitOps Pull Request Synthesizer**: Autonomous security engineering engine auditing NixOS modules and Kubernetes manifests, discovering remediable vulnerabilities, and synthesizing atomic declarative hardening patches without human intervention. Features automated pre-flight canary test validation (`pkg/remediate/canary.go`) executing simulated NixOS pure flake evaluations and `kubectl kustomize` dry-run schema validations to ensure patches are 100% non-breaking before opening GitOps pull requests. Generates unified diff NixOS configuration patches (`remediation-patches.nix`), Kubernetes Kustomize strategic merge patches (`patch-<name>.yaml`), RFC 6902 JSONPatches (`jsonpatch-<name>.yaml`), complete `kustomization.yaml` overlay manifests, and formatted pull request summaries (`PR_SUMMARY.md`) with branch conventions (`remediation/*`) and conventional commit messages (`--remediate`, `--remediate-synth-out`, CVE-2026-98402).
- **🔬 Ephemeral MicroVM Sandbox & Honeypot Detonation Dispatch Engine**: Cloud-native security engine orchestrating ephemeral Firecracker microVMs on NixOS and Kubernetes for isolated detonation and behavioral analysis of untrusted container images, OCI artifacts, and binaries prior to cluster scheduling. Streaming parser for NixOS microvm modules (`microvm.vms.<name>`), hypervisor parameters, jailer confinement settings, and Kubernetes `DetonationJob` CRD manifests. Reconciles live execution telemetry, kernel probes, and decoy honeypot hits (fake Kubelet port 10250, fake etcd port 2379/2380, canary tokens), tracks container quarantine status, detects in-guest reverse shell beaconing, kernel privilege escalation sequences, hypervisor virtio MMIO escape anomalies, and anti-analysis SLA timeouts, and synthesizes hardened microVM modules and honeypot lures (`--sandbox-synth-out`, CVE-2026-97105).
- **⚛️ Post-Quantum Cryptography (PQC) & NSA CNSA 2.0 TLS Audit Engine**: Enterprise cryptographic scanner auditing Kubernetes control plane components, etcd peer clusters, and NixOS host configurations for post-quantum key encapsulation readiness and NSA CNSA 2.0 transition conformance. Streaming parser for kube-apiserver, etcd, and kubelet flags (`--tls-min-version`, `--tls-cipher-suites`, `--tls-key-exchange-groups`, `--peer-tls-min-version`), NixOS OpenSSL configuration (`environment.etc."ssl/openssl.cnf"`, `oqsprovider` activation, default groups), and system-wide GnuTLS priority strings. Evaluates live and declarative TLS connections, calculates hybrid KEM adoption percentages, TLS 1.3 compliance, and evaluates NSA CNSA 2.0 readiness milestones (2025/2030/2033 timelines). Correlates Harvest-Now-Decrypt-Later (HNDL) quantum cryptanalysis threats with `CVE-2026-94301`, and synthesizes quantum-hardened NixOS modules and Kubernetes control plane static pod manifests (`--pqc-synth-out`).
- **🛡️ Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter**: Deep kernel-level security inspection engine analyzing declarative seccomp profiles, NixOS host parameters, and runtime eBPF telemetry across Kubernetes clusters. Detects unconfined container seccomp profiles (`type: Unconfined`), unrestricted administrative syscalls (`ptrace`, `process_vm_writev`, `kexec_load`), missing host eBPF LSM hooks (`security.lsm = [ ... "bpf" ... ]`), host namespace sharing (`hostPID`/`hostIPC`), and unprivileged BPF access. Reconciles live socket creation rates, flags abnormal socket storms exceeding 250 sockets/sec, detects raw socket allocations (`SOCK_RAW`, `AF_PACKET`), and autonomously synthesizes hardened Kubernetes Seccomp profiles, drop-in NixOS systemd sandboxing modules, and declarative eBPF LSM policy manifests (CVE-2026-90412).
- **🔐 Hardware Security Module (HSM) & PKCS#11 Envelope Encryption Pipeline**: Enterprise-grade cryptographic security inspection and auditing engine for Kubernetes etcd encryption at rest, KMS v2 plugins, PKCS#11 tokens, and AWS Nitro Enclaves. Streaming parser for `apiserver.config.k8s.io/v1` EncryptionConfiguration manifests, RFC 7512 PKCS#11 URIs, and NixOS host security modules (`services.p11-kit`, `hardware.nitro-enclaves`). Reconciles runtime KMS plugin health, flags unrotated Key Encryption Keys (> 90 days), detects exposed plaintext PINs in manifests, and prevents Nitro Enclave session leakage / unsealed attestation attacks (CVE-2026-83190).
- **📦 Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation**: Universal multi-format ingestion of SPDX v3.0, SPDX v2.3, CycloneDX v1.6, and Nix store closures. Enforces In-Toto cryptographic statement verification (`_type: https://in-toto.io/Statement/v1`), matches Subject SHA256 digests against build artifacts to detect tampering (CVE-2026-71044), mandates SLSA Level 3 hermetic sandboxing and immutable pinned materials, and reconciles declarative SBOMs against live cluster package telemetry (`--sbom`, `--attestation`, `--sbom-runtime`) to identify version drift, missing dependencies, and shadow container binary injections.
- **🔒 Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation**: Native audit engine for SPIFFE/SPIRE workload identities and Cilium eBPF network microsegmentation. Validates RFC-compliant SPIFFE IDs against trusted domain allowlists, enforces mandatory Cilium mTLS (`authentication.mode: required`), flags weak crypto keys (RSA-1024/2048), detects dangerous wildcard selectors (`k8s:ns:*`), identifies expiring or desynchronized SVIDs (< 15 min remaining) to prevent active workload disconnections (CVE-2026-67210), and autonomously synthesizes zero-trust `CiliumNetworkPolicy` manifests (`--spiffe-policy-out`).
- **🛰️ Multi-Cluster Fleet Synchronization & OIDC Token Radar**: Fleet-wide synchronization and federated identity auditing for geographically distributed Kubernetes clusters. Audits multi-tenant RBAC permissions to eliminate wildcard verbs/resources (`*`), block dangerous privilege escalations (`bind`/`escalate`), prevent impersonation without resourceNames whitelists, disallow cluster-wide secret reading across tenant boundaries, and block `cluster-admin` bindings to broad groups (`system:authenticated`). Intercepts insecure OIDC signing algorithms (`none`, `HS256`), excessive token lifetimes (> 24 hours), and missing audience/issuer claims. Statically audits ArgoCD Applications and Flux Kustomizations for automated self-healing (`selfHeal: true`, `prune: true`), floating branch tracking, and wildcard target clusters (`server: "*"`), while reconciling live cluster telemetry to detect configuration drift and degraded health postures (CVE-2026-60114).
- **🔒 Confidential Computing & Measured Boot Attestation Verifier**: Hardware-rooted security verification for AMD SEV-SNP (`mem_encrypt=on kvm_amd.sev=1`) and Intel TDX (`intel_iommu=on kvm_intel.tdx=1`) confidential computing enclaves. Verifies TPM 2.0 PCR quotations (PCR 0 firmware, PCR 7 Secure Boot, PCR 8 kernel cmdline, PCR 9 initrd, PCR 11 UKI system closure digest) and remote attestation tokens. Intercepts debug mode enclave flags, expired/revoked attestation tokens, missing systemd-boot/Lanzaboote measured boot chains, and desynchronized Nix store path cryptographic signatures against runtime measurements (CVE-2026-51204).
- **🌐 Kubernetes Gateway API & EnvoyFilter Route Threat Radar**: Declarative security inspection of Gateway API resources (`Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `ReferenceGrant`) and Istio `EnvoyFilter` manifests. Enforces cross-namespace `ReferenceGrant` validation to prevent tenant route hijacking (CVE-2026-44219), intercepts unsafe inline Lua script injections (`os.execute`, `io.popen`), detects filter chain order bypasses before authentication modules, flags unencrypted plaintext listeners, identifies path traversal rewrites (`..`, `//`), blocks identity header spoofing (`X-Remote-User`), and guards sensitive control plane ports (2379, 6443).
- **🛡️ CIS Kubernetes Benchmark Declarative Validator**: Audits NixOS systemd unit configurations (`services.kubernetes.*`, `services.etcd.*`) and Kubernetes component manifests against CIS Kubernetes Benchmark sections 1, 2, and 4. Detects unauthenticated anonymous API access (`--anonymous-auth=false`), open port 10255 endpoints (`--read-only-port=0`), insecure `AlwaysAllow` authorization, missing etcd mTLS certificates, and synthesizes drop-in declarative NixOS hardening modules (`--remediation-out`).
- **🌐 Kubernetes Ingress Security**: Automated detection of snippet injections (CVE-2023-5044 / CVE-2026-21801), URI rewrite capture group mismatches, unanchored path traversals, insecure SSL redirect policies, and permissive CORS wildcard configurations.
- **🔌 CNI Network Policy Verification**: Multi-engine policy audits for standard Kubernetes NetworkPolicies, Calico GlobalNetworkPolicies, and CiliumNetworkPolicies. Enforces default-deny zero trust, detects unconstrained 0.0.0.0/0 egress data leaks, sensitive port exposures (etcd, kubelet), and L7 bypasses.
- **🔐 WireGuard Mesh Cryptographic Key Rotation Engine**: Audits declarative NixOS WireGuard configurations for world-readable plaintext private keys in `/nix/store` (CVE-2026-31048), missing pre-shared keys (PSK) for post-quantum defense, allowedIPs 0.0.0.0/0 split-tunnel hijacking, and peer CIDR routing collisions. Reconciles live `wg show` telemetry to detect configuration drift, unmanaged ephemeral peers, stale handshakes (> 24h), and enforces 90-day keypair rotation lifetimes with zero-leak key masking.
- **🗄️ Rook Ceph Storage Integrity Ruleset**: Audits `CephCluster`, `CephBlockPool`, `StorageClass`, and `PVC` manifests for unencrypted wire transport (`msgr2`), missing OSD disk encryption, fragile mon quorums, unsafe ReadWriteMany (RWX) on block storage, OSD peering stalls, and Linux 6.12 BlueStore async direct I/O metadata desync threats (CVE-2026-15509).
- **🔬 Bare-Metal eBPF Telemetry Probes**: Kernel-level socket (`connect`), syscall (`execve`, `ptrace`, `bpf`), and storage integrity monitoring across multi-node bare-metal clusters with automated anomaly correlation.
- **📊 Automated Hourly Threat Briefings**: Synthesizes comprehensive Markdown advisories and CVSS risk telemetry matrices under `intel/briefings/` for audit trails and SecOps dashboards.
- **📡 Normalized Threat Ingestion**: Structured ingestion of CVSS v3.1 scoring, component mapping, and actionable remediation advisories.
- **🛡️ Active Policy Synthesis**: Auto-generation of Falco runtime detection rules and OPA Gatekeeper constraint policies from detected threat signatures.
- **📑 SARIF v2.1.0 & JSON Security Audits**: Native export to OASIS SARIF v2.1.0 for GitHub Security Code Scanning integration and structured JSON telemetry for enterprise CI/CD pipelines.
- **⚡ Zero-Allocation Go Engine**: High-concurrency, standalone binary with zero external runtime dependencies.

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
go run cmd/sentinel/main.go --k8s=fixtures/

# Audit Kubernetes Gateway API routes & Istio EnvoyFilter manifests
go run cmd/sentinel/main.go --gateway=fixtures/gateway-api-routes.yaml
go run cmd/sentinel/main.go --gw=fixtures/ --format=sarif --output=gateway-results.sarif

# Audit NixOS Confidential Computing configurations & Measured Boot
go run cmd/sentinel/main.go --attest=fixtures/nixos-measured-boot.nix

# Verify TPM 2.0 PCR quotations & remote attestation tokens across cluster nodes
go run cmd/sentinel/main.go --attest-telemetry=fixtures/attestation-telemetry.json
go run cmd/sentinel/main.go --attest=fixtures/nixos-measured-boot.nix --attest-telemetry=fixtures/attestation-telemetry.json --format=sarif --output=attest-results.sarif

# Audit SPIFFE/SPIRE workload registration manifests & Cilium microsegmentation
go run cmd/sentinel/main.go --spiffe=fixtures/spiffe-manifests.yaml

# Reconcile runtime SVID telemetry and generate hardened CiliumNetworkPolicies
go run cmd/sentinel/main.go --spiffe=fixtures/spiffe-manifests.yaml --svid-telemetry=fixtures/spiffe-telemetry.json --spiffe-policy-out=policies/generated/cilium-spiffe-policies.yaml --format=sarif --output=spiffe-results.sarif

# Audit Software Bill of Materials (SPDX v3.0 / CycloneDX v1.6) and In-Toto SLSA Level 3 Provenance
go run cmd/sentinel/main.go --sbom=fixtures/spdx-v3-sbom.json --attestation=fixtures/intoto-slsa-attestation.json

# Reconcile Declarative SBOM Against Cluster Runtime State Delta
go run cmd/sentinel/main.go --sbom=fixtures/spdx-v3-sbom.json --sbom-runtime=fixtures/sbom-runtime-state.json --format=sarif --output=sbom-results.sarif

# Audit Kubernetes EncryptionConfiguration & NixOS Hardware Security Module configs
go run cmd/sentinel/main.go --hsm=fixtures/k8s-encryption-config.yaml
go run cmd/sentinel/main.go --hsm=fixtures/nixos-hsm.nix

# Reconcile runtime HSM, PKCS#11, and KMS v2 plugin telemetry
go run cmd/sentinel/main.go --hsm=fixtures/k8s-encryption-config.yaml --hsm-telemetry=fixtures/hsm-telemetry.json --format=sarif --output=hsm-results.sarif

# Audit Kubernetes workload seccomp profiles & NixOS host BPF parameters
go run cmd/sentinel/main.go --bpf=fixtures/k8s-bpf-workload.yaml
go run cmd/sentinel/main.go --bpf=fixtures/nixos-bpf-vulnerable.nix

# Reconcile runtime kernel socket creation telemetry and syscall activity
go run cmd/sentinel/main.go --bpf=fixtures/k8s-bpf-workload.yaml --bpf-telemetry=fixtures/bpf-runtime-telemetry.json --format=sarif --output=bpf-results.sarif

# Synthesize hardened Seccomp profiles and NixOS systemd sandboxing modules
go run cmd/sentinel/main.go --bpf-synth-out=policies/generated/bpf

# Audit Kubernetes control plane & NixOS OpenSSL/GnuTLS post-quantum cryptography
go run cmd/sentinel/main.go --pqc=fixtures/k8s-pqc-vulnerable.yaml
go run cmd/sentinel/main.go --pqc=fixtures/nixos-pqc.nix

# Reconcile runtime TLS handshake telemetry & evaluate NSA CNSA 2.0 readiness
go run cmd/sentinel/main.go --pqc=fixtures/k8s-pqc-vulnerable.yaml --pqc-telemetry=fixtures/pqc-telemetry.json --format=sarif --output=pqc-results.sarif

# Synthesize hardened NixOS & Kubernetes PQC configuration policies
go run cmd/sentinel/main.go --pqc-synth-out=policies/generated/pqc

# Audit NixOS MicroVM declarations & Kubernetes DetonationJob manifests
go run cmd/sentinel/main.go --sandbox=fixtures/nixos-microvm-vulnerable.nix
go run cmd/sentinel/main.go --sandbox=fixtures/k8s-detonation-job.yaml

# Reconcile runtime microVM detonation telemetry, honeypot hits & quarantine status
go run cmd/sentinel/main.go --sandbox=fixtures/nixos-microvm-vulnerable.nix --sandbox-telemetry=fixtures/sandbox-telemetry.json --format=sarif --output=sandbox-results.sarif

# Synthesize hardened NixOS microVM, DetonationJob, and honeypot decoy definitions
go run cmd/sentinel/main.go --sandbox-synth-out=policies/generated/sandbox

# Audit manifests for autonomous threat remediation and synthesize GitOps pull requests
go run cmd/sentinel/main.go --remediate=fixtures/remediation
go run cmd/sentinel/main.go --remediate=fixtures/remediation --remediate-synth-out=policies/generated/remediation
go run cmd/sentinel/main.go --remediate=fixtures/remediation --format=sarif --output=remediation-results.sarif

# Audit host NixOS and Kubernetes manifests for eBPF LSM and Mandatory Access Control
go run cmd/sentinel/main.go --lsm=fixtures/nixos-lsm.nix
go run cmd/sentinel/main.go --lsm=fixtures/nixos-lsm-vulnerable.nix --lsm-mac=fixtures/k8s-lsm-workload.yaml

# Reconcile runtime eBPF LSM denial telemetry and evaluate container MAC enforcement
go run cmd/sentinel/main.go --lsm=fixtures/nixos-lsm-vulnerable.nix --lsm-telemetry=fixtures/lsm-telemetry.json --format=sarif --output=lsm-results.sarif

# Synthesize hardened NixOS LSM module, eBPF C program, and Kubernetes ContainerMACProfile CRD
go run cmd/sentinel/main.go --lsm-synth-out=policies/generated/lsm

# Audit Multi-Cluster fleet manifests (RBAC, ArgoCD, Flux)
go run cmd/sentinel/main.go --fleet=fixtures/fleet-manifests.yaml

# Reconcile runtime fleet telemetry and OIDC federated tokens
go run cmd/sentinel/main.go --fleet-telemetry=fixtures/fleet-telemetry.json
go run cmd/sentinel/main.go --fleet=fixtures/fleet-manifests.yaml --fleet-telemetry=fixtures/fleet-telemetry.json --format=sarif --output=fleet-results.sarif

# Audit NixOS WireGuard mesh configuration & runtime peer telemetry
go run cmd/sentinel/main.go --wg=fixtures/nixos-wireguard.nix
go run cmd/sentinel/main.go --wg=fixtures/nixos-wireguard.nix --wg-telemetry=fixtures/wireguard-telemetry.json

# Audit NixOS and Kubernetes manifests against CIS Kubernetes Benchmark
go run cmd/sentinel/main.go --cis=fixtures/nixos-kubernetes.nix
go run cmd/sentinel/main.go --cis=fixtures/nixos-kubernetes.nix --remediation-out=nixos-cis-hardening.nix

# Audit Rook Ceph distributed storage manifests & runtime health telemetry
go run cmd/sentinel/main.go --ceph=fixtures/rook-ceph-cluster.yaml
go run cmd/sentinel/main.go --ceph-telemetry=fixtures/ceph-health-telemetry.json

# Run bare-metal eBPF kernel telemetry audit across multi-node cluster
go run cmd/sentinel/main.go --probe
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif
go run cmd/sentinel/main.go --probe --format=json

# Export audit findings to OASIS SARIF v2.1.0 for GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Export comprehensive JSON telemetry audit report
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Generate automated hourly threat intelligence briefing
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# Synthesize Falco runtime detection rules & OPA Gatekeeper constraints
go run cmd/sentinel/main.go --policy-out=policies/generated
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml --policy-out=policies/generated --enforce-action=deny

# Filter by target infrastructure
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ Roadmap & Continuous Evolution

Please refer to [ROADMAP.md](./ROADMAP.md) for the active development roadmap, upcoming Flake input parsers, and eBPF bare-metal probes.

---

## 🔒 Security Policy

For vulnerability reporting procedures and disclosure guidelines, consult [SECURITY.md](./SECURITY.md).
