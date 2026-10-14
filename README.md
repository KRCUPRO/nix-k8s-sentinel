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
[![Version](https://img.shields.io/badge/Release-v0.10.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Overview

`nix-k8s-sentinel` is a high-performance declarative vulnerability scanner and continuous threat intelligence engine designed specifically for bare-metal NixOS clusters and Kubernetes infrastructure.

Unlike ephemeral container scanners, `nix-k8s-sentinel` audits declarative configuration matrices (NixOS Flakes, Kubernetes CNI policies, Ingress controllers, Rook Ceph storage clusters, WireGuard mesh networks, and CIS Kubernetes Benchmarks) against real-time normalized CVSS threat intelligence feeds, enabling automated mitigation before workloads are scheduled.

---

## 🏛️ Core Capabilities

- **🔍 Declarative Infrastructure Auditing**: Pattern matching and input tracking for NixOS Flake inputs, Kubernetes manifests, and CNI policies.
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
