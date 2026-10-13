<div align="center">

<p align="center">
  <strong>🇺🇸 English</strong> · 🇰🇷 한국어 · 🇯🇵 日本語 · 🇨🇳 简体中文 · 🇪🇸 Español<br />
  🇫🇷 Français · 🇩🇪 Deutsch · 🇷🇺 Русский · 🇧🇷 Português · 🇸🇦 العربية
</p>

# 🛡️ nix-k8s-sentinel

**Automated Threat Intelligence & Declarative Vulnerability Scanner for NixOS & Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.2.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Overview

`nix-k8s-sentinel` is a high-performance declarative vulnerability scanner and continuous threat intelligence engine designed specifically for bare-metal NixOS clusters and Kubernetes infrastructure.

Unlike ephemeral container scanners, `nix-k8s-sentinel` audits declarative configuration matrices (NixOS Flakes, Kubernetes CNI policies, and Ingress controllers) against real-time normalized CVSS threat intelligence feeds, enabling automated mitigation before workloads are scheduled.

---

## 🏛️ Core Capabilities

- **🔍 Declarative Infrastructure Auditing**: Pattern matching and input tracking for NixOS Flake inputs and Kubernetes manifest specifications.
- **📡 Normalized Threat Ingestion**: Structured ingestion of CVSS v3.1 scoring, component mapping, and actionable remediation advisories.
- **🛡️ Active Policy Synthesis**: Auto-generation of Falco runtime detection rules and OPA Gatekeeper constraint policies from detected threat signatures.
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
