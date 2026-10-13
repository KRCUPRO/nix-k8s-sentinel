# Project Roadmap & Vision

`nix-k8s-sentinel` is designed to provide proactive, declarative vulnerability scanning and automated threat intelligence for modern bare-metal NixOS clusters and Kubernetes production environments.

---

## 🎯 Architecture Pillars

### 1. Declarative Infrastructure Security
Unlike traditional runtime scanners that inspect ephemeral container layers after deployment, `nix-k8s-sentinel` performs static and dynamic audits on the underlying declarative definitions:
- **NixOS Flakes**: Evaluating pure input locks against upstream CVE trackers and kernel advisories.
- **Kubernetes Manifests**: Auditing PodSecurityStandards, Ingress URI rewrites, and CNI policy configurations.

### 2. Live Threat Intelligence Synchronization
Continuous ingestion of high-fidelity security advisories from NIST NVD, GitHub Advisory Database, and Linux kernel CVE feeds, normalized into structured, machine-readable threat models.

### 3. Policy Synthesis & Active Mitigation
Automated generation of defense-in-depth rules:
- **Falco Rules**: Synthesized kernel syscall monitoring for detected vulnerabilities.
- **OPA Gatekeeper**: Validating admission constraints to reject vulnerable declarations prior to scheduling.

---

## 🗺️ Engineering Milestones

### Version 0.1.0 — Core Architecture (Completed)
- [x] High-performance CVSS threat feed normalization engine in Go (`pkg/intel`).
- [x] Declarative scanner for NixOS configurations and Kubernetes manifests (`pkg/scanner`).
- [x] Command-line interface with target filtering and feed querying (`cmd/sentinel`).
- [x] 100% test coverage for core models and configuration pattern matching.

### Version 0.2.0 — Flake Dependency Security (Completed)
- [x] Automated NixOS `flake.lock` recursive input analyzer (`pkg/nix`).
- [x] Upstream CVE & advisory mapping across pinned git revisions.
- [x] Cycle protection and 64-level traversal bounds limits.

### Version 0.3.0 — Kubernetes Ingress & CNI Network Policy Defense Engine (Completed)
- [x] Kubernetes Ingress snippet injection (CVE-2023-5044 / CVE-2026-21801) and path traversal analyzer (`pkg/k8s/ingress.go`).
- [x] Calico, Cilium, and standard Kubernetes CNI network policy verification (`pkg/k8s/cni.go`).
- [x] Default-deny posture audits, sensitive port exposure detection (etcd, kubelet), and 0.0.0.0/0 egress data leak prevention.
- [x] Unified manifest file and directory scanner with feed correlation (`pkg/k8s/scanner.go`).

### Version 0.4.0 — Threat Intelligence Briefing & Policy Synthesis (Active)
- [x] Automated markdown security briefing generator for hourly audit trails (`pkg/report/briefing.go`).
- [x] Multi-source telemetry aggregation with CVSS severity breakdown and risk exposure matrices (`pkg/report/telemetry.go`).
- [x] Integrated CLI reporting (`--briefing`, `--briefing-dir`, `--briefing-file`) linking feed, flake, and k8s audits.
- [ ] Active synthesis of Falco runtime rules from threat mitigations (`pkg/policy/falco.go`).
- [ ] Open Policy Agent (OPA) Gatekeeper ConstraintTemplate auto-generator (`pkg/policy/opa.go`).
- [ ] SARIF v2.1.0 output formatting for GitHub Security Code Scanning integration.

### Version 0.5.0 — Bare-Metal Telemetry & Storage Audits (Planned)
- [ ] eBPF socket monitoring probes for multi-node bare-metal Kubernetes clusters.
- [ ] Rook Ceph distributed storage OSD peering anomaly and BlueStore integrity rules.
- [ ] WireGuard mesh network cryptographic key rotation and ephemeral peer posture.
- [ ] Multi-cluster fleet synchronization and OIDC federated identity radar.
- [ ] SPIFFE/SPIRE workload attestation and cryptographic mTLS certificate monitoring.
