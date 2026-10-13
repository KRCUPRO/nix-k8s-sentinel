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

### Version 0.2.0 — Flake & Ingress Security Modules (In Progress)
- [ ] Automated NixOS `flake.lock` recursive input analyzer.
- [ ] Kubernetes Ingress snippet path traversal & CVE-2026-21801 heuristic detection.
- [ ] Automated markdown security briefing generator for hourly audit trails.

### Version 0.3.0 — Policy Synthesis & Defense Engines
- [ ] Active synthesis of Falco runtime rules from threat mitigations.
- [ ] Open Policy Agent (OPA) Gatekeeper ConstraintTemplate auto-generator.
- [ ] SARIF v2.1.0 output formatting for GitHub Security Code Scanning integration.

### Version 0.4.0 — Bare-Metal Telemetry & Storage Audits
- [ ] eBPF socket monitoring probes for multi-node bare-metal Kubernetes clusters.
- [ ] Rook Ceph distributed storage OSD peering anomaly and BlueStore integrity rules.
