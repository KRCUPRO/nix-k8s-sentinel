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

### Version 0.4.0 — Threat Intelligence Briefing & Telemetry Matrix (Completed)
- [x] Automated markdown security briefing generator for hourly audit trails (`pkg/report/briefing.go`).
- [x] Multi-source telemetry aggregation with CVSS severity breakdown and risk exposure matrices (`pkg/report/telemetry.go`).
- [x] Integrated CLI reporting (`--briefing`, `--briefing-dir`, `--briefing-file`) linking feed, flake, and k8s audits.

### Version 0.5.0 — Falco & OPA Gatekeeper Declarative Policy Synthesis (Completed)
- [x] Active synthesis of Falco runtime rules from threat mitigations (`pkg/policy/falco.go`).
- [x] Open Policy Agent (OPA) Gatekeeper ConstraintTemplate and Constraint auto-generator (`pkg/policy/opa.go`).
- [x] Multi-engine policy orchestration with schema conformance validation and CLI integration (`--policy-out`, `--policy-engine`, `--enforce-action`) (`pkg/policy/synthesizer.go`).

### Version 0.6.0 — SARIF Code Scanning & Security Exporters (Completed)
- [x] Native OASIS SARIF v2.1.0 output formatting for GitHub Security Code Scanning integration (`pkg/report/sarif.go`).
- [x] Structured JSON audit telemetry generator with severity distributions and multi-resource correlation (`pkg/report/json_report.go`).
- [x] CLI output format selection (`--format=console|json|sarif`) with atomic file exports (`--output=<path>`).

### Version 0.7.0 — Bare-Metal eBPF Telemetry Probes & Kernel Defense (Completed)
- [x] eBPF socket and syscall monitoring probe interface for bare-metal Kubernetes clusters (`pkg/probe/types.go`).
- [x] Multi-node eBPF telemetry aggregator and thread-safe streaming manager (`pkg/probe/ebpf.go`).
- [x] Kernel-level runtime anomaly and threat detector (`pkg/probe/detector.go`) catching reverse shells, etcd/kubelet port sweeps, immutable `/nix/store` tampering, and container boundary escape attempts.
- [x] Offline multi-node bare-metal simulation engine and telemetry replay fixtures (`pkg/probe/mock.go`, `fixtures/probe-telemetry.json`).
- [x] Full CLI integration (`--probe`, `--probe-fixture`, `--probe-nodes`) with unified SARIF, JSON, and threat briefing telemetry exports.

### Version 0.8.0 — Rook Ceph Distributed Storage Integrity & BlueStore Anomaly Ruleset (Current)
- [x] Canonical storage integrity ruleset covering hostNetwork, in-transit `msgr2` crypto, at-rest OSD encryption, replication factors, and mon quorum (`pkg/storage/rules.go`).
- [x] Declarative Rook Ceph manifest scanner auditing `CephCluster`, `CephBlockPool`, `StorageClass`, and `PersistentVolumeClaim` (`pkg/storage/crd_scanner.go`).
- [x] Ceph OSD peering stall, placement group degradation, and nearfull watermark anomaly detector (`pkg/storage/osd_detector.go`).
- [x] BlueStore hardware CRC32c/XXH64 checksum corruption detector and Linux 6.12 async direct I/O metadata desync mitigation (CVE-2026-15509).
- [x] Volume health auditor preventing unsafe ReadWriteMany (RWX) multi-attaches on Ceph RBD block storage (`pkg/storage/volume.go`).
- [x] Full CLI integration (`--ceph`, `--storage`, `--ceph-telemetry`) and seamless export to SARIF v2.1.0, JSON, and Markdown briefings.

### Version 0.9.0 — Cryptographic Mesh & CIS Benchmark Security (Planned)
- [ ] WireGuard mesh network cryptographic key rotation and ephemeral peer posture auditing (`pkg/crypto/wireguard.go`).
- [ ] Kube-Bench and CIS Kubernetes Benchmark declarative NixOS validator (`pkg/bench/cis.go`).
- [ ] Kubernetes Gateway API and EnvoyFilter route threat radar (`pkg/gateway/radar.go`).

### Version 1.0.0 — Supply Chain Attestation & Workload Identity (Planned)
- [ ] Confidential Computing AMD SEV-SNP and Intel TDX measured boot attestation verifier.
- [ ] Multi-cluster fleet synchronization and federated OIDC token radar.
- [ ] SPIFFE/SPIRE workload attestation and cryptographic mTLS certificate monitoring.
- [ ] Software Bill of Materials (SBOM) ingestion for SPDX v3.0 / CycloneDX v1.6 and In-Toto provenance validation.
- [ ] Hardware Security Module (HSM) PKCS#11 envelope encryption and KMS v2 key health checks.

### Version 1.1.0 — Ephemeral Sandboxing & Autonomous Remediation (Vision)
- [ ] Dynamic Firecracker microVM orchestration on NixOS for isolated detonating of suspicious container payloads.
- [ ] Autonomous GitOps Pull Request synthesizer generating declarative Kustomize and Flake patches for CVE mitigations.
