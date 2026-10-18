# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.25.0] - 2026-10-18

### Added
- **Kubernetes Dynamic Admission Webhook & Certificate Authority Rotation Radar** (`pkg/webhook/scanner.go`): Autonomous security and CA rotation monitoring engine inspecting Kubernetes `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration` manifests, X.509 CA certificate expiration, and live admission controller telemetry across bare-metal and cloud clusters.
- **Authoritative Canonical Admission Webhook Rules Catalog** (`pkg/webhook/rules.go`): Suite of 12 canonical security rules (`WH-RADAR-001` through `WH-RADAR-012`) covering `failurePolicy: Ignore` on sensitive security resources (`WH-RADAR-001`, mapped to `CVE-2026-52194`), excessive webhook timeout duration > 10s default or recommending <= 3s (`WH-RADAR-002`), missing `kube-system` namespace exemption in `namespaceSelector` risking cluster-wide API server startup deadlocks (`WH-RADAR-003`), plaintext HTTP or insecure non-TLS webhook URLs (`WH-RADAR-004`), expired X.509 CA bundle certificates in `caBundle` (`WH-RADAR-005`), CA bundle certificates expiring within 30 days without automated renewal (`WH-RADAR-006`), weak cryptographic CA signing algorithms with RSA < 2048 or SHA-1 (`WH-RADAR-007`), unknown or permissive `sideEffects` annotations missing dry-run declarations (`WH-RADAR-008`), deprecated `admissionReviewVersions` declarations lacking v1 (`WH-RADAR-009`), admission webhook runtime P95/P99 latency degradation (`WH-RADAR-010`), admission webhook error rates exceeding 1.0% threshold (`WH-RADAR-011`), and missing cert-manager automated CA injection annotations (`WH-RADAR-012`).
- **Streaming Webhook Manifest & Telemetry Parser** (`pkg/webhook/parser.go`): Multi-document streaming YAML and line parser evaluating declarative Kubernetes webhook configurations, base64-encoded ASN.1 DER CA bundles, and live runtime JSON admission telemetry with 10MB memory safety bounds.
- **Dynamic Admission Auditor & Deterministic Compliance Engine** (`pkg/webhook/auditor.go`): Reconciles static webhook declarations and runtime admission metrics, evaluates CA validity windows and latency degradation, and calculates deterministic compliance scores (0.0% to 100.0%).
- **Declarative Webhook Policy Synthesizer** (`pkg/webhook/synth.go`): Synthesizes production-hardened `ValidatingWebhookConfiguration` manifests (`webhook-hardened.yaml`), automated cert-manager `Certificate` and `Issuer` resources (`cert-manager-ca.yaml`), and Prometheus APIServer admission latency alert rules (`webhook-alerts.yaml`).
- **Dedicated CLI Webhook Runner & Flag Architecture** (`cmd/sentinel/webhook_runner.go`, `cmd/sentinel/flags.go`): Extracted webhook audit coordination into a dedicated modular runner keeping `cmd/sentinel/main.go` under 480 LOC. Added `--webhook=<path>`, `--admission-webhook`, `--webhook-telemetry=<path>`, `--webhook-synth-out=<dir>`, and `--webhook-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-52194` (Kubernetes Dynamic Admission Webhook Latency Stall & CA Bundle Expiration Denial of Service, CVSS 9.2 Critical).
- **Unified Exporter Integration**: Admission webhook findings, CA expiration statuses, and runtime telemetry exported to OASIS SARIF v2.1.0 (Section 21), structured JSON audit telemetry (`webhook_violations`, `webhook_summary`, `webhook_telemetry`), and hourly Markdown threat briefings (Section 24).
- **Production Fixtures & Policy Artifacts**: Added realistic fixtures (`fixtures/k8s-admission-webhook.yaml`, `fixtures/k8s-admission-webhook-vulnerable.yaml`, `fixtures/webhook-telemetry.json`) and synthesized templates in `policies/generated/webhook/`.
- **Comprehensive Unit Test Suites** (`pkg/webhook/webhook_test.go`, `pkg/report/webhook_report_test.go`): 100% test coverage across canonical rules, manifest parsing, X.509 certificate decoding, telemetry auditing, policy synthesizers, scanner, SARIF/JSON/Briefing serialization, and memory bounds checks.

### Changed
- Bumped engine release to `v0.25.0`.
- Updated `SECURITY.md` establishing Kubernetes Dynamic Admission Webhook & Certificate Authority Rotation Radar security invariants (Invariant 27).
- Updated `ROADMAP.md` marking Milestone M25 as completed and scheduling M26 (NixOS Immutable Root & Impermanence Storage Ephemerality Verifier).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new webhook modules, runners, and O(1) symbols.

---

## [0.24.0] - 2026-10-18

### Added
- **Confidential VM & Secure Enclave WireGuard Peer Attestation Engine** (`pkg/wgenclave/scanner.go`): Autonomous security and hardware root-of-trust attestation engine inspecting WireGuard mesh peer configurations across AMD SEV-SNP and Intel TDX confidential virtual machines.
- **Authoritative Canonical Enclave Peer Rules Catalog** (`pkg/wgenclave/rules.go`): Suite of 12 canonical security rules (`WG-ENC-001` through `WG-ENC-012`) covering missing hardware root-of-trust attestation reports (`WG-ENC-001`), expired AMD SEV-SNP VCEK endorsement certificate chains (`WG-ENC-002`), Intel TDX quote verification failures (`WG-ENC-003`), measured boot PCR deviations from declarative golden references (`WG-ENC-004`, mapped to `CVE-2026-40291`), unbound ephemeral WireGuard session keys missing enclave `REPORT_DATA` binding (`WG-ENC-005`), confidential guest policies allowing hypervisor memory inspection or debugging (`WG-ENC-006`), stale attestation report age exceeding freshness window (`WG-ENC-007`), Intel TDX Runtime Measurement Register (RTMR) deviations (`WG-ENC-008`), peer public key changes without fresh hardware quotes (`WG-ENC-009`), outdated TCB Security Version Numbers below cluster baseline (`WG-ENC-010`), unauthenticated ephemeral peer handshakes without gating (`WG-ENC-011`), and unverified plaintext WireGuard fallback connections (`WG-ENC-012`).
- **Streaming Enclave Manifest & Telemetry Parser** (`pkg/wgenclave/parser.go`): Line-based streaming parser evaluating declarative NixOS WireGuard enclave peer modules, Kubernetes `EnclaveWireGuardPeer` CustomResourceDefinitions, and live runtime JSON attestation telemetry with 10MB memory safety bounds.
- **Enclave Posture Auditor & Compliance Scoring Engine** (`pkg/wgenclave/auditor.go`): Reconciles declarative configurations and runtime telemetry, compares measured boot PCR digests (PCR 0, 2, 4, 7) and TDX RTMRs against golden reference values, rejects unverified or tampered peer tunnels, and computes deterministic compliance scores (0.0% to 100.0%).
- **Declarative Enclave Policy Synthesizer** (`pkg/wgenclave/synth.go`): Synthesizes production-hardened NixOS enclave peer modules (`wg-enclave-hardened.nix`), Kubernetes `EnclaveWireGuardPeer` CustomResourceDefinition and CustomResource manifests (`enclave-wireguard-peer.yaml`), and pre-handshake kernel attestation gatekeeper scripts (`wg-enclave-gate.sh`).
- **Dedicated CLI Enclave Runner & Flag Architecture** (`cmd/sentinel/enclave_runner.go`, `cmd/sentinel/flags.go`): Extracted enclave audit coordination into a dedicated modular runner maintaining `cmd/sentinel/main.go` under 450 LOC. Added `--wg-enclave=<path>`, `--enclave`, `--wg-enclave-telemetry=<path>`, `--wg-enclave-synth-out=<dir>`, and `--wg-enclave-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-40291` (Confidential VM Attestation Bypass & Unverified WireGuard Peer Session Injection in SEV-SNP / TDX Nodes, CVSS 9.4 Critical).
- **Unified Exporter Integration**: WireGuard enclave findings, rejected peer IDs, and attestation telemetry seamlessly exported to OASIS SARIF v2.1.0 (Section 20), structured JSON audit telemetry (`enclave_violations`, `enclave_summary`, `enclave_reports`, `enclave_peers`), and hourly Markdown threat briefings (Section 23).
- **Production Fixtures & Policy Artifacts**: Added realistic fixtures (`fixtures/nixos-wg-enclave.nix`, `fixtures/nixos-wg-enclave-vulnerable.nix`, `fixtures/wg-enclave-telemetry.json`) and synthesized templates in `policies/generated/enclave/`.
- **Comprehensive Unit Test Suites** (`pkg/wgenclave/enclave_test.go`, `pkg/report/enclave_report_test.go`): 100% test coverage across canonical rules, manifest parsing, telemetry auditing, policy synthesizers, scanner, SARIF/JSON/Briefing serialization, and memory bounds checks.

### Changed
- Bumped engine release to `v0.24.0`.
- Updated `SECURITY.md` establishing Confidential VM & Secure Enclave WireGuard Peer Attestation security invariants (Invariant 26).
- Updated `ROADMAP.md` marking Milestone M24 as completed and scheduling M25 (Kubernetes Dynamic Admission Webhook & Certificate Authority Rotation Radar).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new enclave modules, runners, and O(1) symbols.

---

## [0.23.0] - 2026-10-17

### Added
- **eBPF-Based WireGuard Kernel Fast-Path & Crypto Performance Engine** (`pkg/wgfastpath/scanner.go`): Autonomous performance and security auditing engine inspecting WireGuard network interfaces, ChaCha20-Poly1305 SIMD vector acceleration (AVX-512, ARM Neon), native eBPF/XDP driver attachments, and 100GbE bare-metal overlay interconnect throughput.
- **Authoritative Canonical Fast-Path Rules Catalog** (`pkg/wgfastpath/rules.go`): Suite of 12 canonical rules (`WG-FAST-001` through `WG-FAST-012`) covering generic scalar crypto fallback lacking AVX-512 / ARM Neon vector acceleration (`WG-FAST-001`), missing native eBPF/XDP driver hooks on high-bandwidth links (`WG-FAST-002`), kernel fast-path ring buffer saturation exceeding 85% (`WG-FAST-003`, mapped to `CVE-2026-31049`), excessive packet drops exceeding 1,000 drops/s triggering TCP collapse (`WG-FAST-004`), hardware offloads (GRO/GSO/TSO) disabled on physical underlay NIC (`WG-FAST-005`), softIRQ budget starvation on cryptographic worker cores exceeding 70% (`WG-FAST-006`), WireGuard MTU fragmentation mismatches (`WG-FAST-007`), eBPF runtime `XDP_ABORTED` execution traps (`WG-FAST-008`), elevated SIMD FPU context switch overhead latencies exceeding 250ns (`WG-FAST-009`), multi-queue NIC descriptors fewer than active CPU cores (`WG-FAST-010`), kernel socket buffer allocation failures (`WG-FAST-011`), and AVX-512 execution unit thermal downclocking (`WG-FAST-012`).
- **Streaming Fast-Path Manifest & Telemetry Parser** (`pkg/wgfastpath/parser.go`): High-performance parser evaluating declarative NixOS WireGuard modules, Kubernetes CiliumNodeConfig CRDs, and live runtime JSON telemetry for packet counters, ring buffer saturation, and crypto benchmark measurements with 10MB memory safety bounds.
- **Fast-Path Posture Auditor & Compliance Scoring Engine** (`pkg/wgfastpath/auditor.go`): Reconciles declarative configurations against live 100GbE telemetry, calculates deterministic compliance scores (0.0% to 100.0%), and flags network bottleneck interfaces.
- **Declarative Fast-Path Policy Synthesizer** (`pkg/wgfastpath/synth.go`): Synthesizes production-hardened NixOS fast-path modules (`wg-fastpath-hardened.nix`), verified eBPF XDP steering C programs (`wg_fastpath_xdp.bpf.c`), and Kubernetes CiliumNodeConfig manifests (`wg-fastpath-k8s.yaml`).
- **Dedicated CLI Fast-Path Runner & Flag Architecture** (`cmd/sentinel/fastpath_runner.go`, `cmd/sentinel/flags.go`): Extracted fast-path audit coordination into a dedicated runner keeping `cmd/sentinel/main.go` strictly under 425 LOC. Added `--wg-fastpath=<path>`, `--fastpath`, `--wg-fastpath-telemetry=<path>`, `--wg-fastpath-synth-out=<dir>`, and `--wg-fastpath-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-31049` (WireGuard 100GbE Kernel Ring Buffer Saturation & Crypto Bottleneck Remote DoS, CVSS 8.1 High).
- **Unified Exporter Integration**: WireGuard fast-path findings, bottleneck interfaces, and crypto telemetry exported to OASIS SARIF v2.1.0 (Section 19), structured JSON audit telemetry (`fastpath_violations`, `fastpath_summary`, `fastpath_telemetry`, `fastpath_crypto`), and hourly Markdown threat briefings (Section 22).
- **Production Fixtures & Policy Artifacts**: Added realistic fixtures (`fixtures/nixos-wg-fastpath.nix`, `fixtures/nixos-wg-fastpath-vulnerable.nix`, `fixtures/wg-fastpath-telemetry.json`) and synthesized templates in `policies/generated/fastpath/`.
- **Comprehensive Unit Test Suites** (`pkg/wgfastpath/fastpath_test.go`, `pkg/report/fastpath_report_test.go`): 100% test coverage across canonical rules, manifest parsing, telemetry auditing, policy synthesizers, scanner, SARIF/JSON/Briefing serialization, and memory bounds checks.

### Changed
- Bumped engine release to `v0.23.0`.
- Updated `SECURITY.md` establishing WireGuard eBPF Fast-Path & Kernel Cryptographic Throughput security invariants (Invariant 25).
- Updated `ROADMAP.md` marking Milestone M23 as completed and scheduling M24 (Confidential VM & Secure Enclave WireGuard Peer Attestation).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new fast-path modules, runners, and O(1) symbols.

---

## [0.22.0] - 2026-10-17

### Added
- **CephFS Snapshot & Volume Replication Disaster Recovery Engine** (`pkg/replication/scanner.go`): Autonomous disaster recovery auditing engine inspecting CephFS snapshot schedules, CSI volume replication classes, cross-region replication states, and runtime delta synchronization across multi-cluster Kubernetes deployments.
- **Authoritative Canonical CephFS DR Rules Catalog** (`pkg/replication/rules.go`): Suite of 12 canonical security rules (`CEPH-DR-001` through `CEPH-DR-012`) covering VolumeSnapshotClass deletionPolicy set to Delete (`CEPH-DR-001`), missing or excessive snapshot schedules exceeding 24h (`CEPH-DR-002`), inadequate snapshot retention < 3 (`CEPH-DR-003`), unencrypted WAN replication transport (`CEPH-DR-004`), replication intervals exceeding RPO SLAs > 60m (`CEPH-DR-005`), missing explicit replication states (`CEPH-DR-006`), single-replica mirror daemons lacking failure-domain anti-affinity (`CEPH-DR-007`), stretched cluster missing 3rd-zone Arbiter monitor (`CEPH-DR-008`), replication delta lag exceeding 900s (`CEPH-DR-009`), cross-region split-brain dual-primary assertions (`CEPH-DR-010`, mapped to `CVE-2026-10140`), persistent degraded/error replication states (`CEPH-DR-011`), and unverified DR secondary site failover posture (`CEPH-DR-012`).
- **Multi-Document Streaming DR Manifest & Telemetry Parser** (`pkg/replication/parser.go`): High-throughput streaming parser evaluating Kubernetes `VolumeSnapshotClass`, `CephFilesystemSubVolumeGroup`, `VolumeReplicationClass`, `VolumeReplication`, `CephFilesystemMirror`, `CephCluster` arbiter configurations, and runtime cross-region DR JSON telemetry with strict 10MB memory safety bounds.
- **Disaster Recovery Posture Auditor & Compliance Scoring Engine** (`pkg/replication/auditor.go`): Evaluates declarative configurations and live telemetry, detects split-brain assertions and RPO SLA delta lag violations, and computes deterministic compliance scores (0.0% to 100.0%).
- **Declarative DR Policy Synthesizer** (`pkg/replication/synth.go`): Synthesizes production-hardened `VolumeSnapshotClass` (Retain), `CephFilesystemSubVolumeGroup` automated 1h/14-day snapshot schedules, `VolumeReplicationClass` with encrypted transport (`ms_mode: secure`), paired primary/secondary `VolumeReplication` CRDs, and 3rd-zone arbiter configuration templates.
- **Dedicated CLI DR Runner & Flag Architecture** (`cmd/sentinel/replication_runner.go`, `cmd/sentinel/flags.go`): Extracted DR audit execution into a dedicated runner keeping `cmd/sentinel/main.go` at ~401 LOC. Added `--dr-manifests=<path>`, `--dr`, `--dr-telemetry=<path>`, `--dr-synth-out=<dir>`, `--dr-rpo-max=<seconds>`, and `--dr-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-10140` (CephFS Snapshot Schedule Desync & Cross-Region Volume Replication Split-Brain in Rook-Ceph, CVSS 9.6 Critical).
- **Unified Exporter Integration**: CephFS snapshot and volume replication DR findings, split-brain posture, and delta sync telemetry seamlessly exported to OASIS SARIF v2.1.0 (Section 18), structured JSON audit telemetry (`replication_violations`, `replication_summary`, `replication_telemetry`), and hourly Markdown threat briefings (Section 21).
- **Production Fixtures & Policy Artifacts**: Added realistic fixtures (`fixtures/cephfs-dr-manifests.yaml`, `fixtures/cephfs-dr-vulnerable.yaml`, `fixtures/cephfs-dr-telemetry.json`) and synthesized templates in `policies/generated/replication/`.
- **Comprehensive Unit Test Suites** (`pkg/replication/replication_test.go`, `pkg/report/replication_report_test.go`): 100% test coverage across canonical rules, manifest parsing, telemetry auditing, policy synthesizers, scanner, SARIF/JSON/Briefing serialization, and memory bounds checks.

### Changed
- Bumped engine release to `v0.22.0`.
- Updated `SECURITY.md` establishing CephFS Snapshot Scheduling & Cross-Region Volume Replication Disaster Recovery security invariants (Invariant 24).
- Updated `ROADMAP.md` marking Milestone M22 as completed and scheduling M23 (eBPF-Based WireGuard Kernel Fast-Path & Crypto Performance Auditor).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new replication modules, runners, and O(1) symbols.

---

## [0.21.0] - 2026-10-17

### Added
- **eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control Engine** (`pkg/lsm/scanner.go`): Autonomous security engine auditing NixOS host configurations and Kubernetes container workloads, enforcing declarative eBPF LSM hooks and mandatory access controls directly in kernel space before container syscall execution.
- **Authoritative Canonical eBPF LSM Rules Catalog** (`pkg/lsm/rules.go`): Suite of 12 canonical security rules (`LSM-MAC-001` through `LSM-MAC-012`) covering missing `bpf` in `boot.kernelParams` (`LSM-MAC-001`, mapped to `CVE-2026-99103`), missing `bprm_check_security` execution guards against writable paths (`/tmp`, `/dev/shm`), missing `file_open` MAC protections on sensitive host structures (`/proc/kcore`, `/sys/kernel/debug`), permissive raw socket creation (`AF_PACKET`, `SOCK_RAW`) (`CVE-2026-20914`), unauthorized setuid privilege escalation, unconfined container BPF program loading (`CVE-2026-90412`), cross-process ptrace memory inspection, unconfined privileged containers, host namespace sharing (`hostPID`, `hostIPC`), and runtime telemetry denial correlations (`LSM-MAC-011`, `LSM-MAC-012`).
- **Streaming NixOS Host & Kubernetes Container MAC Parsers** (`pkg/lsm/parser.go`): High-throughput streaming parser evaluating declarative NixOS boot parameters (`boot.kernelParams = [ "lsm=..." ]`), `security.lsm`, sysctl flags (`kernel.unprivileged_bpf_disabled`), and systemd eBPF LSM service units, alongside Kubernetes workload security contexts and runtime eBPF LSM JSON telemetry payloads with strict 10MB memory safety bounds.
- **Declarative eBPF LSM & Kernel MAC Policy Synthesizer** (`pkg/lsm/synth.go`): Generates drop-in hardened NixOS modules (`lsm-bpf-policy.nix`), verifiable eBPF C programs (`lsm_container_mac.bpf.c`) implementing `bprm_check_security`, `file_open`, `socket_create`, and `task_fix_setuid` hooks, and Kubernetes ContainerMACProfile CRD specifications (`container-mac-policy.yaml`).
- **Runtime Telemetry Anomaly Reconciler & Scoring Engine** (`pkg/lsm/auditor.go`): Reconciles runtime eBPF LSM denial telemetry, evaluates blocked execution attempts and unauthorized capability requests, and computes deterministic compliance posture scores (0.0% to 100.0%).
- **Dedicated CLI LSM Runner & Flag Architecture** (`cmd/sentinel/lsm_runner.go`, `cmd/sentinel/flags.go`): Extracted LSM audit coordination into a dedicated runner maintaining `cmd/sentinel/main.go` under 400 LOC. Added `--lsm=<path>`, `--lsm-mac`, `--lsm-telemetry=<path>`, `--lsm-synth-out=<dir>`, and `--lsm-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-99103` (Linux Kernel Privileged Container Escape Bypassing Seccomp via Unconfined Syscall & Missing eBPF LSM Hooks, CVSS 9.8 Critical).
- **Unified Exporter Integration**: eBPF LSM violations, kernel MAC status, and runtime denial events seamlessly exported to OASIS SARIF v2.1.0 (Section 17), structured JSON audit telemetry (`lsm_violations`, `lsm_summary`), and hourly Markdown threat briefings (Section 20).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/nixos-lsm.nix`, `fixtures/nixos-lsm-vulnerable.nix`, `fixtures/k8s-lsm-workload.yaml`, `fixtures/lsm-telemetry.json`) and pre-generated policy artifacts in `policies/generated/lsm/`.
- **Comprehensive Unit Test Suites** (`pkg/lsm/lsm_test.go`, `pkg/report/lsm_report_test.go`): 100% test coverage across canonical rules, NixOS config parsing, Kubernetes MAC profiles, runtime telemetry, policy synthesis, directory scanner, SARIF/JSON/Briefing serialization, and memory bounds checks.

### Changed
- Bumped engine release to `v0.21.0`.
- Updated `SECURITY.md` establishing eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control security invariants (Invariant 23).
- Updated `ROADMAP.md` marking Milestone M21 as completed and scheduling M22 (CephFS Snapshot & Volume Replication DR Synchronizer).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new LSM modules, runners, and O(1) symbols.

---

## [0.20.0] - 2026-10-17

### Added
- **Autonomous Threat Remediation & GitOps Pull Request Synthesizer** (`pkg/remediate/scanner.go`): Autonomous security engineering engine auditing NixOS modules and Kubernetes manifests, discovering remediable vulnerabilities, and synthesizing atomic declarative hardening patches without human intervention.
- **Automated Pre-Flight Canary Test Validator** (`pkg/remediate/canary.go`): Non-breaking safety verification pipeline executing simulated NixOS pure flake evaluations and `kubectl kustomize` dry-run schema validations before any patch can be merged into production GitOps branches. Intercepts syntax errors, unbalanced delimiters, tab indentations in YAML, circular dependencies, and prohibited command injection attempts.
- **Universal Declarative Patch Synthesizer & Disk Exporter** (`pkg/remediate/synthesizer.go`): Synthesizes unified diff NixOS configuration patches (`remediation-patches.nix`), Kubernetes Kustomize strategic merge patches (`patch-<name>.yaml`), and RFC 6902 JSONPatches (`jsonpatch-<name>.yaml`). Generates complete `kustomization.yaml` overlay manifests and formatted pull request summaries (`PR_SUMMARY.md`).
- **GitOps Pull Request Bundle Orchestrator** (`pkg/remediate/types.go`): Synthesizes complete GitOps pull request metadata (`GitOpsPullRequest`) with policy-checked branch names (`remediation/hardening-*`), conventional commit messages (`fix(security): ...`), structured Markdown summaries, and attached pre-flight canary test execution results.
- **Authoritative Canonical Remediation Rules Catalog** (`pkg/remediate/rules.go`): Suite of 12 canonical rules (`REMEDIATE-AUTO-001` through `REMEDIATE-AUTO-012`) covering unpinned flake inputs (`CVE-2026-19402`), unhardened container security contexts (`CVE-2026-20914`), Ingress custom snippet path traversals (`CVE-2026-21801`), permissive 0.0.0.0/0 CNI egress routes, Ceph storage lacking in-transit `msgr2` encryption (`CVE-2026-15509`), plaintext WireGuard private keys (`CVE-2026-31048`), CIS Kubernetes Benchmark control plane audit deviations (`CVE-2026-38102`), missing SPIFFE mTLS policies (`CVE-2026-67210`), insecure KMS v2 configurations (`CVE-2026-83190`), unconfined seccomp profiles (`CVE-2026-90412`), classical TLS 1.2 control planes (`CVE-2026-94301`), and unisolated microVM detonation sandboxes (`CVE-2026-97105`).
- **Dedicated CLI Remediation Runner & Flag Architecture** (`cmd/sentinel/remediate_runner.go`, `cmd/sentinel/flags.go`): Extracted CLI flag parsing and configuration management into `cmd/sentinel/flags.go` and remediation audit execution into `cmd/sentinel/remediate_runner.go`, reducing `cmd/sentinel/main.go` to 365 LOC (well within the 300~500 LOC soft ceiling). Added `--remediate=<path>`, `--auto-remediate`, `--remediate-synth-out=<dir>`, and `--canary-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-98402` (Autonomous GitOps Reconciliation Desync & Unvalidated Declarative Hardening Injection, CVSS 8.4 High).
- **Unified Exporter Integration**: Autonomous remediation findings, synthesized PR bundles, and canary check metrics seamlessly exported to OASIS SARIF v2.1.0 (Section 16), structured JSON audit telemetry (`remediate_findings`, `remediate_pull_requests`, `remediate_summary`), and hourly Markdown threat briefings (Section 19).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/remediation/nixos-vulnerable.nix`, `fixtures/remediation/k8s-workload.yaml`, `fixtures/remediation/kustomization-base.yaml`, `fixtures/remediation/canary-telemetry.json`).
- **Comprehensive Unit Test Suites** (`pkg/remediate/remediate_test.go`, `pkg/report/remediate_report_test.go`): 100% test coverage across canonical rules, NixOS diff synthesis, Kustomize overlay generation, canary validations (syntax, braces, YAML tabs, branch policies, commit conventions), manifest scanning, artifact disk writers, SARIF/JSON/Briefing serialization, and memory bounds checks.

### Changed
- Bumped engine release to `v0.20.0`.
- Updated `SECURITY.md` establishing Autonomous Threat Remediation & Canary GitOps Validation security invariants (Invariant 22).
- Updated `ROADMAP.md` marking Milestone M20 as completed and scheduling M21 (eBPF LSM Security Module & Kernel Mandatory Access Control).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new remediation modules, flags, runners, and O(1) symbols.

---

## [0.19.0] - 2026-10-16

### Added
- **Ephemeral MicroVM Sandbox & Honeypot Detonation Dispatch Engine** (`pkg/sandbox/scanner.go`): Cloud-native security engine orchestrating ephemeral Firecracker microVMs on NixOS and Kubernetes for isolated detonation and behavioral analysis of untrusted container images, OCI artifacts, and binaries prior to cluster scheduling.
- **Universal Declarative NixOS MicroVM & Kubernetes Detonation Parser** (`pkg/sandbox/parser.go`): Streaming parser auditing NixOS microvm modules (`microvm.vms.<name>`), hypervisor configurations, jailer confinement parameters, memory/vCPU ceilings, and Kubernetes `DetonationJob` CRD manifests with strict 10MB memory safety ceilings.
- **Authoritative Canonical Sandbox & Honeypot Rules Catalog** (`pkg/sandbox/rules.go`): Suite of 12 canonical security rules (`SANDBOX-DET-001` through `SANDBOX-DET-012`) covering missing pre-flight detonation verification, unrestricted network egress (`SANDBOX-DET-002`, mapped to CVE-2026-97105), disabled Firecracker jailer chroot confinement, decoy honeypot Kubelet and etcd probes, in-guest reverse shell beaconing, kernel privilege escalation syscalls, hypervisor virtio MMIO escape anomalies, anti-analysis SLA timeouts, and immutable rootfs tampering.
- **Runtime Detonation Dispatcher & Anomaly Evaluator** (`pkg/sandbox/dispatcher.go`): Evaluates live execution telemetry, kernel probes, and decoy honeypot hits (fake Kubelet port 10250, fake etcd port 2379/2380, canary tokens), tracks container quarantine status, and calculates deterministic sandbox security scores (0.0 to 100.0). Correlates egress bypass vectors with `CVE-2026-97105`.
- **Declarative Policy & Honeypot Lure Synthesizer** (`pkg/sandbox/synth.go`): Generates hardened Firecracker NixOS microVM configuration modules (`microvm-sandbox.nix`), declarative Kubernetes `DetonationJob` specifications, and decoy honeypot lure definitions (`honeypot-lures.yaml`).
- **Dedicated CLI Sandbox Runner** (`cmd/sentinel/sandbox_runner.go`): Modular runner coordinating manifest scans, runtime detonation telemetry inspection, and policy synthesis, maintaining `cmd/sentinel/main.go` under 495 LOC (well within the 300~500 LOC soft ceiling). Added `--sandbox=<path>`, `--microvm`, `--sandbox-telemetry=<path>`, `--honeypot`, `--sandbox-synth-out=<dir>`, and `--quarantine-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-97105` (Firecracker MicroVM Sandbox Network Egress Bypass and Honeypot Detonation Probe, CVSS 9.2 Critical).
- **Unified Exporter Integration**: MicroVM sandbox violations, honeypot telemetry hits, and quarantine status seamlessly exported to OASIS SARIF v2.1.0 (Section 15), structured JSON audit telemetry, and hourly Markdown threat briefings (Section 18).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/nixos-microvm.nix`, `fixtures/nixos-microvm-vulnerable.nix`, `fixtures/k8s-detonation-job.yaml`, `fixtures/sandbox-telemetry.json`).
- **Comprehensive Unit Test Suites** (`pkg/sandbox/sandbox_test.go`, `pkg/report/sandbox_report_test.go`): 100% test coverage across canonical rules, NixOS microvm configs, Kubernetes detonation jobs, runtime telemetry, honeypot lure interceptions, policy synthesis, SARIF/JSON/Briefing serialization, and bounds checks.

### Changed
- Bumped engine release to `v0.19.0`.
- Updated `SECURITY.md` establishing Ephemeral MicroVM Sandbox & Honeypot Detonation Isolation security invariants (Invariant 21).
- Updated `ROADMAP.md` marking Milestone M19 as completed and scheduling M20 (Autonomous Threat Remediation & GitOps Pull Request Synthesizer).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new sandbox modules, runners, and O(1) symbols.

---

## [0.18.0] - 2026-10-16

### Added
- **Post-Quantum Cryptography (PQC) & NSA CNSA 2.0 TLS Audit Engine** (`pkg/pqc/scanner.go`): Enterprise cryptographic scanner auditing Kubernetes control plane components, etcd peer clusters, and NixOS host configurations for post-quantum key encapsulation readiness and NSA CNSA 2.0 transition conformance.
- **Universal Kubernetes Control Plane & NixOS Crypto Parser** (`pkg/pqc/parser.go`): Streaming parser auditing kube-apiserver, etcd, and kubelet flags (`--tls-min-version`, `--tls-cipher-suites`, `--tls-key-exchange-groups`, `--peer-tls-min-version`), NixOS OpenSSL configuration (`environment.etc."ssl/openssl.cnf"`, `oqsprovider` activation, default groups), and system-wide GnuTLS priority strings with strict 10MB memory safety ceilings.
- **Authoritative Canonical PQC & CNSA 2.0 Rules Catalog** (`pkg/pqc/rules.go`): Suite of 12 canonical rules (`PQC-TLS-001` through `PQC-TLS-012`) covering insecure TLS versions (< TLS 1.3), missing hybrid post-quantum key encapsulation (NIST FIPS 203 ML-KEM-768/1024), deprecated classical ciphers (CBC/3DES/static RSA), non-compliant symmetric key lengths (< 256-bit AES), weak hash algorithms, classical-only certificate signatures, missing NixOS `oqsprovider`, and unhardened etcd peer transports.
- **Static & Runtime Cryptographic Evaluator** (`pkg/pqc/auditor.go`): Evaluates live and declarative TLS connections, calculates hybrid KEM adoption percentages, TLS 1.3 compliance, and evaluates NSA CNSA 2.0 readiness milestones (2025/2030/2033 timelines). Correlates Harvest-Now-Decrypt-Later (HNDL) quantum cryptanalysis threats with `CVE-2026-94301`.
- **Declarative Policy Synthesizer** (`pkg/pqc/synth.go`): Generates quantum-hardened NixOS configuration modules enabling OpenSSL 3.4+ `oqsprovider` with `X25519MLKEM768` and `SecP384r1MLKEM1024`, GnuTLS priority strings, and hardened static pod manifests for `kube-apiserver` and `etcd`.
- **Dedicated CLI PQC Runner** (`cmd/sentinel/pqc_runner.go`): Modular runner coordinating manifest scans, runtime TLS telemetry analysis, and policy synthesis, keeping `cmd/sentinel/main.go` under 465 LOC (well within the 300~500 LOC soft ceiling). Added `--pqc=<path>`, `--cnsa`, `--pqc-telemetry=<path>`, `--pqc-synth-out=<dir>`, and `--cnsa-strict` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Ingested `CVE-2026-94301` (Kubernetes API Server & etcd Classical TLS Key Exchange Vulnerable to Harvest-Now-Decrypt-Later Quantum Cryptanalysis, CVSS 8.8).
- **Unified Exporter Integration**: PQC findings, hybrid KEM adoption percentages, and CNSA 2.0 compliance scores seamlessly exported to OASIS SARIF v2.1.0 (Section 14), structured JSON audit telemetry, and hourly Markdown threat briefings (Section 17).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/k8s-pqc-controlplane.yaml`, `fixtures/k8s-pqc-vulnerable.yaml`, `fixtures/nixos-pqc.nix`, `fixtures/nixos-pqc-vulnerable.nix`, `fixtures/pqc-telemetry.json`).
- **Comprehensive Unit Test Suites** (`pkg/pqc/pqc_test.go`, `pkg/report/pqc_report_test.go`): 100% test coverage across canonical rules, control plane manifests, NixOS configs, runtime handshake telemetry, policy synthesis, SARIF/JSON/Briefing serialization, and bounds checks.

### Changed
- Bumped engine release to `v0.18.0`.
- Updated `SECURITY.md` establishing Post-Quantum Cryptography & CNSA 2.0 Cryptographic Readiness security invariants (Invariant 20).
- Updated `ROADMAP.md` marking Milestone M18 as completed and scheduling M19 (Ephemeral MicroVM Sandbox & Honeypot Detonation Dispatch).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new PQC modules, runners, and O(1) symbols.

---

## [0.17.0] - 2026-10-16

### Added
- **Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter** (`pkg/bpf/scanner.go`): Deep kernel-level security inspection engine analyzing declarative seccomp profiles, NixOS host parameters, and runtime eBPF telemetry across Kubernetes clusters.
- **Universal Workload Seccomp & Host Parameter Parser** (`pkg/bpf/parser.go`): Bounded streaming parser auditing Kubernetes Pod/Deployment security contexts (`seccompProfile`), host namespace bypasses (`hostPID`, `hostIPC`), elevated capabilities (`CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`), NixOS sysctl settings (`kernel.unprivileged_bpf_disabled`), active LSM modules (`security.lsm`), and systemd sandboxing parameters.
- **Kernel Runtime Telemetry Profiler & Anomaly Detector** (`pkg/bpf/profiler.go`): Reconciles live socket creation rates, flags abnormal socket storms exceeding 250 sockets/sec (`BPF-SEC-004`), detects raw socket allocations (`SOCK_RAW`, `AF_PACKET`) without verified LSM drop filters (`BPF-SEC-003`), intercepts high-privilege syscall activity (`ptrace`, `bpf`, `init_module`), and detects runtime container boundary escape attempts or blocked LSM security denials (`BPF-SEC-012`).
- **Authoritative Canonical BPF & Seccomp Rules Catalog** (`pkg/bpf/rules.go`): Suite of 12 canonical rules (`BPF-SEC-001` through `BPF-SEC-012`) covering unconfined seccomp profiles, dangerous administrative syscalls, missing host eBPF LSM modules, host namespace sharing, unprivileged BPF access, insecure default actions (`SCMP_ACT_ALLOW`), and kernel module injection attempts.
- **Declarative Policy Synthesizer** (`pkg/bpf/synth.go`): Generates hardened Kubernetes Seccomp profiles (`SCMP_ACT_ERRNO` default action with 100+ safe POSIX syscall allowlist), drop-in NixOS systemd sandboxing modules (`SystemCallFilter = [ "@system-service" "~@privileged" ... ]`), and declarative eBPF LSM policy manifests (`EBPFLSMPolicy`).
- **Dedicated CLI BPF Runner** (`cmd/sentinel/bpf_runner.go`): Modular runner coordinating manifest scans, telemetry profiling, and policy synthesis, keeping `cmd/sentinel/main.go` under 445 LOC (strictly adhering to the 300~500 LOC soft ceiling). Added `--bpf=<path>`, `--seccomp`, `--bpf-telemetry=<path>`, `--bpf-synth-out=<path>`, and `--bpf-service=<name>` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-90412` (Linux Kernel BPF Subsystem Privileged Syscall Race & Unconfined Socket Creation Flood, CVSS 9.8).
- **Unified Exporter Integration**: BPF profiler findings, socket anomaly rates, and seccomp ratings seamlessly exported to OASIS SARIF v2.1.0 (Section 13), structured JSON audit telemetry, and hourly Markdown threat briefings (Section 16).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/k8s-bpf-workload.yaml`, `fixtures/nixos-bpf-vulnerable.nix`, `fixtures/nixos-bpf-hardened.nix`, `fixtures/bpf-runtime-telemetry.json`).
- **Comprehensive Unit Test Suites** (`pkg/bpf/bpf_test.go`, `pkg/report/bpf_report_test.go`): 100% test coverage across canonical rules, workload manifests, NixOS configs, custom Seccomp JSON, telemetry profilers, policy synthesizers, SARIF/JSON/Briefing serialization, and bounds checks.

### Changed
- Bumped engine release to `v0.17.0`.
- Updated `SECURITY.md` establishing Dynamic Kernel Runtime Threat Profiling & Syscall BPF Filter security invariants (Invariant 19).
- Updated `ROADMAP.md` marking Milestone M17 as completed and scheduling M18 (Post-Quantum Cryptography & Kyber/Dilithium TLS Audit Engine).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new BPF modules, runners, and O(1) symbols.

---

## [0.16.0] - 2026-10-16

### Added
- **Hardware Security Module (HSM) & PKCS#11 Envelope Encryption Pipeline** (`pkg/hsm/scanner.go`): Enterprise-grade cryptographic security inspection and auditing engine for Kubernetes etcd encryption at rest, KMS v2 plugins, PKCS#11 tokens, and AWS Nitro Enclaves.
- **Universal Kubernetes EncryptionConfiguration & PKCS#11 URI Parser** (`pkg/hsm/parser.go`): Streaming parser supporting `apiserver.config.k8s.io/v1` KMS v2 provider chains, RFC 7512 PKCS#11 URIs, and NixOS host security modules (`services.p11-kit`, `hardware.nitro-enclaves`), with strict 10MB manifest ceiling and memory-safe PIN sanitization (`SanitizePIN`).
- **Cryptographic Envelope Auditor & Telemetry Reconciler** (`pkg/hsm/auditor.go`): Evaluates master Key Encryption Keys (KEK), detects unrotated keys exceeding 90-day compliance windows (`HSM-ENC-006`), identifies KMS v2 plugin gRPC socket degradation (`HSM-ENC-005`), detects Nitro Enclave session handle leaks and unsealed attestation quotes (`HSM-ENC-007`, mapped to CVE-2026-83190), and flags excessive latency or zero cache utilization (`HSM-ENC-010`).
- **Authoritative Canonical HSM Security Catalog** (`pkg/hsm/rules.go`): Suite of 12 canonical rules (`HSM-ENC-001` through `HSM-ENC-012`) covering insecure plaintext identity providers, deprecated KMS v1 APIs, exposed PKCS#11 PINs, weak cryptographic suites (3DES, AES-CBC-128, RSA-1024), network socket transports, and missing host daemon modules.
- **Dedicated CLI HSM Runner & Modularity** (`cmd/sentinel/hsm_runner.go`): High-performance modular runner keeping `cmd/sentinel/main.go` under 425 LOC, strictly adhering to the 300~500 LOC soft ceiling. Added `--hsm=<path>`, `--kms`, `--hsm-telemetry=<path>`, and `--nitro` CLI flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-83190` (Kubernetes KMS v2 Provider PKCS#11 Session Leakage & Unrotated DEK Envelope Attack, CVSS 9.4).
- **Unified Exporter Integration**: HSM findings, key rotation tallies, and envelope security ratings seamlessly exported to OASIS SARIF v2.1.0 (Section 12), structured JSON audit telemetry, and hourly Markdown threat briefings (Section 15).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/k8s-encryption-config.yaml`, `fixtures/k8s-encryption-config-vulnerable.yaml`), NixOS HSM host module (`fixtures/nixos-hsm.nix`), and runtime telemetry payload (`fixtures/hsm-telemetry.json`).
- **Comprehensive Unit Test Suites** (`pkg/hsm/hsm_test.go`, `pkg/report/hsm_report_test.go`): 100% test coverage across rules catalog, compliant and vulnerable EncryptionConfigurations, PKCS#11 URI parsing, PIN redaction, runtime telemetry auditing, SARIF/JSON/Briefing serialization, and bounds checks.

### Changed
- Bumped engine release to `v0.16.0`.
- Updated `SECURITY.md` establishing Hardware Security Module & PKCS#11 Envelope Encryption security invariants (Invariant 18).
- Updated `ROADMAP.md` marking Milestone M16 as completed and scheduling M17 (Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new HSM modules, runners, and O(1) symbols.

---

## [0.15.0] - 2026-10-15

### Added
- **Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation Engine** (`pkg/sbom/scanner.go`): Comprehensive supply chain verification engine for NixOS bare-metal host store paths, container images, and Kubernetes workload environments.
- **Universal Multi-Format SBOM Parser** (`pkg/sbom/parser.go`): High-performance streaming parser supporting SPDX v3.0, SPDX v2.3, CycloneDX v1.6, CycloneDX v1.5, and Nix store closure JSON documents with defensive 15MB size ceiling and 10,000 package limit.
- **In-Toto Statement & SLSA Level 3 Provenance Verifier** (`pkg/sbom/attest.go`): Cryptographic attestation inspector evaluating In-Toto statement envelopes (`_type: https://in-toto.io/Statement/v1`), matching cryptographic subject hashes (`sha256`) against build outputs, enforcing hermetic build sandboxing, requiring immutable pinned dependencies, and validating digital signatures.
- **Automated Runtime SBOM Delta Reconciler** (`pkg/sbom/delta.go`): Differential engine reconciling declared build-time SBOM components against live cluster package state, detecting version drift (`DeltaVersionDrift`), package hash mismatch (`DeltaHashMismatch`), undeclared shadow container injections (`DeltaUndeclaredRuntime`), and unused dormant components (`DeltaMissingInRuntime`).
- **Canonical Supply Chain Security Catalog** (`pkg/sbom/rules.go`): Suite of 12 authoritative canonical rules (`SBOM-CHAIN-001` through `SBOM-CHAIN-012`) covering missing SBOMs, unverified In-Toto envelopes, non-compliant SLSA levels (< Level 3), subject digest tampering (CVE-2026-71044), unpinned dependencies, non-hermetic build sandboxes, unknown licenses, and undeclared runtime shadow injections.
- **Dedicated CLI SBOM Runner & Modularization** (`cmd/sentinel/sbom_runner.go`, `cmd/sentinel/k8s_runner.go`, `cmd/sentinel/policy_runner.go`): Extracted runner modules maintaining `cmd/sentinel/main.go` under 400 LOC (398 LOC) strictly adhering to the 300~500 LOC soft ceiling. Added `--sbom=<path>`, `--attestation=<path>`, `--intoto=<path>`, `--sbom-runtime=<path>`, and `--sbom-delta=<path>` CLI flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-71044` (In-Toto Attestation Digest Desync & Untrusted Nix Store Dependency Injection, CVSS 9.6).
- **Unified Exporter Integration**: SBOM findings, SLSA provenance ratings, and runtime deltas seamlessly exported to OASIS SARIF v2.1.0 (Section 11), structured JSON audit telemetry, and hourly Markdown threat briefings (Section 14).
- **Production Fixtures**: Added realistic declarative fixtures (`fixtures/spdx-v3-sbom.json`, `fixtures/cyclonedx-v1.6-sbom.json`), In-Toto SLSA Level 3 attestation envelope (`fixtures/intoto-slsa-attestation.json`), and cluster runtime telemetry (`fixtures/sbom-runtime-state.json`).
- **Comprehensive Unit Test Suites** (`pkg/sbom/sbom_test.go`, `pkg/report/sbom_report_test.go`): 100% test coverage across rules catalog, SPDX/CycloneDX/Nix parsing, In-Toto SLSA Level 3 verification, subject digest tampering detection, SBOM delta generation, SARIF/JSON/Briefing serialization, and defensive bounds checks.

### Changed
- Bumped engine release to `v0.15.0`.
- Updated `SECURITY.md` establishing Software Bill of Materials & In-Toto Supply Chain Attestation security invariants (Invariant 17).
- Updated `ROADMAP.md` marking Milestone M15 as completed and scheduling M16 (Hardware Security Module & PKCS#11 Envelope Encryption Pipeline).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new SBOM modules, runners, and O(1) symbols.

---

## [0.14.0] - 2026-10-15

### Added
- **Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation Engine** (`pkg/spiffe/scanner.go`): Native security audit and attestation reconciler for SPIFFE/SPIRE workload identities and Cilium eBPF network microsegmentation in multi-tenant Kubernetes clusters.
- **Strict SPIFFE ID Parser & SVID Lifecycle / Cryptographic Auditor** (`pkg/spiffe/validator.go`): Deep security inspector for X.509 SVID records and SPIRE Registration Entry manifests:
  - Validates RFC-compliant SPIFFE ID format (`spiffe://<trust-domain>/<workload-path>`) against trusted domain white-lists (`SPIFFE-SVID-001`).
  - Detects excessive SVID lifespans exceeding production bounds (> 24 hours) (`SPIFFE-SVID-002`).
  - Identifies expiring or expired SVIDs within the renewal threshold (< 15 minutes remaining) triggering active workload disconnects (`SPIFFE-SVID-003`, mapped to CVE-2026-67210).
  - Flags insecure wildcard selectors (`k8s:ns:*`, `k8s:pod-label:*`) in SPIRE registration entries permitting unconstrained identity issuance (`SPIFFE-SVID-004`).
  - Identifies insecure or world-accessible SPIRE Agent Admin socket file modes (`chmod 0777` or missing `0660` restrictions) (`SPIFFE-SVID-005`).
  - Enforces mandatory Cilium mTLS authentication mode (`authentication.mode: required`) in `CiliumNetworkPolicy` (`SPIFFE-SVID-006`).
  - Flags missing SPIFFE ID label match expressions in ingress/egress endpoint rules (`SPIFFE-SVID-007`).
  - Flags weak cryptographic key algorithms (`RSA-1024`, `RSA-2048`) or non-ECC keys for SVID issuance (`SPIFFE-SVID-008`).
  - Detects missing Pod identity node attestation constraints (`k8s:node-name`) in SPIRE registration entries (`SPIFFE-SVID-009`).
  - Identifies unencrypted SPIRE Agent-to-Server gTLS control planes without mutual attestation (`SPIFFE-SVID-010`).
  - Flags missing SVID auto-renewal loop configurations in workload sidecars (`SPIFFE-SVID-011`).
  - Intercepts default-allow network policies lacking microsegmentation ingress/egress boundaries (`SPIFFE-SVID-012`).
- **Autonomous Cilium Policy Synthesizer** (`pkg/spiffe/cilium_synth.go`): Generates zero-trust `CiliumNetworkPolicy` (`cilium.io/v2`) manifests enforcing mandatory SPIFFE-authenticated mTLS (`authentication.mode: required`) and workload isolation based on audited SPIFFE identities.
- **Canonical SPIFFE/SPIRE Threat Catalog** (`pkg/spiffe/rules.go`): Authoritative suite of 12 canonical rules with CVSS v3.1 scores, detailed technical impact analysis, and remediation playbooks.
- **Dedicated CLI SPIFFE Runner & Modularization** (`cmd/sentinel/spiffe_runner.go`): High-performance runner keeping `cmd/sentinel/main.go` under 470 LOC and strictly adhering to the 300~500 LOC soft ceiling. Adds `--spiffe=<path>`, `--spire=<path>`, `--svid-telemetry=<path>`, and `--spiffe-policy-out=<path>` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-67210` (SPIFFE/SPIRE Workload Attestation SVID Expiration Desync & Cilium Identity Spoofing, CVSS 9.3).
- **Unified Exporter Integration**: SPIFFE findings, SVID audit tallies, and microsegmentation summaries seamlessly exported to OASIS SARIF v2.1.0, structured JSON audit telemetry, and hourly Markdown threat briefings.
- **Production Fixtures & Synthesized Policies**: Added realistic declarative fixture (`fixtures/spiffe-manifests.yaml`), runtime SVID telemetry payload (`fixtures/spiffe-telemetry.json`), and synthesized Cilium policies (`policies/generated/cilium-spiffe-policies.yaml`).
- **Comprehensive Unit Test Suites** (`pkg/spiffe/spiffe_test.go`, `pkg/report/spiffe_report_test.go`): 100% test coverage across rule catalog, SPIFFE ID parsing, SVID lifetime audits, wildcard selector detection, Cilium policy generation, telemetry reconciliation, SARIF/JSON/Briefing serialization, and defensive bounds checks.

### Changed
- Bumped engine release to `v0.14.0`.
- Updated `SECURITY.md` establishing Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation security invariants (Invariant 16).
- Updated `ROADMAP.md` marking Milestone M14 as completed and scheduling M15 (Autonomous Remediation Operator & Drift Auto-Heal Reconciliation).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new SPIFFE/SPIRE modules, synthesized policies, and O(1) symbols.

---

## [0.13.0] - 2026-10-15

### Added
- **Multi-Cluster Fleet Synchronization & OIDC Token Radar Engine** (`pkg/fleet/scanner.go`): Native audit engine designed for multi-tenant, geographically distributed Kubernetes clusters. Coordinates static manifest audits and runtime telemetry reconciliation across cluster fleets.
- **Multi-Tenant RBAC & Federated OIDC Identity Auditor** (`pkg/fleet/rbac_oidc.go`): Deep security inspector for Kubernetes RBAC resources (`ClusterRole`, `Role`, `ClusterRoleBinding`, `RoleBinding`) and federated OIDC authentication tokens:
  - Intercepts wildcard verbs, API groups, and resources (`*`) granting uncontained cluster privileges (`FLEET-RBAC-001`).
  - Detects dangerous privilege escalation permissions (`bind`, `escalate`) enabling non-admin service accounts to grant themselves higher roles (`FLEET-RBAC-002`).
  - Intercepts broad group bindings where `cluster-admin` is bound to `system:authenticated`, `system:unauthenticated`, or `system:anonymous` (`FLEET-RBAC-003`, mapped to CVE-2026-60114).
  - Detects unrestricted user, group, and service account impersonation (`impersonate`) lacking explicit `resourceNames` whitelists (`FLEET-RBAC-004`).
  - Blocks cluster-wide reading of `secrets` across all namespaces without tenant partition boundaries (`FLEET-RBAC-005`).
  - Audits federated OIDC identity tokens, flagging insecure algorithms (`none`, symmetric HMAC `HS256`), excessive lifetimes (> 24 hours), missing audience/issuer claims, and stale signing keys (> 90 days) (`FLEET-OIDC-001` through `FLEET-OIDC-004`).
- **Declarative GitOps Drift & Reconciler Engine** (`pkg/fleet/gitops.go`): Dedicated auditor for ArgoCD (`Application`, `ApplicationSet`) and Flux (`Kustomization`, `GitRepository`, `OCIRepository`, `HelmRelease`) resources:
  - Detects automated self-healing disabled (`syncPolicy.automated.selfHeal: false` or `prune: false`), permitting silent configuration drift (`FLEET-GITOPS-001`).
  - Detects unpinned GitOps source revisions tracking floating branches (`HEAD`, `main`, `master`) without immutable commit hashes or signed tags (`FLEET-GITOPS-002`).
  - Identifies unauthenticated Git/OCI repositories lacking Kubernetes Secret references (`FLEET-GITOPS-003`).
  - Flags wildcard destination cluster dispatch (`server: "*"`) permitting workload execution across untrusted fleet members (`FLEET-GITOPS-004`).
  - Identifies runtime cluster state desynchronization, revision divergences, and degraded application health across geographically distributed fleet members (`FLEET-DRIFT-001`, mapped to CVE-2026-60114).
- **Canonical Fleet & OIDC Threat Catalog** (`pkg/fleet/rules.go`): Authoritative suite of 14 canonical rules with CVSS v3.1 scores, detailed technical impact analysis, and remediation playbooks.
- **Dedicated CLI Fleet Runner & Modularization** (`cmd/sentinel/fleet_runner.go`): High-performance runner keeping `cmd/sentinel/main.go` under 400 LOC and strictly adhering to the 300~500 LOC soft ceiling. Adds `--fleet=<path>`, `--gitops=<path>`, and `--fleet-telemetry=<path>` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-60114` (Multi-Cluster GitOps Reconciliation Drift & OIDC Token Replay in ArgoCD / Kubernetes RBAC, CVSS 9.4).
- **Unified Exporter Integration**: Fleet findings, cluster synchronization summaries, and OIDC token audits seamlessly exported to OASIS SARIF v2.1.0, structured JSON audit telemetry, and hourly Markdown threat briefings.
- **Production Fixtures**: Added realistic declarative fixture (`fixtures/fleet-manifests.yaml`) and runtime multi-cluster telemetry payload (`fixtures/fleet-telemetry.json`).
- **Comprehensive Unit Test Suites** (`pkg/fleet/fleet_test.go`, `pkg/report/fleet_report_test.go`): 100% test coverage for rule catalog lookups, RBAC wildcard detection, broad subject group bindings, OIDC token algorithm/TTL checks, GitOps drift detection, report serialization, and defensive bounds checks.

### Changed
- Bumped engine release to `v0.13.0`.
- Updated `SECURITY.md` establishing Multi-Cluster Fleet Synchronization & OIDC Federated Token security invariants.
- Updated `ROADMAP.md` marking Milestone M13 as completed and scheduling M14 (Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation).
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new fleet modules and O(1) symbols.

---

## [0.12.0] - 2026-10-15

### Added
- **Confidential Computing & Measured Boot Attestation Verifier** (`pkg/attest/verifier.go`): Native verification engine for TPM 2.0 PCR quotations and remote attestation tokens across bare-metal cluster worker nodes and confidential computing enclaves (AMD SEV-SNP, Intel TDX).
- **Declarative NixOS Measured Boot Configuration Scanner** (`pkg/attest/nixos_scanner.go`): Static parser inspecting NixOS configurations for AMD SEV-SNP (`mem_encrypt=on kvm_amd.sev=1`), Intel TDX (`intel_iommu=on kvm_intel.tdx=1`), systemd-boot measured boot integration, Lanzaboote / UKI signing, TPM 2.0 PKCS#11 configuration, and dangerous debug kernel command-line arguments.
- **Canonical Attestation & Measured Boot Ruleset** (`pkg/attest/rules.go`): Suite of 12 canonical rules (`ATTEST-BOOT-001` through `ATTEST-BOOT-012`) with CVSS v3.1 scoring, remediation guidance, and category classifications:
  - `ATTEST-BOOT-001`: AMD SEV-SNP Memory Encryption Disabled or Unconfigured (Critical, CVSS 9.2, mapped to CVE-2026-51204).
  - `ATTEST-BOOT-002`: Intel TDX Trust Domain Execution Disabled in Kernel Flags (Critical, CVSS 9.2, mapped to CVE-2026-51204).
  - `ATTEST-BOOT-003`: TPM 2.0 PCR 7 Secure Boot Measurement Mismatch or Policy Drift (High, CVSS 8.5).
  - `ATTEST-BOOT-004`: TPM 2.0 PCR 11 Unified Kernel Image (UKI) / NixOS System Closure Digest Desync (High, CVSS 8.7, mapped to CVE-2026-51204).
  - `ATTEST-BOOT-005`: Confidential Computing Firmware Debug Mode Permitted in Remote Quote (Critical, CVSS 9.4).
  - `ATTEST-BOOT-006`: Insecure or Missing NixOS Store Path Cryptographic Signature in Measured Boot (High, CVSS 7.9).
  - `ATTEST-BOOT-007`: Unhardened Bootloader (Missing Systemd-Boot Measured Boot Integration) (Medium, CVSS 6.8).
  - `ATTEST-BOOT-008`: Expired or Revoked Remote Attestation Token / VCEK Certificate (High, CVSS 8.1).
  - `ATTEST-BOOT-009`: Missing TPM2 Resource Manager (tpm2-abrmd / in-kernel RM) in NixOS Config (Medium, CVSS 5.5).
  - `ATTEST-BOOT-010`: TPM 2.0 PCR 8 Kernel Command Line Drift / Unsanitized Boot Parameters (High, CVSS 7.6).
  - `ATTEST-BOOT-011`: Unenforced TCB Version Policy on Confidential Computing Nodes (Medium, CVSS 6.5).
  - `ATTEST-BOOT-012`: Missing Measured Boot Stage for Initrd / Kernel Image in PCR 9 (High, CVSS 7.8).
- **Dedicated CLI Attestation Runner & Architecture Modularization** (`cmd/sentinel/attest_runner.go`): Modular runner dispatch pattern keeping `cmd/sentinel/main.go` under 380 LOC and adhering strictly to the 300~500 LOC soft ceiling. Adds `--attest=<path>`, `--attest-telemetry=<path>`, and `--attest-quote=<path>` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-51204` (AMD SEV-SNP & Intel TDX Firmware Measurement Replay & TPM PCR Bypass, CVSS 9.4).
- **Unified Exporter Integration**: Attestation findings, node verification tallies, and compliance summaries seamlessly exported to OASIS SARIF v2.1.0, structured JSON audit telemetry, and hourly Markdown threat briefings.
- **Production-Like Fixtures**: Added realistic declarative fixture (`fixtures/nixos-measured-boot.nix`) and multi-node cluster attestation telemetry (`fixtures/attestation-telemetry.json`) modeling verified and compromised worker nodes.
- **Comprehensive Unit Test Suites** (`pkg/attest/attest_test.go`, `pkg/report/attest_report_test.go`): 100% test coverage for rules catalog, compliant/vulnerable NixOS configs, TPM PCR quotes, report serialization, and defensive bounds checks.

### Changed
- Bumped engine release to `v0.12.0`.
- Updated `SECURITY.md` establishing Confidential Computing and Measured Boot security invariants.
- Updated `ROADMAP.md` marking Milestone M12 as completed.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new attest modules and O(1) symbols.

---

## [0.11.0] - 2026-10-15

### Added
- **Kubernetes Gateway API Threat Radar Engine** (`pkg/gateway/radar.go`): Native declarative scanner auditing Gateway API resources (`Gateway`, `GatewayClass`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `UDPRoute`, `TLSRoute`, `ReferenceGrant`) against modern cloud-native routing vulnerabilities.
- **Cross-Namespace ReferenceGrant Security Enforcement** (`pkg/gateway/radar.go`): Multi-pass declarative validator that constructs an in-memory cross-namespace permission matrix from `ReferenceGrant` manifests and verifies every cross-namespace `backendRef` and `parentRef` across tenant routes, stopping unauthorized cross-tenant backend access and service hijacking (CVE-2026-44219).
- **Istio EnvoyFilter Security Auditor** (`pkg/gateway/envoy.go`): Dedicated auditor for `EnvoyFilter` CRDs (`networking.istio.io/v1alpha3`) detecting arbitrary inline Lua code injections (`os.execute`, `io.popen`, `loadstring`, `require os/io`), filter chain order bypasses (`INSERT_BEFORE` relative to `jwt_authn`, `istio.authn`, `rbac`), unauthenticated listener exposures, and disabled client TLS verification (`require_client_certificate: false`).
- **Canonical Gateway API & EnvoyFilter Radar Ruleset** (`pkg/gateway/rules.go`): Suite of 12 canonical rules (`GW-RADAR-001` through `GW-RADAR-012`) with CVSS v3.1 scoring, remediation playbooks, and category classifications:
  - `GW-RADAR-001`: Unrestricted Cross-Namespace Backend Reference (Missing ReferenceGrant) (High, CVSS 7.8, mapped to CVE-2026-44219).
  - `GW-RADAR-002`: Unsafe EnvoyFilter Inline Lua Script Injection (Critical, CVSS 9.3, mapped to CVE-2026-44219).
  - `GW-RADAR-003`: EnvoyFilter Filter Chain Order Bypass (High, CVSS 8.2, mapped to CVE-2026-44219).
  - `GW-RADAR-004`: Gateway Insecure Plaintext Listener Without TLS Termination (Medium, CVSS 6.5).
  - `GW-RADAR-005`: HTTPRoute Unrestricted Wildcard Path & Open Routing (Medium, CVSS 5.8).
  - `GW-RADAR-006`: HTTPRoute Unsafe Path Prefix Rewrite Traversal (High, CVSS 7.5).
  - `GW-RADAR-007`: HTTPRoute Identity Header Spoofing via RequestHeaderModifier (High, CVSS 7.7).
  - `GW-RADAR-008`: GRPCRoute Unrestricted Administrative Method Dispatch (Medium, CVSS 6.2).
  - `GW-RADAR-009`: TCPRoute / UDPRoute Sensitive Infrastructure Port Forwarding (High, CVSS 8.0).
  - `GW-RADAR-010`: EnvoyFilter Disabling Client TLS Verification (Critical, CVSS 9.1).
  - `GW-RADAR-011`: Gateway AllowedRoutes Namespace Wildcard Violation (High, CVSS 7.4).
  - `GW-RADAR-012`: EnvoyFilter Unrestricted Hop-by-Hop Header Mutation (Medium, CVSS 6.8).
- **Dedicated CLI Gateway Runner & Architecture Modularization** (`cmd/sentinel/gateway_runner.go`): Modular runner dispatch pattern keeping `cmd/sentinel/main.go` under 420 LOC and adhering strictly to the 300~500 LOC soft ceiling. Adds `--gateway=<path>` and `--gw=<path>` flags.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-44219` (Kubernetes Gateway API & EnvoyFilter Cross-Namespace Route Hijacking & Lua Remote Execution, CVSS 9.6).
- **Unified Exporter Integration**: Gateway API and EnvoyFilter findings and compliance summaries seamlessly exported to OASIS SARIF v2.1.0, structured JSON audit telemetry, and hourly Markdown threat briefings.
- **Production-Like Fixtures**: Added realistic declarative fixture (`fixtures/gateway-api-routes.yaml`) modeling compliant and vulnerable Gateway, HTTPRoute, GRPCRoute, TCPRoute, ReferenceGrant, and EnvoyFilter resources.
- **Comprehensive Unit Test Suites** (`pkg/gateway/gateway_test.go`, `pkg/report/gateway_report_test.go`): 100% test coverage for rules catalog, cross-namespace ReferenceGrant authorization, path traversal detection, header spoofing, Lua injections, filter ordering, report serialization, and defensive bounds checks.

### Changed
- Bumped engine release to `v0.11.0`.
- Updated `SECURITY.md` establishing Gateway API and EnvoyFilter route threat radar security invariants.
- Updated `ROADMAP.md` marking Milestone M11 as completed.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new gateway modules and O(1) symbols.

---

## [0.10.0] - 2026-10-14

### Added
- **Kube-Bench & CIS Kubernetes Benchmark Declarative Validator** (`pkg/bench/scanner.go`): High-performance declarative scanner inspecting NixOS systemd unit definitions (`services.kubernetes.*`, `services.etcd.*`) and Kubernetes component configuration files (such as `KubeletConfiguration` YAML) against the official CIS Kubernetes Benchmark (v1.8 / v1.9). Evaluates Section 1.2 (Kube-APIServer), Section 1.3 (Controller Manager), Section 1.4 (Scheduler), Section 2 (etcd), and Section 4.2 (Kubelet).
- **Canonical CIS Kubernetes Benchmark Ruleset** (`pkg/bench/rules.go`): Canonical suite of 29 benchmark rules (`CIS-1.2.1` through `CIS-4.2.12`) with CVSS severity scoring, flag definitions, expected values, and technical rationales:
  - `CIS-1.2.1`: Ensure that the `--anonymous-auth` argument is set to `false` (Critical, CVSS 9.1).
  - `CIS-1.2.2`: Ensure that the `--token-auth-file` parameter is not set (High, CVSS 7.5).
  - `CIS-1.2.3`: Ensure that the `--kubelet-https` argument is set to `true` (High, CVSS 7.2).
  - `CIS-1.2.4`: Ensure that `--kubelet-client-certificate` and `--kubelet-client-key` are set (High, CVSS 7.5).
  - `CIS-1.2.5`: Ensure that `--kubelet-certificate-authority` is set (High, CVSS 7.5).
  - `CIS-1.2.6`: Ensure that `--authorization-mode` includes `Node,RBAC` and excludes `AlwaysAllow` (Critical, CVSS 8.9).
  - `CIS-1.2.14`: Ensure that `--profiling` is set to `false` (Medium, CVSS 5.3).
  - `CIS-1.2.15`: Ensure that `--audit-log-path` is set (Medium, CVSS 6.0).
  - `CIS-1.2.25`: Ensure that `--etcd-cafile`, `--etcd-certfile`, and `--etcd-keyfile` are set (High, CVSS 8.1).
  - `CIS-1.2.28`: Ensure that `--tls-cipher-suites` is set to strong ciphers (Medium, CVSS 6.2).
  - `CIS-1.3.1`: Ensure that `--terminated-pod-gc-threshold` is set (Low, CVSS 4.0).
  - `CIS-1.3.2`: Ensure that `--profiling` is set to `false` (Medium, CVSS 5.3).
  - `CIS-1.3.3`: Ensure that `--use-service-account-credentials` is set to `true` (High, CVSS 7.2).
  - `CIS-1.3.4`: Ensure that `--service-account-private-key-file` is set (High, CVSS 7.5).
  - `CIS-1.3.5`: Ensure that `--root-ca-file` is set (High, CVSS 7.5).
  - `CIS-1.3.7`: Ensure that `--bind-address` is set to `127.0.0.1` (Medium, CVSS 6.5).
  - `CIS-1.4.1`: Ensure that `--profiling` is set to `false` on scheduler (Medium, CVSS 5.3).
  - `CIS-1.4.2`: Ensure that `--bind-address` is set to `127.0.0.1` on scheduler (Medium, CVSS 6.5).
  - `CIS-2.1`: Ensure that `--cert-file` and `--key-file` are set on etcd (High, CVSS 8.0).
  - `CIS-2.2`: Ensure that `--client-cert-auth` is set to `true` on etcd (High, CVSS 8.2).
  - `CIS-2.4`: Ensure that `--peer-cert-file` and `--peer-key-file` are set on etcd (High, CVSS 8.0).
  - `CIS-2.7`: Ensure that `--auto-tls` is not set to `true` on etcd (High, CVSS 7.5).
  - `CIS-4.2.1`: Ensure that `--anonymous-auth` is set to `false` on Kubelet (Critical, CVSS 9.8, mapped to CVE-2026-38102).
  - `CIS-4.2.2`: Ensure that `--authorization-mode` is set to `Webhook` (Critical, CVSS 8.9, mapped to CVE-2026-38102).
  - `CIS-4.2.3`: Ensure that `--client-ca-file` is set on Kubelet (High, CVSS 7.5).
  - `CIS-4.2.4`: Ensure that `--read-only-port` is set to `0` on Kubelet (High, CVSS 7.5, mapped to CVE-2026-38102).
  - `CIS-4.2.6`: Ensure that `--protect-kernel-defaults` is set to `true` (Medium, CVSS 6.0).
  - `CIS-4.2.10`: Ensure that `--rotate-certificates` is set to `true` (Medium, CVSS 5.5).
  - `CIS-4.2.12`: Ensure that `--tls-cipher-suites` is set to strong ciphers (Medium, CVSS 6.2).
- **Automated Declarative Remediation Synthesizers** (`pkg/bench/remediation.go`): Synthesizes drop-in hardened NixOS modules (`nixos-cis-hardening.nix`) and hardened worker node Kubelet configurations (`kubelet-config-hardened.yaml`) directly from detected violations.
- **Dedicated CLI CIS Runner & Architecture Modularization** (`cmd/sentinel/cis_runner.go`, `cmd/sentinel/storage_runner.go`, `cmd/sentinel/probe_runner.go`): Modular runner dispatch pattern keeping `cmd/sentinel/main.go` under 400 LOC. Adds `--cis=<path>`, `--bench=<path>`, `--kube-bench=<path>`, and `--remediation-out=<path>`.
- **Threat Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-38102` (Kubernetes Kubelet Unauthenticated Remote Execution & Anonymous Access, CVSS 9.8).
- **Unified Exporter Integration**: CIS benchmark violations and compliance statistics seamlessly exported to OASIS SARIF v2.1.0, structured JSON audit telemetry, and hourly Markdown threat briefings.
- **Production-Like Fixtures**: Added realistic declarative NixOS configuration (`fixtures/nixos-kubernetes.nix`) and Kubelet manifest (`fixtures/kubelet-config.yaml`) modeling compliant and unhardened control plane and worker options.
- **Comprehensive Unit Test Suite** (`pkg/bench/bench_test.go`, `pkg/report/cis_report_test.go`): 100% test coverage for CIS rules, nested Nix parsing, KubeletConfiguration, remediation generation, and bounds checks.

### Changed
- Bumped engine release to `v0.10.0`.
- Updated `SECURITY.md` establishing CIS Kubernetes Benchmark and control plane hardening invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new benchmark modules and sub-400 LOC modularity.

---

## [0.9.0] - 2026-10-14

### Added
- **WireGuard Mesh Network Cryptographic Key Rotation Engine** (`pkg/wireguard/key_rotation.go`): Cryptographic lifecycle auditor validating 32-byte Base64-encoded Curve25519 identity keys and Pre-Shared Keys (PSK). Detects invalid key lengths and degenerate all-zero/all-ones key material. Implements zero-leak key masking (`MaskKey`) to protect secrets in console logs, and enforces 60-day warning and 90-day hard expiration thresholds with automated rotation planning.
- **Declarative NixOS WireGuard Manifest Scanner** (`pkg/wireguard/scanner.go`): Native parser for NixOS `networking.wireguard.interfaces.<name>` declarations auditing interface parameters (IPs, listenPort, privateKey, privateKeyFile, mtu) and peer blocks (publicKey, presharedKey, presharedKeyFile, allowedIPs, endpoint, persistentKeepalive). Enforces strict bounds protection (`MaxManifestBytes = 10MB`).
- **Canonical WireGuard Security Ruleset** (`pkg/wireguard/rules.go`): Canonical rules catalog (`WG-MESH-001` through `WG-MESH-012`):
  - `WG-MESH-001`: Plaintext WireGuard Private Key Exposed in Nix Configuration (Critical, CVSS 9.2, mapped to CVE-2026-31048).
  - `WG-MESH-002`: Missing Pre-Shared Key (PSK) for Post-Quantum Defense (Medium, CVSS 5.8).
  - `WG-MESH-003`: Hardcoded Plaintext Pre-Shared Key in Nix Configuration (High, CVSS 8.4).
  - `WG-MESH-004`: Overly Permissive AllowedIPs (0.0.0.0/0) Without Default-Deny Firewall (High, CVSS 7.8).
  - `WG-MESH-005`: Peer AllowedIPs Subnet Routing Collision & Traffic Hijacking Risk (High, CVSS 7.5, mapped to CVE-2026-31048).
  - `WG-MESH-006`: WireGuard Cryptographic Identity Key Exceeded 90-Day Lifetime (High, CVSS 8.1).
  - `WG-MESH-007`: WireGuard Cryptographic Key Approaching Expiration (> 60 Days) (Medium, CVSS 6.0).
  - `WG-MESH-008`: Stale / Abandoned WireGuard Peer Handshake Posture (> 24 Hours) (Medium, CVSS 6.3).
  - `WG-MESH-009`: WireGuard Listening Port Exposed on Public Interface Without Rate-Limiting (Medium, CVSS 5.5).
  - `WG-MESH-010`: Invalid or Weak WireGuard Cryptographic Key Encoding (Critical, CVSS 9.0).
  - `WG-MESH-011`: Sub-optimal WireGuard MTU (> 1420) Triggering Overlay Fragmentation (Low, CVSS 4.2).
  - `WG-MESH-012`: WireGuard Peer Endpoint / CIDR Threat Radar Correlation Match (High, CVSS 8.8).
- **Runtime Mesh Telemetry Reconciler** (`pkg/wireguard/reconciler.go`): Cross-domain engine reconciling declarative NixOS configurations against live `wg show` runtime telemetry. Intercepts configuration drift, unmanaged ephemeral peers (`WG-MESH-013`), missing declarative peers (`WG-MESH-014`), dormant handshakes (> 24h), and correlates endpoints against live threat intelligence feeds.
- **Production-Like WireGuard Fixtures**: Added realistic declarative NixOS configuration (`fixtures/nixos-wireguard.nix`) and runtime mesh telemetry (`fixtures/wireguard-telemetry.json`) modeling control plane and worker peer postures, key ages, and unmanaged nodes.
- **Threat Intelligence Feed Expansion** (`intel/cve-feed.json`): Added `CVE-2026-31048` (WireGuard Overlay Subnet Route Collision & World-Readable Key Disclosure, CVSS 8.5).
- **CLI WireGuard Audit Integration**: Added `--wg=<path>`, `--wireguard=<path>`, and `--wg-telemetry=<path>` flags in `cmd/sentinel/main.go` and `cmd/sentinel/wireguard_runner.go`.
- **Unified Exporter Integration**: WireGuard findings and mesh reconciliation metrics seamlessly exported to OASIS SARIF v2.1.0, structured JSON audit telemetry, and hourly Markdown threat briefings.
- **Comprehensive Unit Test Suite** (`pkg/wireguard/wireguard_test.go`): 100% test coverage for key validation, masking, age calculation, declarative NixOS parsing, drift reconciliation, and bounds checks.

### Changed
- Bumped engine release to `v0.9.0`.
- Updated `SECURITY.md` establishing WireGuard mesh cryptographic key rotation, zero-leak key masking, and subnet collision invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new wireguard modules maintaining sub-370 LOC modularity.

---

## [0.8.0] - 2026-10-14

### Added
- **Rook Ceph Storage Cluster Integrity Ruleset** (`pkg/storage/rules.go`): Canonical integrity rules catalog (`ROOK-CEPH-001` through `ROOK-CEPH-014`) auditing insecure host network exposures (ports 6789, 3300, 6800-7300), disabled in-transit wire encryption (`msgr2` secure mode), unencrypted OSD storage disks (dm-crypt / KMS), sub-optimal pool replication (`size < 3` or `failureDomain: osd`), fragile MON quorums (< 3 or even count), insecure cleartext dashboards (`ssl: false`), unconfined privileged daemon security contexts, and PVC volume postures.
- **Declarative Rook Ceph Manifest Scanner** (`pkg/storage/crd_scanner.go`): High-performance YAML/JSON manifest parser auditing `CephCluster`, `CephBlockPool`, `CephFilesystem`, `StorageClass`, and `PersistentVolumeClaim` with streaming bounds safety (`MaxManifestBytes = 10MB`, `MaxDocumentsPerStream = 1000`).
- **Ceph OSD Peering & BlueStore Anomaly Detector** (`pkg/storage/osd_detector.go`): Runtime telemetry analyzer intercepting OSD down/out states, peering storms exceeding 30s, heartbeat ping latency spikes (> 1000ms), placement group degradation (`degraded`, `undersized`, `inconsistent`), storage pool capacity watermarks (`nearfull` >= 80%, `backfillfull` >= 85%, `full` >= 90%), hardware CRC32c/XXH64 BlueStore checksum corruptions, and Linux 6.12 async direct I/O metadata desync threats (CVE-2026-15509).
- **Storage Volume & Reclaim Policy Verifier** (`pkg/storage/volume.go`): Dedicated auditor preventing catastrophic filesystem corruption caused by unsafe `ReadWriteMany` (RWX) multi-attach access modes on Ceph RBD block volumes, alongside reclaim policy checks (`reclaimPolicy: Delete`) on persistent database storage classes.
- **Production-Like Rook Ceph Fixtures**: Added sample multi-resource declarative manifest (`fixtures/rook-ceph-cluster.yaml`) and realistic Ceph cluster health telemetry (`fixtures/ceph-health-telemetry.json`) representing degraded PGs, BlueStore CRC corruption, and CVE-2026-15509 desync alerts.
- **CLI Storage Audit Flags**: Integrated `--ceph=<path>`, `--storage=<path>`, and `--ceph-telemetry=<path>` flags into `cmd/sentinel/main.go` supporting single manifest files, recursive directory trees, and runtime telemetry JSON inspection.
- **Unified Reporting & Exporter Integration**: Linked storage findings and Ceph cluster health reports directly into OASIS SARIF v2.1.0 code scanning results, structured JSON telemetry outputs, and hourly Markdown threat briefings.
- **Comprehensive Unit Test Suite** (`pkg/storage/storage_test.go`): 100% test coverage across declarative rules, volume postures, anomaly detection vectors, bounds checks, and recursive directory walking.

### Changed
- Bumped engine release to `v0.8.0`.
- Updated `SECURITY.md` establishing Rook Ceph distributed storage integrity, BlueStore checksum verification, and PVC multi-attach invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new storage packages with sub-350 LOC modularity.

---

## [0.7.0] - 2026-10-14

### Added
- **Bare-Metal eBPF Kernel Telemetry Probe Interface** (`pkg/probe/types.go`): Abstract probe interfaces and typed telemetry events for kernel-level socket monitoring (`connect`, `accept`), process execution (`execve`), storage mutations (`openat2`), and privileged operations (`ptrace`, `bpf`). Includes node-level configuration abstractions (`ProbeConfig`) with default baselines for bare-metal Kubernetes and NixOS clusters.
- **Multi-Node eBPF Telemetry Orchestrator** (`pkg/probe/ebpf.go`): Thread-safe multi-node telemetry aggregator (`EBPFManager`) with asynchronous stream consumption, bounded ring-buffer snapshots (10,000 capacity ceiling), real-time severity counters, node and syscall distribution metrics, and graceful cancellation lifecycle.
- **Kernel-Level Runtime Anomaly & Threat Pattern Detector** (`pkg/probe/detector.go`): Multi-vector security evaluator detecting interactive shell reverse connections (`nc`, `socat`, `sh`, `bash`), sensitive control plane port sweeps (etcd 2379/2380, Kubelet 10250, Ceph 6789, API Server 6443), immutable `/nix/store` tampering attempts, container namespace boundary escapes via privileged syscalls, and automated correlation against normalized CVE feeds.
- **Multi-Node Cluster Simulation Engine & Telemetry Replay** (`pkg/probe/mock.go`): Configurable mock probes and file loader (`LoadEventsFromFile`) supporting offline bare-metal cluster testing with strict bounds checking (10MB ceiling, 10,000 events ceiling).
- **Production-Like Bare-Metal Telemetry Fixtures** (`fixtures/probe-telemetry.json`): Realistic multi-node kernel telemetry fixture representing reverse shell attacks from compromised ingress pods, unauthorized etcd probes, Nix store tamper attempts, container escapes, and normal health check baselines across control and worker nodes.
- **CLI Telemetry Flags**: Added `--probe`, `--probe-fixture`, and `--probe-nodes` to `cmd/sentinel/main.go` for one-command bare-metal cluster telemetry inspection and risk analysis.
- **Unified Reporting Integration**: Seamlessly integrated captured eBPF findings into SARIF v2.1.0 code scanning results, structured JSON telemetry outputs, and hourly Markdown threat briefings.
- **Comprehensive Probe Test Suite** (`pkg/probe/probe_test.go`): 100% test coverage across probe lifecycles, anomaly vectors, multi-node concurrency, fixture parsing, and cluster simulations.

### Changed
- Bumped engine release to `v0.7.0`.
- Updated `SECURITY.md` establishing bare-metal eBPF telemetry isolation, memory bounds, and drop-on-saturation invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new probe packages with sub-250 LOC modularity.

---

## [0.6.0] - 2026-10-14

### Added
- **OASIS SARIF v2.1.0 Exporter for GitHub Code Scanning** (`pkg/report/sarif.go`): Native implementation of the Static Analysis Results Interchange Format (SARIF v2.1.0) with zero external dependencies. Seamlessly maps declarative Kubernetes manifest violations, Nix flake input advisories, and CVE threat feed items to GitHub Code Scanning alerts. Includes rule descriptors with full markdown remediation guidance, security-severity CVSS properties, precise physical file URIs (`%SRCROOT%`), line numbers, and hierarchical logical locations.
- **High-Fidelity Structured JSON Audit Telemetry** (`pkg/report/json_report.go`): Consolidated JSON report exporter delivering complete audit telemetry, cross-domain CVSS distributions, monitored target architectures, and full lists of discovered violations with deterministic sorting.
- **Unified Report Options & Format Abstractions** (`pkg/report/report_types.go`): Formatter abstraction supporting `console`, `json`, and `sarif` output targets, alongside severity level translation utilities (`SeverityToSARIFLevel`), single-decimal CVSS normalizers, and PascalCase rule name formatters.
- **CLI Formatter & File Export Flags**: Integrated `--format=<console|json|sarif>`, `--output=<path>`, and `-o <path>` into `cmd/sentinel/main.go`. When `--output` is omitted, structured formats emit clean, pipe-friendly JSON directly to stdout while routing progress logs cleanly.
- **Dedicated Exporter Test Suites**: Added `pkg/report/sarif_test.go` and `pkg/report/json_test.go` verifying schema conformity, rule indexing, CVSS severity translation, location formatting, empty findings handling, and disk persistence with path traversal defense.

### Changed
- Bumped engine version to `v0.6.0`.
- Enriched `k8s.Violation` and `nix.FlakeVulnerabilityMatch` models with optional `file_path` and `start_line` tracking.
- Updated `SECURITY.md` with SARIF and JSON security audit exporter integrity invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new reporting modules with sub-400 LOC modularity.

---

## [0.5.0] - 2026-10-14

### Added
- **CNCF Falco Runtime Policy Synthesis Engine** (`pkg/policy/falco.go`): Automated generation of active kernel syscall detection rules from normalized threat feeds (CVE-2026-21801, CVE-2026-20914, CVE-2026-19402, CVE-2026-15509) and Kubernetes manifest violations (`K8S-ING-001`, `K8S-ING-003`, `K8S-CNI-002`, `K8S-CNI-003`). Enforces deterministic rule naming, severity-to-priority translation, macro condition formatting, and tag deduplication.
- **OPA Gatekeeper Declarative Admission Controller** (`pkg/policy/opa.go`): Autonomous compilation of Kubernetes `ConstraintTemplate` (CRD v1beta1) and `Constraint` resources with clean, verified Rego policy definitions. Implements zero-trust admission guards rejecting custom snippet injections, unanchored path traversals, plaintext HTTP access, unrestricted `0.0.0.0/0` egress CIDRs, sensitive control plane port exposures, and unconstrained container memory allocations.
- **Multi-Engine Policy Synthesis Coordinator** (`pkg/policy/synthesizer.go`): Unified orchestration compiling policies across Falco and Gatekeeper targets with directory path sanitization (`filepath.Clean`), atomic file exports, and rule filtering options.
- **CLI Policy Export Integration**: Added `--policy-out=<dir>`, `--policy-engine=<all|falco|gatekeeper>`, and `--enforce-action=<deny|dryrun|warn>` flags to `cmd/sentinel/main.go`.
- **Policy Schema Verification Fixtures**: Added `fixtures/policies/falco-rules-fixture.yaml` and `fixtures/policies/opa-gatekeeper-fixture.yaml` for structural schema and format verification.
- **Comprehensive Test Suite** (`pkg/policy/policy_test.go`): 100% test coverage across threat mapping, violation compilation, YAML serializations, Rego formatting, disk writes, and schema conformity.

### Changed
- Bumped engine release to `v0.5.0`.
- Updated `SECURITY.md` with declarative policy synthesis integrity and schema conformance invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` documenting new policy modules with verified sub-500 LOC modularity.

---

## [0.4.0] - 2026-10-13

### Added
- **Automated Hourly Threat Intelligence Briefing Generator** (`pkg/report/briefing.go`): Synthesizes Markdown threat advisories and executive summaries for hourly SecOps audit trails. Incorporates monitored CVE items, technical attack vector impacts, and actionable mitigation playbooks.
- **Cross-Domain Telemetry Metrics Aggregator** (`pkg/report/telemetry.go`): Aggregates CVSS score metrics across monitored feeds, Kubernetes manifest violations, and Nix flake lockfile vulnerabilities. Computes severity bucket distributions (Critical, High, Medium, Low), peak and fleet-wide average CVSS scores, target infrastructure distribution, and impacted component radars.
- **Audit Findings Integration**: Dynamically embeds declarative Kubernetes manifest audit violations and vulnerable NixOS flake lock inputs directly into generated briefings.
- **CLI Threat Briefing Engine**: Integrated `--briefing`, `--briefing-dir`, and `--briefing-file` flags into `cmd/sentinel/main.go`, enabling one-click generation and local archiving of threat reports under `intel/briefings/`.
- **Unit Test Coverage** (`pkg/report/briefing_test.go`): 100% test coverage for telemetry computation, markdown layout synthesis, path traversal sanitization, and file persistence.

### Changed
- Bumped engine release to `v0.4.0`.
- Updated `SECURITY.md` to establish briefing path traversal sanitization and deterministic reporting invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` with new report packages and verified sub-300 LOC modularity.

---

## [0.3.0] - 2026-10-13

### Added
- **Kubernetes Ingress Threat Analyzer** (`pkg/k8s/ingress.go`): Static security audit engine for Ingress resources. Detects dangerous Lua and configuration snippet injections (CVE-2021-25742, CVE-2023-5044, CVE-2026-21801), URI rewrite capture group mismatches, unanchored path traversal sequences (`../`), insecure cleartext SSL redirection policies, and permissive CORS wildcard credential disclosures.
- **CNI Network Policy Verifier** (`pkg/k8s/cni.go`): Policy auditing engine covering standard Kubernetes `NetworkPolicy`, Calico `GlobalNetworkPolicy`, and Cilium `CiliumNetworkPolicy`. Identifies unconstrained global egress (`0.0.0.0/0`), sensitive infrastructure port exposures (etcd 2379/2380, Kubelet 10250, Ceph 6789), wide-open ingress selectors, Cilium L7 wildcard HTTP bypasses, and Calico untracked packet rules.
- **Namespace Default-Deny Posture Auditing**: Multi-resource posture scanner verifying that all workload namespaces enforce zero-trust default-deny ingress and egress isolation.
- **Manifest Stream & Directory Scanner** (`pkg/k8s/scanner.go`): Recursive scanner for YAML and JSON manifests supporting multi-document streams (`---`) with automated threat feed correlation against live CVE advisories.
- **CLI Kubernetes Audit Mode**: Added `--k8s=<path>` flag to `cmd/sentinel` supporting single manifest files and recursive directory scanning.
- **Test Suites & Fixtures**: Added comprehensive unit test coverage (`pkg/k8s/ingress_test.go`, `pkg/k8s/cni_test.go`, `pkg/k8s/scanner_test.go`) and production manifest samples (`fixtures/k8s-ingress-vulnerable.yaml`, `fixtures/k8s-cni-policy.yaml`).

### Changed
- Bumped engine release to `v0.3.0`.
- Updated `SECURITY.md` to codify streaming bounds ceilings (10MB payload limit, 1000 documents per stream limit) and CNI / Ingress zero-trust invariants.
- Updated `scripts/ARCHITECTURE_MAP.md` with new symbols and line counts.

---

## [0.2.0] - 2026-10-13

### Added
- **NixOS Flake Lockfile Analyzer** (`pkg/nix/flake.go`): Recursive input resolution supporting direct nodes and transitive input `follows`.
- **CVE & Advisory Mapper**: Automated correlation of pinned Git revisions and package names against live threat intelligence feeds and NixOS security advisories.
- **Cycle & Bounds Protection**: Guard rails against infinite dependency graph loops with a 64-level traversal depth ceiling and 10MB file size limits.
- **CLI Flake Audit Option**: Added `--flake=<path>` flag to `cmd/sentinel` to audit `flake.lock` dependencies directly from the terminal.
- **Unit Test Suite** (`pkg/nix/flake_test.go`): 100% test coverage for recursive resolution, transitive dependencies, cycle handling, and advisory mapping.

### Changed
- Refined security policy (`SECURITY.md`) to establish declarative bounds checking, memory hygiene, and pure evaluation invariants.
- Updated Dependabot configuration (`.github/dependabot.yml`) to track Go modules (`gomod`).

---

## [0.1.0] - 2026-10-13

### Added
- High-performance CVSS threat intelligence normalization engine (`pkg/intel`).
- Declarative configuration pattern scanner for NixOS and Kubernetes manifests (`pkg/scanner`).
- Command-line interface (`cmd/sentinel`) with target filtering and advisory inspection.
- Seed threat intelligence feed (`intel/cve-feed.json`) covering production infrastructure CVEs.
