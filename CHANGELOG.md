# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
