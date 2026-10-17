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

### Version 0.8.0 — Rook Ceph Distributed Storage Integrity & BlueStore Anomaly Ruleset (Completed)
- [x] Canonical storage integrity ruleset covering hostNetwork, in-transit `msgr2` crypto, at-rest OSD encryption, replication factors, and mon quorum (`pkg/storage/rules.go`).
- [x] Declarative Rook Ceph manifest scanner auditing `CephCluster`, `CephBlockPool`, `StorageClass`, and `PersistentVolumeClaim` (`pkg/storage/crd_scanner.go`).
- [x] Ceph OSD peering stall, placement group degradation, and nearfull watermark anomaly detector (`pkg/storage/osd_detector.go`).
- [x] BlueStore hardware CRC32c/XXH64 checksum corruption detector and Linux 6.12 async direct I/O metadata desync mitigation (CVE-2026-15509).
- [x] Volume health auditor preventing unsafe ReadWriteMany (RWX) multi-attaches on Ceph RBD block storage (`pkg/storage/volume.go`).
- [x] Full CLI integration (`--ceph`, `--storage`, `--ceph-telemetry`) and seamless export to SARIF v2.1.0, JSON, and Markdown briefings.

### Version 0.9.0 — WireGuard Mesh Network Cryptographic Key Rotation Engine (Completed)
- [x] WireGuard mesh network cryptographic key rotation and ephemeral peer posture auditing (`pkg/wireguard`).
- [x] Canonical rule catalog `WG-MESH-001` through `WG-MESH-012` detecting plaintext private keys in `/nix/store` (CVE-2026-31048), missing PSK for post-quantum defense, allowedIPs 0.0.0.0/0 route hijacking, and subnet collisions.
- [x] Runtime mesh telemetry reconciler identifying configuration drift, unmanaged ephemeral peers, and stale/abandoned handshakes (> 24 hours).
- [x] Zero-leak key masking and 60-day warning / 90-day hard expiration lifecycle enforcement with Curve25519 format validation.
- [x] Integrated CLI flags (`--wg`, `--wireguard`, `--wg-telemetry`) with unified export to SARIF v2.1.0, JSON telemetry, and Markdown threat briefings.

### Version 0.10.0 — Kube-Bench & CIS Benchmark Declarative Validator (Completed)
- [x] Declarative audit of NixOS systemd unit definitions and Kubernetes component manifests against CIS Kubernetes Benchmark (`pkg/bench/scanner.go`).
- [x] Canonical CIS benchmark rule catalog `CIS-1.2.1` through `CIS-4.2.12` covering API Server, Controller Manager, Scheduler, etcd, and Kubelet (`pkg/bench/rules.go`).
- [x] Automated remediation synthesis for unhardened control plane components, producing drop-in NixOS modules and hardened Kubelet configs (`pkg/bench/remediation.go`).
- [x] Full CLI integration (`--cis`, `--bench`, `--kube-bench`, `--remediation-out`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports.
- [x] Production sample fixtures (`fixtures/nixos-kubernetes.nix`, `fixtures/kubelet-config.yaml`) and threat feed correlation with `CVE-2026-38102`.

### Version 0.11.0 — Kubernetes Gateway API & EnvoyFilter Route Threat Radar (Completed)
- [x] Static threat radar and cross-namespace authorization engine for Kubernetes Gateway API resources (`pkg/gateway/radar.go`).
- [x] Canonical rule catalog `GW-RADAR-001` through `GW-RADAR-012` detecting missing ReferenceGrants, unauthenticated HTTP listeners, path traversal rewrites, and identity header injections (`pkg/gateway/rules.go`).
- [x] Istio EnvoyFilter security auditor intercepting arbitrary Lua code injections (`os.execute`, `io.popen`), filter chain order bypasses before authentication filters, and disabled client TLS verification (`pkg/gateway/envoy.go`).
- [x] Comprehensive manifest file and directory scanner with CVE threat feed correlation (`CVE-2026-44219`) (`pkg/gateway/scanner.go`).
- [x] Full CLI integration (`--gateway`, `--gw`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports.
- [x] Production sample fixture `fixtures/gateway-api-routes.yaml` modeling realistic edge gateways, HTTPRoutes, GRPCRoutes, TCPRoutes, and EnvoyFilters.

### Version 0.12.0 — Confidential Computing & Measured Boot Attestation Verifier (Completed)
- [x] Audit AMD SEV-SNP and Intel TDX measured boot artifacts against NixOS store path signatures (`pkg/attest/nixos_scanner.go`).
- [x] Canonical rule catalog `ATTEST-BOOT-001` through `ATTEST-BOOT-012` detecting disabled hardware memory encryption, debug mode enclaves, expired attestation tokens, and missing systemd-boot / Lanzaboote UKI integration (`pkg/attest/rules.go`).
- [x] Verify TPM 2.0 PCR quotations (PCR 0, 7, 8, 9, 11) and remote attestation tokens for bare-metal cluster worker nodes (`pkg/attest/verifier.go`).
- [x] Full CLI integration (`--attest`, `--attest-telemetry`, `--attest-quote`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/attest_runner.go`).
- [x] Production sample fixtures (`fixtures/nixos-measured-boot.nix`, `fixtures/attestation-telemetry.json`) and threat feed correlation with `CVE-2026-51204`.

### Version 0.13.0 — Multi-Cluster Fleet Synchronization & OIDC Token Radar (Completed)
- [x] Multi-cluster fleet synchronization and federated OIDC token radar (`pkg/fleet/scanner.go`).
- [x] Canonical rule catalog `FLEET-RBAC-001` through `FLEET-DRIFT-001` detecting wildcard ClusterRoles, privilege escalation via `bind`/`escalate`, `cluster-admin` bindings to broad groups (`system:authenticated`), and cross-namespace secret access (`pkg/fleet/rules.go`).
- [x] Federated OIDC token security auditing intercepting insecure algorithms (`none`, `HS256`), excessive lifetimes (> 24h), missing audience/issuer claims, and unrotated keys (`pkg/fleet/rbac_oidc.go`).
- [x] Declarative GitOps manifest inspection auditing ArgoCD Applications and Flux Kustomizations for automated self-healing (`selfHeal: true`, `prune: true`), unpinned floating branches, unauthenticated repositories, and wildcard destination servers (`pkg/fleet/gitops.go`).
- [x] Runtime fleet telemetry reconciliation detecting configuration drift, degraded cluster states, and revision desynchronization across geographically distributed clusters.
- [x] Full CLI integration (`--fleet`, `--gitops`, `--fleet-telemetry`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/fleet_runner.go`).
- [x] Production sample fixtures (`fixtures/fleet-manifests.yaml`, `fixtures/fleet-telemetry.json`) and threat feed correlation with `CVE-2026-60114`.

### Version 0.14.0 — Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation (Completed)
- [x] SPIFFE/SPIRE workload attestation and X.509 SVID issuing authority validation (`pkg/spiffe/validator.go`).
- [x] Canonical rule catalog `SPIFFE-SVID-001` through `SPIFFE-SVID-012` detecting unauthorized foreign trust domains, excessive certificate lifespans (> 24h), expired/near-expiry SVIDs (< 15m), permissive wildcard selectors (`k8s:ns:*`), insecure agent admin sockets, missing mTLS in Cilium policies, and weak crypto keys (`pkg/spiffe/rules.go`).
- [x] Declarative manifest scanner and runtime SVID telemetry reconciler evaluating node attestation health across cluster workers (`pkg/spiffe/scanner.go`).
- [x] Automated synthesis of hardened Cilium Network Policies (`CiliumNetworkPolicy`, `apiVersion: cilium.io/v2`) enforcing mutual TLS authentication (`mode: required`), `io.spiffe.id` label matching, and baseline default-deny microsegmentation posture (`pkg/spiffe/cilium_synth.go`).
- [x] Full CLI integration (`--spiffe`, `--spire`, `--svid-telemetry`, `--spiffe-policy-out`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/spiffe_runner.go`).
- [x] Production sample fixtures (`fixtures/spiffe-manifests.yaml`, `fixtures/spiffe-telemetry.json`) and threat feed correlation with `CVE-2026-67210`.

### Version 0.15.0 — Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation (Completed)
- [x] High-performance multi-format parser for SPDX v3.0, SPDX v2.3, CycloneDX v1.6, and Nix store closures (`pkg/sbom/parser.go`).
- [x] Canonical rule catalog `SBOM-CHAIN-001` through `SBOM-CHAIN-012` covering missing SBOMs, unverified In-Toto envelopes, non-compliant SLSA levels (< Level 3), subject digest tampering (CVE-2026-71044), unpinned dependencies, non-hermetic build sandboxes, unknown licenses, and undeclared runtime shadow injections (`pkg/sbom/rules.go`).
- [x] Cryptographic In-Toto Statement and SLSA Level 3 provenance verifier evaluating hermetic build environments, pinned dependency materials, and verified signatures (`pkg/sbom/attest.go`).
- [x] Automated SBOM delta reconciliation comparing cluster runtime state against declarative manifests to identify version drift, missing components, and shadow binary injections (`pkg/sbom/delta.go`).
- [x] Full CLI integration (`--sbom`, `--attestation`, `--intoto`, `--sbom-runtime`, `--sbom-delta`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/sbom_runner.go`).
- [x] Production sample fixtures (`fixtures/spdx-v3-sbom.json`, `fixtures/cyclonedx-v1.6-sbom.json`, `fixtures/intoto-slsa-attestation.json`, `fixtures/sbom-runtime-state.json`) and threat feed correlation with `CVE-2026-71044`.

### Version 0.16.0 — Hardware Security Module (HSM) & PKCS#11 Envelope Encryption Pipeline (Completed)
- [x] Hardware Security Module (HSM), KMS v2, and PKCS#11 envelope encryption scanner (`pkg/hsm/scanner.go`).
- [x] Universal parser for Kubernetes `EncryptionConfiguration` (`apiserver.config.k8s.io/v1`), RFC 7512 PKCS#11 URIs, and NixOS host security modules (`pkg/hsm/parser.go`).
- [x] Canonical rule catalog `HSM-ENC-001` through `HSM-ENC-012` covering insecure plaintext identity providers, deprecated KMS v1 APIs, exposed PKCS#11 PINs, weak cryptographic suites (3DES, AES-CBC-128, RSA-1024), network socket transports, and missing host daemon modules (`pkg/hsm/rules.go`).
- [x] Cryptographic envelope auditor and runtime telemetry reconciler evaluating master Key Encryption Keys (KEK), detecting unrotated keys exceeding 90 days, identifying KMS v2 plugin degradation, and detecting AWS Nitro Enclave session handle leaks (CVE-2026-83190) (`pkg/hsm/auditor.go`).
- [x] Full CLI integration (`--hsm`, `--kms`, `--hsm-telemetry`, `--nitro`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/hsm_runner.go`).
- [x] Production sample fixtures (`fixtures/k8s-encryption-config.yaml`, `fixtures/k8s-encryption-config-vulnerable.yaml`, `fixtures/nixos-hsm.nix`, `fixtures/hsm-telemetry.json`) and threat feed correlation with `CVE-2026-83190`.

### Version 0.17.0 — Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter (Completed)
- [x] Dynamic kernel runtime threat profiling and syscall filtering engine (`pkg/bpf`).
- [x] Canonical rule catalog `BPF-SEC-001` through `BPF-SEC-012` detecting unconfined container seccomp profiles, unrestricted administrative syscalls (`ptrace`, `process_vm_writev`, `kexec_load`), missing host eBPF LSM hooks, host namespace sharing (`hostPID`/`hostIPC`), and unprivileged BPF access (`pkg/bpf/rules.go`).
- [x] Streaming parser for Kubernetes Pod/Deployment security contexts, NixOS kernel sysctls (`kernel.unprivileged_bpf_disabled`), and custom Seccomp profile JSON structures (`pkg/bpf/parser.go`).
- [x] Kernel runtime telemetry reconciler evaluating socket creation bursts (> 250/sec), raw socket allocations (`SOCK_RAW`, `AF_PACKET`), blocked LSM denials, and container escape attempts (`pkg/bpf/profiler.go`).
- [x] Declarative policy synthesizer generating hardened Kubernetes Seccomp profiles, drop-in NixOS systemd sandboxing modules, and declarative eBPF LSM policy manifests (`pkg/bpf/synth.go`).
- [x] Full CLI integration (`--bpf`, `--seccomp`, `--bpf-telemetry`, `--bpf-synth-out`, `--bpf-service`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/bpf_runner.go`).
- [x] Production sample fixtures (`fixtures/k8s-bpf-workload.yaml`, `fixtures/nixos-bpf-vulnerable.nix`, `fixtures/nixos-bpf-hardened.nix`, `fixtures/bpf-runtime-telemetry.json`) and threat feed correlation with `CVE-2026-90412`.

### Version 0.18.0 — Post-Quantum Cryptography (PQC) & CNSA 2.0 TLS Audit Engine (Completed)
- [x] Post-quantum cryptography and NSA CNSA 2.0 readiness audit engine (`pkg/pqc`).
- [x] Canonical rule catalog `PQC-TLS-001` through `PQC-TLS-012` detecting insecure TLS versions (< TLS 1.3), missing hybrid post-quantum key encapsulation (ML-KEM-768/1024, NIST FIPS 203), deprecated classical ciphers (CBC/3DES/static RSA), non-compliant symmetric key lengths (< 256-bit AES), weak hash algorithms, classical-only certificate signatures, missing NixOS `oqsprovider`, and unhardened etcd peer transports (`pkg/pqc/rules.go`).
- [x] Streaming parser for Kubernetes control plane manifests (`kube-apiserver`, `etcd`, `kubelet`), NixOS OpenSSL (`environment.etc."ssl/openssl.cnf"`) and GnuTLS configurations, and runtime TLS handshake telemetry (`pkg/pqc/parser.go`).
- [x] Static and runtime cryptographic evaluator tracking hybrid KEM adoption percentages, TLS 1.3 compliance, and NSA CNSA 2.0 transition milestones (2025/2030/2033) (`pkg/pqc/auditor.go`).
- [x] Declarative policy synthesizer generating quantum-hardened NixOS modules and Kubernetes control plane static pod manifests (`pkg/pqc/synth.go`).
- [x] Full CLI integration (`--pqc`, `--cnsa`, `--pqc-telemetry`, `--pqc-synth-out`, `--cnsa-strict`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/pqc_runner.go`).
- [x] Production sample fixtures (`fixtures/k8s-pqc-controlplane.yaml`, `fixtures/k8s-pqc-vulnerable.yaml`, `fixtures/nixos-pqc.nix`, `fixtures/nixos-pqc-vulnerable.nix`, `fixtures/pqc-telemetry.json`) and threat feed correlation with `CVE-2026-94301`.

### Version 0.19.0 — Ephemeral MicroVM Sandbox & Honeypot Detonation Dispatch (Completed)
- [x] Ephemeral microVM sandbox orchestration and honeypot detonation dispatch engine (`pkg/sandbox`).
- [x] Canonical rule catalog `SANDBOX-DET-001` through `SANDBOX-DET-012` detecting missing pre-flight detonation, unrestricted microVM network egress (CVE-2026-97105), disabled Firecracker jailer chroot confinement, decoy honeypot Kubelet and etcd probes, in-guest reverse shell beaconing, kernel privilege escalation sequences, hypervisor virtio MMIO escape anomalies, anti-analysis SLA timeouts, and immutable rootfs tampering (`pkg/sandbox/rules.go`).
- [x] Streaming parser for declarative NixOS microvm specifications (`microvm.vms.<name>`), Kubernetes `DetonationJob` CRD manifests, and runtime detonation telemetry (`pkg/sandbox/parser.go`).
- [x] Detonation dispatch evaluator and decoy honeypot reconciler tracking lure interactions, container quarantine status, and calculating deterministic sandbox security compliance scores (`pkg/sandbox/dispatcher.go`).
- [x] Declarative policy synthesizer generating hardened NixOS microVM configurations, Kubernetes detonation jobs, and synthetic decoy honeypot lure definitions (`pkg/sandbox/synth.go`).
- [x] Full CLI integration (`--sandbox`, `--microvm`, `--sandbox-telemetry`, `--honeypot`, `--sandbox-synth-out`, `--quarantine-strict`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/sandbox_runner.go`).
- [x] Production sample fixtures (`fixtures/nixos-microvm.nix`, `fixtures/nixos-microvm-vulnerable.nix`, `fixtures/k8s-detonation-job.yaml`, `fixtures/sandbox-telemetry.json`) and threat feed correlation with `CVE-2026-97105`.

### Version 0.20.0 — Autonomous Threat Remediation & GitOps Pull Request Synthesizer (Completed)
- [x] Autonomous threat remediation and declarative GitOps patch synthesis engine (`pkg/remediate/scanner.go`).
- [x] Canonical rule catalog `REMEDIATE-AUTO-001` through `REMEDIATE-AUTO-012` covering unpinned flake inputs (`CVE-2026-19402`), unhardened container security contexts (`CVE-2026-20914`), Ingress custom snippet path traversals (`CVE-2026-21801`), permissive 0.0.0.0/0 CNI egress routes, Ceph storage lacking in-transit `msgr2` encryption (`CVE-2026-15509`), plaintext WireGuard private keys (`CVE-2026-31048`), CIS Kubernetes Benchmark control plane audit deviations (`CVE-2026-38102`), missing SPIFFE mTLS policies (`CVE-2026-67210`), insecure KMS v2 configurations (`CVE-2026-83190`), unconfined seccomp profiles (`CVE-2026-90412`), classical TLS 1.2 control planes (`CVE-2026-94301`), and unisolated microVM detonation sandboxes (`CVE-2026-97105`) (`pkg/remediate/rules.go`).
- [x] Automated pre-flight canary test validation pipeline (`pkg/remediate/canary.go`) executing simulated NixOS pure flake evaluations and `kubectl kustomize` dry-run schema checks before GitOps PR synthesis.
- [x] Declarative patch synthesizer generating unified diff NixOS configuration patches, Kubernetes Kustomize strategic merge patches, RFC 6902 JSONPatches, and complete `kustomization.yaml` overlay manifests (`pkg/remediate/synthesizer.go`).
- [x] GitOps pull request bundle orchestrator generating branch names (`remediation/hardening-*`), conventional commit messages, structured Markdown summaries, and attached canary execution results (`pkg/remediate/types.go`).
- [x] Full CLI integration (`--remediate`, `--auto-remediate`, `--remediate-synth-out`, `--canary-strict`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/remediate_runner.go`, `cmd/sentinel/flags.go`).
- [x] Production sample fixtures (`fixtures/remediation/nixos-vulnerable.nix`, `fixtures/remediation/k8s-workload.yaml`, `fixtures/remediation/kustomization-base.yaml`, `fixtures/remediation/canary-telemetry.json`) and threat feed correlation with `CVE-2026-98402`.

### Version 0.21.0 — eBPF LSM Security Module & Kernel Mandatory Access Control (Completed)
- [x] Declarative eBPF Linux Security Module (LSM) hooks and Kernel Mandatory Access Control (MAC) engine (`pkg/lsm/scanner.go`).
- [x] Canonical rule catalog `LSM-MAC-001` through `LSM-MAC-012` detecting missing `bpf` in `boot.kernelParams` (`CVE-2026-99103`), unconfined executable execution from `/tmp` and `/dev/shm`, unprotected sensitive host kernel structures (`/proc/kcore`), unconfined raw sockets (`CVE-2026-20914`), unauthorized setuid privilege escalation, unprivileged BPF loading (`CVE-2026-90412`), cross-process ptrace memory injection, unconfined privileged containers, and host namespace sharing (`pkg/lsm/rules.go`).
- [x] Streaming line parsers for declarative NixOS host configurations (`boot.kernelParams`, `security.lsm`, sysctls, systemd eBPF units), Kubernetes workload security contexts, and runtime eBPF LSM denial telemetry (`pkg/lsm/parser.go`).
- [x] Declarative policy synthesizer generating drop-in hardened NixOS modules (`lsm-bpf-policy.nix`), verifiable eBPF C programs (`lsm_container_mac.bpf.c`), and Kubernetes ContainerMACProfile CRD specifications (`pkg/lsm/synth.go`).
- [x] Deterministic compliance posture scoring (0.0% to 100.0%) and runtime telemetry anomaly reconciler tracking blocked syscalls (`pkg/lsm/auditor.go`).
- [x] Full CLI integration (`--lsm`, `--lsm-mac`, `--lsm-telemetry`, `--lsm-synth-out`, `--lsm-strict`) with unified SARIF v2.1.0 code scanning, JSON audit telemetry, and Markdown briefing exports (`cmd/sentinel/lsm_runner.go`, `cmd/sentinel/flags.go`).
- [x] Production sample fixtures (`fixtures/nixos-lsm.nix`, `fixtures/nixos-lsm-vulnerable.nix`, `fixtures/k8s-lsm-workload.yaml`, `fixtures/lsm-telemetry.json`) and threat feed correlation with `CVE-2026-99103`.

### Version 0.22.0 — CephFS Snapshot & Volume Replication DR Synchronizer (Planned)
- [ ] Implement scheduled volume snapshot policy auditor and delta replication monitor.
- [ ] Automated disaster recovery posture verification across cross-region storage clusters.
- [ ] Real-time CephFS snapshot consistency group verification and immutable retention locks.

### Version 1.0.0 — Enterprise Workload Identity & Ephemeral Detonation Pipeline (Planned)
- [ ] Full end-to-end integration of SPIFFE/SPIRE workload attestation, In-Toto provenance, and HSM envelope encryption.
- [ ] Enterprise continuous audit mode with asynchronous event streaming and webhook alerting.

### Version 1.1.0 — Autonomous Self-Healing & Continuous Cloud Defense (Vision)
- [ ] Autonomous GitOps Pull Request synthesizer generating declarative Kustomize and Flake patches for CVE mitigations.
- [ ] Real-time eBPF LSM kernel hotpatching without node reboot or workload disruption.
