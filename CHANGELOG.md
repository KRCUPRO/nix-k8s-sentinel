# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
