# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
