# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
