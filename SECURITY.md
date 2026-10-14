# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.5.0` | :x:                |

## Security & Integrity Invariants

1. **Declarative Bounds & Recursion Limits**: Nix `flake.lock` and Kubernetes manifest parsers enforce strict depth limits (default max depth: 64) and streaming size ceilings (10MB payload ceiling, 1000 documents per stream) to mitigate parser recursion and resource exhaustion attacks.
2. **Kubernetes & CNI Zero-Trust Enforcement**: Ingress analyzers and CNI policy verifiers proactively detect unanchored URI regex rewrites (CVE-2026-21801), Lua/command snippet injections (CVE-2023-5044), 0.0.0.0/0 egress data leaks, and unauthenticated infrastructure port exposures.
3. **Memory Hygiene & Zero Secret Exposure**: Threat feed caches, API tokens, and internal vulnerability buffers are kept ephemeral in memory with zero plaintext secrets written to logs, disk, or terminal output.
4. **Pure Evaluation & Hash Verification**: Nix input locks require strict revision and `narHash` integrity validation to detect tampered upstream git references and unauthenticated binary cache overrides.
5. **Input Sanitization & Safe Deserialization**: All untrusted JSON and YAML feeds pass through strict schema validation with bounded streaming before evaluating threat signatures.
6. **Briefing Sanitization & Path Traversal Guard**: Automated Markdown briefing generators sanitize output directories and file paths (`filepath.Clean` and `filepath.Base`), preventing directory traversal when persisting reports. Telemetry aggregations strictly enforce deterministic sorting and bounds checking.
7. **Declarative Policy Synthesis Integrity & Schema Conformance**: Synthetic Falco runtime rules and OPA Gatekeeper ConstraintTemplates enforce sanitized YAML escaping, strict Rego syntax constraints, and schema conformance to prevent policy injection or admission bypass vulnerabilities.
8. **SARIF & JSON Security Audit Exporter Integrity**: Exporters for OASIS SARIF v2.1.0 and structured JSON enforce strict schema validation, defend against directory traversal (`filepath.Clean`), guarantee deterministic rule index mapping, and prevent arbitrary field injection in CI/CD and GitHub Code Scanning pipelines.

## Reporting a Vulnerability

If you discover a potential security issue, memory safety bug, or threat model flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
