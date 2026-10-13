# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Security & Integrity Invariants

1. **Declarative Bounds & Recursion Limits**: Nix `flake.lock` and Kubernetes manifest parsers enforce strict depth limits (default max depth: 32) and size bounds to mitigate graph recursion exhaustion attacks.
2. **Memory Hygiene & Zero Secret Exposure**: Threat feed caches, API tokens, and internal vulnerability buffers are kept ephemeral in memory with zero plaintext secrets written to logs or disk.
3. **Pure Evaluation & Hash Verification**: Nix input locks require strict revision and `narHash` integrity validation to detect tampered upstream git references and unauthenticated binary cache overrides.
4. **Input Sanitization & Safe Deserialization**: All untrusted JSON and YAML feeds pass through strict schema validation with bounded streaming before evaluating threat signatures.

## Reporting a Vulnerability

If you discover a potential security issue, memory safety bug, or threat model flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
