package sbom

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

var canonicalRules = map[string]SBOMRule{
	"SBOM-CHAIN-001": {
		ID:          "SBOM-CHAIN-001",
		Title:       "Missing or Unparseable Software Bill of Materials (SBOM)",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.0,
		Description: "Workload deployment or Nix store path does not supply a valid, parseable SPDX or CycloneDX SBOM manifest.",
		Remediation: "Generate and embed a machine-readable SPDX v3.0 or CycloneDX v1.6 SBOM during Nix build or image compilation.",
	},
	"SBOM-CHAIN-002": {
		ID:          "SBOM-CHAIN-002",
		Title:       "Missing In-Toto Cryptographic Attestation Envelope",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.2,
		Description: "Artifact lacks an In-Toto cryptographic attestation envelope verifying build authenticity and provenance.",
		Remediation: "Sign the build envelope using Cosign or Sigstore In-Toto attestation predicate prior to deployment.",
	},
	"SBOM-CHAIN-003": {
		ID:          "SBOM-CHAIN-003",
		Title:       "Non-Compliant SLSA Provenance Level (< SLSA Level 3)",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 8.5,
		Description: "Artifact provenance does not satisfy SLSA Level 3 requirements for isolated, hermetic, and reproducible builds.",
		Remediation: "Build within an isolated, hardened build platform (e.g. Nix pure-eval or SLSA-compliant GitHub Actions runner).",
	},
	"SBOM-CHAIN-004": {
		ID:          "SBOM-CHAIN-004",
		Title:       "Tampered or Mismatched Subject Digest / Cryptographic Checksum",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.8,
		Description: "Artifact cryptographic SHA256 digest deviates from the signed In-Toto attestation subject, indicating tampering.",
		Remediation: "Immediately quarantine artifact, inspect build logs, and regenerate attestation from authentic build output.",
		AssociatedCVE: "CVE-2026-71044",
	},
	"SBOM-CHAIN-005": {
		ID:          "SBOM-CHAIN-005",
		Title:       "Ephemeral / Unpinned Upstream Material Dependency",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 7.8,
		Description: "Build materials reference mutable branch references or unpinned upstream URLs without cryptographic hashes.",
		Remediation: "Pin all dependency sources to immutable commit SHAs, nix narHash digests, or cryptographic package hashes.",
	},
	"SBOM-CHAIN-006": {
		ID:          "SBOM-CHAIN-006",
		Title:       "Non-Hermetic Build Environment Lacking Sandboxing",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 8.1,
		Description: "Attestation indicates network access or host contamination occurred during the compilation and build phase.",
		Remediation: "Enforce strict Nix sandboxing (`sandbox = true`) or SLSA container isolation without ambient network access.",
	},
	"SBOM-CHAIN-007": {
		ID:          "SBOM-CHAIN-007",
		Title:       "Known Critical CVE Vulnerability in SBOM Component",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.5,
		Description: "Component listed in Software Bill of Materials matches a known critical vulnerability in active threat feed.",
		Remediation: "Upgrade the vulnerable component package version or apply vendor-recommended patch in declarative manifest.",
	},
	"SBOM-CHAIN-008": {
		ID:          "SBOM-CHAIN-008",
		Title:       "Runtime Undeclared Package / Shadow Binary Injection",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.4,
		Description: "Package observed in runtime cluster execution was never declared in the authoritative build-time SBOM.",
		Remediation: "Evict untrusted workload, enforce immutable root filesystems, and inspect container image for unauthorized injections.",
	},
	"SBOM-CHAIN-009": {
		ID:          "SBOM-CHAIN-009",
		Title:       "Runtime Package Version Drift Against Declarative SBOM",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 7.6,
		Description: "Observed package version in runtime deviates from declared version in baseline SBOM, indicating configuration drift.",
		Remediation: "Reconcile runtime deployment with GitOps declarative source and prevent in-place container mutations.",
	},
	"SBOM-CHAIN-010": {
		ID:          "SBOM-CHAIN-010",
		Title:       "Deprecated / Obsolete SBOM Specification Version",
		Severity:    intel.SeverityMedium,
		DefaultCVSS: 5.3,
		Description: "SBOM document relies on deprecated specification versions (< SPDX 2.3 or < CycloneDX 1.5).",
		Remediation: "Upgrade SBOM generation tooling to produce SPDX v3.0 or CycloneDX v1.6 formatted outputs.",
	},
	"SBOM-CHAIN-011": {
		ID:          "SBOM-CHAIN-011",
		Title:       "Prohibited or Unrecognized Open Source License Identifier",
		Severity:    intel.SeverityMedium,
		DefaultCVSS: 4.5,
		Description: "Component specifies an unrecognized license or a license with restrictive commercial or copyleft clauses.",
		Remediation: "Review component licensing and align with organization approved SPDX license expression whitelist.",
	},
	"SBOM-CHAIN-012": {
		ID:          "SBOM-CHAIN-012",
		Title:       "Missing Nix Store Derivation Closure Hash or Output Hash",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 7.5,
		Description: "NixOS component SBOM lacks cryptographic store path hash or reproducible derivation output validation.",
		Remediation: "Enable `structuredAttrs` and emit `.drv` output hashes in Nix derivation metadata for full reproducibility.",
	},
}

// GetRule returns the canonical rule for a given identifier.
func GetRule(id string) (SBOMRule, bool) {
	rule, exists := canonicalRules[id]
	return rule, exists
}

// AllRules returns a slice of all canonical SBOM rules.
func AllRules() []SBOMRule {
	list := make([]SBOMRule, 0, len(canonicalRules))
	for _, r := range canonicalRules {
		list = append(list, r)
	}
	return list
}
