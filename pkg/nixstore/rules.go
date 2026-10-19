package nixstore

import (
	"sort"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Canonical rule catalog for Multi-Tenant Nix Store Signature & Binary Cache Isolation Gate.
var RuleCatalog = map[string]StoreRule{
	"NIX-STORE-001": {
		ID:             "NIX-STORE-001",
		Name:           "Unsigned Binary Cache Substitution Allowed",
		Severity:       intel.SeverityCritical,
		CVSSScore:      9.4,
		Description:    "Nix daemon allows unsigned binary cache substitutes (require-sigs = false or unset), permitting unauthenticated third-party substitutes to poison the shared multi-tenant /nix/store.",
		Remediation:    "Set `nix.settings.require-sigs = true;` in NixOS or `require-sigs = true` in /etc/nix/nix.conf to reject any substitute lacking a trusted Ed25519 signature.",
		DefaultEnabled: true,
	},
	"NIX-STORE-002": {
		ID:             "NIX-STORE-002",
		Name:           "Missing or Insecure Ed25519 Trusted Public Keys",
		Severity:       intel.SeverityHigh,
		CVSSScore:      8.5,
		Description:    "trusted-public-keys is empty, omitted, or contains malformed Ed25519 key declarations, preventing cryptographic validation of substitute .narinfo archives.",
		Remediation:    "Declare valid Ed25519 public keys in `nix.settings.trusted-public-keys` (e.g. `cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=`).",
		DefaultEnabled: true,
	},
	"NIX-STORE-003": {
		ID:             "NIX-STORE-003",
		Name:           "Insecure Plaintext HTTP Binary Cache Substituter",
		Severity:       intel.SeverityHigh,
		CVSSScore:      8.2,
		Description:    "Configured binary cache substituter uses plaintext HTTP (http://...), exposing build dependency downloads to active network MITM eavesdropping and tampering.",
		Remediation:    "Enforce TLS encryption on all substituters (`https://...` or `s3://...`) and reject unencrypted HTTP transport.",
		DefaultEnabled: true,
	},
	"NIX-STORE-004": {
		ID:             "NIX-STORE-004",
		Name:           "Overly Permissive Trusted Users Configuration",
		Severity:       intel.SeverityCritical,
		CVSSScore:      9.1,
		Description:    "trusted-users includes wildcards (`*`) or unconstrained user groups, allowing non-privileged multi-tenant users to inject arbitrary substituters and bypass signature checks.",
		Remediation:    "Restrict `trusted-users` exclusively to `[ \"root\" ]` and manage substituters globally through declarative cluster configuration.",
		DefaultEnabled: true,
	},
	"NIX-STORE-005": {
		ID:             "NIX-STORE-005",
		Name:           "Build Sandboxing Disabled or Fallback Permitted",
		Severity:       intel.SeverityCritical,
		CVSSScore:      9.0,
		Description:    "Nix build sandboxing is disabled (`sandbox = false`) or permitted to fall back (`sandbox-fallback = true`), allowing builds to escape isolated user namespaces and access host resources.",
		Remediation:    "Set `nix.settings.sandbox = true;` and `nix.settings.sandbox-fallback = false;` to guarantee build confinement in Linux user/mount namespaces.",
		DefaultEnabled: true,
	},
	"NIX-STORE-006": {
		ID:             "NIX-STORE-006",
		Name:           "Impure Evaluation or Untrusted Flake Config Permitted",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.8,
		Description:    "pure-eval is disabled or accept-flake-config is enabled without confinement, allowing untrusted flake expressions to read host environment variables or override daemon settings.",
		Remediation:    "Enforce `nix.settings.pure-eval = true;` and `nix.settings.accept-flake-config = false;` for multi-tenant developer builds.",
		DefaultEnabled: true,
	},
	"NIX-STORE-007": {
		ID:             "NIX-STORE-007",
		Name:           "Missing or Insufficient Build User Pool Confinement",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.2,
		Description:    "build-users-group is not configured or build user pool allocation is insufficient (< 10 nixbld users), risking multi-tenant build privilege collisions.",
		Remediation:    "Configure `nix.settings.build-users-group = \"nixbld\";` with at least 32 distinct unprivileged build UIDs in the nixbld group.",
		DefaultEnabled: true,
	},
	"NIX-STORE-008": {
		ID:             "NIX-STORE-008",
		Name:           "Unprotected Private Binary Cache Credentials",
		Severity:       intel.SeverityHigh,
		CVSSScore:      7.9,
		Description:    "Binary cache credentials (netrc-file) reside in world-readable paths or are declared in plaintext in the world-readable /nix/store.",
		Remediation:    "Manage `netrc-file` through sops-nix runtime secret provision with 0400/0600 file permissions owned by the nix daemon.",
		DefaultEnabled: true,
	},
	"NIX-STORE-009": {
		ID:             "NIX-STORE-009",
		Name:           "High Binary Cache Signature Rejection Rate",
		Severity:       intel.SeverityHigh,
		CVSSScore:      8.7,
		Description:    "Runtime telemetry indicates a high substitute signature rejection rate (> 5%), signaling active cache poisoning attempts or severe cryptographic key desynchronization.",
		Remediation:    "Isolate the offending binary cache mirror, rotate compromised Ed25519 signing keys, and investigate host daemon audit logs.",
		DefaultEnabled: true,
	},
	"NIX-STORE-010": {
		ID:             "NIX-STORE-010",
		Name:           "NAR Archive Checksum Mismatch Detected",
		Severity:       intel.SeverityCritical,
		CVSSScore:      9.3,
		Description:    "Downloaded substitute NAR archive SHA-256 checksum fails to match the signed .narinfo digest, indicating in-flight payload corruption or cache tampering.",
		Remediation:    "Evict the corrupted substitute from upstream CDN caches, verify TLS certificates, and enforce NAR hash verification on all substitutes.",
		DefaultEnabled: true,
	},
	"NIX-STORE-011": {
		ID:             "NIX-STORE-011",
		Name:           "Excessive Substitute Download Latency",
		Severity:       intel.SeverityMedium,
		CVSSScore:      5.8,
		Description:    "Binary cache substitute download P95 latency exceeds 15,000ms, risking build timeouts, worker starvation, and cluster deployment stalls.",
		Remediation:    "Configure geographic cache mirrors, increase connect-timeout in nix.settings, or establish an internal local binary cache proxy.",
		DefaultEnabled: true,
	},
	"NIX-STORE-012": {
		ID:             "NIX-STORE-012",
		Name:           "Nix Store Volume Exhaustion or GC Disabled",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.4,
		Description:    "Nix store volume utilization exceeds 85% capacity or automated garbage collection (nix.gc) is disabled, risking builder disk exhaustion.",
		Remediation:    "Enable `nix.gc.automatic = true;` with `options = \"--delete-older-than 14d\";` and configure nix.settings.min-free and max-free storage thresholds.",
		DefaultEnabled: true,
	},
}

// LookupRule retrieves a rule definition by its canonical ID.
func LookupRule(id string) (StoreRule, bool) {
	rule, ok := RuleCatalog[id]
	return rule, ok
}

// AllRules returns all catalog rules sorted deterministically by ID.
func AllRules() []StoreRule {
	rules := make([]StoreRule, 0, len(RuleCatalog))
	for _, r := range RuleCatalog {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})
	return rules
}
