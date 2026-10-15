package spiffe

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// CanonicalRules contains the authoritative security rules for SPIFFE/SPIRE workload attestation and Cilium microsegmentation.
var CanonicalRules = []SPIFFERule{
	{
		RuleID:          "SPIFFE-SVID-001",
		Title:           "Untrusted Foreign Trust Domain in SPIFFE ID",
		Category:        CategoryTrustDomain,
		DefaultSeverity: intel.SeverityCritical,
		BaseCVSS:        9.1,
		Description:     "A workload presents a SPIFFE ID belonging to an untrusted foreign trust domain without explicit SPIFFE federation peering, risking cross-tenant identity spoofing.",
		Remediation:     "Configure explicit SPIFFE federation relationships in spire-server.conf or restrict workloads to the local trust domain authority.",
		ThreatPattern:   `spiffe:\/\/(?!%s)[^\/]+`,
	},
	{
		RuleID:          "SPIFFE-SVID-002",
		Title:           "Excessive SVID Certificate Lifespan (> 24 Hours)",
		Category:        CategorySVIDValidity,
		DefaultSeverity: intel.SeverityMedium,
		BaseCVSS:        6.2,
		Description:     "The issued X.509 SVID certificate lifespan exceeds the 24-hour zero-trust threshold, increasing exposure windows if a private key is compromised.",
		Remediation:     "Configure default_x509_svid_ttl in SPIRE server to <= 24h (recommended 1h to 12h) to enforce ephemeral credential rotation.",
		ThreatPattern:   `lifespan > 24h`,
	},
	{
		RuleID:          "SPIFFE-SVID-003",
		Title:           "SVID Approaching Expiration Without Renewal Window (< 15 Minutes Remaining)",
		Category:        CategorySVIDValidity,
		DefaultSeverity: intel.SeverityHigh,
		BaseCVSS:        7.8,
		Description:     "Active workload SVID certificate has less than 15 minutes of validity remaining or has already expired, risking imminent mTLS authentication failures and service blackout.",
		Remediation:     "Ensure SPIRE Agent workload attester is actively connected and renewing certificates at >= 50% of the SVID validity window.",
		ThreatPattern:   `remaining < 15m`,
	},
	{
		RuleID:          "SPIFFE-SVID-004",
		Title:           "Permissive Wildcard Attestation Selector in SPIRE Registration Entry",
		Category:        CategoryAttestation,
		DefaultSeverity: intel.SeverityCritical,
		BaseCVSS:        9.3,
		Description:     "SPIRE registration entry uses overly broad wildcard selectors (e.g. k8s:ns:* or wildcard service account), allowing any container on the node to claim the workload identity.",
		Remediation:     "Bind registration entries to concrete, immutable selectors: k8s:ns, k8s:sa, and container image digest (k8s:container-image).",
		ThreatPattern:   `selector:\s*k8s:(ns|sa):\*`,
	},
	{
		RuleID:          "SPIFFE-SVID-005",
		Title:           "Insecure SPIRE Agent Admin API Socket Exposure",
		Category:        CategoryAgentSecurity,
		DefaultSeverity: intel.SeverityHigh,
		BaseCVSS:        8.4,
		Description:     "The SPIRE agent admin API UNIX domain socket is exposed without root-only permissions or AppArmor / SELinux host isolation, risking unauthorized workload SVID minting.",
		Remediation:     "Restrict spire-agent.sock permissions to 0600 (root:root) or use dedicated CSIVolume / spire-workload-registrar with strict DAC permissions.",
		ThreatPattern:   `chmod\s+777.*spire-agent\.sock`,
	},
	{
		RuleID:          "SPIFFE-SVID-006",
		Title:           "Missing mTLS Enforcement in Cilium Ingress Policy",
		Category:        CategoryMicrosegment,
		DefaultSeverity: intel.SeverityHigh,
		BaseCVSS:        8.2,
		Description:     "Cilium Network Policy permits ingress traffic without enforcing mutual TLS authentication with SPIFFE identity verification.",
		Remediation:     "Add 'authentication.mode: required' and match on 'io.spiffe.id' under ingress fromEndpoints in CiliumNetworkPolicy.",
		ThreatPattern:   `missing authentication.mode or io.spiffe.id`,
	},
	{
		RuleID:          "SPIFFE-SVID-007",
		Title:           "Plaintext Non-SPIFFE Workload Communication Permitted",
		Category:        CategoryMicrosegment,
		DefaultSeverity: intel.SeverityHigh,
		BaseCVSS:        7.9,
		Description:     "Network policy permits unauthenticated plaintext communication fallback between sensitive microservices, bypassing zero-trust boundaries.",
		Remediation:     "Enforce strict default-deny ingress and require cryptographic X.509 SVID authentication for all east-west pod communications.",
		ThreatPattern:   `allow-all-plaintext`,
	},
	{
		RuleID:          "SPIFFE-SVID-008",
		Title:           "Unfederated Cross-Cluster Workload Identity Reference",
		Category:        CategoryTrustDomain,
		DefaultSeverity: intel.SeverityMedium,
		BaseCVSS:        6.8,
		Description:     "A network policy or registration entry references an external trust domain without an active SPIRE federation bundle synchronization endpoint.",
		Remediation:     "Register the foreign trust domain under Federation in spire-server.conf and verify bundle endpoint HTTPS certificate.",
		ThreatPattern:   `foreign-trust-domain-unfederated`,
	},
	{
		RuleID:          "SPIFFE-SVID-009",
		Title:           "Weak Cryptographic Key Algorithm in X.509 SVID",
		Category:        CategoryCryptographicKey,
		DefaultSeverity: intel.SeverityHigh,
		BaseCVSS:        7.5,
		Description:     "The SVID was issued using an obsolete or weak cryptographic key algorithm (e.g. RSA < 2048 or SHA-1), vulnerable to cryptanalytic collision attacks.",
		Remediation:     "Migrate SPIRE CA and workload SVID keys to ECDSA P-256 (default) or RSA 3072+.",
		ThreatPattern:   `RSA-(1024|512)|SHA-?1`,
	},
	{
		RuleID:          "SPIFFE-SVID-010",
		Title:           "Missing Default-Deny Workload Microsegmentation Posture",
		Category:        CategoryMicrosegment,
		DefaultSeverity: intel.SeverityMedium,
		BaseCVSS:        6.5,
		Description:     "Workload namespace lacks a default-deny CiliumNetworkPolicy, allowing non-attested pods to initiate unrestricted lateral connections.",
		Remediation:     "Deploy a baseline default-deny CiliumNetworkPolicy restricting ingress and egress to explicitly attested SPIFFE identities.",
		ThreatPattern:   `missing default-deny policy`,
	},
	{
		RuleID:          "SPIFFE-SVID-011",
		Title:           "Unsigned or Unverified SPIRE Bundle Endpoint / OIDC Federation URL",
		Category:        CategoryTrustDomain,
		DefaultSeverity: intel.SeverityHigh,
		BaseCVSS:        8.0,
		Description:     "SPIRE Federation bundle endpoint uses insecure HTTP or lacks HTTPS pin, allowing man-in-the-middle attackers to poison trusted CA roots.",
		Remediation:     "Enforce TLS on all SPIRE bundle endpoints and configure trusted root CA fingerprints for bundle verification.",
		ThreatPattern:   `http:\/\/.*bundle`,
	},
	{
		RuleID:          "SPIFFE-SVID-012",
		Title:           "SPIFFE/SPIRE Workload Attestation Threat Radar Correlation Match",
		Category:        CategoryAttestation,
		DefaultSeverity: intel.SeverityCritical,
		BaseCVSS:        9.3,
		Description:     "Workload attestation or SVID renewal posture matches a known CVE vulnerability in the active threat intelligence feed (e.g. CVE-2026-67210).",
		Remediation:     "Upgrade SPIRE Server & Agent to patched releases and synthesize hardened Cilium Network Policies.",
		ThreatPattern:   `CVE-2026-67210`,
	},
}

// RuleMap indexes canonical rules by RuleID for fast O(1) lookups.
var RuleMap = func() map[string]SPIFFERule {
	m := make(map[string]SPIFFERule, len(CanonicalRules))
	for _, r := range CanonicalRules {
		m[r.RuleID] = r
	}
	return m
}()

// GetRule returns a rule by its ID, or false if not found.
func GetRule(ruleID string) (SPIFFERule, bool) {
	r, exists := RuleMap[ruleID]
	return r, exists
}
