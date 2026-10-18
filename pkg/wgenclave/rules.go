package wgenclave

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// Canonical WireGuard Enclave Peer Attestation rule catalog (WG-ENC-001 through WG-ENC-012).
var rulesCatalog = map[string]WGEnclaveRule{
	"WG-ENC-001": {
		ID:          "WG-ENC-001",
		Title:       "WireGuard Peer Missing Hardware Root-of-Trust Attestation",
		Description: "A WireGuard peer connection is configured or established without binding to a hardware-rooted enclave attestation report (AMD SEV-SNP, Intel TDX, or AWS Nitro Enclaves).",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Remediation: "Mandate hardware attestation binding by setting enclave.platform and requireHardwareRoot = true in NixOS / Kubernetes manifests.",
		MatchedCVE:  "CVE-2026-40291",
	},
	"WG-ENC-002": {
		ID:          "WG-ENC-002",
		Title:       "AMD SEV-SNP VCEK Endorsement Certificate Expired or Invalid",
		Description: "The AMD SEV-SNP Versioned Chip Endorsement Key (VCEK) certificate chain validating the hardware quote is expired, untrusted, or revoked.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Remediation: "Renew AMD KDS (Key Distribution Service) VCEK certificates and verify AMD root CA certificate pinning.",
		MatchedCVE:  "CVE-2026-40291",
	},
	"WG-ENC-003": {
		ID:          "WG-ENC-003",
		Title:       "Intel TDX Quote Signature Verification Failure",
		Description: "The Intel TDX Quote signature cannot be cryptographically verified against the Intel Provisioning Certification Service (PCS) attestation collateral.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Remediation: "Synchronize Intel PCS collateral and verify TDX Quote format v4/v5 validity.",
		MatchedCVE:  "CVE-2026-40291",
	},
	"WG-ENC-004": {
		ID:          "WG-ENC-004",
		Title:       "Node Measured Boot PCR Deviation From Declarative Golden Reference",
		Description: "Runtime TPM / enclave measured boot PCRs (PCR 0, 2, 4, or 7) deviate from declarative golden reference values, indicating potential kernel or firmware tampering.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.2,
		Remediation: "Reject peer tunnel establishment, isolate deviated node, and verify firmware / kernel store path measurements.",
		MatchedCVE:  "CVE-2026-40291",
	},
	"WG-ENC-005": {
		ID:          "WG-ENC-005",
		Title:       "WireGuard Ephemeral Session Key Missing Enclave REPORT_DATA Binding",
		Description: "The active WireGuard ephemeral session key hash is not bound to the hardware enclave REPORT_DATA field, allowing session hijacking or replay injection.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Remediation: "Enforce cryptographic binding of WireGuard ephemeral session key hashes to enclave report data (REPORT_DATA) before tunnel initiation.",
		MatchedCVE:  "CVE-2026-40291",
	},
	"WG-ENC-006": {
		ID:          "WG-ENC-006",
		Title:       "Confidential VM Guest Policy Permits Insecure Hypervisor Debugging",
		Description: "The AMD SEV-SNP or Intel TDX guest policy allows hypervisor debugging or unencrypted memory inspection, violating confidentiality invariants.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Remediation: "Set guest policy flag to disallow debugging (debug = false) and require memory encryption integrity in launch configurations.",
	},
	"WG-ENC-007": {
		ID:          "WG-ENC-007",
		Title:       "Enclave Attestation Report Age Exceeds Maximum Freshness Window",
		Description: "The peer attestation report timestamp exceeds the maximum freshness threshold (> 3600s), presenting risk of stale key state or delayed compromise detection.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.5,
		Remediation: "Trigger periodic attestation renewal and re-validate hardware quotes every 15 to 60 minutes.",
	},
	"WG-ENC-008": {
		ID:          "WG-ENC-008",
		Title:       "Intel TDX Runtime Measurement Register (RTMR) Workload Mismatch",
		Description: "Intel TDX Runtime Measurement Registers (RTMR 0, 1, or 2) do not match expected container image or initrd measurements.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Remediation: "Validate container workload hashes against declarative Nix store paths and re-issue attestation quotes.",
	},
	"WG-ENC-009": {
		ID:          "WG-ENC-009",
		Title:       "WireGuard Peer Key Renegotiation Without Fresh Attestation Proof",
		Description: "WireGuard peer updated or rotated its public key without submitting a fresh cryptographic hardware attestation report.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Remediation: "Require synchronous hardware attestation renegotiation alongside every WireGuard public key rotation.",
	},
	"WG-ENC-010": {
		ID:          "WG-ENC-010",
		Title:       "Node TCB Security Version Number Below Minimum Cluster Baseline",
		Description: "The hardware enclave Trusted Computing Base (TCB) Security Version Number (SVN) is lower than the mandatory minimum cluster security baseline.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Remediation: "Upgrade host microcode, PSP firmware, or hypervisor SEV/TDX kernel modules to meet cluster minimum TCB SVN.",
	},
	"WG-ENC-011": {
		ID:          "WG-ENC-011",
		Title:       "Unauthenticated Ephemeral Peer Handshake Accepted Without Enclave Gating",
		Description: "The WireGuard interface accepts peer handshakes from unknown or unauthenticated IP endpoints without pre-flight enclave verification.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Remediation: "Deploy kernel eBPF admission hook or attestation daemon rejecting peer handshakes prior to cryptographic validation.",
	},
	"WG-ENC-012": {
		ID:          "WG-ENC-012",
		Title:       "Non-Confidential Plaintext WireGuard Fallback Allowed in Zero-Trust Mesh",
		Description: "Configuration permits fallback to unverified standard WireGuard peer connections when confidential hardware attestation fails.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.8,
		Remediation: "Set fallbackToUnverified = false and enforce fail-closed zero-trust network policy across the cluster.",
	},
}

// GetRule returns a copy of a rule from the catalog by ID.
func GetRule(id string) (WGEnclaveRule, bool) {
	rule, found := rulesCatalog[id]
	return rule, found
}

// AllRules returns all registered rules in the catalog.
func AllRules() []WGEnclaveRule {
	rules := make([]WGEnclaveRule, 0, len(rulesCatalog))
	for _, r := range rulesCatalog {
		rules = append(rules, r)
	}
	return rules
}
