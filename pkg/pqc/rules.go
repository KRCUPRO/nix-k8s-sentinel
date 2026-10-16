package pqc

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var defaultPQCRules = []PQCRule{
	{
		RuleID:         "PQC-TLS-001",
		Title:          "Insecure TLS Protocol Version Configured on Kubernetes Control Plane",
		Description:    "Kubernetes kube-apiserver, etcd, or kubelet endpoints permit TLS protocol versions earlier than TLS 1.3 (e.g. TLS 1.0, 1.1, or 1.2), exposing connections to classical protocol downgrade attacks and handshake tampering.",
		Severity:       intel.SeverityHigh,
		CVSSScore:      8.2,
		Remediation:    "Configure '--tls-min-version=VersionTLS13' on all control plane daemons (kube-apiserver, etcd, kubelet).",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-002",
		Title:          "Missing Hybrid Post-Quantum Key Encapsulation (Harvest-Now-Decrypt-Later Threat)",
		Description:    "TLS connections rely solely on classical discrete-log or elliptic curve Diffie-Hellman key exchange (X25519, P-256) without hybrid post-quantum encapsulation (ML-KEM-768/Kyber), allowing adversaries to capture encrypted traffic today for retroactive decryption when cryptanalytically relevant quantum computers emerge.",
		Severity:       intel.SeverityHigh,
		CVSSScore:      8.8,
		Remediation:    "Enable hybrid post-quantum key encapsulation groups (X25519MLKEM768, SecP384r1MLKEM1024) in client and server TLS configurations.",
		MatchedCVE:     "CVE-2026-94301",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-003",
		Title:          "Deprecated or Weak Classical Cipher Suite Declared",
		Description:    "The TLS cipher suite declaration includes legacy cipher block chaining (CBC), 3DES, RC4, or static RSA key exchange algorithms vulnerable to padding oracle and cryptanalytic attacks.",
		Severity:       intel.SeverityCritical,
		CVSSScore:      9.1,
		Remediation:    "Restrict '--tls-cipher-suites' strictly to AEAD suites: TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256.",
		CNSATargetYear: 2025,
	},
	{
		RuleID:         "PQC-TLS-004",
		Title:          "Non-Compliant CNSA 2.0 Symmetric Key Length (< 256-bit AES)",
		Description:    "Cipher suites utilizing 128-bit symmetric keys (e.g. TLS_AES_128_GCM_SHA256) fail to meet the National Security Agency CNSA 2.0 mandate requiring 256-bit symmetric encryption to resist Grover's quantum search algorithm.",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.5,
		Remediation:    "Enforce 256-bit symmetric ciphers (TLS_AES_256_GCM_SHA384) across high-assurance Kubernetes endpoints.",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-005",
		Title:          "Non-Compliant CNSA 2.0 Hash Digest Algorithm (< SHA-384)",
		Description:    "Integrity check or HMAC hash functions use SHA-1 or SHA-256 in high-assurance control plane links. CNSA 2.0 requires SHA-384 or SHA-512 for quantum-resistant collision resistance.",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.0,
		Remediation:    "Upgrade certificate hashing and TLS integrity digests to SHA-384 or SHA-512.",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-006",
		Title:          "Classical-Only Public Key Signatures on Control Plane Certificates",
		Description:    "X.509 certificates for cluster API servers, etcd peers, and service accounts use classical RSA (< 3072-bit) or ECDSA P-256 signatures lacking ML-DSA (FIPS 204 / Dilithium) quantum resistance or composite dual-key transition paths.",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.8,
		Remediation:    "Transition PKI root and intermediate authorities to ML-DSA-65/87 or hybrid dual-signature certificates.",
		CNSATargetYear: 2033,
	},
	{
		RuleID:         "PQC-TLS-007",
		Title:          "NixOS OpenSSL Configuration Missing OQS/PQC Provider",
		Description:    "NixOS host OpenSSL configuration lacks the Open Quantum Safe provider ('oqsprovider') or native ML-KEM provider activation in openssl.cnf, preventing system services from negotiating post-quantum key encapsulation.",
		Severity:       intel.SeverityHigh,
		CVSSScore:      7.9,
		Remediation:    "Configure 'environment.etc.\"ssl/openssl.cnf\"' to activate 'oqsprovider' and declare quantum-safe default groups.",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-008",
		Title:          "NixOS GnuTLS Insecure Priority String Declared",
		Description:    "System GnuTLS configuration permits legacy cipher priorities without explicit quantum-safe group bindings (+GROUP-X25519-KYBER768 or +GROUP-SECP384R1-MLKEM1024) or fails to restrict protocol version to TLS 1.3.",
		Severity:       intel.SeverityMedium,
		CVSSScore:      6.2,
		Remediation:    "Update GnuTLS priority string to '@SYSTEM:!VERS-ALL:+VERS-TLS1.3:+GROUP-X25519-KYBER768:+GROUP-SECP384R1-MLKEM1024'.",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-009",
		Title:          "etcd Peer Transport Lacking Quantum-Safe Mutual TLS",
		Description:    "Distributed etcd cluster peer-to-peer synchronization operates over unencrypted channels or classical TLS without quantum-safe hybrid key encapsulation, risking entire cluster state compromise under retroactive cryptanalysis.",
		Severity:       intel.SeverityCritical,
		CVSSScore:      9.3,
		Remediation:    "Enforce '--peer-tls-min-version=VersionTLS13' and hybrid ML-KEM key exchange across all etcd member manifests.",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-010",
		Title:          "Kubelet TLS Autonegotiation Downgrade Vulnerability",
		Description:    "Worker node kubelet configuration permits client certificate authentication with negotiable cipher suites vulnerable to cipher suite fallback and non-PQC downgrade.",
		Severity:       intel.SeverityHigh,
		CVSSScore:      7.5,
		Remediation:    "Pin kubelet server TLS cipher suites to TLS_AES_256_GCM_SHA384 and disable fallback cipher negotiation.",
		CNSATargetYear: 2030,
	},
	{
		RuleID:         "PQC-TLS-011",
		Title:          "Expired or Inadmissible PQC Algorithm Parameter Set",
		Description:    "Configuration references non-standardized early draft PQC parameters (e.g. Kyber-v1/v2 or Round-2 candidates) rather than official NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) ratified specifications.",
		Severity:       intel.SeverityLow,
		CVSSScore:      3.8,
		Remediation:    "Update cryptographic libraries and configuration strings to standardized FIPS 203/204 parameter identifiers.",
		CNSATargetYear: 2025,
	},
	{
		RuleID:         "PQC-TLS-012",
		Title:          "Missing CNSA 2.0 Quantum-Readiness Migration Milestone Gate",
		Description:    "Cluster governance and declarative deployment policies lack automated timeline tracking for CNSA 2.0 cryptographic deprecation deadlines (2025/2030/2033).",
		Severity:       intel.SeverityLow,
		CVSSScore:      3.5,
		Remediation:    "Incorporate automated PQC compliance gates into deployment pipelines via nix-k8s-sentinel.",
		CNSATargetYear: 2025,
	},
}

// GetRulesCatalog returns the authoritative list of all 12 canonical PQC & CNSA 2.0 security rules.
func GetRulesCatalog() []PQCRule {
	catalog := make([]PQCRule, len(defaultPQCRules))
	copy(catalog, defaultPQCRules)
	return catalog
}

// LookupRule retrieves a rule from the catalog by its unique identifier.
func LookupRule(ruleID string) (PQCRule, bool) {
	for _, r := range defaultPQCRules {
		if r.RuleID == ruleID {
			return r, true
		}
	}
	return PQCRule{}, false
}
