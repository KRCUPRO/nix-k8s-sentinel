package hsm

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

var canonicalRules = map[string]HSMRule{
	"HSM-ENC-001": {
		ID:          "HSM-ENC-001",
		Title:       "Insecure etcd Encryption-At-Rest Configuration",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.5,
		Description: "Kubernetes EncryptionConfiguration has plaintext 'identity' provider configured first or secrets are unencrypted in etcd.",
		Remediation: "Place an authenticated hardware-backed KMS v2 provider at the top of the provider chain before fallback providers.",
	},
	"HSM-ENC-002": {
		ID:          "HSM-ENC-002",
		Title:       "Deprecated KMS v1 Plugin Specification in Use",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 8.2,
		Description: "EncryptionConfiguration specifies deprecated KMS v1 API ('v1' or 'v1beta1') which lacks health status checks and dynamic key rotation.",
		Remediation: "Migrate EncryptionConfiguration to 'apiserver.config.k8s.io/v1' with KMS v2 provider specifications.",
	},
	"HSM-ENC-003": {
		ID:          "HSM-ENC-003",
		Title:       "Plaintext PKCS#11 PIN or Password Exposed in Manifest",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.8,
		Description: "PKCS#11 URI or host configuration embeds plaintext 'pin-value' parameter, exposing hardware security module credentials.",
		Remediation: "Remove plaintext PIN from manifests; inject PIN via pin-source file with 0400 permissions or protected kernel keyrings.",
	},
	"HSM-ENC-004": {
		ID:          "HSM-ENC-004",
		Title:       "Insecure or Deprecated Cryptographic Cipher Suite",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 8.4,
		Description: "KMS or PKCS#11 configuration utilizes deprecated or weak algorithms (DES, 3DES, AES-CBC-128, or RSA-1024).",
		Remediation: "Enforce AES-GCM-256, ChaCha20-Poly1305, RSA-4096, or post-quantum hybrid ML-KEM-768 for master envelope encryption.",
	},
	"HSM-ENC-005": {
		ID:          "HSM-ENC-005",
		Title:       "KMS v2 Plugin gRPC Health Check Failure or Socket Unreachable",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.2,
		Description: "Runtime telemetry indicates the KMS v2 plugin daemon is offline or returning errors during gRPC status inquiries.",
		Remediation: "Inspect KMS plugin daemon systemd status, verify socket connectivity, and check hardware HSM device drivers.",
	},
	"HSM-ENC-006": {
		ID:          "HSM-ENC-006",
		Title:       "Unrotated Envelope Key Encryption Key (KEK > 90 Days)",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 7.8,
		Description: "Key Encryption Key (KEK) wrapped in HSM or Nitro Enclave has not been rotated within the 90-day compliance window.",
		Remediation: "Trigger master key rotation on the HSM, generate a new Key ID in KMS v2, and perform etcd storage migration.",
	},
	"HSM-ENC-007": {
		ID:          "HSM-ENC-007",
		Title:       "Nitro Enclave / HSM Session Leakage or Unsealed Attestation",
		Severity:    intel.SeverityCritical,
		DefaultCVSS: 9.4,
		Description: "AWS Nitro Enclave or HSM session handle leakage detected, or attestation quotation failed cryptographic sealing.",
		Remediation: "Re-bind enclave session to measured boot PCR0/PCR1, refresh ephemeral session credentials, and isolate vsock CID.",
		AssociatedCVE: "CVE-2026-83190",
	},
	"HSM-ENC-008": {
		ID:          "HSM-ENC-008",
		Title:       "Insecure KMS Plugin Network Transport (Non-Unix Domain Socket)",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 8.7,
		Description: "KMS provider endpoint is configured with a network protocol (TCP/HTTP) rather than a local unix domain socket.",
		Remediation: "Configure endpoint to use local unix domain socket ('unix:///var/run/kmsplugin/socket.sock') with 0600 permissions.",
	},
	"HSM-ENC-009": {
		ID:          "HSM-ENC-009",
		Title:       "Missing Fallback KMS Provider or Single Point of Failure",
		Severity:    intel.SeverityMedium,
		DefaultCVSS: 6.8,
		Description: "EncryptionConfiguration specifies only a single KMS provider without secondary failover or read-only identity fallback.",
		Remediation: "Declare secondary KMS provider or append identity provider as terminal fallback to prevent cluster lockouts.",
	},
	"HSM-ENC-010": {
		ID:          "HSM-ENC-010",
		Title:       "Excessive KMS Encryption Latency or Zero Cache Utilization",
		Severity:    intel.SeverityMedium,
		DefaultCVSS: 6.5,
		Description: "Runtime telemetry reports average KMS v2 encryption latency exceeding 100ms or 0% cache hit ratio.",
		Remediation: "Tune KMS plugin cachesize (recommended >= 1000) and investigate HSM hardware acceleration throughput.",
	},
	"HSM-ENC-011": {
		ID:          "HSM-ENC-011",
		Title:       "NixOS Host Missing Hardware Security Module Daemons",
		Severity:    intel.SeverityMedium,
		DefaultCVSS: 6.0,
		Description: "Host NixOS declarative configuration lacks 'services.p11-kit' or 'hardware.nitro-enclaves' for HSM integration.",
		Remediation: "Enable 'services.p11-kit.enable = true' and configure enclave kernel modules in NixOS configuration.",
	},
	"HSM-ENC-012": {
		ID:          "HSM-ENC-012",
		Title:       "Missing Memory Zeroization or PIN Masking in Process Context",
		Severity:    intel.SeverityHigh,
		DefaultCVSS: 8.0,
		Description: "PKCS#11 authentication tokens or PIN strings persist in unmasked memory regions or debug logs.",
		Remediation: "Ensure cryptographic libraries call explicit memory zeroization and sanitize sensitive logs upon process exit.",
	},
}

// GetRule returns a canonical rule definition by its identifier.
func GetRule(id string) (HSMRule, bool) {
	rule, ok := canonicalRules[id]
	return rule, ok
}

// GetAllRules returns a copy of the canonical rule catalog.
func GetAllRules() map[string]HSMRule {
	res := make(map[string]HSMRule, len(canonicalRules))
	for k, v := range canonicalRules {
		res[k] = v
	}
	return res
}
