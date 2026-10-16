package hsm

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes defines the strict 10MB size ceiling for HSM and KMS configuration manifests.
	MaxManifestBytes = 10 * 1024 * 1024

	// MaxTelemetryBytes defines the strict 5MB size ceiling for runtime HSM and KMS telemetry data.
	MaxTelemetryBytes = 5 * 1024 * 1024

	// MaxKeyCount defines the defensive bounds ceiling for keys audited in a single report.
	MaxKeyCount = 5000

	// MaxSlotCount defines the maximum PKCS#11 slots parsed in a single session.
	MaxSlotCount = 256

	// MaxRotationAgeDays defines the warning threshold for unrotated Key Encryption Keys (KEK).
	MaxRotationAgeDays = 90.0

	// CriticalRotationAgeDays defines the critical threshold for overdue Key Encryption Keys.
	CriticalRotationAgeDays = 180.0

	// MaxKMSLatencyMs defines the latency threshold above which a KMS v2 plugin risks API server stalls.
	MaxKMSLatencyMs = 100.0
)

// HSMProviderType enumerates supported hardware security module and KMS providers.
type HSMProviderType string

const (
	ProviderPKCS11       HSMProviderType = "PKCS11"
	ProviderNitroEnclave HSMProviderType = "NitroEnclave"
	ProviderTPM2         HSMProviderType = "TPM2"
	ProviderVaultKMS     HSMProviderType = "VaultKMS"
	ProviderKMSv2Generic HSMProviderType = "KMSv2Generic"
	ProviderUnknown      HSMProviderType = "Unknown"
)

// KMSVersion represents the Kubernetes KMS plugin API contract version.
type KMSVersion string

const (
	KMSVersionV1      KMSVersion = "v1"
	KMSVersionV2      KMSVersion = "v2"
	KMSVersionUnknown KMSVersion = "unknown"
)

// CipherSuite represents cryptographic algorithms audited for envelope encryption.
type CipherSuite string

const (
	CipherAESGCM256        CipherSuite = "AES-GCM-256"
	CipherChaCha20Poly1305 CipherSuite = "ChaCha20-Poly1305"
	CipherAESCBC256        CipherSuite = "AES-CBC-256"
	CipherAESCBC128        CipherSuite = "AES-CBC-128"
	Cipher3DES             CipherSuite = "3DES"
	CipherRSA4096          CipherSuite = "RSA-4096"
	CipherRSA2048          CipherSuite = "RSA-2048"
	CipherRSA1024          CipherSuite = "RSA-1024"
	CipherPQCMLKEM         CipherSuite = "ML-KEM-768"
	CipherUnknown          CipherSuite = "Unknown"
)

// PluginHealthStatus indicates the runtime operational state of a KMS or HSM plugin.
type PluginHealthStatus string

const (
	PluginStatusHealthy   PluginHealthStatus = "HEALTHY"
	PluginStatusDegraded  PluginHealthStatus = "DEGRADED"
	PluginStatusOffline   PluginHealthStatus = "OFFLINE"
	PluginStatusUnchecked PluginHealthStatus = "UNCHECKED"
)

// KMSProviderConfig represents an individual provider entry within a Kubernetes EncryptionConfiguration.
type KMSProviderConfig struct {
	Name           string     `json:"name"`
	ApiVersion     KMSVersion `json:"api_version"`
	Endpoint       string     `json:"endpoint"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	CacheSize      int        `json:"cache_size"`
	IsUnixSocket   bool       `json:"is_unix_socket"`
}

// KMSEncryptionConfig represents a parsed Kubernetes etcd EncryptionConfiguration manifest.
type KMSEncryptionConfig struct {
	ApiVersion          string              `json:"api_version"`
	EncryptedResources  []string            `json:"encrypted_resources"`
	PrimaryProviderType string              `json:"primary_provider_type"`
	KMSProviders        []KMSProviderConfig `json:"kms_providers"`
	HasIdentityFallback bool                `json:"has_identity_fallback"`
	HasKMSFallback      bool                `json:"has_kms_fallback"`
	IsKMSv2             bool                `json:"is_kms_v2"`
	FilePath            string              `json:"file_path,omitempty"`
}

// PKCS11Declaration represents a parsed PKCS#11 configuration block or URI.
type PKCS11Declaration struct {
	ModulePath       string      `json:"module_path"`
	SlotID           int         `json:"slot_id"`
	TokenLabel       string      `json:"token_label"`
	KeyLabel         string      `json:"key_label"`
	KeyID            string      `json:"key_id"`
	CipherSuite      CipherSuite `json:"cipher_suite"`
	HasPlaintextPIN  bool        `json:"has_plaintext_pin"`
	HasPinSourceFile bool        `json:"has_pin_source_file"`
	IsReadOnlySlot   bool        `json:"is_read_only_slot"`
	SourceFile       string      `json:"source_file,omitempty"`
	LineNumber       int         `json:"line_number,omitempty"`
}

// NitroEnclaveDeclaration represents AWS Nitro Enclave isolation settings for master key wrapping.
type NitroEnclaveDeclaration struct {
	VSockCID               int    `json:"vsock_cid"`
	VSockPort              int    `json:"vsock_port"`
	PCR0Digest             string `json:"pcr0_digest"`
	EnclaveImageFile       string `json:"enclave_image_file"`
	AttestationTimeoutSecs int    `json:"attestation_timeout_secs"`
	IsSessionSealed        bool   `json:"is_session_sealed"`
	SourceFile             string `json:"source_file,omitempty"`
	LineNumber             int    `json:"line_number,omitempty"`
}

// HSMKeyTelemetry represents runtime status of an individual Key Encryption Key (KEK).
type HSMKeyTelemetry struct {
	KeyID        string    `json:"key_id"`
	KeyLabel     string    `json:"key_label"`
	ProviderType string    `json:"provider_type"`
	Algorithm    string    `json:"algorithm"`
	CreatedAt    time.Time `json:"created_at"`
	LastRotated  time.Time `json:"last_rotated"`
	AgeDays      float64   `json:"age_days"`
	IsRotated    bool      `json:"is_rotated"`
	IsCompromised bool     `json:"is_compromised"`
}

// HSMRuntimeTelemetry represents live cluster telemetry from KMS plugins and HSM daemons.
type HSMRuntimeTelemetry struct {
	ClusterID        string             `json:"cluster_id"`
	NodeName         string             `json:"node_name"`
	ProviderType     HSMProviderType    `json:"provider_type"`
	PluginStatus     PluginHealthStatus `json:"plugin_status"`
	CurrentKeyID     string             `json:"current_key_id"`
	AverageLatencyMs float64            `json:"average_latency_ms"`
	CacheHitRatio    float64            `json:"cache_hit_ratio"`
	TotalOperations  uint64             `json:"total_operations"`
	FailedOperations uint64             `json:"failed_operations"`
	ActiveKeys       []HSMKeyTelemetry  `json:"active_keys"`
	NitroEnclaveOK   bool               `json:"nitro_enclave_ok"`
	ObservedAt       time.Time          `json:"observed_at"`
}

// HSMRule represents a canonical security rule for HSM and PKCS#11 envelope encryption.
type HSMRule struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Severity      intel.Severity `json:"severity"`
	DefaultCVSS   float64        `json:"default_cvss"`
	Description   string         `json:"description"`
	Remediation   string         `json:"remediation"`
	AssociatedCVE string         `json:"associated_cve,omitempty"`
}

// HSMViolation represents an audited deviation against canonical HSM and KMS security policies.
type HSMViolation struct {
	RuleID        string         `json:"rule_id"`
	Title         string         `json:"title"`
	Severity      intel.Severity `json:"severity"`
	CVSSScore     float64        `json:"cvss_score"`
	Description   string         `json:"description"`
	Remediation   string         `json:"remediation"`
	ResourceURI   string         `json:"resource_uri"`
	LineNumber    int            `json:"line_number,omitempty"`
	ProviderName  string         `json:"provider_name,omitempty"`
	MatchedCVE    string         `json:"matched_cve,omitempty"`
	ActualValue   string         `json:"actual_value,omitempty"`
	ExpectedValue string         `json:"expected_value,omitempty"`
}

// HSMSummary encapsulates statistical findings across an HSM & KMS audit session.
type HSMSummary struct {
	TotalConfigsScanned int     `json:"total_configs_scanned"`
	TotalKeysAudited    int     `json:"total_keys_audited"`
	ViolationsCount     int     `json:"violations_count"`
	CriticalCount       int     `json:"critical_count"`
	HighCount           int     `json:"high_count"`
	MediumCount         int     `json:"medium_count"`
	LowCount            int     `json:"low_count"`
	ComplianceScore     float64 `json:"compliance_score"`
	AuditStatus         string  `json:"audit_status"`
}

// HSMAuditReport captures the complete outcome of an HSM and envelope encryption audit.
type HSMAuditReport struct {
	Timestamp  time.Time      `json:"timestamp"`
	Summary    HSMSummary     `json:"summary"`
	Violations []HSMViolation `json:"violations"`
	Configs    []KMSEncryptionConfig `json:"configs,omitempty"`
	Telemetry  []HSMRuntimeTelemetry `json:"telemetry,omitempty"`
}
