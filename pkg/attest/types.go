package attest

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB defensive limit to prevent resource exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxAttestationBytes limits JSON telemetry payloads to 10MB.
	MaxAttestationBytes = 10 * 1024 * 1024
	// MaxScanLines guards against unbounded line iteration in Nix expressions.
	MaxScanLines = 20000
	// MaxPCRCount defines the maximum number of TPM 2.0 PCR registers supported (0-23).
	MaxPCRCount = 24
)

// PlatformType defines the confidential computing hardware architecture.
type PlatformType string

const (
	PlatformAmdSEVSNP PlatformType = "AMD SEV-SNP"
	PlatformIntelTDX  PlatformType = "Intel TDX"
	PlatformBareMetal PlatformType = "Bare-Metal TPM2"
	PlatformGeneric   PlatformType = "Generic Attestation"
)

// AttestationViolation represents an identified policy, measurement, or configuration vulnerability.
type AttestationViolation struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	Severity     intel.Severity `json:"severity"`
	CVSSScore    float64        `json:"cvss_score"`
	Category     string         `json:"category"`
	Target       string         `json:"target"`
	Technology   string         `json:"technology"`
	FilePath     string         `json:"file_path,omitempty"`
	StartLine    int            `json:"start_line,omitempty"`
	Message      string         `json:"message"`
	Remediation  string         `json:"remediation"`
	MatchedCVE   string         `json:"matched_cve,omitempty"`
}

// AttestationRule defines a static security rule in the Confidential Computing & Measured Boot catalog.
type AttestationRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Category    string         `json:"category"`
	Technology  string         `json:"technology"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
}

// PCRQuote represents an individual TPM 2.0 Platform Configuration Register reading and verification.
type PCRQuote struct {
	Index           int    `json:"index"`
	DigestAlgorithm string `json:"digest_algorithm"`
	ExpectedDigest  string `json:"expected_digest"`
	ActualDigest    string `json:"actual_digest"`
	Description     string `json:"description"`
	Valid           bool   `json:"valid"`
}

// NodeAttestationReport models a host or worker node's remote attestation and measured boot status.
type NodeAttestationReport struct {
	NodeName                   string            `json:"node_name"`
	Platform                   PlatformType      `json:"platform"`
	AttestationEnclave         string            `json:"attestation_enclave,omitempty"`
	AttestedAt                 time.Time         `json:"attested_at"`
	TokenExpired               bool              `json:"token_expired"`
	DebugMode                  bool              `json:"debug_mode"`
	MemoryEncryptionEnabled    bool              `json:"memory_encryption_enabled"`
	StorePathSignature         string            `json:"store_path_signature"`
	ExpectedStorePathSignature string            `json:"expected_store_path_signature"`
	TCBVersion                 string            `json:"tcb_version,omitempty"`
	MinRequiredTCB             string            `json:"min_required_tcb,omitempty"`
	PCRs                       map[int]string    `json:"pcrs,omitempty"`
	Quotes                     []PCRQuote        `json:"quotes,omitempty"`
	Verified                   bool              `json:"verified"`
}

// AttestationSummary provides aggregate attestation and measured boot metrics across cluster nodes.
type AttestationSummary struct {
	TotalChecks     int     `json:"total_checks"`
	PassedChecks    int     `json:"passed_checks"`
	ComplianceScore float64 `json:"compliance_score"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
	NodesAttested   int     `json:"nodes_attested"`
	NodesVerified   int     `json:"nodes_verified"`
}

// AttestationAuditReport compiles findings across all inspected NixOS manifests and node attestation telemetry.
type AttestationAuditReport struct {
	TargetPath     string                 `json:"target_path,omitempty"`
	TelemetryPath  string                 `json:"telemetry_path,omitempty"`
	TotalFiles     int                    `json:"total_files"`
	TotalNodes     int                    `json:"total_nodes"`
	Violations     []AttestationViolation `json:"violations"`
	Summary        AttestationSummary     `json:"summary"`
	EvaluatedNodes []string               `json:"evaluated_nodes,omitempty"`
}
