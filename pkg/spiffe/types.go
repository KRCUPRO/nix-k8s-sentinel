package spiffe

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Defensive size and count ceilings to prevent memory exhaustion and unbounded allocation.
const (
	MaxManifestBytes             = 10 * 1024 * 1024 // 10MB manifest limit
	MaxTelemetryBytes            = 5 * 1024 * 1024  // 5MB telemetry payload limit
	MaxSVIDCount                 = 1000             // Maximum SVID records processed per run
	MaxScanLines                 = 20000            // Maximum lines scanned per file
	MaxSVIDLifespanHours         = 24.0             // Ephemeral SVID threshold (24 hours)
	MinSVIDRenewalRemainingHours = 0.25             // Minimum renewal window: 15 minutes (0.25h)
)

// SPIFFEViolationCategory categorizes findings in workload identity and microsegmentation.
type SPIFFEViolationCategory string

const (
	CategorySVIDValidity     SPIFFEViolationCategory = "svid-validity"
	CategoryTrustDomain      SPIFFEViolationCategory = "trust-domain"
	CategoryAttestation      SPIFFEViolationCategory = "attestation"
	CategoryMicrosegment     SPIFFEViolationCategory = "microsegmentation"
	CategoryAgentSecurity    SPIFFEViolationCategory = "agent-security"
	CategoryCryptographicKey SPIFFEViolationCategory = "crypto-key"
)

// SPIFFEViolation represents a detected security finding in SPIFFE/SPIRE or Cilium policy.
type SPIFFEViolation struct {
	RuleID       string                  `json:"rule_id"`
	Title        string                  `json:"title"`
	Severity     intel.Severity          `json:"severity"`
	CVSSScore    float64                 `json:"cvss_score"`
	Category     SPIFFEViolationCategory `json:"category"`
	ResourceKind string                  `json:"resource_kind"`
	ResourceName string                  `json:"resource_name"`
	Namespace    string                  `json:"namespace,omitempty"`
	FilePath     string                  `json:"file_path,omitempty"`
	StartLine    int                     `json:"start_line,omitempty"`
	Message      string                  `json:"message"`
	Remediation  string                  `json:"remediation"`
	MatchedCVE   string                  `json:"matched_cve,omitempty"`
	SPIFFEID     string                  `json:"spiffe_id,omitempty"`
	TrustDomain  string                  `json:"trust_domain,omitempty"`
	Workload     string                  `json:"workload,omitempty"`
}

// SPIFFERule defines a canonical security benchmark check for SPIFFE/SPIRE and Cilium.
type SPIFFERule struct {
	RuleID          string
	Title           string
	Category        SPIFFEViolationCategory
	DefaultSeverity intel.Severity
	BaseCVSS        float64
	Description     string
	Remediation     string
	ThreatPattern   string
}

// SVIDRecord models an issued X.509 SVID credential record from runtime telemetry.
type SVIDRecord struct {
	SPIFFEID           string    `json:"spiffe_id"`
	TrustDomain        string    `json:"trust_domain"`
	Namespace          string    `json:"namespace"`
	ServiceAccount     string    `json:"service_account"`
	WorkloadID         string    `json:"workload_id"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	KeyType            string    `json:"key_type"` // e.g. "ECDSA-P256", "Ed25519", "RSA-2048", "RSA-1024"
	KeyBits            int       `json:"key_bits"`
	SerialNumber       string    `json:"serial_number"`
	IssuerCA           string    `json:"issuer_ca"`
	RevocationEndpoint string    `json:"revocation_endpoint,omitempty"`
	ActiveNode         string    `json:"active_node"`
}

// WorkloadIdentity encapsulates attested workload identity attributes.
type WorkloadIdentity struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	SPIFFEID    string            `json:"spiffe_id"`
	TrustDomain string            `json:"trust_domain"`
	Selectors   map[string]string `json:"selectors"`
	Attested    bool              `json:"attested"`
	TTLSeconds  int               `json:"ttl_seconds"`
}

// SPIFFETelemetryReport captures live runtime SVID and SPIRE agent telemetry across nodes.
type SPIFFETelemetryReport struct {
	ClusterID          string       `json:"cluster_id"`
	PrimaryTrustDomain string       `json:"primary_trust_domain"`
	FederatedDomains   []string     `json:"federated_domains,omitempty"`
	SVIDs              []SVIDRecord `json:"svids"`
	AgentAdminSockets  []string     `json:"agent_admin_sockets,omitempty"`
	CapturedAt         time.Time    `json:"captured_at"`
}

// SPIFFESummary aggregates compliance statistics across SPIFFE/SPIRE and Cilium policies.
type SPIFFESummary struct {
	TotalChecks                 int     `json:"total_checks"`
	PassedChecks                int     `json:"passed_checks"`
	ComplianceScore             float64 `json:"compliance_score"`
	CriticalCount               int     `json:"critical_count"`
	HighCount                   int     `json:"high_count"`
	MediumCount                 int     `json:"medium_count"`
	LowCount                    int     `json:"low_count"`
	SVIDsAudited                int     `json:"svids_audited"`
	SVIDsValid                  int     `json:"svids_valid"`
	SVIDsExpiredOrNearExpiry    int     `json:"svids_expired_or_near_expiry"`
	CiliumPoliciesSynthesized   int     `json:"cilium_policies_synthesized"`
}

// SPIFFEAuditReport consolidates results from declarative manifests and runtime telemetry.
type SPIFFEAuditReport struct {
	TotalFiles     int               `json:"total_files"`
	TotalResources int               `json:"total_resources"`
	Violations     []SPIFFEViolation `json:"violations"`
	Summary        SPIFFESummary     `json:"summary"`
	ScannedPaths   []string          `json:"scanned_paths"`
}
