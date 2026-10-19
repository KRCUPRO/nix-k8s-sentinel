package nixstore

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes defines the 10MB memory safety ceiling for Nix store manifest files.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes defines the 5MB memory safety ceiling for runtime substitute telemetry.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines defines the line count ceiling for configuration scans.
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents defines the ceiling for runtime telemetry events.
	MaxTelemetryEvents = 5000
)

// Ed25519KeyDeclaration encapsulates an authorized public key used to verify binary cache substitutes.
type Ed25519KeyDeclaration struct {
	KeyName     string `json:"key_name"`
	PublicKey   string `json:"public_key"`
	RawString   string `json:"raw_string"`
	ValidFormat bool   `json:"valid_format"`
	LineNumber  int    `json:"line_number,omitempty"`
}

// SubstituterDeclaration describes a configured remote binary cache substituter.
type SubstituterDeclaration struct {
	URL        string `json:"url"`
	IsHTTPS    bool   `json:"is_https"`
	Priority   int    `json:"priority,omitempty"`
	LineNumber int    `json:"line_number,omitempty"`
}

// StoreSecurityConfig models the declarative security settings of a Nix daemon or builder host.
type StoreSecurityConfig struct {
	FilePath          string                   `json:"file_path"`
	HostName          string                   `json:"host_name,omitempty"`
	RequireSigs       *bool                    `json:"require_sigs"`
	TrustedPublicKeys []Ed25519KeyDeclaration  `json:"trusted_public_keys"`
	Substituters      []SubstituterDeclaration `json:"substituters"`
	TrustedUsers      []string                 `json:"trusted_users"`
	AllowedUsers      []string                 `json:"allowed_users"`
	Sandbox           *bool                    `json:"sandbox"`
	SandboxFallback   *bool                    `json:"sandbox_fallback"`
	PureEval          *bool                    `json:"pure_eval"`
	AcceptFlakeConfig *bool                    `json:"accept_flake_config"`
	BuildUsersGroup   string                   `json:"build_users_group"`
	BuildUsersCount   int                      `json:"build_users_count"`
	NetrcFile         string                   `json:"netrc_file"`
	NetrcPermissions  string                   `json:"netrc_permissions"`
	GCAutomatic       *bool                    `json:"gc_automatic"`
	LineNumbers       map[string]int           `json:"line_numbers,omitempty"`
}

// SubstituterTelemetry captures runtime metrics for an individual binary cache substituter.
type SubstituterTelemetry struct {
	URL                 string  `json:"url"`
	DownloadsTotal      int     `json:"downloads_total"`
	SignaturesVerified  int     `json:"signatures_verified"`
	SignaturesRejected  int     `json:"signatures_rejected"`
	P95LatencyMs        float64 `json:"p95_latency_ms"`
	Healthy             bool    `json:"healthy"`
}

// StoreTelemetryEvent models an individual anomalous runtime event logged by the Nix daemon.
type StoreTelemetryEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // e.g. "SIGNATURE_REJECTED", "CHECKSUM_MISMATCH", "UNAUTHORIZED_ELEVATION"
	Substituter string    `json:"substituter,omitempty"`
	StorePath   string    `json:"store_path,omitempty"`
	Details     string    `json:"details"`
}

// NixStoreTelemetryReport consolidates live runtime substitute and store health metrics.
type NixStoreTelemetryReport struct {
	HostName                     string                 `json:"host_name"`
	CollectedAt                  time.Time              `json:"collected_at"`
	StorePathCount               int                    `json:"store_path_count"`
	StoreUsedBytes               int64                  `json:"store_used_bytes"`
	StoreCapacityBytes           int64                  `json:"store_capacity_bytes"`
	StoreUsagePercent            float64                `json:"store_usage_percent"`
	ActiveSubstituters           []SubstituterTelemetry `json:"active_substituters"`
	SignatureVerificationsTotal  int                    `json:"signature_verifications_total"`
	SignatureRejectionsCount     int                    `json:"signature_rejections_count"`
	SignatureRejectionRate       float64                `json:"signature_rejection_rate"`
	NARChecksumFailuresCount     int                    `json:"nar_checksum_failures_count"`
	DownloadP95LatencyMs         float64                `json:"download_p95_latency_ms"`
	UnauthorizedElevationAttempts int                   `json:"unauthorized_elevation_attempts"`
	Events                       []StoreTelemetryEvent  `json:"events"`
}

// StoreRule defines a canonical security rule for Nix store and binary cache posture.
type StoreRule struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Severity       intel.Severity `json:"severity"`
	CVSSScore      float64        `json:"cvss_score"`
	Description    string         `json:"description"`
	Remediation    string         `json:"remediation"`
	DefaultEnabled bool           `json:"default_enabled"`
}

// StoreViolation represents an identified vulnerability or compliance deviation.
type StoreViolation struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Severity     intel.Severity `json:"severity"`
	CVSSScore    float64        `json:"cvss_score"`
	ConfigTarget string         `json:"config_target"`
	FilePath     string         `json:"file_path"`
	StartLine    int            `json:"start_line"`
	Remediation  string         `json:"remediation"`
	MatchedCVE   string         `json:"matched_cve,omitempty"`
}

// StoreSummary summarizes overall audit findings and compliance posture.
type StoreSummary struct {
	TotalConfigs        int     `json:"total_configs"`
	TotalViolations     int     `json:"total_violations"`
	CriticalCount       int     `json:"critical_count"`
	HighCount           int     `json:"high_count"`
	MediumCount         int     `json:"medium_count"`
	LowCount            int     `json:"low_count"`
	ComplianceScore     float64 `json:"compliance_score"`
	SandboxingEnforced  bool    `json:"sandboxing_enforced"`
	SignaturesEnforced  bool    `json:"signatures_enforced"`
}

// StoreAuditReport consolidates all configurations, telemetry, and violations.
type StoreAuditReport struct {
	Configs     []StoreSecurityConfig    `json:"configs"`
	Telemetry   *NixStoreTelemetryReport `json:"telemetry,omitempty"`
	Violations  []StoreViolation         `json:"violations"`
	Summary     StoreSummary             `json:"summary"`
	ScannedAt   time.Time                `json:"scanned_at"`
}
