package webhook

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Defensive memory safety bounds and streaming thresholds.
const (
	MaxManifestBytes       int64         = 10 * 1024 * 1024 // 10MB maximum manifest payload
	MaxTelemetryBytes      int64         = 5 * 1024 * 1024  // 5MB maximum runtime telemetry payload
	MaxAllowedScanLines    int           = 20000            // Maximum configuration lines to process
	MaxTelemetryEvents     int           = 5000             // Maximum telemetry events per audit cycle
	MaxSafeTimeoutSeconds  int           = 3                // Maximum safe webhook latency timeout
	MinCARenewalWindowDays int           = 30               // Minimum safe CA certificate renewal buffer in days
	CriticalP99LatencyMs   float64       = 500.0            // Latency threshold triggering API server stall warning
	MaxAcceptableErrorRate float64       = 5.0              // Maximum allowable admission error/timeout percentage
)

// WebhookType specifies whether an admission webhook validates or mutates admission payloads.
type WebhookType string

const (
	WebhookTypeValidating WebhookType = "VALIDATING"
	WebhookTypeMutating   WebhookType = "MUTATING"
)

// FailurePolicy defines how the Kubernetes API server handles admission webhook call failures.
type FailurePolicy string

const (
	FailurePolicyFail   FailurePolicy = "Fail"
	FailurePolicyIgnore FailurePolicy = "Ignore"
)

// SideEffectClass defines whether an admission webhook has operational side-effects.
type SideEffectClass string

const (
	SideEffectNone        SideEffectClass = "None"
	SideEffectNoneOnDryRun SideEffectClass = "NoneOnDryRun"
	SideEffectSome        SideEffectClass = "Some"
)

// ReinvocationPolicy defines whether a mutating webhook is reinvoked after subsequent mutations.
type ReinvocationPolicy string

const (
	ReinvocationIfNeeded ReinvocationPolicy = "IfNeeded"
	ReinvocationNever    ReinvocationPolicy = "Never"
)

// WebhookServiceRef describes in-cluster Service endpoints for admission webhooks.
type WebhookServiceRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Path      string `json:"path"`
	Port      int32  `json:"port"`
}

// AdmissionRule defines matching criteria for intercepted API operations and resources.
type AdmissionRule struct {
	Operations  []string `json:"operations"`
	APIGroups   []string `json:"api_groups"`
	APIVersions []string `json:"api_versions"`
	Resources   []string `json:"resources"`
	Scope       string   `json:"scope,omitempty"`
}

// WebhookConfig models declarative ValidatingWebhookConfiguration and MutatingWebhookConfiguration.
type WebhookConfig struct {
	Name                    string             `json:"name"`
	Type                    WebhookType        `json:"type"`
	FailurePolicy           FailurePolicy      `json:"failure_policy"`
	TimeoutSeconds          int                `json:"timeout_seconds"`
	NamespaceSelector       map[string]string  `json:"namespace_selector,omitempty"`
	ExemptsKubeSystem       bool               `json:"exempts_kube_system"`
	ObjectSelector          map[string]string  `json:"object_selector,omitempty"`
	Rules                   []AdmissionRule    `json:"rules"`
	CABundleRaw             string             `json:"ca_bundle_raw,omitempty"`
	CAExpiration            time.Time          `json:"ca_expiration"`
	CADaysRemaining         int                `json:"ca_days_remaining"`
	CAValid                 bool               `json:"ca_valid"`
	CAExpired               bool               `json:"ca_expired"`
	InsecureSkipTLSVerify   bool               `json:"insecure_skip_tls_verify"`
	Service                 *WebhookServiceRef `json:"service,omitempty"`
	URL                     string             `json:"url,omitempty"`
	AdmissionReviewVersions []string           `json:"admission_review_versions"`
	SideEffects             SideEffectClass    `json:"side_effects"`
	ReinvocationPolicy      ReinvocationPolicy `json:"reinvocation_policy,omitempty"`
	FilePath                string             `json:"file_path,omitempty"`
	StartLine               int                `json:"start_line,omitempty"`
}

// WebhookLatencyMetric tracks live admission webhook performance from API server metrics.
type WebhookLatencyMetric struct {
	WebhookName      string  `json:"webhook_name"`
	P50Ms            float64 `json:"p50_ms"`
	P95Ms            float64 `json:"p95_ms"`
	P99Ms            float64 `json:"p99_ms"`
	RequestCount     int64   `json:"request_count"`
	ErrorRatePercent float64 `json:"error_rate_percent"`
	TimeoutCount     int64   `json:"timeout_count"`
	StallWarning     bool    `json:"stall_warning"`
}

// CACertStatus tracks the rotation health of an admission webhook CA certificate.
type CACertStatus struct {
	CertName            string    `json:"cert_name"`
	Issuer              string    `json:"issuer"`
	Subject             string    `json:"subject"`
	NotBefore           time.Time `json:"not_before"`
	NotAfter            time.Time `json:"not_after"`
	DaysRemaining       int       `json:"days_remaining"`
	IsExpired           bool      `json:"is_expired"`
	AutoRotationEnabled bool      `json:"auto_rotation_enabled"`
}

// WebhookTelemetry encapsulates runtime telemetry collected from the Kubernetes API server and cert-manager.
type WebhookTelemetry struct {
	Timestamp       time.Time              `json:"timestamp"`
	ClusterID       string                 `json:"cluster_id"`
	Metrics         []WebhookLatencyMetric `json:"metrics"`
	CACertificates  []CACertStatus         `json:"ca_certificates"`
}

// WebhookRule represents an authoritative security rule in the admission webhook catalog.
type WebhookRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// WebhookViolation represents a non-compliant webhook finding identified during an audit.
type WebhookViolation struct {
	RuleID      string         `json:"rule_id"`
	WebhookName string         `json:"webhook_name"`
	WebhookType WebhookType    `json:"webhook_type"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
	FilePath    string         `json:"file_path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
}

// WebhookSummary provides aggregated posture statistics on admission webhooks and CA certificates.
type WebhookSummary struct {
	TotalWebhooksScanned int      `json:"total_webhooks_scanned"`
	ValidatingCount      int      `json:"validating_count"`
	MutatingCount        int      `json:"mutating_count"`
	CompliantWebhooks    int      `json:"compliant_webhooks"`
	CriticalCount        int      `json:"critical_count"`
	HighCount            int      `json:"high_count"`
	MediumCount          int      `json:"medium_count"`
	LowCount             int      `json:"low_count"`
	ExpiredCACount       int      `json:"expired_ca_count"`
	ExpiringCACount      int      `json:"expiring_ca_count"`
	TimeoutRiskCount     int      `json:"timeout_risk_count"`
	BypassRiskCount      int      `json:"bypass_risk_count"`
	AverageP99LatencyMs  float64  `json:"average_p99_latency_ms"`
	ComplianceScore      float64  `json:"compliance_score"`
	HighRiskWebhookNames []string `json:"high_risk_webhook_names,omitempty"`
}

// WebhookAuditReport holds the complete evaluation results of an admission webhook audit.
type WebhookAuditReport struct {
	Configurations []WebhookConfig    `json:"configurations"`
	Violations     []WebhookViolation `json:"violations"`
	Summary        WebhookSummary     `json:"summary"`
	Telemetry      *WebhookTelemetry  `json:"telemetry,omitempty"`
}
