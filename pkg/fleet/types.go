package fleet

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB defensive limit to prevent resource exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes limits JSON fleet telemetry payloads to 10MB.
	MaxTelemetryBytes = 10 * 1024 * 1024
	// MaxScanLines guards against unbounded line iteration in manifests.
	MaxScanLines = 20000
	// MaxDocumentsPerStream prevents algorithmic complexity attacks via document flooding.
	MaxDocumentsPerStream = 2000
	// MaxClustersInFleet sets a defensive ceiling on cluster nodes in telemetry.
	MaxClustersInFleet = 100
	// MaxTokenAgeHours defines the ceiling for valid short-lived OIDC federated tokens (24 hours).
	MaxTokenAgeHours = 24.0
)

// FleetViolationCategory categorizes multi-cluster and federated identity findings.
type FleetViolationCategory string

const (
	CategoryRBAC         FleetViolationCategory = "RBAC"
	CategoryOIDC         FleetViolationCategory = "OIDC"
	CategoryGitOpsDrift  FleetViolationCategory = "GitOps-Drift"
	CategoryMultiCluster FleetViolationCategory = "Multi-Cluster"
)

// FleetViolation represents a security or drift violation in fleet RBAC, OIDC, or GitOps states.
type FleetViolation struct {
	RuleID       string                 `json:"rule_id"`
	Title        string                 `json:"title"`
	Severity     intel.Severity         `json:"severity"`
	CVSSScore    float64                `json:"cvss_score"`
	Category     FleetViolationCategory `json:"category"`
	ResourceKind string                 `json:"resource_kind"`
	ResourceName string                 `json:"resource_name"`
	ClusterID    string                 `json:"cluster_id,omitempty"`
	Namespace    string                 `json:"namespace,omitempty"`
	FilePath     string                 `json:"file_path,omitempty"`
	StartLine    int                    `json:"start_line,omitempty"`
	Message      string                 `json:"message"`
	Remediation  string                 `json:"remediation"`
	MatchedCVE   string                 `json:"matched_cve,omitempty"`
}

// FleetRule defines a canonical static or telemetry audit rule in the Fleet & OIDC threat catalog.
type FleetRule struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Severity    intel.Severity         `json:"severity"`
	CVSSScore   float64                `json:"cvss_score"`
	Category    FleetViolationCategory `json:"category"`
	Description string                 `json:"description"`
	Remediation string                 `json:"remediation"`
}

// OIDCTokenDeclaration models a short-lived federated identity token or authenticator configuration.
type OIDCTokenDeclaration struct {
	TokenID         string    `json:"token_id"`
	ClusterID       string    `json:"cluster_id"`
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"client_id"`
	Audience        string    `json:"audience"`
	Subject         string    `json:"subject"`
	SigningAlg      string    `json:"signing_alg"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	TTLSeconds      int64     `json:"ttl_seconds"`
	KeyRotationDays int       `json:"key_rotation_days,omitempty"`
}

// GitOpsSyncStatus captures runtime synchronization, drift, and health of an ArgoCD or Flux application.
type GitOpsSyncStatus struct {
	AppName           string `json:"app_name"`
	TargetCluster     string `json:"target_cluster"`
	Namespace         string `json:"namespace"`
	Engine            string `json:"engine"` // "ArgoCD" or "Flux"
	SourceRepo        string `json:"source_repo"`
	TargetRevision    string `json:"target_revision"`
	CurrentRevision   string `json:"current_revision"`
	SyncStatus        string `json:"sync_status"`   // "Synced", "OutOfSync", "Unknown"
	HealthStatus      string `json:"health_status"` // "Healthy", "Degraded", "Progressing", "Missing"
	AutomatedSelfHeal bool   `json:"automated_self_heal"`
	DriftDetails      string `json:"drift_details,omitempty"`
}

// ClusterFleetNode models an individual cluster in the geographically distributed fleet.
type ClusterFleetNode struct {
	ClusterID        string `json:"cluster_id"`
	Region           string `json:"region"`
	Provider         string `json:"provider"`
	K8sVersion       string `json:"k8s_version"`
	Connected        bool   `json:"connected"`
	RBACAdminRoles   int    `json:"rbac_admin_roles"`
	ActiveOIDCTokens int    `json:"active_oidc_tokens"`
}

// FleetTelemetryReport represents the runtime multi-cluster telemetry payload ingested by the radar.
type FleetTelemetryReport struct {
	Timestamp      time.Time              `json:"timestamp"`
	FleetID        string                 `json:"fleet_id"`
	Clusters       []ClusterFleetNode     `json:"clusters"`
	GitOpsApps     []GitOpsSyncStatus     `json:"gitops_apps"`
	OIDCTokens     []OIDCTokenDeclaration `json:"oidc_tokens"`
	TelemetryNotes string                 `json:"telemetry_notes,omitempty"`
}

// FleetSummary aggregates compliance metrics across fleet RBAC, OIDC tokens, and GitOps sync states.
type FleetSummary struct {
	TotalChecks        int     `json:"total_checks"`
	PassedChecks       int     `json:"passed_checks"`
	ComplianceScore    float64 `json:"compliance_score"`
	CriticalCount      int     `json:"critical_count"`
	HighCount          int     `json:"high_count"`
	MediumCount        int     `json:"medium_count"`
	LowCount           int     `json:"low_count"`
	ClustersAudited    int     `json:"clusters_audited"`
	ClustersInSync     int     `json:"clusters_in_sync"`
	DriftingApps       int     `json:"drifting_apps"`
	OIDCTokensVerified int     `json:"oidc_tokens_verified"`
}

// FleetAuditReport models the consolidated output of static manifest audits and runtime telemetry.
type FleetAuditReport struct {
	Timestamp     time.Time        `json:"timestamp"`
	TotalFiles    int              `json:"total_files"`
	TotalClusters int              `json:"total_clusters"`
	Violations    []FleetViolation `json:"violations"`
	Summary       FleetSummary     `json:"summary"`
}
