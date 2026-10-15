package gateway

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB defensive limit to prevent resource exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxDocumentsPerStream prevents algorithmic complexity attacks via document flooding.
	MaxDocumentsPerStream = 2000
	// MaxScanLines guards against unbounded line iteration.
	MaxScanLines = 20000
)

// RouteKind identifies the type of Gateway API or Envoy routing resource.
type RouteKind string

const (
	KindGateway        RouteKind = "Gateway"
	KindGatewayClass   RouteKind = "GatewayClass"
	KindHTTPRoute      RouteKind = "HTTPRoute"
	KindGRPCRoute      RouteKind = "GRPCRoute"
	KindTCPRoute       RouteKind = "TCPRoute"
	KindUDPRoute       RouteKind = "UDPRoute"
	KindTLSRoute       RouteKind = "TLSRoute"
	KindReferenceGrant RouteKind = "ReferenceGrant"
	KindEnvoyFilter    RouteKind = "EnvoyFilter"
)

// GatewayViolation represents a concrete security violation in Gateway API or EnvoyFilter configurations.
type GatewayViolation struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	Severity     intel.Severity `json:"severity"`
	CVSSScore    float64        `json:"cvss_score"`
	Category     string         `json:"category"`
	ResourceKind string         `json:"resource_kind"`
	ResourceName string         `json:"resource_name"`
	Namespace    string         `json:"namespace"`
	FilePath     string         `json:"file_path,omitempty"`
	StartLine    int            `json:"start_line,omitempty"`
	Message      string         `json:"message"`
	Remediation  string         `json:"remediation"`
	MatchedCVE   string         `json:"matched_cve,omitempty"`
}

// GatewayRule defines a static security rule in the Gateway API threat radar catalog.
type GatewayRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Category    string         `json:"category"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
}

// ReferenceGrantEntry stores a declarative permission granted across namespace boundaries.
type ReferenceGrantEntry struct {
	GrantNamespace string `json:"grant_namespace"`
	FromGroup      string `json:"from_group"`
	FromKind       string `json:"from_kind"`
	FromNamespace  string `json:"from_namespace"`
	ToGroup        string `json:"to_group"`
	ToKind         string `json:"to_kind"`
	ToName         string `json:"to_name,omitempty"`
}

// GatewaySummary provides fleet-wide aggregate compliance metrics for Gateway API and Envoy resources.
type GatewaySummary struct {
	TotalChecks     int     `json:"total_checks"`
	PassedChecks    int     `json:"passed_checks"`
	ComplianceScore float64 `json:"compliance_score"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
}

// GatewayAuditReport compiles findings across all inspected Gateway and EnvoyFilter manifests.
type GatewayAuditReport struct {
	TargetPath          string                `json:"target_path"`
	TotalFiles          int                   `json:"total_files"`
	TotalResources      int                   `json:"total_resources"`
	Violations          []GatewayViolation    `json:"violations"`
	Summary             GatewaySummary        `json:"summary"`
	ReferenceGrants     []ReferenceGrantEntry `json:"reference_grants,omitempty"`
	EvaluatedResources  []string              `json:"evaluated_resources,omitempty"`
}
