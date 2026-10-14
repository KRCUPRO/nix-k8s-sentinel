package bench

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes restricts benchmark manifest size to 10MB to prevent memory exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024

	// MaxScanLines bounds per-file line inspection to protect scanner throughput.
	MaxScanLines = 10000
)

// ComponentType identifies the target Kubernetes control plane or worker node component.
type ComponentType string

const (
	ComponentAPIServer         ComponentType = "apiserver"
	ComponentControllerManager ComponentType = "controller-manager"
	ComponentScheduler         ComponentType = "scheduler"
	ComponentEtcd              ComponentType = "etcd"
	ComponentKubelet           ComponentType = "kubelet"
)

// CISRule defines a standardized CIS Kubernetes Benchmark security check.
type CISRule struct {
	ID             string             `json:"id"`
	Section        string             `json:"section"`
	Component      ComponentType      `json:"component"`
	Title          string             `json:"title"`
	Description    string             `json:"description"`
	Severity       intel.Severity `json:"severity"`
	CVSSScore      float64            `json:"cvss_score"`
	FlagName       string             `json:"flag_name"`
	ExpectedValue  string             `json:"expected_value"`
	RemediationNix string             `json:"remediation_nix"`
	RemediationYAML string            `json:"remediation_yaml"`
	Rationale      string             `json:"rationale"`
}

// CISViolation represents an unhardened control plane or worker flag identified during benchmark inspection.
type CISViolation struct {
	RuleID         string             `json:"rule_id"`
	Section        string             `json:"section"`
	Component      ComponentType      `json:"component"`
	FilePath       string             `json:"file_path"`
	StartLine      int                `json:"start_line"`
	Severity       intel.Severity `json:"severity"`
	CVSSScore      float64            `json:"cvss_score"`
	Title          string             `json:"title"`
	Description    string             `json:"description"`
	FlagName       string             `json:"flag_name"`
	ActualValue    string             `json:"actual_value"`
	ExpectedValue  string             `json:"expected_value"`
	Remediation    string             `json:"remediation"`
	RemediationNix string             `json:"remediation_nix,omitempty"`
	MatchedCVE     string             `json:"matched_cve,omitempty"`
}

// CISSummary contains aggregated compliance statistics across the audited cluster components.
type CISSummary struct {
	TotalChecks      int            `json:"total_checks"`
	PassedChecks     int            `json:"passed_checks"`
	FailedChecks     int            `json:"failed_checks"`
	ComplianceScore  float64        `json:"compliance_score"` // Percentage 0.0 - 100.0%
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	MediumCount      int            `json:"medium_count"`
	LowCount         int            `json:"low_count"`
	ComponentScores  map[string]float64 `json:"component_scores"` // Component -> Pass percentage
}

// ComponentDeclaration models an extracted declarative component definition with parsed configuration flags.
type ComponentDeclaration struct {
	Component ComponentType     `json:"component"`
	FilePath  string            `json:"file_path"`
	StartLine int               `json:"start_line"`
	Flags     map[string]string `json:"flags"`
	RawBlock  string            `json:"raw_block,omitempty"`
}

// CISAuditReport encapsulates the full result of a CIS Kubernetes Benchmark scan.
type CISAuditReport struct {
	AuditTime    time.Time              `json:"audit_time"`
	TotalFiles   int                    `json:"total_files"`
	Components   []ComponentDeclaration `json:"components"`
	Violations   []CISViolation         `json:"violations"`
	Summary      CISSummary             `json:"summary"`
}
