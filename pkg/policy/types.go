package policy

import (
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Supported policy engine types.
const (
	EngineFalco      = "falco"
	EngineGatekeeper = "gatekeeper"
	EngineAll        = "all"
)

// Supported Gatekeeper admission enforcement actions.
const (
	EnforceDeny   = "deny"
	EnforceDryRun = "dryrun"
	EnforceWarn   = "warn"
)

// Falco priority levels conforming to official Falco rule schemas.
const (
	FalcoPriorityCritical = "CRITICAL"
	FalcoPriorityError    = "ERROR"
	FalcoPriorityWarning  = "WARNING"
	FalcoPriorityNotice   = "NOTICE"
	FalcoPriorityInfo     = "INFO"
)

// SynthesisOptions configures the behavior of the policy generation engine.
type SynthesisOptions struct {
	EnforcementAction string
	TargetEngines     []string
	NamespaceFilter   []string
	ExcludedRuleIDs   []string
	CustomTags        []string
	IncludeComments   bool
}

// DefaultSynthesisOptions provides production-ready secure defaults.
func DefaultSynthesisOptions() SynthesisOptions {
	return SynthesisOptions{
		EnforcementAction: EnforceDeny,
		TargetEngines:     []string{EngineAll},
		NamespaceFilter:   nil,
		ExcludedRuleIDs:   nil,
		CustomTags:        []string{"sentinel", "declarative-defense"},
		IncludeComments:   true,
	}
}

// SyntheticPolicySet holds the compiled security policies across all target engines.
type SyntheticPolicySet struct {
	GeneratedAt                 time.Time            `json:"generated_at"`
	TotalFalcoRules             int                  `json:"total_falco_rules"`
	TotalOPAConstraintTemplates int                  `json:"total_opa_constraint_templates"`
	TotalOPAConstraints         int                  `json:"total_opa_constraints"`
	FalcoRules                  []FalcoRule          `json:"falco_rules,omitempty"`
	GatekeeperTemplates         []ConstraintTemplate `json:"gatekeeper_templates,omitempty"`
	GatekeeperConstraints       []Constraint         `json:"gatekeeper_constraints,omitempty"`
}

// MapSeverityToFalcoPriority converts CVSS severity levels to standard Falco priority levels.
func MapSeverityToFalcoPriority(severity intel.Severity) string {
	switch strings.ToUpper(string(severity)) {
	case string(intel.SeverityCritical):
		return FalcoPriorityCritical
	case string(intel.SeverityHigh):
		return FalcoPriorityError
	case string(intel.SeverityMedium):
		return FalcoPriorityWarning
	case string(intel.SeverityLow):
		return FalcoPriorityNotice
	default:
		return FalcoPriorityInfo
	}
}
