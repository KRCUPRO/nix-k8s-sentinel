package remediate

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Security bounds and memory safety invariants.
const (
	MaxPatchBytes       = 5 * 1024 * 1024 // 5MB maximum patch file size
	MaxAllowedScanLines = 20000           // Maximum lines processed in streaming parser
	MaxCanaryChecks     = 128             // Maximum canary validation checks per run
	MaxPullRequests     = 100             // Maximum synthesized GitOps PRs per run
	MaxPatchItems       = 500             // Maximum patch items per report
)

// PatchFormat designates the representation of declarative remediation patches.
type PatchFormat string

const (
	PatchFormatNixOS                  PatchFormat = "nixos-module"
	PatchFormatKustomizeStrategicMerge PatchFormat = "kustomize-strategic-merge"
	PatchFormatKustomizeJSONPatch     PatchFormat = "kustomize-json6902"
	PatchFormatUnifiedDiff            PatchFormat = "unified-diff"
)

// CanaryStatus defines the execution state of a patch pre-flight canary test.
type CanaryStatus string

const (
	CanaryPending CanaryStatus = "PENDING"
	CanaryPassed  CanaryStatus = "PASSED"
	CanaryFailed  CanaryStatus = "FAILED"
	CanarySkipped CanaryStatus = "SKIPPED"
)

// CanaryCheck records the result of an automated pre-flight canary validation.
type CanaryCheck struct {
	Name        string       `json:"name"`
	Target      string       `json:"target"`
	Status      CanaryStatus `json:"status"`
	DurationMs  int64        `json:"durationMs"`
	Description string       `json:"description"`
	Details     string       `json:"details,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// NixOSPatch defines a synthesized declarative NixOS configuration patch.
type NixOSPatch struct {
	TargetModule  string `json:"targetModule"`
	OptionPath    string `json:"optionPath"`
	OldValue      string `json:"oldValue"`
	NewValue      string `json:"newValue"`
	FlakeOverride string `json:"flakeOverride,omitempty"`
	DiffContent   string `json:"diffContent"`
	MitigatedCVE  string `json:"mitigatedCve,omitempty"`
	Description   string `json:"description"`
}

// KustomizePatch defines a synthesized Kubernetes Kustomize overlay patch.
type KustomizePatch struct {
	TargetResource string `json:"targetResource"`
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace,omitempty"`
	PatchType      string `json:"patchType"` // "strategic-merge" or "json6902"
	PatchYAML      string `json:"patchYaml"`
	TargetFile     string `json:"targetFile,omitempty"`
	MitigatedCVE   string `json:"mitigatedCve,omitempty"`
	Description    string `json:"description"`
}

// GitOpsPullRequest encapsulates a synthesized GitOps pull request bundle.
type GitOpsPullRequest struct {
	PRNumber      int              `json:"prNumber"`
	Title         string           `json:"title"`
	HeadBranch    string           `json:"headBranch"`
	BaseBranch    string           `json:"baseBranch"`
	Summary       string           `json:"summary"`
	CommitMessage string           `json:"commitMessage"`
	NixPatches    []NixOSPatch     `json:"nixPatches,omitempty"`
	K8sPatches    []KustomizePatch `json:"k8sPatches,omitempty"`
	CanaryResults []CanaryCheck    `json:"canaryResults,omitempty"`
	CanaryPassed  bool             `json:"canaryPassed"`
	CreatedAt     time.Time        `json:"createdAt"`
}

// RemediationRule represents an authoritative remediation standard.
type RemediationRule struct {
	ID                   string         `json:"id"`
	Target               string         `json:"target"` // "nixos" or "kubernetes"
	Severity             intel.Severity `json:"severity"`
	CVSSScore            float64        `json:"cvssScore"`
	Title                string         `json:"title"`
	Description          string         `json:"description"`
	SuggestedRemediation string         `json:"suggestedRemediation"`
	MatchedCVE           string         `json:"matchedCve,omitempty"`
}

// RemediationFinding records an identified vulnerability eligible for automated remediation.
type RemediationFinding struct {
	RuleID            string       `json:"ruleId"`
	Target            string       `json:"target"`
	ResourceKind      string       `json:"resourceKind"`
	ResourceName      string       `json:"resourceName"`
	Namespace         string       `json:"namespace,omitempty"`
	Severity          string       `json:"severity"`
	CVSSScore         float64      `json:"cvssScore"`
	Title             string       `json:"title"`
	Description       string       `json:"description"`
	Remediation       string       `json:"remediation"`
	MatchedCVE        string       `json:"matchedCve,omitempty"`
	SynthesizedPatch  string       `json:"synthesizedPatch,omitempty"`
	CanaryStatus      CanaryStatus `json:"canaryStatus"`
	SourceFile        string       `json:"sourceFile,omitempty"`
	LineNumber        int          `json:"lineNumber,omitempty"`
}

// RemediationSummary compiles statistical metrics across all synthesized remediations.
type RemediationSummary struct {
	TotalFindings           int     `json:"totalFindings"`
	NixOSPatchCount         int     `json:"nixosPatchCount"`
	KustomizePatchCount     int     `json:"kustomizePatchCount"`
	CanaryChecksTotal       int     `json:"canaryChecksTotal"`
	CanaryPassedCount       int     `json:"canaryPassedCount"`
	CanaryFailedCount       int     `json:"canaryFailedCount"`
	PullRequestsSynthesized int     `json:"pullRequestsSynthesized"`
	RemediationScore        float64 `json:"remediationScore"` // 0.0 to 100.0
	Status                  string  `json:"status"`           // "PASSED", "DEGRADED", "FAILED"
}

// RemediationAuditReport represents the complete output of an autonomous remediation audit.
type RemediationAuditReport struct {
	Findings     []RemediationFinding `json:"findings"`
	PullRequests []GitOpsPullRequest  `json:"pullRequests"`
	Summary      RemediationSummary   `json:"summary"`
	GeneratedAt  time.Time            `json:"generatedAt"`
}
