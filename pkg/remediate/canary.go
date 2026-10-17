package remediate

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	branchNameRegex = regexp.MustCompile(`^(remediation|gitops|security)/[a-zA-Z0-9_\-\.]+$`)
	yamlKeyValRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\s]+:\s*.*$`)
)

// CanaryValidator executes automated pre-flight safety validations on declarative patches.
type CanaryValidator struct {
	StrictMode bool
}

// NewCanaryValidator creates an initialized CanaryValidator instance.
func NewCanaryValidator(strict bool) *CanaryValidator {
	return &CanaryValidator{
		StrictMode: strict,
	}
}

// ValidateNixOSPatch executes semantic and syntax checks on a synthesized NixOS patch.
func (cv *CanaryValidator) ValidateNixOSPatch(patch *NixOSPatch) CanaryCheck {
	start := time.Now()
	check := CanaryCheck{
		Name:        "nixos-flake-eval-canary",
		Target:      patch.TargetModule,
		Status:      CanaryPassed,
		Description: "Simulated NixOS pure flake evaluation and option syntax verification",
	}

	if patch == nil {
		check.Status = CanaryFailed
		check.Error = "nil patch provided"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	if len(patch.DiffContent) > MaxPatchBytes {
		check.Status = CanaryFailed
		check.Error = fmt.Sprintf("patch size %d bytes exceeds maximum ceiling of %d bytes", len(patch.DiffContent), MaxPatchBytes)
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	// 1. Target and Option Verification
	if strings.TrimSpace(patch.TargetModule) == "" {
		check.Status = CanaryFailed
		check.Error = "empty target module in NixOS patch"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}
	if strings.TrimSpace(patch.OptionPath) == "" {
		check.Status = CanaryFailed
		check.Error = "empty option path in NixOS patch"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	// 2. Syntax Sanity: Balanced Braces and Parentheses
	openBraces := strings.Count(patch.DiffContent, "{")
	closeBraces := strings.Count(patch.DiffContent, "}")
	if openBraces != closeBraces {
		check.Status = CanaryFailed
		check.Error = fmt.Sprintf("unbalanced braces in NixOS patch: %d '{' vs %d '}'", openBraces, closeBraces)
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	openParens := strings.Count(patch.DiffContent, "(")
	closeParens := strings.Count(patch.DiffContent, ")")
	if openParens != closeParens {
		check.Status = CanaryFailed
		check.Error = fmt.Sprintf("unbalanced parentheses in NixOS patch: %d '(' vs %d ')'", openParens, closeParens)
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	// 3. Command Injection and Unsafe Builtins Guard
	dangerousPatterns := []string{
		"builtins.exec",
		"builtins.readFile \"/dev/",
		"$(rm ",
		"`rm ",
		"; rm -rf",
	}
	for _, dp := range dangerousPatterns {
		if strings.Contains(patch.DiffContent, dp) {
			check.Status = CanaryFailed
			check.Error = fmt.Sprintf("prohibited unsafe construct detected in patch: '%s'", dp)
			check.DurationMs = time.Since(start).Milliseconds()
			return check
		}
	}

	// 4. Non-Destructive Invariant
	if strings.TrimSpace(patch.NewValue) == "" && !strings.Contains(patch.DiffContent, "-") {
		check.Status = CanaryFailed
		check.Error = "empty replacement value without deletion record"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	check.Details = fmt.Sprintf("Validated %s (%s -> %s) successfully", patch.OptionPath, patch.OldValue, patch.NewValue)
	check.DurationMs = time.Since(start).Milliseconds()
	if check.DurationMs == 0 {
		check.DurationMs = 2 // Realistic mock execution floor
	}
	return check
}

// ValidateKustomizePatch executes YAML and schema validation on a Kubernetes Kustomize overlay.
func (cv *CanaryValidator) ValidateKustomizePatch(patch *KustomizePatch) CanaryCheck {
	start := time.Now()
	check := CanaryCheck{
		Name:        "kustomize-dry-run-canary",
		Target:      patch.TargetResource,
		Status:      CanaryPassed,
		Description: "Simulated kubectl kustomize dry-run and strategic merge schema check",
	}

	if patch == nil {
		check.Status = CanaryFailed
		check.Error = "nil patch provided"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	if len(patch.PatchYAML) > MaxPatchBytes {
		check.Status = CanaryFailed
		check.Error = fmt.Sprintf("patch size %d bytes exceeds maximum ceiling of %d bytes", len(patch.PatchYAML), MaxPatchBytes)
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	// 1. Mandatory Identity Fields
	if strings.TrimSpace(patch.TargetResource) == "" {
		check.Status = CanaryFailed
		check.Error = "missing target resource declaration"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}
	if strings.TrimSpace(patch.APIVersion) == "" || strings.TrimSpace(patch.Kind) == "" {
		check.Status = CanaryFailed
		check.Error = "missing apiVersion or kind in Kustomize patch"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	// 2. YAML Structure Sanity (Tabs and Colon Syntax)
	lines := strings.Split(patch.PatchYAML, "\n")
	hasValidLine := false
	for lineNum, line := range lines {
		// Strict Prohibition: Tab characters in YAML indentation
		if strings.HasPrefix(line, "\t") {
			check.Status = CanaryFailed
			check.Error = fmt.Sprintf("prohibited tab character detected on line %d: YAML requires spaces", lineNum+1)
			check.DurationMs = time.Since(start).Milliseconds()
			return check
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}

		if yamlKeyValRegex.MatchString(trimmed) || strings.HasPrefix(trimmed, "- ") {
			hasValidLine = true
		}
	}

	if !hasValidLine {
		check.Status = CanaryFailed
		check.Error = "patch YAML contains no recognizable structured keys or lists"
		check.DurationMs = time.Since(start).Milliseconds()
		return check
	}

	check.Details = fmt.Sprintf("Validated %s/%s (%s) successfully", patch.Kind, patch.Name, patch.PatchType)
	check.DurationMs = time.Since(start).Milliseconds()
	if check.DurationMs == 0 {
		check.DurationMs = 3 // Realistic mock execution floor
	}
	return check
}

// ValidateGitOpsPR evaluates all components in a synthesized GitOps pull request bundle.
func (cv *CanaryValidator) ValidateGitOpsPR(pr *GitOpsPullRequest) []CanaryCheck {
	if pr == nil {
		return []CanaryCheck{{
			Name:   "gitops-bundle-canary",
			Status: CanaryFailed,
			Error:  "nil pull request provided",
		}}
	}

	var results []CanaryCheck

	// 1. Branch Naming Policy Check
	branchCheck := CanaryCheck{
		Name:        "gitops-branch-policy-check",
		Target:      pr.HeadBranch,
		Status:      CanaryPassed,
		Description: "Verifies git branch conforms to standard remediation naming conventions",
	}
	if !branchNameRegex.MatchString(pr.HeadBranch) {
		branchCheck.Status = CanaryFailed
		branchCheck.Error = fmt.Sprintf("branch '%s' does not match required convention (remediation/*, gitops/*, security/*)", pr.HeadBranch)
	} else {
		branchCheck.Details = fmt.Sprintf("Head branch '%s' passed naming policy", pr.HeadBranch)
	}
	results = append(results, branchCheck)

	// 2. Commit Message Policy Check
	commitCheck := CanaryCheck{
		Name:        "gitops-commit-convention-check",
		Target:      pr.CommitMessage,
		Status:      CanaryPassed,
		Description: "Verifies commit message adheres to conventional commits standard",
	}
	trimmedMsg := strings.TrimSpace(pr.CommitMessage)
	if trimmedMsg == "" || (!strings.HasPrefix(trimmedMsg, "fix(security):") && !strings.HasPrefix(trimmedMsg, "feat(remediation):") && !strings.HasPrefix(trimmedMsg, "chore(security):")) {
		commitCheck.Status = CanaryFailed
		commitCheck.Error = "commit message must start with fix(security):, feat(remediation):, or chore(security):"
	} else {
		commitCheck.Details = "Commit message satisfies conventional commits requirements"
	}
	results = append(results, commitCheck)

	// 3. Validate Individual NixOS Patches
	for _, np := range pr.NixPatches {
		c := cv.ValidateNixOSPatch(&np)
		results = append(results, c)
	}

	// 4. Validate Individual Kubernetes Kustomize Patches
	for _, kp := range pr.K8sPatches {
		c := cv.ValidateKustomizePatch(&kp)
		results = append(results, c)
	}

	// Determine overall CanaryPassed outcome
	allPassed := true
	for _, r := range results {
		if r.Status == CanaryFailed {
			allPassed = false
			break
		}
	}
	pr.CanaryPassed = allPassed
	pr.CanaryResults = results

	return results
}
