package fleet

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	reTargetRevFloating = regexp.MustCompile(`^\s*targetRevision:\s*["']?(HEAD|main|master|latest|trunk)["']?`)
	reFluxRefBranch     = regexp.MustCompile(`^\s*branch:\s*["']?(main|master|latest|trunk)["']?`)
	reDestServerWild    = regexp.MustCompile(`^\s*server:\s*["']?\*["']?`)
	reSelfHealFalse     = regexp.MustCompile(`^\s*selfHeal:\s*false`)
	reFluxPruneFalse    = regexp.MustCompile(`^\s*prune:\s*false`)
)

// GitOpsAuditor inspects ArgoCD and Flux manifests along with runtime synchronization telemetry.
type GitOpsAuditor struct {
	feed *intel.Feed
}

// NewGitOpsAuditor constructs a new GitOpsAuditor instance.
func NewGitOpsAuditor(feed *intel.Feed) *GitOpsAuditor {
	return &GitOpsAuditor{feed: feed}
}

// AuditGitOpsDocument statically inspects a declarative GitOps manifest document.
func (g *GitOpsAuditor) AuditGitOpsDocument(lines []string, startLine int, filePath, kind, name, namespace string) []FleetViolation {
	var violations []FleetViolation
	if len(lines) == 0 {
		return violations
	}

	isArgoApp := kind == "Application" || kind == "ApplicationSet"
	isFluxKustomization := kind == "Kustomization"
	isFluxRepo := kind == "GitRepository" || kind == "OCIRepository"
	isFluxHelm := kind == "HelmRelease"

	if !isArgoApp && !isFluxKustomization && !isFluxRepo && !isFluxHelm {
		return violations
	}

	// 1. Audit ArgoCD Applications
	if isArgoApp {
		hasAutomated := false
		hasSelfHealTrue := false
		hasSelfHealFalse := false
		selfHealLine := startLine

		hasFloatingRev := false
		floatingRevLine := startLine
		floatingRevVal := ""

		hasWildcardServer := false
		wildcardServerLine := startLine

		for idx, line := range lines {
			currentLineNum := startLine + idx
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "automated:") {
				hasAutomated = true
			}
			if reSelfHealFalse.MatchString(line) {
				hasSelfHealFalse = true
				selfHealLine = currentLineNum
			} else if strings.Contains(line, "selfHeal: true") {
				hasSelfHealTrue = true
			}

			if m := reTargetRevFloating.FindStringSubmatch(line); len(m) > 1 {
				hasFloatingRev = true
				floatingRevLine = currentLineNum
				floatingRevVal = m[1]
			}

			if reDestServerWild.MatchString(line) {
				hasWildcardServer = true
				wildcardServerLine = currentLineNum
			}
		}

		// Self-healing disabled or omitted in automated sync
		if hasAutomated && (hasSelfHealFalse || !hasSelfHealTrue) {
			rule, _ := LookupFleetRule("FLEET-GITOPS-001")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryGitOpsDrift,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    selfHealLine,
				Message:      fmt.Sprintf("ArgoCD Application '%s' has automated sync without selfHeal enabled, allowing unmonitored configuration drift", name),
				Remediation:  rule.Remediation,
				MatchedCVE:   g.matchCVE(rule.ID),
			})
		}

		// Floating branch revision
		if hasFloatingRev {
			rule, _ := LookupFleetRule("FLEET-GITOPS-002")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryGitOpsDrift,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    floatingRevLine,
				Message:      fmt.Sprintf("ArgoCD Application '%s' specifies floating targetRevision '%s' instead of an immutable commit hash or tag", name, floatingRevVal),
				Remediation:  rule.Remediation,
				MatchedCVE:   g.matchCVE(rule.ID),
			})
		}

		// Wildcard target cluster
		if hasWildcardServer {
			rule, _ := LookupFleetRule("FLEET-GITOPS-004")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryGitOpsDrift,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    wildcardServerLine,
				Message:      fmt.Sprintf("ArgoCD Application '%s' permits wildcard target destination server ('*'), risking unauthorized workload dispatch", name),
				Remediation:  rule.Remediation,
				MatchedCVE:   g.matchCVE(rule.ID),
			})
		}
	}

	// 2. Audit Flux Kustomization and Repository declarations
	if isFluxKustomization {
		hasPruneFalse := false
		pruneLine := startLine

		for idx, line := range lines {
			if reFluxPruneFalse.MatchString(line) {
				hasPruneFalse = true
				pruneLine = startLine + idx
			}
		}

		if hasPruneFalse {
			rule, _ := LookupFleetRule("FLEET-GITOPS-001")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryGitOpsDrift,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    pruneLine,
				Message:      fmt.Sprintf("Flux Kustomization '%s' has prune: false, leaving orphaned resources and causing permanent cluster drift", name),
				Remediation:  rule.Remediation,
				MatchedCVE:   g.matchCVE(rule.ID),
			})
		}
	}

	if isFluxRepo {
		hasSecretRef := false
		hasFloatingBranch := false
		branchVal := ""
		branchLine := startLine

		for idx, line := range lines {
			if strings.Contains(line, "secretRef:") {
				hasSecretRef = true
			}
			if m := reFluxRefBranch.FindStringSubmatch(line); len(m) > 1 {
				hasFloatingBranch = true
				branchVal = m[1]
				branchLine = startLine + idx
			}
		}

		if hasFloatingBranch {
			rule, _ := LookupFleetRule("FLEET-GITOPS-002")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryGitOpsDrift,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    branchLine,
				Message:      fmt.Sprintf("Flux repository '%s' tracks mutable branch '%s' without commit pinning", name, branchVal),
				Remediation:  rule.Remediation,
				MatchedCVE:   g.matchCVE(rule.ID),
			})
		}

		if !hasSecretRef {
			rule, _ := LookupFleetRule("FLEET-GITOPS-003")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryGitOpsDrift,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    startLine,
				Message:      fmt.Sprintf("Flux repository '%s' lacks secretRef credential authentication", name),
				Remediation:  rule.Remediation,
				MatchedCVE:   g.matchCVE(rule.ID),
			})
		}
	}

	return violations
}

// AuditSyncStatus inspects a runtime GitOps application status for synchronization drift and health degradation.
func (g *GitOpsAuditor) AuditSyncStatus(status GitOpsSyncStatus) []FleetViolation {
	var violations []FleetViolation

	// Rule 1: Out-of-sync or degraded cluster application
	syncNorm := strings.ToLower(strings.TrimSpace(status.SyncStatus))
	healthNorm := strings.ToLower(strings.TrimSpace(status.HealthStatus))

	if syncNorm == "outofsync" || healthNorm == "degraded" || healthNorm == "missing" {
		rule, _ := LookupFleetRule("FLEET-DRIFT-001")
		details := status.DriftDetails
		if details == "" {
			details = fmt.Sprintf("sync=%s, health=%s", status.SyncStatus, status.HealthStatus)
		}
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryMultiCluster,
			ResourceKind: "GitOpsApplication",
			ResourceName: status.AppName,
			ClusterID:    status.TargetCluster,
			Namespace:    status.Namespace,
			Message:      fmt.Sprintf("Cluster '%s' application '%s' (%s) is out-of-sync or degraded: %s", status.TargetCluster, status.AppName, status.Engine, details),
			Remediation:  rule.Remediation,
			MatchedCVE:   g.matchCVE(rule.ID),
		})
	}

	// Rule 2: Automated self-heal disabled in runtime status
	if !status.AutomatedSelfHeal {
		rule, _ := LookupFleetRule("FLEET-GITOPS-001")
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryGitOpsDrift,
			ResourceKind: "GitOpsApplication",
			ResourceName: status.AppName,
			ClusterID:    status.TargetCluster,
			Namespace:    status.Namespace,
			Message:      fmt.Sprintf("GitOps application '%s' on cluster '%s' has automated self-heal disabled in live state", status.AppName, status.TargetCluster),
			Remediation:  rule.Remediation,
			MatchedCVE:   g.matchCVE(rule.ID),
		})
	}

	// Rule 3: Divergence between target revision and current live revision
	if status.TargetRevision != "" && status.CurrentRevision != "" && status.TargetRevision != status.CurrentRevision && syncNorm != "synced" {
		rule, _ := LookupFleetRule("FLEET-GITOPS-002")
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryGitOpsDrift,
			ResourceKind: "GitOpsApplication",
			ResourceName: status.AppName,
			ClusterID:    status.TargetCluster,
			Namespace:    status.Namespace,
			Message:      fmt.Sprintf("Application '%s' on cluster '%s' live revision '%s' diverges from target revision '%s'", status.AppName, status.TargetCluster, status.CurrentRevision, status.TargetRevision),
			Remediation:  rule.Remediation,
			MatchedCVE:   g.matchCVE(rule.ID),
		})
	}

	return violations
}

// matchCVE correlates rule IDs with known threat items in the feed.
func (g *GitOpsAuditor) matchCVE(ruleID string) string {
	if g.feed == nil {
		return ""
	}
	for _, item := range g.feed.Items {
		if ruleID == "FLEET-GITOPS-004" || ruleID == "FLEET-DRIFT-001" {
			if strings.Contains(item.ID, "CVE-2026-60114") || strings.Contains(item.Description, "GitOps") || strings.Contains(item.Description, "Fleet") {
				return item.ID
			}
		}
	}
	return ""
}
