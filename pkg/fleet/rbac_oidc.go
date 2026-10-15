package fleet

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	reVerbsWildcard     = regexp.MustCompile(`^\s*-\s*["']?\*["']?`)
	reVerbsEscalate     = regexp.MustCompile(`^\s*-\s*["']?(bind|escalate)["']?`)
	reVerbsImpersonate  = regexp.MustCompile(`^\s*-\s*["']?impersonate["']?`)
	reVerbsSecretRead   = regexp.MustCompile(`^\s*-\s*["']?(get|list|watch|\*)["']?`)
	reResSecrets        = regexp.MustCompile(`^\s*-\s*["']?secrets["']?`)
	reSubjectBroadGroup = regexp.MustCompile(`^\s*name:\s*["']?(system:authenticated|system:unauthenticated|system:anonymous)["']?`)
	reRoleRefAdmin      = regexp.MustCompile(`^\s*name:\s*["']?cluster-admin["']?`)
)

// RBACOIDCAuditor provides static and runtime inspection for multi-tenant RBAC and OIDC tokens.
type RBACOIDCAuditor struct {
	feed *intel.Feed
}

// NewRBACOIDCAuditor constructs a new RBACOIDCAuditor instance.
func NewRBACOIDCAuditor(feed *intel.Feed) *RBACOIDCAuditor {
	return &RBACOIDCAuditor{feed: feed}
}

// AuditRBACDocument inspects lines of a Kubernetes manifest document for RBAC vulnerabilities.
func (a *RBACOIDCAuditor) AuditRBACDocument(lines []string, startLine int, filePath, kind, name, namespace string) []FleetViolation {
	var violations []FleetViolation
	if len(lines) == 0 {
		return violations
	}

	isClusterRole := kind == "ClusterRole"
	isRole := kind == "Role"
	isClusterRoleBinding := kind == "ClusterRoleBinding"
	isRoleBinding := kind == "RoleBinding"

	if !isClusterRole && !isRole && !isClusterRoleBinding && !isRoleBinding {
		return violations
	}

	// 1. Audit Role and ClusterRole rules
	if isClusterRole || isRole {
		inRules := false
		inVerbs := false
		inResources := false
		inAPIGroups := false

		hasWildcardVerb := false
		hasWildcardResource := false
		hasWildcardAPIGroup := false
		hasEscalateVerb := false
		hasImpersonateVerb := false
		hasSecretReadVerb := false
		hasSecretsResource := false
		hasResourceNames := false

		ruleLine := startLine

		flushRule := func(lineIdx int) {
			if hasWildcardVerb && (hasWildcardResource || hasWildcardAPIGroup || isClusterRole) {
				rule, _ := LookupFleetRule("FLEET-RBAC-001")
				violations = append(violations, FleetViolation{
					RuleID:       rule.ID,
					Title:        rule.Title,
					Severity:     rule.Severity,
					CVSSScore:    rule.CVSSScore,
					Category:     CategoryRBAC,
					ResourceKind: kind,
					ResourceName: name,
					Namespace:    namespace,
					FilePath:     filePath,
					StartLine:    ruleLine,
					Message:      fmt.Sprintf("%s '%s' defines wildcard '*' in verbs/resources, granting full cluster privileges", kind, name),
					Remediation:  rule.Remediation,
					MatchedCVE:   a.matchCVE(rule.ID),
				})
			}

			if hasEscalateVerb {
				rule, _ := LookupFleetRule("FLEET-RBAC-002")
				violations = append(violations, FleetViolation{
					RuleID:       rule.ID,
					Title:        rule.Title,
					Severity:     rule.Severity,
					CVSSScore:    rule.CVSSScore,
					Category:     CategoryRBAC,
					ResourceKind: kind,
					ResourceName: name,
					Namespace:    namespace,
					FilePath:     filePath,
					StartLine:    ruleLine,
					Message:      fmt.Sprintf("%s '%s' grants dangerous 'bind' or 'escalate' verbs enabling uncontained privilege escalation", kind, name),
					Remediation:  rule.Remediation,
					MatchedCVE:   a.matchCVE(rule.ID),
				})
			}

			if hasImpersonateVerb && !hasResourceNames {
				rule, _ := LookupFleetRule("FLEET-RBAC-004")
				violations = append(violations, FleetViolation{
					RuleID:       rule.ID,
					Title:        rule.Title,
					Severity:     rule.Severity,
					CVSSScore:    rule.CVSSScore,
					Category:     CategoryRBAC,
					ResourceKind: kind,
					ResourceName: name,
					Namespace:    namespace,
					FilePath:     filePath,
					StartLine:    ruleLine,
					Message:      fmt.Sprintf("%s '%s' grants user/group impersonation without restricting resourceNames", kind, name),
					Remediation:  rule.Remediation,
					MatchedCVE:   a.matchCVE(rule.ID),
				})
			}

			if isClusterRole && hasSecretReadVerb && hasSecretsResource {
				rule, _ := LookupFleetRule("FLEET-RBAC-005")
				violations = append(violations, FleetViolation{
					RuleID:       rule.ID,
					Title:        rule.Title,
					Severity:     rule.Severity,
					CVSSScore:    rule.CVSSScore,
					Category:     CategoryRBAC,
					ResourceKind: kind,
					ResourceName: name,
					Namespace:    namespace,
					FilePath:     filePath,
					StartLine:    ruleLine,
					Message:      fmt.Sprintf("ClusterRole '%s' grants cluster-wide reading of 'secrets' across all namespaces", name),
					Remediation:  rule.Remediation,
					MatchedCVE:   a.matchCVE(rule.ID),
				})
			}

			// Reset per-rule state
			hasWildcardVerb = false
			hasWildcardResource = false
			hasWildcardAPIGroup = false
			hasEscalateVerb = false
			hasImpersonateVerb = false
			hasSecretReadVerb = false
			hasSecretsResource = false
			hasResourceNames = false
			ruleLine = lineIdx
		}

		for idx, line := range lines {
			trimmed := strings.TrimSpace(line)
			currentLineNum := startLine + idx

			if strings.HasPrefix(trimmed, "rules:") {
				inRules = true
				continue
			}

			if !inRules {
				continue
			}

			// New rule item indicated by "- apiGroups:" or top-level list element
			if strings.HasPrefix(trimmed, "- apiGroups:") || strings.HasPrefix(trimmed, "- resources:") || strings.HasPrefix(trimmed, "- verbs:") {
				flushRule(currentLineNum)
			}

			if strings.Contains(line, "verbs:") {
				inVerbs = true
				inResources = false
				inAPIGroups = false
				if strings.Contains(line, `*`) {
					hasWildcardVerb = true
				}
				if strings.Contains(line, "bind") || strings.Contains(line, "escalate") {
					hasEscalateVerb = true
				}
				if strings.Contains(line, "impersonate") {
					hasImpersonateVerb = true
				}
				if strings.Contains(line, "get") || strings.Contains(line, "list") || strings.Contains(line, "watch") {
					hasSecretReadVerb = true
				}
				continue
			} else if strings.Contains(line, "resources:") {
				inResources = true
				inVerbs = false
				inAPIGroups = false
				if strings.Contains(line, `*`) {
					hasWildcardResource = true
				}
				if strings.Contains(line, "secrets") {
					hasSecretsResource = true
				}
				continue
			} else if strings.Contains(line, "apiGroups:") {
				inAPIGroups = true
				inVerbs = false
				inResources = false
				if strings.Contains(line, `*`) {
					hasWildcardAPIGroup = true
				}
				continue
			} else if strings.Contains(line, "resourceNames:") {
				inVerbs = false
				inResources = false
				inAPIGroups = false
				hasResourceNames = true
				continue
			}

			// Parse item lists
			if inVerbs {
				if strings.Contains(line, `*`) {
					hasWildcardVerb = true
				}
				if strings.Contains(line, "bind") || strings.Contains(line, "escalate") {
					hasEscalateVerb = true
				}
				if strings.Contains(line, "impersonate") {
					hasImpersonateVerb = true
				}
				if strings.Contains(line, "get") || strings.Contains(line, "list") || strings.Contains(line, "watch") {
					hasSecretReadVerb = true
				}
			}
			if inResources {
				if strings.Contains(line, `*`) {
					hasWildcardResource = true
				}
				if strings.Contains(line, "secrets") {
					hasSecretsResource = true
				}
			}
			if inAPIGroups {
				if strings.Contains(line, `*`) {
					hasWildcardAPIGroup = true
				}
			}
		}
		// Flush trailing rule
		flushRule(startLine + len(lines))
	}

	// 2. Audit RoleBinding and ClusterRoleBinding for broad group bindings to cluster-admin
	if isClusterRoleBinding {
		hasBroadGroup := false
		broadGroupName := ""
		isClusterAdmin := false
		broadGroupLine := startLine

		for idx, line := range lines {
			if m := reSubjectBroadGroup.FindStringSubmatch(line); len(m) > 1 {
				hasBroadGroup = true
				broadGroupName = m[1]
				broadGroupLine = startLine + idx
			}
			if reRoleRefAdmin.MatchString(line) {
				isClusterAdmin = true
			}
		}

		if hasBroadGroup && isClusterAdmin {
			rule, _ := LookupFleetRule("FLEET-RBAC-003")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryRBAC,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FilePath:     filePath,
				StartLine:    broadGroupLine,
				Message:      fmt.Sprintf("ClusterRoleBinding '%s' binds 'cluster-admin' to broad subject '%s', granting full administrative control to untrusted callers", name, broadGroupName),
				Remediation:  rule.Remediation,
				MatchedCVE:   a.matchCVE(rule.ID),
			})
		}
	}

	return violations
}

// AuditOIDCToken inspects an individual federated identity token declaration for security weaknesses.
func (a *RBACOIDCAuditor) AuditOIDCToken(tok OIDCTokenDeclaration, clusterID string) []FleetViolation {
	var violations []FleetViolation

	// Rule 1: Insecure signing algorithm
	normAlg := strings.ToUpper(strings.TrimSpace(tok.SigningAlg))
	if normAlg == "NONE" || normAlg == "" || strings.HasPrefix(normAlg, "HS") {
		rule, _ := LookupFleetRule("FLEET-OIDC-001")
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryOIDC,
			ResourceKind: "OIDCToken",
			ResourceName: tok.TokenID,
			ClusterID:    clusterID,
			Message:      fmt.Sprintf("OIDC token '%s' uses insecure signing algorithm '%s'; asymmetric RS256/ES256 required", tok.TokenID, tok.SigningAlg),
			Remediation:  rule.Remediation,
			MatchedCVE:   a.matchCVE(rule.ID),
		})
	}

	// Rule 2: Token TTL ceiling (max 24 hours = 86400s)
	ttlHours := float64(tok.TTLSeconds) / 3600.0
	if tok.TTLSeconds <= 0 && !tok.ExpiresAt.IsZero() && !tok.IssuedAt.IsZero() {
		ttlHours = tok.ExpiresAt.Sub(tok.IssuedAt).Hours()
	}

	if ttlHours > MaxTokenAgeHours || tok.ExpiresAt.IsZero() {
		rule, _ := LookupFleetRule("FLEET-OIDC-002")
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryOIDC,
			ResourceKind: "OIDCToken",
			ResourceName: tok.TokenID,
			ClusterID:    clusterID,
			Message:      fmt.Sprintf("OIDC token '%s' has excessive lifespan of %.1f hours (exceeds %.0f-hour ceiling) or missing expiration", tok.TokenID, ttlHours, MaxTokenAgeHours),
			Remediation:  rule.Remediation,
			MatchedCVE:   a.matchCVE(rule.ID),
		})
	}

	// Rule 3: Missing audience or issuer claim
	if strings.TrimSpace(tok.Audience) == "" || strings.TrimSpace(tok.Issuer) == "" {
		rule, _ := LookupFleetRule("FLEET-OIDC-003")
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryOIDC,
			ResourceKind: "OIDCToken",
			ResourceName: tok.TokenID,
			ClusterID:    clusterID,
			Message:      fmt.Sprintf("OIDC token '%s' lacks mandatory audience ('aud') or issuer ('iss') validation claims", tok.TokenID),
			Remediation:  rule.Remediation,
			MatchedCVE:   a.matchCVE(rule.ID),
		})
	}

	// Rule 4: Stale signing key rotation (> 90 days)
	if tok.KeyRotationDays > 90 {
		rule, _ := LookupFleetRule("FLEET-OIDC-004")
		violations = append(violations, FleetViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     CategoryOIDC,
			ResourceKind: "OIDCKey",
			ResourceName: tok.TokenID,
			ClusterID:    clusterID,
			Message:      fmt.Sprintf("OIDC signing key for token '%s' has not been rotated in %d days (exceeds 90-day threshold)", tok.TokenID, tok.KeyRotationDays),
			Remediation:  rule.Remediation,
			MatchedCVE:   a.matchCVE(rule.ID),
		})
	}

	return violations
}

// matchCVE correlates rule IDs with known threat items in the feed.
func (a *RBACOIDCAuditor) matchCVE(ruleID string) string {
	if a.feed == nil {
		return ""
	}
	for _, item := range a.feed.Items {
		if ruleID == "FLEET-RBAC-003" || ruleID == "FLEET-OIDC-001" {
			if strings.Contains(item.ID, "CVE-2026-60114") || strings.Contains(item.Description, "OIDC") || strings.Contains(item.Description, "RBAC") {
				return item.ID
			}
		}
	}
	return ""
}
