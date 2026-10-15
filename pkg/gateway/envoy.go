package gateway

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

var (
	reDangerousLua = regexp.MustCompile(`(?i)(os\.execute|io\.popen|loadstring\s*\(|load\s*\(|require\s*\(?\s*["']os["']\)?|require\s*\(?\s*["']io["']\)?|package\.loadlib|debug\.)`)
	reHopByHopLua  = regexp.MustCompile(`(?i)headers\(\):(add|set)\s*\(\s*["'](connection|transfer-encoding|upgrade|keep-alive|proxy-authorization)["']`)
	reInsecureTLS  = regexp.MustCompile(`(?i)(require_client_certificate\s*:\s*false|trust_chain_verification\s*:\s*ACCEPT_UNTRUSTED|allow_untrusted_certificate\s*:\s*true)`)
)

var protectedAuthFilters = map[string]string{
	"envoy.filters.http.jwt_authn": "JWT Authentication",
	"istio.authn":                 "Istio Mutual TLS & Authn",
	"envoy.filters.http.rbac":      "RBAC Authorization",
	"envoy.filters.http.ext_authz": "External Authorization",
}

// EnvoyFilterAuditor inspects Istio EnvoyFilter custom resources for proxy bypasses and Lua code injection.
type EnvoyFilterAuditor struct{}

// NewEnvoyFilterAuditor constructs a new EnvoyFilter auditor.
func NewEnvoyFilterAuditor() *EnvoyFilterAuditor {
	return &EnvoyFilterAuditor{}
}

// AuditEnvoyFilter scans an EnvoyFilter resource for security vulnerabilities.
func (a *EnvoyFilterAuditor) AuditEnvoyFilter(res k8s.RawResource, filePath string) []GatewayViolation {
	var violations []GatewayViolation
	ns := res.Namespace
	if ns == "" {
		ns = "default"
	}

	lines := strings.Split(res.RawContent, "\n")
	inLuaBlock := false
	var luaBlockLines []string
	luaBlockStart := 1

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := idx + 1

		// 1. Detect GW-RADAR-003: Filter Chain Order Bypass via INSERT_BEFORE on auth filters
		if strings.HasPrefix(trimmed, "operation:") && strings.Contains(trimmed, "INSERT_BEFORE") {
			// Check surrounding context for subFilter or filter targeting authentication
			subFilterName := extractContextSubFilter(lines, idx)
			if authDesc, isAuth := protectedAuthFilters[subFilterName]; isAuth {
				rule, _ := LookupGatewayRule("GW-RADAR-003")
				violations = append(violations, GatewayViolation{
					RuleID:       rule.ID,
					Title:        rule.Title,
					Severity:     rule.Severity,
					CVSSScore:    rule.CVSSScore,
					Category:     rule.Category,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    ns,
					FilePath:     filePath,
					StartLine:    lineNum,
					Message:      fmt.Sprintf("EnvoyFilter '%s' uses INSERT_BEFORE relative to '%s' (%s), enabling filter chain order bypass", res.Name, subFilterName, authDesc),
					Remediation:  rule.Remediation,
				})
			}
		}

		// 2. Detect GW-RADAR-010: Disabling Client TLS Verification in Transport Socket
		if reInsecureTLS.MatchString(trimmed) {
			rule, _ := LookupGatewayRule("GW-RADAR-010")
			violations = append(violations, GatewayViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     rule.Category,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    ns,
				FilePath:     filePath,
				StartLine:    lineNum,
				Message:      fmt.Sprintf("EnvoyFilter '%s' disables downstream mutual TLS client certificate verification (%s)", res.Name, trimmed),
				Remediation:  rule.Remediation,
			})
		}

		// Detect Lua block start
		if strings.HasPrefix(trimmed, "inlineCode:") {
			inLuaBlock = true
			luaBlockStart = lineNum
			continue
		}

		if inLuaBlock {
			// If unindented or leaves YAML scalar block
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
				// Process accumulated Lua block
				v := a.auditLuaContent(strings.Join(luaBlockLines, "\n"), res, ns, filePath, luaBlockStart)
				violations = append(violations, v...)
				luaBlockLines = nil
				inLuaBlock = false
			} else {
				luaBlockLines = append(luaBlockLines, line)
			}
		}
	}

	if inLuaBlock && len(luaBlockLines) > 0 {
		v := a.auditLuaContent(strings.Join(luaBlockLines, "\n"), res, ns, filePath, luaBlockStart)
		violations = append(violations, v...)
	}

	return violations
}

func (a *EnvoyFilterAuditor) auditLuaContent(content string, res k8s.RawResource, ns, filePath string, startLine int) []GatewayViolation {
	var violations []GatewayViolation

	// GW-RADAR-002: Unsafe Lua injection
	if matches := reDangerousLua.FindStringSubmatch(content); len(matches) > 1 {
		rule, _ := LookupGatewayRule("GW-RADAR-002")
		violations = append(violations, GatewayViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     rule.Category,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    ns,
			FilePath:     filePath,
			StartLine:    startLine,
			Message:      fmt.Sprintf("EnvoyFilter '%s' executes dangerous Lua primitive '%s' inside proxy sidecar", res.Name, matches[1]),
			Remediation:  rule.Remediation,
		})
	}

	// GW-RADAR-012: Unrestricted hop-by-hop header mutation
	if matches := reHopByHopLua.FindStringSubmatch(content); len(matches) > 2 {
		rule, _ := LookupGatewayRule("GW-RADAR-012")
		violations = append(violations, GatewayViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Category:     rule.Category,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    ns,
			FilePath:     filePath,
			StartLine:    startLine,
			Message:      fmt.Sprintf("EnvoyFilter '%s' dynamically mutates hop-by-hop header '%s' via Lua script", res.Name, matches[2]),
			Remediation:  rule.Remediation,
		})
	}

	return violations
}

func extractContextSubFilter(lines []string, currentIdx int) string {
	// Look back up to 25 lines for subFilter: name: or filter: name:
	start := currentIdx - 25
	if start < 0 {
		start = 0
	}
	for i := currentIdx; i >= start; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "name:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				nameVal := strings.TrimSpace(parts[1])
				nameVal = strings.Trim(nameVal, `"'`)
				if _, ok := protectedAuthFilters[nameVal]; ok {
					return nameVal
				}
			}
		}
	}

	// Also look ahead up to 15 lines if patch targets subFilter below
	end := currentIdx + 15
	if end > len(lines) {
		end = len(lines)
	}
	for i := currentIdx; i < end; i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "name:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				nameVal := strings.TrimSpace(parts[1])
				nameVal = strings.Trim(nameVal, `"'`)
				if _, ok := protectedAuthFilters[nameVal]; ok {
					return nameVal
				}
			}
		}
	}
	return ""
}
