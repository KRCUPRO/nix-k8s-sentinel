package gateway

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

var (
	rePathTraversal      = regexp.MustCompile(`(?i)(\.\./|\.\.\\|/\.\.|//)`)
	reSensitiveHeader    = regexp.MustCompile(`(?i)^(x-remote-user|x-forwarded-user|x-authenticated-groups|x-consumer-custom-id|x-auth-user|x-jwt-claim)`)
	reSensitivePortCheck = regexp.MustCompile(`(?m)^\s*port:\s*(\d+)`)
)

// SensitiveControlPlanePorts flags unsegmented forwarding to internal cluster or datastore ports.
var SensitiveControlPlanePorts = map[int]string{
	2379:  "etcd Client API",
	2380:  "etcd Peer Comm",
	6443:  "Kubernetes API Server",
	10250: "Kubelet API",
	5432:  "PostgreSQL Datastore",
	3306:  "MySQL Datastore",
	6379:  "Redis In-Memory Store",
	27017: "MongoDB Datastore",
	9200:  "Elasticsearch REST",
}

// GatewayRadar performs static threat inspections on Kubernetes Gateway API resources.
type GatewayRadar struct {
	grants []ReferenceGrantEntry
}

// NewGatewayRadar constructs a new Gateway API radar instance.
func NewGatewayRadar() *GatewayRadar {
	return &GatewayRadar{
		grants: make([]ReferenceGrantEntry, 0),
	}
}

// RegisterReferenceGrants parses all ReferenceGrant resources to construct the cross-namespace permission matrix.
func (r *GatewayRadar) RegisterReferenceGrants(resources []k8s.RawResource) {
	for _, res := range resources {
		if res.Kind != string(KindReferenceGrant) {
			continue
		}
		ns := res.Namespace
		if ns == "" {
			ns = "default"
		}
		entries := parseReferenceGrantDoc(res.RawContent, ns)
		r.grants = append(r.grants, entries...)
	}
}

// ReferenceGrants returns a copy of all loaded reference grants.
func (r *GatewayRadar) ReferenceGrants() []ReferenceGrantEntry {
	out := make([]ReferenceGrantEntry, len(r.grants))
	copy(out, r.grants)
	return out
}

// HasReferenceGrant verifies if a cross-namespace reference is permitted by an explicit ReferenceGrant.
func (r *GatewayRadar) HasReferenceGrant(fromNs, fromKind, toNs, toKind, toName string) bool {
	if fromNs == toNs {
		return true // Same namespace references never require a ReferenceGrant
	}
	for _, g := range r.grants {
		if g.GrantNamespace != toNs {
			continue
		}
		fromKindMatch := g.FromKind == "" || g.FromKind == fromKind || g.FromKind == "*"
		fromNsMatch := g.FromNamespace == "" || g.FromNamespace == fromNs || g.FromNamespace == "*"
		if !fromKindMatch || !fromNsMatch {
			continue
		}
		toKindMatch := g.ToKind == "" || g.ToKind == toKind || g.ToKind == "*"
		toNameMatch := g.ToName == "" || g.ToName == toName || toName == ""
		if toKindMatch && toNameMatch {
			return true
		}
	}
	return false
}

// AuditGateway audits Gateway resources for insecure plaintext listeners and wildcard allowedRoutes.
func (r *GatewayRadar) AuditGateway(res k8s.RawResource, filePath string) []GatewayViolation {
	var violations []GatewayViolation
	ns := res.Namespace
	if ns == "" {
		ns = "default"
	}

	lines := strings.Split(res.RawContent, "\n")
	hasHTTPListener := false
	hasTLS := false
	httpListenerLine := 1

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := idx + 1

		// Check for allowedRoutes.namespaces.from: All
		if strings.HasPrefix(trimmed, "from:") && strings.Contains(trimmed, "All") {
			rule, _ := LookupGatewayRule("GW-RADAR-011")
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
				Message:      fmt.Sprintf("Gateway '%s' configures allowedRoutes.namespaces.from: All, permitting untrusted tenants across all namespaces to bind routes to edge gateway", res.Name),
				Remediation:  rule.Remediation,
			})
		}

		if strings.Contains(trimmed, "protocol: HTTP") || (strings.Contains(trimmed, "port: 80") && !strings.Contains(trimmed, "8080")) {
			hasHTTPListener = true
			httpListenerLine = lineNum
		}
		if strings.Contains(trimmed, "protocol: HTTPS") || strings.Contains(trimmed, "certificateRefs:") || strings.Contains(trimmed, "tls:") {
			hasTLS = true
		}
	}

	if hasHTTPListener && !hasTLS && !strings.Contains(res.RawContent, "RequestRedirect") {
		rule, _ := LookupGatewayRule("GW-RADAR-004")
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
			StartLine:    httpListenerLine,
			Message:      fmt.Sprintf("Gateway '%s' defines unencrypted HTTP listener without TLS termination or HTTPS redirection", res.Name),
			Remediation:  rule.Remediation,
		})
	}

	return violations
}

// AuditHTTPRoute audits HTTPRoute resources for cross-namespace leaks, wildcard routes, path rewrites, and header spoofing.
func (r *GatewayRadar) AuditHTTPRoute(res k8s.RawResource, filePath string) []GatewayViolation {
	var violations []GatewayViolation
	ns := res.Namespace
	if ns == "" {
		ns = "default"
	}

	lines := strings.Split(res.RawContent, "\n")
	backendRefs := extractBackendRefs(res.RawContent)

	for _, backend := range backendRefs {
		targetNs := backend.Namespace
		if targetNs != "" && targetNs != ns {
			if !r.HasReferenceGrant(ns, string(KindHTTPRoute), targetNs, backend.Kind, backend.Name) {
				rule, _ := LookupGatewayRule("GW-RADAR-001")
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
					StartLine:    backend.Line,
					Message:      fmt.Sprintf("HTTPRoute '%s' references backend Service '%s' in namespace '%s' without a valid ReferenceGrant", res.Name, backend.Name, targetNs),
					Remediation:  rule.Remediation,
				})
			}
		}
	}

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := idx + 1

		// Check GW-RADAR-006: Path Traversal in URLRewrite or RequestRedirect
		if strings.HasPrefix(trimmed, "replacePrefixMatch:") || strings.HasPrefix(trimmed, "value:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `"'`)
				if rePathTraversal.MatchString(val) {
					rule, _ := LookupGatewayRule("GW-RADAR-006")
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
						Message:      fmt.Sprintf("HTTPRoute '%s' contains unsafe path rewrite traversal sequence '%s'", res.Name, val),
						Remediation:  rule.Remediation,
					})
				}
			}
		}

		// Check GW-RADAR-007: Identity Header Spoofing in RequestHeaderModifier
		nameLine := strings.TrimPrefix(trimmed, "- ")
		if strings.HasPrefix(nameLine, "name:") {
			parts := strings.SplitN(nameLine, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[1])
				headerName = strings.Trim(headerName, `"'`)
				if reSensitiveHeader.MatchString(headerName) {
					rule, _ := LookupGatewayRule("GW-RADAR-007")
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
						Message:      fmt.Sprintf("HTTPRoute '%s' injects or modifies sensitive identity header '%s'", res.Name, headerName),
						Remediation:  rule.Remediation,
					})
				}
			}
		}
	}

	// Check GW-RADAR-005: Unrestricted Wildcard Path Match
	if strings.Contains(res.RawContent, "value: /") || strings.Contains(res.RawContent, "value: \"/\"") {
		if !strings.Contains(res.RawContent, "filters:") && !strings.Contains(res.RawContent, "headers:") && !strings.Contains(res.RawContent, "method:") {
			rule, _ := LookupGatewayRule("GW-RADAR-005")
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
				StartLine:    1,
				Message:      fmt.Sprintf("HTTPRoute '%s' matches catch-all root prefix '/' without granular method, header, or rate-limiting filters", res.Name),
				Remediation:  rule.Remediation,
			})
		}
	}

	return violations
}

// AuditGRPCRoute audits GRPCRoute resources for cross-namespace references and unrestricted method wildcards.
func (r *GatewayRadar) AuditGRPCRoute(res k8s.RawResource, filePath string) []GatewayViolation {
	var violations []GatewayViolation
	ns := res.Namespace
	if ns == "" {
		ns = "default"
	}

	backendRefs := extractBackendRefs(res.RawContent)
	for _, backend := range backendRefs {
		targetNs := backend.Namespace
		if targetNs != "" && targetNs != ns {
			if !r.HasReferenceGrant(ns, string(KindGRPCRoute), targetNs, backend.Kind, backend.Name) {
				rule, _ := LookupGatewayRule("GW-RADAR-001")
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
					StartLine:    backend.Line,
					Message:      fmt.Sprintf("GRPCRoute '%s' references backend Service '%s' in namespace '%s' without a valid ReferenceGrant", res.Name, backend.Name, targetNs),
					Remediation:  rule.Remediation,
				})
			}
		}
	}

	lines := strings.Split(res.RawContent, "\n")
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := idx + 1
		if strings.HasPrefix(trimmed, "method:") && (strings.Contains(trimmed, `*`) || strings.Contains(trimmed, `""`)) {
			rule, _ := LookupGatewayRule("GW-RADAR-008")
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
				Message:      fmt.Sprintf("GRPCRoute '%s' configures unrestricted wildcard method routing without granular method constraints", res.Name),
				Remediation:  rule.Remediation,
			})
		}
	}

	return violations
}

// AuditTCPRoute audits TCPRoute and UDPRoute for cross-namespace references and raw sensitive port forwarding.
func (r *GatewayRadar) AuditTCPRoute(res k8s.RawResource, filePath string) []GatewayViolation {
	var violations []GatewayViolation
	ns := res.Namespace
	if ns == "" {
		ns = "default"
	}

	backendRefs := extractBackendRefs(res.RawContent)
	for _, backend := range backendRefs {
		targetNs := backend.Namespace
		if targetNs != "" && targetNs != ns {
			if !r.HasReferenceGrant(ns, res.Kind, targetNs, backend.Kind, backend.Name) {
				rule, _ := LookupGatewayRule("GW-RADAR-001")
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
					StartLine:    backend.Line,
					Message:      fmt.Sprintf("%s '%s' references backend Service '%s' in namespace '%s' without a valid ReferenceGrant", res.Kind, res.Name, backend.Name, targetNs),
					Remediation:  rule.Remediation,
				})
			}
		}
	}

	lines := strings.Split(res.RawContent, "\n")
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := idx + 1
		matches := reSensitivePortCheck.FindStringSubmatch(trimmed)
		if len(matches) == 2 {
			port, err := strconv.Atoi(matches[1])
			if err == nil {
				desc, isSensitive := SensitiveControlPlanePorts[port]
				if isSensitive {
					rule, _ := LookupGatewayRule("GW-RADAR-009")
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
						Message:      fmt.Sprintf("%s '%s' forwards external traffic directly to sensitive infrastructure port %d (%s)", res.Kind, res.Name, port, desc),
						Remediation:  rule.Remediation,
					})
				}
			}
		}
	}

	return violations
}

type backendRefInfo struct {
	Name      string
	Namespace string
	Kind      string
	Port      int
	Line      int
}

func extractBackendRefs(content string) []backendRefInfo {
	var refs []backendRefInfo
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	inBackendRefs := false
	var current *backendRefInfo

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "backendRefs:") {
			inBackendRefs = true
			continue
		}
		if inBackendRefs {
			if strings.HasPrefix(trimmed, "- name:") {
				if current != nil {
					refs = append(refs, *current)
				}
				parts := strings.SplitN(trimmed, ":", 2)
				nameVal := ""
				if len(parts) == 2 {
					nameVal = strings.TrimSpace(parts[1])
					nameVal = strings.Trim(nameVal, `"'`)
				}
				current = &backendRefInfo{
					Name: nameVal,
					Kind: "Service",
					Line: lineNum,
				}
				continue
			}
			if current != nil {
				if strings.HasPrefix(trimmed, "namespace:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						current.Namespace = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				} else if strings.HasPrefix(trimmed, "kind:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						current.Kind = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				} else if strings.HasPrefix(trimmed, "port:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						p, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
						current.Port = p
					}
				} else if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
					refs = append(refs, *current)
					current = nil
					inBackendRefs = false
				}
			}
		}
	}
	if current != nil {
		refs = append(refs, *current)
	}
	return refs
}

func parseReferenceGrantDoc(content string, grantNamespace string) []ReferenceGrantEntry {
	var entries []ReferenceGrantEntry
	scanner := bufio.NewScanner(strings.NewReader(content))

	var currentFrom []struct {
		group string
		kind  string
		ns    string
	}
	var currentTo []struct {
		group string
		kind  string
		name  string
	}

	mode := ""
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(trimmed, "from:") {
			mode = "from"
			continue
		}
		if strings.HasPrefix(trimmed, "to:") {
			mode = "to"
			continue
		}

		if mode == "from" {
			if strings.HasPrefix(trimmed, "- group:") {
				parts := strings.SplitN(trimmed, ":", 2)
				g := ""
				if len(parts) == 2 {
					g = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
				currentFrom = append(currentFrom, struct{ group, kind, ns string }{group: g})
			} else if len(currentFrom) > 0 {
				last := &currentFrom[len(currentFrom)-1]
				if strings.HasPrefix(trimmed, "kind:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						last.kind = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				} else if strings.HasPrefix(trimmed, "namespace:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						last.ns = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				}
			}
		} else if mode == "to" {
			if strings.HasPrefix(trimmed, "- group:") {
				parts := strings.SplitN(trimmed, ":", 2)
				g := ""
				if len(parts) == 2 {
					g = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
				currentTo = append(currentTo, struct{ group, kind, name string }{group: g})
			} else if len(currentTo) > 0 {
				last := &currentTo[len(currentTo)-1]
				if strings.HasPrefix(trimmed, "kind:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						last.kind = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				} else if strings.HasPrefix(trimmed, "name:") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						last.name = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				}
			}
		}
	}

	for _, f := range currentFrom {
		for _, t := range currentTo {
			entries = append(entries, ReferenceGrantEntry{
				GrantNamespace: grantNamespace,
				FromGroup:      f.group,
				FromKind:       f.kind,
				FromNamespace:  f.ns,
				ToGroup:        t.group,
				ToKind:         t.kind,
				ToName:         t.name,
			})
		}
	}
	return entries
}
