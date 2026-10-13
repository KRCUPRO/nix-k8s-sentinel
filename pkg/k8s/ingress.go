package k8s

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	dangerousDirectives = []string{
		"root", "alias", "lua_", "proxy_pass", "eval", "internal",
		"access_by_lua", "content_by_lua", "header_filter_by_lua",
		"exec", "return 301 http", "return 302 http",
	}

	snippetAnnotationKeys = []string{
		"nginx.ingress.kubernetes.io/configuration-snippet",
		"nginx.ingress.kubernetes.io/server-snippet",
		"nginx.ingress.kubernetes.io/auth-snippet",
		"nginx.ingress.kubernetes.io/stream-snippet",
	}

	pathTraversalPattern = regexp.MustCompile(`\.\./|\.\.\\|%2e%2e`)
	rewriteTargetRegex   = regexp.MustCompile(`/\$[0-9]`)
)

// IngressAnalyzer performs static security checks on Ingress declarations.
type IngressAnalyzer struct{}

// NewIngressAnalyzer creates an instance of IngressAnalyzer.
func NewIngressAnalyzer() *IngressAnalyzer {
	return &IngressAnalyzer{}
}

// AuditIngress audits a single RawResource if its Kind is "Ingress".
func (a *IngressAnalyzer) AuditIngress(res RawResource) []Violation {
	if res.Kind != "Ingress" {
		return nil
	}

	var violations []Violation

	// 1. Audit Snippet Injection (CVE-2021-25742 / CVE-2023-5044 / CVE-2026-21801)
	violations = append(violations, a.checkSnippetInjections(res)...)

	// 2. Audit URI Pattern & Rewrite Path Traversals
	violations = append(violations, a.checkURIPatterns(res)...)

	// 3. Audit TLS & SSL Redirect Policies
	violations = append(violations, a.checkSSLRedirect(res)...)

	// 4. Audit CORS Wildcard & Credential Disclosure
	violations = append(violations, a.checkCORSConfiguration(res)...)

	// 5. Audit Unbounded Request Body Uploads
	violations = append(violations, a.checkProxyLimits(res)...)

	// 6. Audit Missing TLS Blocks on Exposed Hosts
	violations = append(violations, a.checkTLSConfig(res)...)

	return violations
}

func (a *IngressAnalyzer) checkSnippetInjections(res RawResource) []Violation {
	var violations []Violation

	for _, key := range snippetAnnotationKeys {
		snippet, exists := res.Annotations[key]
		if !exists {
			continue
		}

		lower := strings.ToLower(snippet)
		hasDangerousDirective := false
		var foundDirective string
		for _, d := range dangerousDirectives {
			if strings.Contains(lower, d) {
				hasDangerousDirective = true
				foundDirective = d
				break
			}
		}

		if hasDangerousDirective {
			violations = append(violations, Violation{
				RuleID:       "K8S-ING-001",
				Title:        "Ingress-Nginx Dangerous Directive Snippet Injection",
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Severity:     intel.SeverityCritical,
				CVSSScore:    9.8,
				Description:  fmt.Sprintf("Annotation '%s' contains high-risk directive '%s' capable of arbitrary Nginx reconfiguration or escape.", key, foundDirective),
				Remediation:  "Disable custom snippets in ingress-nginx controller configmap (allow-snippet-annotations: false) and remove annotation.",
				MatchedCVE:   "CVE-2023-5044",
			})
		} else {
			violations = append(violations, Violation{
				RuleID:       "K8S-ING-002",
				Title:        "Custom Configuration Snippet Enabled",
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Severity:     intel.SeverityHigh,
				CVSSScore:    8.4,
				Description:  fmt.Sprintf("Annotation '%s' is present. Ingress controllers without strict snippet validation are susceptible to arbitrary lua/command injection.", key),
				Remediation:  "Refactor custom configuration into declarative controller configmaps or migrate to Kubernetes Gateway API.",
				MatchedCVE:   "CVE-2026-21801",
			})
		}
	}

	return violations
}

func (a *IngressAnalyzer) checkURIPatterns(res RawResource) []Violation {
	var violations []Violation
	rewriteTarget, hasRewrite := res.Annotations["nginx.ingress.kubernetes.io/rewrite-target"]

	// Scan lines in the manifest for path definitions
	scanner := bufio.NewScanner(strings.NewReader(res.RawContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "- ")
		if !strings.HasPrefix(line, "path:") {
			continue
		}

		pathVal := cleanYamlValue(strings.TrimPrefix(line, "path:"))

		// Path Traversal Check
		if pathTraversalPattern.MatchString(pathVal) {
			violations = append(violations, Violation{
				RuleID:       "K8S-ING-003",
				Title:        "Ingress Path Traversal Pattern Detected",
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Severity:     intel.SeverityHigh,
				CVSSScore:    8.1,
				Description:  fmt.Sprintf("Path specification '%s' contains directory traversal sequences.", pathVal),
				Remediation:  "Normalize URI paths to canonical absolute paths without traversal sequences.",
				MatchedCVE:   "CVE-2026-21801",
			})
		}

		// Rewrite target capture group mismatch check
		if hasRewrite && rewriteTargetRegex.MatchString(rewriteTarget) {
			if !strings.Contains(pathVal, "(") || !strings.Contains(pathVal, ")") {
				violations = append(violations, Violation{
					RuleID:       "K8S-ING-004",
					Title:        "Unanchored Rewrite Target Capture Group Misconfiguration",
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Severity:     intel.SeverityMedium,
					CVSSScore:    6.5,
					Description:  fmt.Sprintf("rewrite-target '%s' uses capture groups but path '%s' lacks balanced regex capture boundaries.", rewriteTarget, pathVal),
					Remediation:  "Ensure regex capture groups in path align strictly with rewrite-target substitutions.",
				})
			}
		}
	}

	return violations
}

func (a *IngressAnalyzer) checkSSLRedirect(res RawResource) []Violation {
	var violations []Violation

	sslRedirect, hasSSL := res.Annotations["nginx.ingress.kubernetes.io/ssl-redirect"]
	if !hasSSL {
		sslRedirect, hasSSL = res.Annotations["ingress.kubernetes.io/ssl-redirect"]
	}

	forceSSL, hasForceSSL := res.Annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"]

	if (hasSSL && strings.EqualFold(sslRedirect, "false")) || (hasForceSSL && strings.EqualFold(forceSSL, "false")) {
		violations = append(violations, Violation{
			RuleID:       "K8S-ING-005",
			Title:        "Ingress Insecure Plaintext HTTP Allowed (SSL-Redirect Disabled)",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityMedium,
			CVSSScore:    5.9,
			Description:  "SSL redirection is explicitly set to false, permitting unencrypted cleartext HTTP access to backend services.",
			Remediation:  "Enable ssl-redirect: 'true' and force-ssl-redirect: 'true' to enforce transport-layer encryption.",
		})
	}

	return violations
}

func (a *IngressAnalyzer) checkCORSConfiguration(res RawResource) []Violation {
	var violations []Violation

	enableCors := res.Annotations["nginx.ingress.kubernetes.io/enable-cors"]
	allowOrigin := res.Annotations["nginx.ingress.kubernetes.io/cors-allow-origin"]
	allowCreds := res.Annotations["nginx.ingress.kubernetes.io/cors-allow-credentials"]

	if strings.EqualFold(enableCors, "true") && allowOrigin == "*" && strings.EqualFold(allowCreds, "true") {
		violations = append(violations, Violation{
			RuleID:       "K8S-ING-006",
			Title:        "Permissive CORS Wildcard Origin With Credentials Enabled",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.5,
			Description:  "CORS allows wildcard origin '*' while permitting credentials (cookies/tokens), enabling arbitrary cross-origin token theft.",
			Remediation:  "Specify explicit trusted origins in cors-allow-origin or disable cors-allow-credentials.",
		})
	}

	return violations
}

func (a *IngressAnalyzer) checkProxyLimits(res RawResource) []Violation {
	var violations []Violation

	bodySize, exists := res.Annotations["nginx.ingress.kubernetes.io/proxy-body-size"]
	if exists && (bodySize == "0" || strings.EqualFold(bodySize, "0m")) {
		violations = append(violations, Violation{
			RuleID:       "K8S-ING-007",
			Title:        "Unbounded Proxy Body Size Buffer Overflow Exposure",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityLow,
			CVSSScore:    3.7,
			Description:  "proxy-body-size is set to 0 (unlimited), exposing backend services to denial of service via large payload buffering.",
			Remediation:  "Set a bounded proxy-body-size limit (e.g., '10m' or '25m') appropriate for backend payload requirements.",
		})
	}

	return violations
}

func (a *IngressAnalyzer) checkTLSConfig(res RawResource) []Violation {
	var violations []Violation

	// If hosts are defined under rules but no tls block exists in raw content
	if strings.Contains(res.RawContent, "host:") && !strings.Contains(res.RawContent, "tls:") {
		violations = append(violations, Violation{
			RuleID:       "K8S-ING-008",
			Title:        "Ingress Host Defined Without TLS Certificate Termination",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityMedium,
			CVSSScore:    5.3,
			Description:  "Ingress routes expose host domain rules without a matching spec.tls secret certificate declaration.",
			Remediation:  "Configure spec.tls with secretName pointing to a valid certificate or cert-manager cluster issuer.",
		})
	}

	return violations
}
