package gateway

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var defaultGatewayRules = map[string]GatewayRule{
	"GW-RADAR-001": {
		ID:          "GW-RADAR-001",
		Title:       "Unrestricted Cross-Namespace Backend Reference (Missing ReferenceGrant)",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Category:    "CrossNamespaceAuthorization",
		Description: "Route references a backend service or secret across namespace boundaries without an explicit ReferenceGrant authorizing the source namespace and route kind.",
		Remediation: "Define a declarative ReferenceGrant in the target namespace explicitly permitting references from the route namespace and kind.",
	},
	"GW-RADAR-002": {
		ID:          "GW-RADAR-002",
		Title:       "Unsafe EnvoyFilter Inline Lua Script Injection",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.3,
		Category:    "CodeInjection",
		Description: "EnvoyFilter contains envoy.filters.http.lua with dangerous runtime primitives (os.execute, io.popen, loadstring, require os/io) enabling arbitrary proxy sidecar execution.",
		Remediation: "Disallow dynamic Lua script injection; replace with compiled Wasm plugins or declarative Istio AuthorizationPolicies.",
	},
	"GW-RADAR-003": {
		ID:          "GW-RADAR-003",
		Title:       "EnvoyFilter Filter Chain Order Bypass",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Category:    "FilterOrdering",
		Description: "EnvoyFilter utilizes INSERT_BEFORE targeting authentication or authorization filters (jwt_authn, istio.authn, rbac), executing unauthenticated logic prior to identity verification.",
		Remediation: "Position custom HTTP filters strictly after authentication and authorization modules using INSERT_AFTER or INSERT_FIRST on ingress listener chains only.",
	},
	"GW-RADAR-004": {
		ID:          "GW-RADAR-004",
		Title:       "Gateway Insecure Plaintext Listener Without TLS Termination",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.5,
		Category:    "TransportSecurity",
		Description: "Gateway resource exposes HTTP listeners on port 80 without a corresponding HTTPS redirect filter or TLS termination certificate references.",
		Remediation: "Configure TLS termination with valid certificateRefs or attach a RequestRedirect filter enforcing HTTPS scheme on HTTP listeners.",
	},
	"GW-RADAR-005": {
		ID:          "GW-RADAR-005",
		Title:       "HTTPRoute Unrestricted Wildcard Path & Open Routing",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Category:    "RouteExposure",
		Description: "HTTPRoute rule matches catch-all root prefix (/) without header, method, or query parameter restrictions, exposing internal services to unbounded traffic.",
		Remediation: "Constrain route matching rules to explicit URI prefixes, define allowed HTTP methods, and attach rate limiting or authentication filters.",
	},
	"GW-RADAR-006": {
		ID:          "GW-RADAR-006",
		Title:       "HTTPRoute Unsafe Path Prefix Rewrite Traversal",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Category:    "PathTraversal",
		Description: "HTTPRoute URLRewrite or RequestRedirect filter configures ambiguous relative prefix replacements containing '..' or unanchored slashes ('//'), enabling upstream path traversal.",
		Remediation: "Ensure URLRewrite replacePrefixMatch uses canonical absolute paths without path traversal sequences.",
	},
	"GW-RADAR-007": {
		ID:          "GW-RADAR-007",
		Title:       "HTTPRoute Identity Header Spoofing via RequestHeaderModifier",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.7,
		Category:    "HeaderInjection",
		Description: "HTTPRoute RequestHeaderModifier sets or adds trusted identity and authentication headers (X-Remote-User, X-Forwarded-User, X-Authenticated-Groups) from client request context without sanitization.",
		Remediation: "Strip incoming identity headers via remove in RequestHeaderModifier before injecting upstream security context, or delegate identity extraction to an external authorizer.",
	},
	"GW-RADAR-008": {
		ID:          "GW-RADAR-008",
		Title:       "GRPCRoute Unrestricted Administrative Method Dispatch",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.2,
		Category:    "GranularAuthorization",
		Description: "GRPCRoute routes all methods (*) to internal backend services without service or method-level authorization constraints.",
		Remediation: "Explicitly define allowed gRPC service and method pairs in GRPCRoute rules.",
	},
	"GW-RADAR-009": {
		ID:          "GW-RADAR-009",
		Title:       "TCPRoute / UDPRoute Sensitive Infrastructure Port Forwarding",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Category:    "NetworkSegmentation",
		Description: "TCPRoute or UDPRoute forwards external traffic directly to sensitive infrastructure or database ports (e.g. 2379, 6443, 5432, 3306, 6379, 10250) without mutual TLS or network boundary isolation.",
		Remediation: "Restrict TCP/UDP routing to application-level services and enforce network policies guarding infrastructure control plane endpoints.",
	},
	"GW-RADAR-010": {
		ID:          "GW-RADAR-010",
		Title:       "EnvoyFilter Disabling Client TLS Verification",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Category:    "TransportSecurity",
		Description: "EnvoyFilter modifies downstream TLS transport socket to disable client certificate verification (require_client_certificate: false or trust_chain_verification: ACCEPT_UNTRUSTED), breaking mutual TLS zero-trust guarantees.",
		Remediation: "Mandate client certificate verification on all internal mesh listeners and reject untrusted certificate chains.",
	},
	"GW-RADAR-011": {
		ID:          "GW-RADAR-011",
		Title:       "Gateway AllowedRoutes Namespace Wildcard Violation",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.4,
		Category:    "MultiTenancyIsolation",
		Description: "Gateway listener sets allowedRoutes.namespaces.from: All, allowing untrusted tenant namespaces to attach routes to cluster ingress gateways.",
		Remediation: "Restrict allowedRoutes.namespaces.from to Same or Selector with explicit tenant label constraints.",
	},
	"GW-RADAR-012": {
		ID:          "GW-RADAR-012",
		Title:       "EnvoyFilter Unrestricted Hop-by-Hop Header Mutation",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.8,
		Category:    "HeaderSmuggling",
		Description: "EnvoyFilter modifies or forwards hop-by-hop HTTP headers (Connection, Transfer-Encoding, Upgrade) via Lua filter scripts, introducing request smuggling vulnerabilities.",
		Remediation: "Strip hop-by-hop headers and validate Envoy HTTP connection manager header sanitation settings.",
	},
}

// LookupGatewayRule retrieves a rule definition by its identifier.
func LookupGatewayRule(id string) (GatewayRule, bool) {
	rule, found := defaultGatewayRules[id]
	return rule, found
}

// DefaultGatewayRules returns the full catalog of Gateway API and EnvoyFilter radar rules.
func DefaultGatewayRules() []GatewayRule {
	rules := make([]GatewayRule, 0, len(defaultGatewayRules))
	for _, rule := range defaultGatewayRules {
		rules = append(rules, rule)
	}
	return rules
}
