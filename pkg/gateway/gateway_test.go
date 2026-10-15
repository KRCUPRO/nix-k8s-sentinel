package gateway_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

func TestGatewayRulesCatalog(t *testing.T) {
	rules := gateway.DefaultGatewayRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical gateway rules, got %d", len(rules))
	}

	expectedIDs := []string{
		"GW-RADAR-001", "GW-RADAR-002", "GW-RADAR-003", "GW-RADAR-004",
		"GW-RADAR-005", "GW-RADAR-006", "GW-RADAR-007", "GW-RADAR-008",
		"GW-RADAR-009", "GW-RADAR-010", "GW-RADAR-011", "GW-RADAR-012",
	}

	for _, id := range expectedIDs {
		rule, found := gateway.LookupGatewayRule(id)
		if !found {
			t.Errorf("expected rule %s to be present in catalog", id)
		}
		if rule.Title == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has empty metadata fields", id)
		}
		if rule.CVSSScore <= 0 {
			t.Errorf("rule %s has invalid CVSS score: %f", id, rule.CVSSScore)
		}
	}
}

func TestReferenceGrantAuthorization(t *testing.T) {
	radar := gateway.NewGatewayRadar()

	// Same namespace is always permitted
	if !radar.HasReferenceGrant("tenant-a", "HTTPRoute", "tenant-a", "Service", "api") {
		t.Errorf("same-namespace reference should always be permitted")
	}

	// Cross-namespace without grant should be rejected
	if radar.HasReferenceGrant("tenant-a", "HTTPRoute", "backend-ns", "Service", "api") {
		t.Errorf("cross-namespace reference should be rejected when no grant exists")
	}

	manifest := `
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-tenant-a
  namespace: backend-ns
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: tenant-a
  to:
    - group: ""
      kind: Service
      name: api-service
`
	res, err := k8s.ParseManifestDocuments(manifest)
	if err != nil {
		t.Fatalf("failed to parse reference grant manifest: %v", err)
	}

	radar.RegisterReferenceGrants(res)

	// Explicit name matching
	if !radar.HasReferenceGrant("tenant-a", "HTTPRoute", "backend-ns", "Service", "api-service") {
		t.Errorf("expected granted reference to be permitted")
	}
	// Different service name should be rejected
	if radar.HasReferenceGrant("tenant-a", "HTTPRoute", "backend-ns", "Service", "other-service") {
		t.Errorf("unnamed service should be rejected when specific name was granted")
	}
	// Different source namespace should be rejected
	if radar.HasReferenceGrant("tenant-b", "HTTPRoute", "backend-ns", "Service", "api-service") {
		t.Errorf("unauthorized source namespace should be rejected")
	}
}

func TestAuditGateway(t *testing.T) {
	radar := gateway.NewGatewayRadar()

	vulnerableGW := k8s.RawResource{
		Kind: "Gateway",
		Name: "insecure-edge",
		RawContent: `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: insecure-edge
spec:
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: All
`,
	}

	violations := radar.AuditGateway(vulnerableGW, "gateway.yaml")
	if len(violations) < 2 {
		t.Fatalf("expected at least 2 violations (plaintext listener & allowedRoutes All), got %d", len(violations))
	}

	foundPlaintext := false
	foundAllowedRoutes := false
	for _, v := range violations {
		if v.RuleID == "GW-RADAR-004" {
			foundPlaintext = true
		}
		if v.RuleID == "GW-RADAR-011" {
			foundAllowedRoutes = true
		}
	}

	if !foundPlaintext {
		t.Errorf("expected GW-RADAR-004 violation for plaintext port 80 listener")
	}
	if !foundAllowedRoutes {
		t.Errorf("expected GW-RADAR-011 violation for allowedRoutes from: All")
	}

	// Hardened Gateway with TLS
	hardenedGW := k8s.RawResource{
		Kind: "Gateway",
		Name: "secure-edge",
		RawContent: `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: secure-edge
spec:
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        certificateRefs:
          - name: edge-cert
      allowedRoutes:
        namespaces:
          from: Same
`,
	}

	cleanViolations := radar.AuditGateway(hardenedGW, "secure-gateway.yaml")
	if len(cleanViolations) != 0 {
		t.Errorf("expected 0 violations for hardened Gateway, got %d", len(cleanViolations))
	}
}

func TestAuditHTTPRoute(t *testing.T) {
	radar := gateway.NewGatewayRadar()

	vulnerableRoute := k8s.RawResource{
		Kind:      "HTTPRoute",
		Name:      "insecure-route",
		Namespace: "tenant-dev",
		RawContent: `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: insecure-route
  namespace: tenant-dev
spec:
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      filters:
        - type: URLRewrite
          urlRewrite:
            path:
              type: ReplacePrefixMatch
              replacePrefixMatch: /../../etc/shadow
        - type: RequestHeaderModifier
          requestHeaderModifier:
            set:
              - name: X-Remote-User
                value: root
      backendRefs:
        - name: database-svc
          namespace: core-infra
          port: 5432
`,
	}

	violations := radar.AuditHTTPRoute(vulnerableRoute, "route.yaml")
	if len(violations) < 3 {
		t.Fatalf("expected at least 3 violations, got %d", len(violations))
	}

	foundRefGrant := false
	foundTraversal := false
	foundHeader := false
	for _, v := range violations {
		if v.RuleID == "GW-RADAR-001" {
			foundRefGrant = true
		}
		if v.RuleID == "GW-RADAR-006" {
			foundTraversal = true
		}
		if v.RuleID == "GW-RADAR-007" {
			foundHeader = true
		}
	}

	if !foundRefGrant {
		t.Errorf("expected GW-RADAR-001 for missing ReferenceGrant")
	}
	if !foundTraversal {
		t.Errorf("expected GW-RADAR-006 for path traversal in replacePrefixMatch")
	}
	if !foundHeader {
		t.Errorf("expected GW-RADAR-007 for X-Remote-User header injection")
	}
}

func TestAuditGRPCRouteAndTCPRoute(t *testing.T) {
	radar := gateway.NewGatewayRadar()

	grpcRes := k8s.RawResource{
		Kind: "GRPCRoute",
		Name: "admin-grpc",
		RawContent: `
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: admin-grpc
spec:
  rules:
    - matches:
        - method:
            service: com.internal.admin
            method: "*"
`,
	}
	grpcViolations := radar.AuditGRPCRoute(grpcRes, "grpc.yaml")
	if len(grpcViolations) == 0 || grpcViolations[0].RuleID != "GW-RADAR-008" {
		t.Errorf("expected GW-RADAR-008 for wildcard gRPC method routing")
	}

	tcpRes := k8s.RawResource{
		Kind: "TCPRoute",
		Name: "etcd-exposure",
		RawContent: `
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: etcd-exposure
spec:
  rules:
    - backendRefs:
        - name: etcd-svc
          port: 2379
`,
	}
	tcpViolations := radar.AuditTCPRoute(tcpRes, "tcp.yaml")
	if len(tcpViolations) == 0 || tcpViolations[0].RuleID != "GW-RADAR-009" {
		t.Errorf("expected GW-RADAR-009 for sensitive etcd port forwarding")
	}
}

func TestAuditEnvoyFilter(t *testing.T) {
	auditor := gateway.NewEnvoyFilterAuditor()

	vulnerableEnvoy := k8s.RawResource{
		Kind: "EnvoyFilter",
		Name: "unsafe-filter",
		RawContent: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: unsafe-filter
spec:
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
              subFilter:
                name: envoy.filters.http.jwt_authn
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.lua
          typed_config:
            inlineCode: |
              function envoy_on_request(handle)
                local f = io.popen("id")
                handle:headers():add("connection", "close")
              end
    - applyTo: LISTENER
      patch:
        operation: MERGE
        value:
          require_client_certificate: false
`,
	}

	violations := auditor.AuditEnvoyFilter(vulnerableEnvoy, "envoy.yaml")
	if len(violations) < 4 {
		t.Fatalf("expected 4 violations (Lua inject, hop-by-hop, auth bypass, insecure TLS), got %d", len(violations))
	}

	foundLua := false
	foundOrder := false
	foundTLS := false
	foundHop := false
	for _, v := range violations {
		if v.RuleID == "GW-RADAR-002" {
			foundLua = true
		}
		if v.RuleID == "GW-RADAR-003" {
			foundOrder = true
		}
		if v.RuleID == "GW-RADAR-010" {
			foundTLS = true
		}
		if v.RuleID == "GW-RADAR-012" {
			foundHop = true
		}
	}

	if !foundLua {
		t.Errorf("expected GW-RADAR-002 for io.popen Lua injection")
	}
	if !foundOrder {
		t.Errorf("expected GW-RADAR-003 for INSERT_BEFORE jwt_authn")
	}
	if !foundTLS {
		t.Errorf("expected GW-RADAR-010 for require_client_certificate: false")
	}
	if !foundHop {
		t.Errorf("expected GW-RADAR-012 for connection: close hop-by-hop mutation")
	}
}

func TestGatewayScanner_FixtureIntegration(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "gateway-api-routes.yaml")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skipf("fixture file %s does not exist, skipping", fixturePath)
	}

	feedData := `{"version":"1.0","items":[{"id":"CVE-2026-44219","title":"Kubernetes Gateway API Cross-Namespace Hijacking","component":"gateway-api","target":"kubernetes","severity":"CRITICAL","cvss_score":9.6}]}`
	feed, err := intel.ParseFeed([]byte(feedData))
	if err != nil {
		t.Fatalf("failed to parse feed: %v", err)
	}

	scanner := gateway.NewGatewayScanner(feed)
	report, err := scanner.ScanFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to scan fixture: %v", err)
	}

	if report.TotalResources == 0 {
		t.Errorf("expected evaluated resources from fixture, got 0")
	}
	if len(report.Violations) == 0 {
		t.Errorf("expected violations in vulnerable fixture, got 0")
	}

	// Verify correlation
	foundCorrelated := false
	for _, v := range report.Violations {
		if v.MatchedCVE == "CVE-2026-44219" {
			foundCorrelated = true
			break
		}
	}
	if !foundCorrelated {
		t.Errorf("expected CVE-2026-44219 correlation in gateway audit findings")
	}

	// Verify ReferenceGrant registry in report
	if len(report.ReferenceGrants) == 0 {
		t.Errorf("expected registered ReferenceGrants in report, got 0")
	}
}

func TestGatewayBoundsChecking(t *testing.T) {
	tmpDir := t.TempDir()
	hugeFile := filepath.Join(tmpDir, "huge-gateway.yaml")

	// Generate oversized payload (> 10MB)
	hugeContent := strings.Repeat("# comment padding\n", (gateway.MaxManifestBytes/18)+1000)
	if err := os.WriteFile(hugeFile, []byte(hugeContent), 0644); err != nil {
		t.Fatalf("failed to create huge file: %v", err)
	}

	scanner := gateway.NewGatewayScanner(nil)
	_, err := scanner.ScanFile(hugeFile)
	if err == nil {
		t.Fatalf("expected scan of huge file (> 10MB) to return defensive bounds error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowable size") {
		t.Errorf("expected size limit error message, got: %v", err)
	}
}
