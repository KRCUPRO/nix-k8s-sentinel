package flow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalFlowRules(t *testing.T) {
	if len(CanonicalFlowRules) != 12 {
		t.Fatalf("expected 12 canonical flow rules, got %d", len(CanonicalFlowRules))
	}

	for _, rule := range CanonicalFlowRules {
		if rule.ID == "" || rule.Name == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has empty required fields", rule.ID)
		}
		if rule.CVSSScore <= 0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", rule.ID, rule.CVSSScore)
		}
		if rule.MatchedCVE == "" {
			t.Errorf("rule %s missing matched CVE", rule.ID)
		}
	}

	found := LookupFlowRule("FLOW-RADAR-001")
	if found == nil || found.Name != "UnrestrictedExternalDNSEgress" {
		t.Errorf("LookupFlowRule failed for FLOW-RADAR-001")
	}

	if LookupFlowRule("FLOW-NONEXISTENT") != nil {
		t.Errorf("LookupFlowRule returned non-nil for invalid rule ID")
	}
}

func TestShannonEntropyCalculation(t *testing.T) {
	// Empty string
	if e := CalculateShannonEntropy(""); e != 0.0 {
		t.Errorf("expected 0.0 for empty string, got %f", e)
	}

	// Repeated single character (zero entropy)
	if e := CalculateShannonEntropy("aaaaaaaaaa"); e != 0.0 {
		t.Errorf("expected 0.0 for uniform string, got %f", e)
	}

	// Benign domain: lower entropy
	benignEntropy := CalculateShannonEntropy("kubernetes")
	if benignEntropy > 3.5 {
		t.Errorf("benign word entropy unexpectedly high: %f", benignEntropy)
	}

	// High entropy base64-like hex payload
	highEntropyString := "a4f89d0c2e1b74a3f89e2c1d0b"
	highEntropy := CalculateShannonEntropy(highEntropyString)
	if highEntropy < 3.5 {
		t.Errorf("expected high entropy for hex payload, got %f", highEntropy)
	}
}

func TestAnalyzeDomainQuery(t *testing.T) {
	// 1. Benign domain
	entropy, maxLen, isDGA, isTunneling := AnalyzeDomainQuery("api.github.com")
	if isTunneling || isDGA {
		t.Errorf("benign domain misclassified: entropy=%f, maxLen=%d, isDGA=%v, isTunneling=%v",
			entropy, maxLen, isDGA, isTunneling)
	}

	// 2. High entropy tunneling domain
	tunnelDomain := "4f8a92b3c1d4e7f0123456789abcdef0123456789abcdef0123456789abcdef.tunnel.attacker.com"
	_, _, _, isTunneling = AnalyzeDomainQuery(tunnelDomain)
	if !isTunneling {
		t.Errorf("failed to detect tunneling in domain '%s'", tunnelDomain)
	}

	// 3. DGA consonant-heavy domain
	dgaDomain := "bcfgzjklmnpqrstvwxyz89012.evil-c2.net"
	_, _, isDGA, _ = AnalyzeDomainQuery(dgaDomain)
	if !isDGA {
		t.Errorf("failed to detect DGA in domain '%s'", dgaDomain)
	}
}

func TestParseCiliumPolicy(t *testing.T) {
	manifest := []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: test-flow-policy
  namespace: production
  annotations:
    io.cilium/enable-dns-proxy: "true"
spec:
  endpointSelector:
    matchLabels:
      app: backend
  egress:
  - toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      rules:
        dns:
        - matchPattern: "*.internal.cluster.local"
  - toFQDNs:
    - matchPattern: "api.github.com"
`)

	cfg, err := ParseCiliumPolicy(manifest, "test-policy.yaml")
	if err != nil {
		t.Fatalf("failed to parse Cilium policy: %v", err)
	}

	if cfg.Name != "test-flow-policy" || cfg.Namespace != "production" {
		t.Errorf("unexpected metadata: %s/%s", cfg.Namespace, cfg.Name)
	}
	if cfg.EnableDNSProxy == nil || !*cfg.EnableDNSProxy {
		t.Errorf("expected enable-dns-proxy to be true")
	}
	if len(cfg.EgressRules) == 0 {
		t.Fatalf("expected egress rules to be parsed")
	}

	// Memory limit check
	hugeManifest := make([]byte, MaxManifestBytes+10)
	_, err = ParseCiliumPolicy(hugeManifest, "huge.yaml")
	if err == nil {
		t.Errorf("expected error for manifest exceeding MaxManifestBytes")
	}
}

func TestParseNixOSFlow(t *testing.T) {
	nixConfig := []byte(`
{
  networking.hostName = "sentinel-worker-01";
  services.cilium.enable = true;
  programs.ebpf.flowProfiler.enable = true;
  programs.ebpf.flowProfiler.bpfConnectMonitoring = true;
  programs.ebpf.flowProfiler.maxSocketRate = 250;
  programs.ebpf.flowProfiler.dnsProxyPort = 10053;
  programs.ebpf.flowProfiler.ringBufferSizeKB = 65536;
  programs.ebpf.flowProfiler.dropThresholdPercent = 0.5;
}
`)

	cfg, err := ParseNixOSFlow(nixConfig, "nixos-flow.nix")
	if err != nil {
		t.Fatalf("failed to parse NixOS flow config: %v", err)
	}

	if cfg.HostName != "sentinel-worker-01" {
		t.Errorf("unexpected hostName: %s", cfg.HostName)
	}
	if cfg.CiliumEnabled == nil || !*cfg.CiliumEnabled {
		t.Errorf("expected CiliumEnabled to be true")
	}
	if cfg.FlowProfilerEnabled == nil || !*cfg.FlowProfilerEnabled {
		t.Errorf("expected FlowProfilerEnabled to be true")
	}
	if cfg.MaxSocketRate != 250 {
		t.Errorf("expected MaxSocketRate 250, got %d", cfg.MaxSocketRate)
	}
	if cfg.RingBufferSizeKB != 65536 {
		t.Errorf("expected RingBufferSizeKB 65536, got %d", cfg.RingBufferSizeKB)
	}
}

func TestParseFlowTelemetryJSON(t *testing.T) {
	sampleTelemetry := FlowTelemetryReport{
		HostName:              "worker-01",
		ClusterName:           "k8s-prod",
		CollectedAt:           time.Now().UTC(),
		TotalDNSQueries:       1000,
		SuspiciousQueries:     12,
		NXDomainCount:         300,
		NXDomainRatePercent:   30.0,
		PeakSocketConnectRate: 650,
		DroppedPackets:        50,
		BufferOverruns:        5,
		DropRatePercent:       1.5,
		Queries: []DNSQueryEvent{
			{
				Timestamp:      time.Now().UTC(),
				ClientPod:      "payment-pod",
				Namespace:      "prod",
				ClientIP:       "10.244.1.20",
				ServerIP:       "10.96.0.10",
				QueryName:      "4a8f9c1e2d3b4a5f6e7d8c9b0a1f2e3d.tunnel.c2.io",
				RecordType:     RecordTypeTXT,
				ResponseCode:   "NOERROR",
				TTL:            300,
				IsAnomaly:      true,
			},
		},
		SocketEvents: []SocketConnectEvent{
			{
				Timestamp:      time.Now().UTC(),
				SourcePod:      "scanner-pod",
				Namespace:      "compromised",
				SourceIP:       "10.244.2.15",
				DestIP:         "192.168.1.100",
				DestPort:       445,
				Protocol:       FlowProtocolTCP,
				ConnectsPerSec: 650,
				IsAnomaly:      true,
			},
		},
	}

	data, err := json.Marshal(sampleTelemetry)
	if err != nil {
		t.Fatalf("failed to marshal sample telemetry: %v", err)
	}

	parsed, err := ParseFlowTelemetryJSON(data)
	if err != nil {
		t.Fatalf("failed to parse telemetry JSON: %v", err)
	}

	if parsed.HostName != "worker-01" {
		t.Errorf("unexpected host: %s", parsed.HostName)
	}
	if parsed.PeakSocketConnectRate != 650 {
		t.Errorf("expected PeakSocketConnectRate 650, got %d", parsed.PeakSocketConnectRate)
	}
	if len(parsed.Queries) != 1 {
		t.Fatalf("expected 1 query event, got %d", len(parsed.Queries))
	}
	if parsed.Queries[0].Vector != VectorTunneling {
		t.Errorf("expected VectorTunneling for query event, got %s", parsed.Queries[0].Vector)
	}

	// Memory safety limit check
	oversized := make([]byte, MaxTelemetryBytes+10)
	_, err = ParseFlowTelemetryJSON(oversized)
	if err == nil {
		t.Errorf("expected error for oversized telemetry data")
	}
}

func TestAuditCiliumPolicyAndNixOS(t *testing.T) {
	// Vulnerable policy: Unrestricted port 53, wildcard FQDN, no DNS proxy
	disabledProxy := false
	vulnPolicy := &CiliumNetworkPolicyConfig{
		FilePath:       "vuln-policy.yaml",
		Name:           "vuln-policy",
		Namespace:      "default",
		EnableDNSProxy: &disabledProxy,
		EgressRules: []EgressRuleConfig{
			{
				LineNumber: 10,
				ToPorts: []PortRuleConfig{
					{
						Port:       53,
						Protocol:   FlowProtocolUDP,
						DNSRules:   nil, // Missing L7 DNS rules!
						LineNumber: 12,
					},
					{
						Port:       6667, // Non-standard IRC port to 0.0.0.0/0
						Protocol:   FlowProtocolTCP,
						LineNumber: 16,
					},
				},
				ToCIDRs: []string{"0.0.0.0/0"},
				ToFQDNs: []FQDNRule{
					{
						MatchPattern: "*", // Wildcard!
						LineNumber:   20,
					},
				},
			},
		},
	}

	violations := AuditCiliumPolicy(vulnPolicy)
	if len(violations) < 4 {
		t.Errorf("expected at least 4 violations for vulnerable policy, got %d", len(violations))
	}

	hasDNSUnrestricted := false
	hasWildcardFQDN := false
	hasDirectEgress := false
	hasProxyDisabled := false
	for _, v := range violations {
		switch v.RuleID {
		case "FLOW-RADAR-001":
			hasDNSUnrestricted = true
		case "FLOW-RADAR-002":
			hasWildcardFQDN = true
		case "FLOW-RADAR-007":
			hasDirectEgress = true
		case "FLOW-RADAR-008":
			hasProxyDisabled = true
		}
	}

	if !hasDNSUnrestricted || !hasWildcardFQDN || !hasDirectEgress || !hasProxyDisabled {
		t.Errorf("missing expected violations: DNS=%v, Wildcard=%v, Direct=%v, Proxy=%v",
			hasDNSUnrestricted, hasWildcardFQDN, hasDirectEgress, hasProxyDisabled)
	}

	// Vulnerable NixOS config
	bpfDisabled := false
	vulnNix := &NixOSFlowConfig{
		FilePath:             "nixos-vuln.nix",
		HostName:             "vuln-node",
		BPFConnectMonitoring: &bpfDisabled,
		RingBufferSizeKB:     4096, // Under 16384 KB
	}

	nixViolations := AuditNixOSFlow(vulnNix)
	if len(nixViolations) < 2 {
		t.Errorf("expected at least 2 violations for vulnerable NixOS config, got %d", len(nixViolations))
	}
}

func TestAuditFlowTelemetry(t *testing.T) {
	tel := &FlowTelemetryReport{
		HostName:              "test-node",
		ClusterName:           "prod-k8s",
		TotalDNSQueries:       1000,
		NXDomainCount:         350,
		NXDomainRatePercent:   35.0, // Exceeds 25%
		PeakSocketConnectRate: 750,  // Exceeds 500
		DropRatePercent:       2.5,  // Exceeds 1.0%
		BufferOverruns:        10,
		Queries: []DNSQueryEvent{
			{
				ClientPod:      "bad-pod",
				Namespace:      "apps",
				QueryName:      "4a8f9c1e2d3b4a5f6e7d8c9b0a1f2e3d4a8f9c1e2d3b4a5f6e7d8c9b0a1f2e3d.tunnel.com",
				Entropy:        4.10, // Exceeds 3.85
				QueryLength:    190,  // Exceeds 180
				MaxLabelLength: 64,   // Exceeds 50
				RecordType:     RecordTypeTXT,
				IsAnomaly:      true,
			},
			{
				ClientPod: "fastflux-pod",
				Namespace: "apps",
				QueryName: "c2.fastflux.com",
				TTL:       5, // Under 10s
				Vector:    VectorFastFlux,
			},
		},
	}

	violations := AuditFlowTelemetry(tel)
	if len(violations) < 5 {
		t.Errorf("expected at least 5 telemetry violations, got %d", len(violations))
	}

	summary := ComputeFlowSummary(2, violations)
	if summary.ComplianceScore > 50.0 {
		t.Errorf("compliance score unexpectedly high for degraded telemetry: %f", summary.ComplianceScore)
	}
}

func TestSynthesizers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flow-synth-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	written, err := WriteSynthesizedPolicies(tmpDir, nil)
	if err != nil {
		t.Fatalf("WriteSynthesizedPolicies failed: %v", err)
	}

	if len(written) != 3 {
		t.Fatalf("expected 3 files written, got %d", len(written))
	}

	for _, file := range written {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("failed to read synthesized file %s: %v", file, err)
		}
		if len(content) == 0 {
			t.Errorf("synthesized file %s is empty", file)
		}
	}
}

func TestFlowScanner(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flow-scan-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ciliumFile := filepath.Join(tmpDir, "cilium.yaml")
	ciliumContent := SynthesizeHardenedCiliumPolicy("kube-system", "hardened-flow", "core", nil)
	if err := os.WriteFile(ciliumFile, []byte(ciliumContent), 0o644); err != nil {
		t.Fatalf("failed to write test manifest: %v", err)
	}

	scanner := NewFlowScanner()
	feed := &intel.Feed{}
	report, err := scanner.ScanFlowTarget(tmpDir, "", feed)
	if err != nil {
		t.Fatalf("ScanFlowTarget failed: %v", err)
	}

	if report.Summary.TotalScanned != 1 {
		t.Errorf("expected 1 scanned file, got %d", report.Summary.TotalScanned)
	}
	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations for hardened policy, got %d", len(report.Violations))
	}
	if report.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected compliance score 100.0, got %f", report.Summary.ComplianceScore)
	}
}
