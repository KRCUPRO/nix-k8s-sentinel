package bgp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalBGPRules(t *testing.T) {
	if len(CanonicalBGPRules) != 12 {
		t.Fatalf("expected 12 canonical rules, got %d", len(CanonicalBGPRules))
	}

	for i, r := range CanonicalBGPRules {
		expectedID := "BGP-RADAR-" + strings.TrimPrefix(CanonicalBGPRules[i].ID, "BGP-RADAR-")
		if r.ID != expectedID {
			t.Errorf("rule index %d has unexpected ID %s", i, r.ID)
		}
		if r.Title == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s has empty fields", r.ID)
		}
		if r.CVSSScore <= 0.0 || r.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score %.1f", r.ID, r.CVSSScore)
		}
	}

	r1 := FindRule("BGP-RADAR-001")
	if r1.ID != "BGP-RADAR-001" || r1.Severity != intel.SeverityCritical {
		t.Errorf("expected BGP-RADAR-001 to be Critical, got %v", r1)
	}

	rUnknown := FindRule("NON-EXISTENT")
	if rUnknown.ID != "NON-EXISTENT" {
		t.Errorf("expected placeholder for non-existent rule")
	}
}

func TestParseCiliumBGPPeeringPolicy_ValidAndVulnerable(t *testing.T) {
	validYAML := `
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPPeeringPolicy
metadata:
  name: hardened-bgp
spec:
  virtualRouters:
    - localASN: 65001
      exportPodCIDR: true
      exportServiceCIDR: true
      prefixFilters:
        - "10.244.0.0/16"
        - "fd00:10:244::/64"
      neighbors:
        - peerAddress: "192.168.1.1/32"
          peerASN: 65000
          authSecretRef: "bgp-auth-key"
          eBGP:
            multihopTTL: 2
          gracefulRestart:
            enabled: true
            restartTimeSeconds: 120
          holdTimeSeconds: 30
          keepAliveTimeSeconds: 10
          families:
            - "IPv4"
            - "IPv6"
          community: "65000:100"
`

	policies, err := ParseCiliumBGPPeeringPolicy([]byte(validYAML), "test-valid.yaml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	pol := policies[0]
	if pol.PolicyName != "hardened-bgp" {
		t.Errorf("expected name hardened-bgp, got %s", pol.PolicyName)
	}
	if len(pol.VirtualRouters) != 1 {
		t.Fatalf("expected 1 virtual router, got %d", len(pol.VirtualRouters))
	}
	vr := pol.VirtualRouters[0]
	if vr.LocalASN != 65001 || !vr.ExportPodCIDR || !vr.ExportServiceCIDR {
		t.Errorf("unexpected virtual router fields: %+v", vr)
	}
	if len(vr.PrefixFilters) != 2 {
		t.Errorf("expected 2 prefix filters, got %d", len(vr.PrefixFilters))
	}
	if len(vr.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(vr.Neighbors))
	}
	n := vr.Neighbors[0]
	if n.PeerAddress != "192.168.1.1/32" || n.PeerASN != 65000 || !n.HasMD5 || !n.GracefulRestart {
		t.Errorf("unexpected neighbor fields: %+v", n)
	}

	violations := AuditCiliumBGPPeeringPolicies(policies)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for hardened policy, got %d: %+v", len(violations), violations)
	}
}

func TestParseCiliumLoadBalancerIPPool(t *testing.T) {
	manifest := `
apiVersion: cilium.io/v2alpha1
kind: CiliumLoadBalancerIPPool
metadata:
  name: dual-stack-pool
spec:
  cidrs:
    - cidr: "10.0.10.0/24"
    - cidr: "2001:db8:10::/64"
  disabled: false
`
	pools, err := ParseCiliumLoadBalancerIPPool([]byte(manifest), "test-ippool.yaml")
	if err != nil {
		t.Fatalf("unexpected error parsing IP pool: %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(pools))
	}
	if pools[0].PoolName != "dual-stack-pool" || len(pools[0].CIDRs) != 2 {
		t.Errorf("unexpected pool content: %+v", pools[0])
	}

	violations := AuditCiliumLoadBalancerIPPools(pools)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for dual-stack pool, got %d", len(violations))
	}

	// Test IPv4-only pool triggers BGP-RADAR-002
	ipv4Only := `
apiVersion: cilium.io/v2alpha1
kind: CiliumLoadBalancerIPPool
metadata:
  name: ipv4-only-pool
spec:
  cidrs:
    - cidr: "10.0.10.0/24"
`
	v4Pools, _ := ParseCiliumLoadBalancerIPPool([]byte(ipv4Only), "v4.yaml")
	v4Violations := AuditCiliumLoadBalancerIPPools(v4Pools)
	if len(v4Violations) == 0 {
		t.Errorf("expected BGP-RADAR-002 for IPv4-only pool")
	}
}

func TestParseNixOSBGPModule(t *testing.T) {
	nixConfig := `
{ config, pkgs, ... }:
{
  services.frr.bgp.enable = true;
  services.frr.bgp.localASN = 65001;
  networking.firewall.allowedTCPPorts = [ 179 443 ];
  networking.firewall.extraCommands = "iptables -A INPUT -p tcp --dport 179 -s 192.168.1.0/24 -j ACCEPT";
  boot.kernel.sysctl = {
    "net.ipv6.conf.all.accept_ra" = 0;
  };
}
`
	cfg, err := ParseNixOSBGPModule([]byte(nixConfig), "configuration.nix")
	if err != nil {
		t.Fatalf("unexpected error parsing NixOS BGP: %v", err)
	}
	if !cfg.FRREnabled || cfg.LocalASN != 65001 || !cfg.TCP179Allowed || !cfg.FirewallRestricted || cfg.IPv6AcceptRA != 0 {
		t.Errorf("unexpected NixOS config fields: %+v", cfg)
	}

	violations := AuditNixOSBGP(cfg)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for hardened NixOS module, got %d", len(violations))
	}

	// Vulnerable NixOS config
	vulnNix := `
{
  networking.firewall.allowedTCPPorts = [ 179 ];
  boot.kernel.sysctl."net.ipv6.conf.all.accept_ra" = 1;
}
`
	vulnCfg, _ := ParseNixOSBGPModule([]byte(vulnNix), "vuln.nix")
	vulnViolations := AuditNixOSBGP(vulnCfg)
	if len(vulnViolations) != 2 {
		t.Errorf("expected 2 violations (BGP-RADAR-007, BGP-RADAR-008), got %d", len(vulnViolations))
	}
}

func TestAuditCiliumBGPPeeringPolicies_Vulnerabilities(t *testing.T) {
	vulnYAML := `
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPPeeringPolicy
metadata:
  name: vulnerable-bgp
spec:
  virtualRouters:
    - localASN: 65001
      exportPodCIDR: true
      exportServiceCIDR: true
      prefixFilters:
        - "0.0.0.0/0"
      neighbors:
        - peerAddress: "192.168.1.2/32"
          peerASN: 65002
          eBGP:
            multihopTTL: 1
          gracefulRestart:
            enabled: false
          holdTimeSeconds: 120
          families:
            - "IPv4"
`
	policies, err := ParseCiliumBGPPeeringPolicy([]byte(vulnYAML), "vuln-policy.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	violations := AuditCiliumBGPPeeringPolicies(policies)
	// Expected violations:
	// 1. BGP-RADAR-004 (0.0.0.0/0 prefix filter)
	// 2. BGP-RADAR-001 (unauthenticated BGP peer)
	// 3. BGP-RADAR-002 (missing IPv6 family)
	// 4. BGP-RADAR-005 (eBGP multihop TTL <= 1)
	// 5. BGP-RADAR-006 (graceful restart disabled)
	// 6. BGP-RADAR-009 (holdTime 120 > 90)
	// 7. BGP-RADAR-011 (missing community tags)

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	expectedRules := []string{
		"BGP-RADAR-001",
		"BGP-RADAR-002",
		"BGP-RADAR-004",
		"BGP-RADAR-005",
		"BGP-RADAR-006",
		"BGP-RADAR-009",
		"BGP-RADAR-011",
	}

	for _, ruleID := range expectedRules {
		if !ruleMap[ruleID] {
			t.Errorf("expected violation %s not triggered", ruleID)
		}
	}
}

func TestAuditBGPTelemetry(t *testing.T) {
	tel := &BGPTelemetryReport{
		ClusterName: "prod-baremetal",
		NodeID:      "node-worker-01",
		Timestamp:   time.Now().UTC().Add(-400 * time.Second), // Stale > 300s
		Peers: []BGPPeerTelemetry{
			{
				PeerAddress:       "192.168.1.1",
				PeerASN:           65000,
				State:             StateActive, // Not established
				ResetCount:        8,           // Flapping > 5
				FlapDampingActive: true,
				LastResetReason:   "NotificationCease",
				LastUpdateSeconds: 350,
			},
		},
		IPAMPools: []IPAMPoolTelemetry{
			{
				PoolName:     "default-pool",
				CIDR:         "10.244.0.0/16",
				Family:       FamilyIPv4,
				TotalIPs:     65536,
				AllocatedIPs: 60000,
				UsagePercent: 91.5, // > 85%
			},
		},
	}

	configuredPeers := map[string]bool{"192.168.1.1": true}
	violations := AuditBGPTelemetry(tel, configuredPeers)

	ruleMap := make(map[string]bool)
	for _, v := range violations {
		ruleMap[v.RuleID] = true
	}

	if !ruleMap["BGP-RADAR-003"] {
		t.Errorf("expected BGP-RADAR-003 for IPAM usage > 85%%")
	}
	if !ruleMap["BGP-RADAR-010"] {
		t.Errorf("expected BGP-RADAR-010 for reset count > 5")
	}
	if !ruleMap["BGP-RADAR-012"] {
		t.Errorf("expected BGP-RADAR-012 for stale telemetry")
	}

	summary := ComputeBGPSummary(nil, nil, tel, violations)
	if summary.ComplianceScore > 80.0 {
		t.Errorf("expected degraded compliance score with violations, got %.1f", summary.ComplianceScore)
	}
}

func TestSynthesizeHardenedPoliciesAndWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bgp-synth-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	written, err := WriteSynthesizedPolicies(tmpDir, "test-policy", 65001, 65000, "192.168.100.1/32", "test-secret")
	if err != nil {
		t.Fatalf("unexpected error synthesizing policies: %v", err)
	}

	if len(written) != 3 {
		t.Fatalf("expected 3 files written, got %d: %+v", len(written), written)
	}

	for _, f := range written {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("failed to read synthesized file %s: %v", f, err)
		}
		if len(content) == 0 {
			t.Errorf("file %s is empty", f)
		}
	}
}

func TestBGPScanner_DirectoryWalk(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bgp-scan-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "bgp-policy.yaml")
	manifestContent := SynthesizeHardenedCiliumBGPPolicy("hardened-peering", 65001, 65000, "192.168.1.1/32", "auth-key")
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0640); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	telPath := filepath.Join(tmpDir, "telemetry.json")
	tel := &BGPTelemetryReport{
		ClusterName: "test-cluster",
		Timestamp:   time.Now().UTC(),
		Peers: []BGPPeerTelemetry{
			{
				PeerAddress:        "192.168.1.1/32",
				State:              StateEstablished,
				PrefixesReceived:   15,
				PrefixesAdvertised: 4,
			},
		},
	}
	telBytes, _ := json.Marshal(tel)
	if err := os.WriteFile(telPath, telBytes, 0640); err != nil {
		t.Fatalf("failed to write telemetry: %v", err)
	}

	scanner := NewBGPScanner()
	report, err := scanner.ScanTarget(tmpDir, telPath)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if len(report.Policies) != 1 {
		t.Errorf("expected 1 policy scanned, got %d", len(report.Policies))
	}
	if report.Telemetry == nil {
		t.Errorf("expected telemetry ingested")
	}
	if report.Summary.ComplianceScore < 90.0 {
		t.Errorf("expected high compliance score for hardened setup, got %.1f", report.Summary.ComplianceScore)
	}
}

func TestMemorySafetyBounds(t *testing.T) {
	hugeManifest := make([]byte, MaxManifestBytes+1024)
	_, err := ParseCiliumBGPPeeringPolicy(hugeManifest, "huge.yaml")
	if err == nil {
		t.Errorf("expected error for oversized manifest payload")
	}

	hugeTelemetry := make([]byte, MaxTelemetryBytes+1024)
	_, err = ParseBGPTelemetryJSON(hugeTelemetry)
	if err == nil {
		t.Errorf("expected error for oversized telemetry payload")
	}
}
