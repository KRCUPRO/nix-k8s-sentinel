package wgenclave

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestRulesCatalog(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical rules, found %d", len(rules))
	}

	for _, ruleID := range []string{"WG-ENC-001", "WG-ENC-004", "WG-ENC-005", "WG-ENC-006"} {
		rule, found := GetRule(ruleID)
		if !found {
			t.Errorf("missing expected rule %s", ruleID)
		}
		if rule.Severity != intel.SeverityCritical {
			t.Errorf("rule %s expected CRITICAL, got %s", ruleID, rule.Severity)
		}
		if rule.CVSSScore < 9.0 {
			t.Errorf("rule %s expected CVSS >= 9.0, got %.1f", ruleID, rule.CVSSScore)
		}
	}
}

func TestParseNixOSEnclavePeer(t *testing.T) {
	nixContent := `
{ config, pkgs, ... }:
{
  networking.wireguard.interfaces.wg0 = {
    peers = [
      {
        # peer: confidential-worker-01
        publicKey = "K3vL8zP8sY4w8Qv8K3vL8zP8sY4w8Qv8K3vL8zP8sY4=";
        endpoint = "192.168.1.50:51820";
        enclave.platform = "AMD_SEV_SNP";
        enclave.minTcbSvn = 4;
        enclave.requireHardwareRoot = true;
        enclave.requireSessionKeyBinding = true;
        enclave.allowDebug = false;
        enclave.goldenImageDigest = "a1b2c3d4e5f6";
        enclave.pcrs."0" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        enclave.pcrs."2" = "f4c1d2e3";
      }
    ];
  };
}
`
	peers, err := ParseNixOSEnclavePeerBytes([]byte(nixContent), "test-nixos.nix")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	p := peers[0]
	if p.PeerName != "confidential-worker-01" {
		t.Errorf("expected peer name confidential-worker-01, got %s", p.PeerName)
	}
	if p.Platform != PlatformSEVSNP {
		t.Errorf("expected platform AMD_SEV_SNP, got %s", p.Platform)
	}
	if !p.RequireHardwareRoot || !p.SessionKeyBinding || p.AllowDebug {
		t.Errorf("flags mismatch: hw=%t session=%t debug=%t", p.RequireHardwareRoot, p.SessionKeyBinding, p.AllowDebug)
	}
	if p.RequiredPCRs[0] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("PCR 0 mismatch: %s", p.RequiredPCRs[0])
	}
}

func TestParseK8sEnclavePeerConfig(t *testing.T) {
	k8sYAML := `
apiVersion: security.nixos.k8s.io/v1alpha1
kind: EnclaveWireGuardPeer
metadata:
  name: tdx-peer-node
spec:
  interfaceName: "wg-mesh"
  peerName: "tdx-peer-node"
  publicKey: "intelTDXPubkey1234567890="
  endpoint: "10.0.0.12:51820"
  platform: "INTEL_TDX"
  minTcbSvn: 5
  requireHardwareRoot: true
  sessionKeyBinding: true
  allowDebug: false
  goldenImageDigest: "sha256:778899aabbcc"
  requiredPCRs:
    "0": "11223344"
    "7": "55667788"
  requiredRTMRs:
    "0": "aabbccdd"
`
	peers, err := ParseK8sEnclavePeerBytes([]byte(k8sYAML), "test-k8s.yaml")
	if err != nil {
		t.Fatalf("unexpected k8s parse error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	p := peers[0]
	if p.PeerName != "tdx-peer-node" || p.Platform != PlatformTDX || p.MinTCBSVN != 5 {
		t.Errorf("parsed fields mismatch: name=%s, platform=%s, svn=%d", p.PeerName, p.Platform, p.MinTCBSVN)
	}
	if p.RequiredPCRs[7] != "55667788" || p.RequiredRTMRs[0] != "aabbccdd" {
		t.Errorf("measurements mismatch: pcr7=%s, rtmr0=%s", p.RequiredPCRs[7], p.RequiredRTMRs[0])
	}
}

func TestAuditorViolationsAndPCRDeviation(t *testing.T) {
	now := time.Now()
	cfg := EnclavePeerConfig{
		InterfaceName:       "wg0",
		PeerName:            "vulnerable-peer",
		PublicKey:           "pubkey1",
		Platform:            PlatformSEVSNP,
		MinTCBSVN:           4,
		RequireHardwareRoot: true,
		SessionKeyBinding:   true,
		AllowDebug:          true, // Violation WG-ENC-006
		RequiredPCRs: map[int]string{
			0: "golden-pcr-0",
			2: "golden-pcr-2",
		},
	}

	var violations []WGEnclaveViolation
	AuditEnclavePeerConfig(cfg, &violations)

	hasDebugViolation := false
	for _, v := range violations {
		if v.RuleID == "WG-ENC-006" {
			hasDebugViolation = true
		}
	}
	if !hasDebugViolation {
		t.Errorf("expected WG-ENC-006 violation for AllowDebug=true")
	}

	// Runtime attestation report with PCR deviation and expired report age
	report := AttestationReport{
		ReportID:           "rep-001",
		Platform:           PlatformSEVSNP,
		NodeID:             "vulnerable-peer",
		PeerPublicKey:      "pubkey1",
		ReportDataHash:     "hash-bound-key",
		TCBSVN:             4,
		DebugAllowed:       true,
		VCEKCertChainValid: false, // Violation WG-ENC-002
		Timestamp:          now.Add(-2 * time.Hour), // Violation WG-ENC-007
		MeasuredPCRs: map[int]string{
			0: "deviated-pcr-0", // Violation WG-ENC-004
			2: "golden-pcr-2",
		},
	}

	summary := WGEnclaveSummary{}
	AuditAttestationReport(report, &cfg, now, &violations, &summary)

	if summary.PCRDeviationsDetected != 1 {
		t.Errorf("expected 1 PCR deviation, got %d", summary.PCRDeviationsDetected)
	}

	ruleHits := make(map[string]bool)
	for _, v := range violations {
		ruleHits[v.RuleID] = true
	}

	for _, expectedRule := range []string{"WG-ENC-002", "WG-ENC-004", "WG-ENC-006", "WG-ENC-007"} {
		if !ruleHits[expectedRule] {
			t.Errorf("expected rule %s to be triggered in audit", expectedRule)
		}
	}
}

func TestReconcilePeerTunnels(t *testing.T) {
	now := time.Now()
	peers := []PeerTunnelStatus{
		{
			InterfaceName:        "wg0",
			PeerName:             "valid-peer",
			PeerPublicKey:        "key-valid",
			TunnelState:          TunnelEstablished,
			ActiveSessionKeyHash: "session-hash-1",
			BoundReportID:        "rep-valid",
		},
		{
			InterfaceName:        "wg0",
			PeerName:             "rogue-peer",
			PeerPublicKey:        "key-rogue",
			TunnelState:          TunnelEstablished,
			ActiveSessionKeyHash: "session-hash-unbound",
			BoundReportID:        "", // Missing report
		},
	}

	reports := []AttestationReport{
		{
			ReportID:           "rep-valid",
			Platform:           PlatformSEVSNP,
			NodeID:             "valid-peer",
			PeerPublicKey:      "key-valid",
			ReportDataHash:     "session-hash-1",
			TCBSVN:             4,
			VCEKCertChainValid: true,
			Timestamp:          now.Add(-5 * time.Minute),
		},
	}

	configs := []EnclavePeerConfig{
		{
			PeerName:          "valid-peer",
			PublicKey:         "key-valid",
			Platform:          PlatformSEVSNP,
			SessionKeyBinding: true,
		},
		{
			PeerName:          "rogue-peer",
			PublicKey:         "key-rogue",
			Platform:          PlatformTPM,
			SessionKeyBinding: false,
		},
	}

	var violations []WGEnclaveViolation
	summary := WGEnclaveSummary{}

	reconciled := ReconcilePeerTunnels(peers, reports, configs, now, &violations, &summary)

	if len(reconciled) != 2 {
		t.Fatalf("expected 2 reconciled peers, got %d", len(reconciled))
	}

	if reconciled[0].TunnelState != TunnelEstablished || !reconciled[0].AttestationValid {
		t.Errorf("expected valid-peer to remain ESTABLISHED, got %s (valid=%t)", reconciled[0].TunnelState, reconciled[0].AttestationValid)
	}

	if reconciled[1].TunnelState != TunnelRejected {
		t.Errorf("expected rogue-peer to be REJECTED, got %s", reconciled[1].TunnelState)
	}
	if summary.RejectedPeers != 1 {
		t.Errorf("expected 1 rejected peer, got %d", summary.RejectedPeers)
	}
}

func TestSynthesizeAndWritePolicies(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wgenclave-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := EnclavePeerConfig{
		InterfaceName:       "wg-conf",
		PeerName:            "enclave-node-01",
		PublicKey:           "dGVzdHB1YmtleTEyMzQ1Njc4OTA=",
		Endpoint:            "10.10.10.50:51820",
		Platform:            PlatformSEVSNP,
		MinTCBSVN:           4,
		RequireHardwareRoot: true,
		SessionKeyBinding:   true,
		GoldenImageDigest:   "sha256:abc12345",
		RequiredPCRs: map[int]string{
			0: "hash0",
			2: "hash2",
			4: "hash4",
			7: "hash7",
		},
	}

	err = WriteSynthesizedPolicies(tempDir, cfg)
	if err != nil {
		t.Fatalf("WriteSynthesizedPolicies failed: %v", err)
	}

	for _, f := range []string{"wg-enclave-hardened.nix", "enclave-wireguard-peer.yaml", "wg-enclave-gate.sh"} {
		path := filepath.Join(tempDir, f)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("expected file %s to exist: %v", f, err)
		}
		if len(data) == 0 {
			t.Errorf("file %s is empty", f)
		}
	}
}

func TestMemoryBoundsEnforcement(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wgenclave-bounds-*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tempDir)

	oversizedFile := filepath.Join(tempDir, "oversized.json")
	// Write dummy data larger than MaxTelemetryBytes (5MB + 1KB)
	oversizedBytes := make([]byte, MaxTelemetryBytes+1024)
	if err := os.WriteFile(oversizedFile, oversizedBytes, 0o644); err != nil {
		t.Fatalf("failed to write oversized file: %v", err)
	}

	_, err = ParseEnclaveTelemetryJSON(oversizedFile)
	if err == nil {
		t.Errorf("expected error parsing oversized telemetry file, got nil")
	} else if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected 'exceeds maximum size' error, got %v", err)
	}
}
