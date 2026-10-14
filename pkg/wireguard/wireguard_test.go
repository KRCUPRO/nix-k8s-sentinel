package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func sampleValidKey() string {
	raw := []byte("01234567890123456789012345678901") // exactly 32 bytes
	return base64.StdEncoding.EncodeToString(raw)
}

func sampleValidKey2() string {
	raw := []byte("abcdefghijklmnopqrstuvwxyz123456") // exactly 32 bytes
	return base64.StdEncoding.EncodeToString(raw)
}

func TestKeyRotationEngine_ValidationAndMasking(t *testing.T) {
	engine := NewKeyRotationEngine()

	// 1. Valid Key
	validKey := sampleValidKey()
	ok, err := engine.ValidateKeyFormat(validKey)
	if !ok || err != nil {
		t.Fatalf("expected valid key to pass, got err: %v", err)
	}

	// 2. Invalid length
	if ok, err := engine.ValidateKeyFormat("short"); ok || err == nil {
		t.Fatalf("expected short key to fail validation")
	}

	// 3. Degenerate all zeros
	zeroKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if ok, err := engine.ValidateKeyFormat(zeroKey); ok || err == nil {
		t.Fatalf("expected degenerate all-zero key to fail validation")
	}

	// 4. Zero secret leakage masking
	masked := engine.MaskKey(validKey)
	if strings.Contains(masked, validKey[10:20]) {
		t.Fatalf("masked key must not reveal internal characters: %s", masked)
	}
	if !strings.Contains(masked, "...") {
		t.Fatalf("masked key should contain ellipsis: %s", masked)
	}
}

func TestKeyRotationEngine_AuditKeyAge(t *testing.T) {
	engine := NewKeyRotationEngine()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	// Active key: 30 days old
	created30 := now.AddDate(0, 0, -30)
	status, days := engine.AuditKeyAge(created30, now)
	if status != KeyStatusActive || days != 30 {
		t.Fatalf("expected Active at 30 days, got %s (%d days)", status, days)
	}

	// Warning key: 65 days old
	created65 := now.AddDate(0, 0, -65)
	status, days = engine.AuditKeyAge(created65, now)
	if status != KeyStatusNeedsRotation || days != 65 {
		t.Fatalf("expected NeedsRotation at 65 days, got %s (%d days)", status, days)
	}

	// Expired key: 95 days old
	created95 := now.AddDate(0, 0, -95)
	status, days = engine.AuditKeyAge(created95, now)
	if status != KeyStatusExpired || days != 95 {
		t.Fatalf("expected Expired at 95 days, got %s (%d days)", status, days)
	}
}

func TestWireGuardScanner_DeclarativeNixScan(t *testing.T) {
	key1 := sampleValidKey()
	key2 := sampleValidKey2()

	vulnerableNix := `
networking.wireguard.interfaces.wg0 = {
  ips = [ "10.100.0.1/24" ];
  listenPort = 51820;
  privateKey = "super-secret-plaintext-key-in-nix-store";
  mtu = 1500;
  peers = [
    {
      publicKey = "` + key1 + `";
      presharedKey = "plaintext-psk-token-value-here";
      allowedIPs = [ "0.0.0.0/0" "10.100.0.2/32" ];
      endpoint = "203.0.113.10:51820";
      persistentKeepalive = 25;
    }
    {
      publicKey = "` + key2 + `";
      allowedIPs = [ "10.100.0.2/32" ];
      endpoint = "203.0.113.11:51820";
    }
  ];
};
`
	scanner := NewWireGuardScanner(nil)
	ifaces, violations, err := scanner.ScanContent(vulnerableNix, "test-wg.nix")
	if err != nil {
		t.Fatalf("unexpected error scanning nix content: %v", err)
	}

	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}

	if ifaces[0].Name != "wg0" || len(ifaces[0].Peers) != 2 {
		t.Fatalf("interface properties mismatch: %+v", ifaces[0])
	}

	ruleHits := make(map[string]bool)
	for _, v := range violations {
		ruleHits[v.RuleID] = true
	}

	// Must detect plaintext private key (WG-MESH-001)
	if !ruleHits[RuleWGPlaintextPrivateKey] {
		t.Errorf("missing expected rule hit: %s", RuleWGPlaintextPrivateKey)
	}

	// Must detect plaintext PSK (WG-MESH-003)
	if !ruleHits[RuleWGPlaintextPSK] {
		t.Errorf("missing expected rule hit: %s", RuleWGPlaintextPSK)
	}

	// Must detect missing PSK on peer 2 (WG-MESH-002)
	if !ruleHits[RuleWGMpyMissingPSK] {
		t.Errorf("missing expected rule hit: %s", RuleWGMpyMissingPSK)
	}

	// Must detect 0.0.0.0/0 allowedIPs (WG-MESH-004)
	if !ruleHits[RuleWGPermissiveAllowedIPs] {
		t.Errorf("missing expected rule hit: %s", RuleWGPermissiveAllowedIPs)
	}

	// Must detect allowedIPs collision on 10.100.0.2/32 (WG-MESH-005)
	if !ruleHits[RuleWGAllowedIPsOverlap] {
		t.Errorf("missing expected rule hit: %s", RuleWGAllowedIPsOverlap)
	}

	// Must detect suboptimal MTU (WG-MESH-011)
	if !ruleHits[RuleWGSuboptimalMTU] {
		t.Errorf("missing expected rule hit: %s", RuleWGSuboptimalMTU)
	}
}

func TestWireGuardScanner_HardenedNixScan(t *testing.T) {
	key1 := sampleValidKey()
	hardenedNix := `
networking.wireguard.interfaces.wg0 = {
  ips = [ "10.100.0.1/24" ];
  listenPort = 51820;
  privateKeyFile = "/run/keys/wg0.key";
  mtu = 1420;
  peers = [
    {
      publicKey = "` + key1 + `";
      presharedKeyFile = "/run/keys/wg0-peer1.psk";
      allowedIPs = [ "10.100.0.2/32" ];
      endpoint = "198.51.100.5:51820";
      persistentKeepalive = 25;
    }
  ];
};
`
	scanner := NewWireGuardScanner(nil)
	ifaces, violations, err := scanner.ScanContent(hardenedNix, "hardened.nix")
	if err != nil {
		t.Fatalf("unexpected error scanning hardened nix content: %v", err)
	}

	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}

	criticalOrHighViolations := 0
	for _, v := range violations {
		if v.Severity == intel.SeverityCritical || v.Severity == intel.SeverityHigh {
			criticalOrHighViolations++
		}
	}

	if criticalOrHighViolations > 0 {
		t.Fatalf("hardened config should have zero Critical or High violations, got %d: %+v", criticalOrHighViolations, violations)
	}
}

func TestWireGuardReconciler_RuntimePostureAndDrift(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	keyDecl := sampleValidKey()
	keyUnmanaged := sampleValidKey2()

	declared := []InterfaceDeclaration{
		{
			Name: "wg0",
			Peers: []PeerDeclaration{
				{
					PublicKey: keyDecl,
					Endpoint:  "192.0.2.1:51820",
				},
			},
		},
	}

	runtime := []RuntimeInterfaceTelemetry{
		{
			InterfaceName: "wg0",
			Peers: []RuntimePeerTelemetry{
				{
					PublicKey:           keyDecl,
					PresharedKeyPresent: true,
					Endpoint:            "192.0.2.1:51820",
					LatestHandshake:     now.Add(-48 * time.Hour), // Stale > 24h
					KeyCreatedAt:        now.AddDate(0, 0, -100),  // Expired > 90d
				},
				{
					PublicKey:           keyUnmanaged,
					PresharedKeyPresent: false, // Missing PSK
					Endpoint:            "192.0.2.99:51820",
					LatestHandshake:     now.Add(-2 * time.Minute),
					KeyCreatedAt:        now.AddDate(0, 0, -10),
				},
			},
		},
	}

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-31048",
				Title:       "WireGuard Overlay Subnet Route Collision",
				Component:   "wireguard",
				Target:      "nixos",
				Description: "Known vulnerable peer at 192.0.2.99:51820",
				Severity:    intel.SeverityHigh,
				CVSSScore:   8.5,
			},
		},
	}

	reconciler := NewReconciler(feed)
	rep := reconciler.Reconcile(declared, runtime, now)

	if rep.RuntimePeersCount != 2 {
		t.Fatalf("expected 2 runtime peers, got %d", rep.RuntimePeersCount)
	}

	if rep.UnmanagedPeersCount != 1 {
		t.Errorf("expected 1 unmanaged peer, got %d", rep.UnmanagedPeersCount)
	}

	if rep.StaleHandshakeCount != 1 {
		t.Errorf("expected 1 stale handshake, got %d", rep.StaleHandshakeCount)
	}

	if rep.KeyRotation.ExpiredKeys != 1 {
		t.Errorf("expected 1 expired key, got %d", rep.KeyRotation.ExpiredKeys)
	}

	ruleHits := make(map[string]bool)
	for _, v := range rep.Violations {
		ruleHits[v.RuleID] = true
	}

	if !ruleHits[RuleWGKeyExpired] {
		t.Errorf("expected key expired violation %s", RuleWGKeyExpired)
	}

	if !ruleHits[RuleWGStaleHandshake] {
		t.Errorf("expected stale handshake violation %s", RuleWGStaleHandshake)
	}

	if !ruleHits[RuleWGThreatRadarMatch] {
		t.Errorf("expected threat radar match %s", RuleWGThreatRadarMatch)
	}
}
