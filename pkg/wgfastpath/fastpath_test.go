package wgfastpath

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestRuleCatalogIntegrity(t *testing.T) {
	if len(CanonicalRuleCatalog) != 12 {
		t.Fatalf("expected 12 canonical rules, got %d", len(CanonicalRuleCatalog))
	}

	seen := make(map[string]bool)
	for _, rule := range CanonicalRuleCatalog {
		if rule.ID == "" {
			t.Error("rule ID must not be empty")
		}
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seen[rule.ID] = true

		if rule.Title == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has empty metadata fields", rule.ID)
		}
		if rule.CVSSScore <= 0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %.1f", rule.ID, rule.CVSSScore)
		}

		r, found := GetRuleByID(rule.ID)
		if !found || r.ID != rule.ID {
			t.Errorf("GetRuleByID failed for %s", rule.ID)
		}
	}

	_, found := GetRuleByID("NON_EXISTENT")
	if found {
		t.Error("expected GetRuleByID to return false for non-existent rule")
	}
}

func TestParseNixOSFastPathManifest(t *testing.T) {
	content := `
{
  networking.wireguard.interfaces.wg0 = {
    mtu = 1420;
    fastpath.enable = true;
    fastpath.mode = "native_xdp";
    cryptoVector = "AVX512";
    ringBufferSize = 4096;
    hardwareOffload = true;
    queueCount = 16;
    xdpDriver = "mlx5_core";
  };
}
`
	tmpFile := filepath.Join(t.TempDir(), "nixos-wg.nix")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write tmp nixos manifest: %v", err)
	}

	cfgs, err := ParseFastPathManifest(tmpFile)
	if err != nil {
		t.Fatalf("ParseFastPathManifest failed: %v", err)
	}

	if len(cfgs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(cfgs))
	}

	cfg := cfgs[0]
	if cfg.InterfaceName != "wg0" {
		t.Errorf("expected wg0, got %s", cfg.InterfaceName)
	}
	if cfg.MTU != 1420 {
		t.Errorf("expected MTU 1420, got %d", cfg.MTU)
	}
	if cfg.FastPathMode != ModeNativeXDP {
		t.Errorf("expected ModeNativeXDP, got %s", cfg.FastPathMode)
	}
	if cfg.CryptoVector != VectorAVX512 {
		t.Errorf("expected VectorAVX512, got %s", cfg.CryptoVector)
	}
	if cfg.RingBufferSize != 4096 {
		t.Errorf("expected RingBufferSize 4096, got %d", cfg.RingBufferSize)
	}
	if !cfg.HardwareOffload {
		t.Error("expected HardwareOffload true")
	}
	if cfg.QueueCount != 16 {
		t.Errorf("expected QueueCount 16, got %d", cfg.QueueCount)
	}
}

func TestParseK8sFastPathManifest(t *testing.T) {
	content := `
apiVersion: cilium.io/v2
kind: CiliumWireGuardFastPath
metadata:
  name: wg-k8s
spec:
  interfaceName: wg-mesh
  mtu: 8920
  fastPathMode: "OFFLOAD_XDP"
  cryptoVector: "ARM_NEON"
  ringBufferSize: 8192
  queueCount: 8
  hardwareOffload: true
  xdpDriver: "nfp"
`
	tmpFile := filepath.Join(t.TempDir(), "k8s-wg.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write tmp k8s manifest: %v", err)
	}

	cfgs, err := ParseFastPathManifest(tmpFile)
	if err != nil {
		t.Fatalf("ParseFastPathManifest failed: %v", err)
	}

	if len(cfgs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(cfgs))
	}

	cfg := cfgs[0]
	if cfg.InterfaceName != "wg-mesh" {
		t.Errorf("expected wg-mesh, got %s", cfg.InterfaceName)
	}
	if cfg.MTU != 8920 {
		t.Errorf("expected MTU 8920, got %d", cfg.MTU)
	}
	if cfg.FastPathMode != ModeOffloadXDP {
		t.Errorf("expected ModeOffloadXDP, got %s", cfg.FastPathMode)
	}
	if cfg.CryptoVector != VectorARMNeon {
		t.Errorf("expected VectorARMNeon, got %s", cfg.CryptoVector)
	}
}

func TestParseFastPathTelemetry(t *testing.T) {
	data := map[string]interface{}{
		"telemetry": []map[string]interface{}{
			{
				"interface_name":            "wg0",
				"rx_packets_per_sec":        12500000.0,
				"tx_packets_per_sec":        11800000.0,
				"rx_drops_per_sec":          0.0,
				"tx_drops_per_sec":          0.0,
				"ring_buffer_util_percent":  42.5,
				"xdp_aborted_drops":         0,
				"memory_alloc_failures":     0,
				"softirq_cpu_percent":       35.2,
				"active_peers":              64,
			},
		},
		"crypto_benchmarks": []map[string]interface{}{
			{
				"vector_engine":        "AVX512",
				"chunk_size_bytes":     65536,
				"cycles_per_byte":      0.45,
				"gbps_throughput":      85.4,
				"simd_register_width": 512,
				"thermal_throttled":    false,
				"context_switch_ns":    45.0,
			},
		},
	}

	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "telemetry.json")
	if err := os.WriteFile(tmpFile, raw, 0644); err != nil {
		t.Fatalf("failed to write tmp telemetry: %v", err)
	}

	telemetry, crypto, err := ParseFastPathTelemetry(tmpFile)
	if err != nil {
		t.Fatalf("ParseFastPathTelemetry failed: %v", err)
	}

	if len(telemetry) != 1 {
		t.Fatalf("expected 1 telemetry item, got %d", len(telemetry))
	}
	if len(crypto) != 1 {
		t.Fatalf("expected 1 crypto item, got %d", len(crypto))
	}

	if telemetry[0].InterfaceName != "wg0" || telemetry[0].RingBufferUtilPercent != 42.5 {
		t.Errorf("unexpected telemetry values: %+v", telemetry[0])
	}
	if crypto[0].VectorEngine != VectorAVX512 || crypto[0].GbpsThroughput != 85.4 {
		t.Errorf("unexpected crypto values: %+v", crypto[0])
	}
}

func TestAuditFastPathCompliant(t *testing.T) {
	configs := []WireGuardInterfaceFastPathConfig{
		{
			InterfaceName:   "wg0",
			MTU:             1420,
			FastPathMode:    ModeNativeXDP,
			RingBufferSize:  4096,
			HardwareOffload: true,
			QueueCount:      16,
			CryptoVector:    VectorAVX512,
		},
	}

	telemetry := []FastPathTelemetry{
		{
			InterfaceName:         "wg0",
			RXPacketsPerSec:       10000000.0,
			TXPacketsPerSec:       10000000.0,
			RXDropsPerSec:         0.0,
			TXDropsPerSec:         0.0,
			RingBufferUtilPercent: 40.0,
			XDPAbortedDrops:       0,
			MemoryAllocFailures:   0,
			SoftIRQCpuPercent:     30.0,
			ActivePeers:           32,
		},
	}

	crypto := []CryptoBenchmarkTelemetry{
		{
			VectorEngine:      VectorAVX512,
			ChunkSizeBytes:    65536,
			GbpsThroughput:    92.0,
			ThermalThrottled:  false,
			ContextSwitchNs:   50.0,
		},
	}

	violations, summary := AuditFastPath(configs, telemetry, crypto, false, nil)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for compliant setup, got %d: %s", len(violations), FormatViolationSummary(violations))
	}

	if summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score, got %.1f", summary.ComplianceScore)
	}
	if !summary.AVX512Accelerated {
		t.Error("expected AVX512Accelerated to be true")
	}
}

func TestAuditFastPathVulnerabilitiesAndThreatFeed(t *testing.T) {
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-31049",
				Title:     "WireGuard 100GbE Kernel Ring Buffer Saturation",
				Severity:  "HIGH",
				CVSSScore: 8.1,
			},
		},
	}

	configs := []WireGuardInterfaceFastPathConfig{
		{
			InterfaceName:   "wg-vuln",
			MTU:             1500, // Non-standard MTU (WG-FAST-007)
			FastPathMode:    ModeNone, // Missing XDP (WG-FAST-002)
			RingBufferSize:  512,
			HardwareOffload: false, // Offload disabled (WG-FAST-005)
			QueueCount:      1,     // Low queue count (WG-FAST-010)
			CryptoVector:    VectorScalar, // Scalar fallback (WG-FAST-001)
		},
	}

	telemetry := []FastPathTelemetry{
		{
			InterfaceName:         "wg-vuln",
			RXDropsPerSec:         800.0,
			TXDropsPerSec:         500.0, // Drops > 1000 (WG-FAST-004)
			RingBufferUtilPercent: 92.5,  // Ring buffer > 85% (WG-FAST-003, CVE-2026-31049)
			XDPAbortedDrops:       12,    // XDP Aborted (WG-FAST-008)
			MemoryAllocFailures:   4,     // Alloc failures (WG-FAST-011)
			SoftIRQCpuPercent:     85.0,  // SoftIRQ > 70% (WG-FAST-006)
		},
	}

	crypto := []CryptoBenchmarkTelemetry{
		{
			VectorEngine:      VectorScalar,
			ContextSwitchNs:   320.0, // Latency > 250ns (WG-FAST-009)
			ThermalThrottled:  true,  // Thermal throttling (WG-FAST-012)
		},
	}

	violations, summary := AuditFastPath(configs, telemetry, crypto, false, feed)

	if len(violations) != 12 {
		t.Fatalf("expected all 12 rules to trigger, got %d violations", len(violations))
	}

	// Verify threat feed match on WG-FAST-003
	var foundThreatMatch bool
	for _, v := range violations {
		if v.RuleID == "WG-FAST-003" && strings.Contains(v.Description, "CVE-2026-31049") {
			foundThreatMatch = true
			break
		}
	}
	if !foundThreatMatch {
		t.Error("expected threat feed match for CVE-2026-31049 on WG-FAST-003")
	}

	if summary.ComplianceScore > 0.0 {
		t.Logf("compliance score heavily degraded to: %.1f", summary.ComplianceScore)
	}
	if len(summary.BottleneckInterfaces) == 0 {
		t.Error("expected bottleneck interfaces to be populated")
	}
}

func TestPolicySynthesizers(t *testing.T) {
	cfg := WireGuardInterfaceFastPathConfig{
		InterfaceName:  "wg-test",
		MTU:            1420,
		RingBufferSize: 4096,
	}

	nixMod := SynthesizeNixOSFastPathModule(cfg)
	if !strings.Contains(nixMod, "wireguard.crypto=avx512") || !strings.Contains(nixMod, "rx 4096 tx 4096") {
		t.Errorf("SynthesizeNixOSFastPathModule missing expected config:\n%s", nixMod)
	}

	bpfProg := SynthesizeEBPFXDPProgram("wg-test")
	if !strings.Contains(bpfProg, "SEC(\"xdp\")") || !strings.Contains(bpfProg, "WG_PORT 51820") {
		t.Errorf("SynthesizeEBPFXDPProgram missing expected BPF markers:\n%s", bpfProg)
	}

	k8sCfg := SynthesizeK8sFastPathConfig("wg-test", 1420, 4096)
	if !strings.Contains(k8sCfg, "kind: CiliumNodeConfig") || !strings.Contains(k8sCfg, "fastPathMode: NATIVE_XDP") {
		t.Errorf("SynthesizeK8sFastPathConfig missing expected fields:\n%s", k8sCfg)
	}

	outDir := filepath.Join(t.TempDir(), "synth_out")
	if err := WriteSynthesizedPolicies(outDir, cfg); err != nil {
		t.Fatalf("WriteSynthesizedPolicies failed: %v", err)
	}

	expectedFiles := []string{"wg-fastpath-hardened.nix", "wg_fastpath_xdp.bpf.c", "wg-fastpath-k8s.yaml"}
	for _, f := range expectedFiles {
		p := filepath.Join(outDir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("expected synthesized file %s to exist", f)
		}
	}
}

func TestScanFastPath(t *testing.T) {
	tmpDir := t.TempDir()
	nixFile := filepath.Join(tmpDir, "fastpath.nix")
	nixContent := `
{
  networking.wireguard.interfaces.wg0 = {
    mtu = 1420;
    fastpath.enable = true;
    fastpath.mode = "native_xdp";
    cryptoVector = "AVX512";
    ringBufferSize = 4096;
    hardwareOffload = true;
    queueCount = 16;
  };
}
`
	if err := os.WriteFile(nixFile, []byte(nixContent), 0644); err != nil {
		t.Fatalf("failed to write nix file: %v", err)
	}

	report, err := ScanFastPath(tmpDir, "", false, nil)
	if err != nil {
		t.Fatalf("ScanFastPath failed: %v", err)
	}

	if len(report.Configurations) != 1 {
		t.Fatalf("expected 1 config, got %d", len(report.Configurations))
	}
	if report.Summary.ComplianceScore != 100.0 {
		t.Errorf("expected compliance score 100.0, got %.1f", report.Summary.ComplianceScore)
	}
}
