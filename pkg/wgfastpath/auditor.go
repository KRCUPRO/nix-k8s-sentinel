package wgfastpath

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditFastPath executes static and telemetry-driven security audits over WireGuard fast-path configurations.
func AuditFastPath(
	configs []WireGuardInterfaceFastPathConfig,
	telemetry []FastPathTelemetry,
	cryptoTelemetry []CryptoBenchmarkTelemetry,
	strictMode bool,
	feed *intel.Feed,
) ([]WGFastPathViolation, WGFastPathSummary) {
	var violations []WGFastPathViolation
	bottlenecks := make(map[string]bool)
	avx512Active := false
	armNeonActive := false

	// Map feed CVEs for rapid lookup
	feedCVEs := make(map[string]intel.ThreatItem)
	if feed != nil {
		for _, item := range feed.Items {
			feedCVEs[item.ID] = item
		}
	}

	addViolation := func(ruleID, ifaceName, descExtra string, filePath string, startLine int) {
		rule, ok := GetRuleByID(ruleID)
		if !ok {
			return
		}

		desc := rule.Description
		if descExtra != "" {
			desc = fmt.Sprintf("%s (%s)", rule.Description, descExtra)
		}

		matchedCVE := rule.MatchedCVE
		if matchedCVE != "" {
			if threat, exists := feedCVEs[matchedCVE]; exists {
				desc = fmt.Sprintf("%s [Threat Feed Match: %s - %s]", desc, threat.ID, threat.Title)
			}
		}

		v := WGFastPathViolation{
			RuleID:        rule.ID,
			InterfaceName: ifaceName,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.CVSSScore,
			Description:   desc,
			Remediation:   rule.Remediation,
			MatchedCVE:    matchedCVE,
			FilePath:      filePath,
			StartLine:     startLine,
		}
		violations = append(violations, v)
		if ifaceName != "" {
			bottlenecks[ifaceName] = true
		}
	}

	// 1. Audit Declarative Configurations
	for _, cfg := range configs {
		if cfg.CryptoVector == VectorAVX512 {
			avx512Active = true
		} else if cfg.CryptoVector == VectorARMNeon {
			armNeonActive = true
		}

		// WG-FAST-001: Scalar Fallback
		if cfg.CryptoVector == VectorScalar {
			addViolation("WG-FAST-001", cfg.InterfaceName, "configured with generic scalar crypto vector", cfg.FilePath, cfg.StartLine)
		}

		// WG-FAST-002: Missing Native XDP / FastPath
		if cfg.FastPathMode == ModeNone || cfg.FastPathMode == "" {
			addViolation("WG-FAST-002", cfg.InterfaceName, "operating in standard kernel socket mode without fastpath", cfg.FilePath, cfg.StartLine)
		}

		// WG-FAST-005: Hardware Offload Disabled
		if !cfg.HardwareOffload {
			addViolation("WG-FAST-005", cfg.InterfaceName, "GRO/GSO hardware offload disabled", cfg.FilePath, cfg.StartLine)
		}

		// WG-FAST-007: MTU Mismatch
		if cfg.MTU != 1420 && cfg.MTU != 8920 {
			addViolation("WG-FAST-007", cfg.InterfaceName, fmt.Sprintf("MTU is %d (expected 1420 or 8920)", cfg.MTU), cfg.FilePath, cfg.StartLine)
		}

		// WG-FAST-010: Low Queue Count (< 4)
		if cfg.QueueCount < 4 {
			addViolation("WG-FAST-010", cfg.InterfaceName, fmt.Sprintf("queue count is %d (minimum recommended is 4)", cfg.QueueCount), cfg.FilePath, cfg.StartLine)
		}
	}

	// 2. Audit Fast-Path Telemetry
	for _, t := range telemetry {
		// WG-FAST-003: Ring Buffer Saturation
		if t.RingBufferUtilPercent >= CriticalRingBufferSaturation {
			addViolation("WG-FAST-003", t.InterfaceName, fmt.Sprintf("ring buffer utilization at %.1f%%", t.RingBufferUtilPercent), "", 0)
		}

		// WG-FAST-004: Excessive Packet Drops
		totalDrops := t.RXDropsPerSec + t.TXDropsPerSec
		if totalDrops >= MaxAllowedPacketDropRate || (strictMode && totalDrops > 0) {
			addViolation("WG-FAST-004", t.InterfaceName, fmt.Sprintf("packet drop rate is %.1f drops/sec (RX: %.1f, TX: %.1f)", totalDrops, t.RXDropsPerSec, t.TXDropsPerSec), "", 0)
		}

		// WG-FAST-006: SoftIRQ Starvation
		if t.SoftIRQCpuPercent >= MaxSoftIRQPercent {
			addViolation("WG-FAST-006", t.InterfaceName, fmt.Sprintf("softIRQ utilization at %.1f%%", t.SoftIRQCpuPercent), "", 0)
		}

		// WG-FAST-008: XDP Aborted Exceptions
		if t.XDPAbortedDrops > 0 {
			addViolation("WG-FAST-008", t.InterfaceName, fmt.Sprintf("detected %d XDP_ABORTED frame drops", t.XDPAbortedDrops), "", 0)
		}

		// WG-FAST-011: Memory Allocation Failures
		if t.MemoryAllocFailures > 0 {
			addViolation("WG-FAST-011", t.InterfaceName, fmt.Sprintf("detected %d kernel socket buffer allocation failures", t.MemoryAllocFailures), "", 0)
		}
	}

	// 3. Audit Cryptographic Benchmarks
	for _, cb := range cryptoTelemetry {
		if cb.VectorEngine == VectorAVX512 {
			avx512Active = true
		} else if cb.VectorEngine == VectorARMNeon {
			armNeonActive = true
		}

		// WG-FAST-009: SIMD Context Switch Latency Spike
		if cb.ContextSwitchNs > MaxContextSwitchLatencyNs {
			addViolation("WG-FAST-009", "kernel-crypto", fmt.Sprintf("FPU context switch latency is %.1fns (limit: %.1fns)", cb.ContextSwitchNs, MaxContextSwitchLatencyNs), "", 0)
		}

		// WG-FAST-012: Thermal Throttling
		if cb.ThermalThrottled {
			addViolation("WG-FAST-012", "cpu-simd", "thermal throttling active on AVX-512 execution units", "", 0)
		}
	}

	// Compile summary
	summary := WGFastPathSummary{
		TotalInterfacesAudited: len(configs),
		TotalTelemetrySamples:  len(telemetry) + len(cryptoTelemetry),
		ViolationsCount:        len(violations),
		AVX512Accelerated:      avx512Active,
		ARMNeonAccelerated:     armNeonActive,
	}

	penalty := 0.0
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
			penalty += 25.0
		case intel.SeverityHigh:
			summary.HighCount++
			penalty += 15.0
		case intel.SeverityMedium:
			summary.MediumCount++
			penalty += 8.0
		case intel.SeverityLow:
			summary.LowCount++
			penalty += 3.0
		}
	}

	for iface := range bottlenecks {
		if iface != "" {
			summary.BottleneckInterfaces = append(summary.BottleneckInterfaces, iface)
		}
	}

	rawScore := 100.0 - penalty
	if rawScore < 0.0 {
		rawScore = 0.0
	}
	summary.ComplianceScore = math.Round(rawScore*10.0) / 10.0

	return violations, summary
}

// FormatViolationSummary formats a human-readable summary of violations.
func FormatViolationSummary(violations []WGFastPathViolation) string {
	if len(violations) == 0 {
		return "Zero fast-path or cryptographic performance violations detected."
	}

	var sb strings.Builder
	for i, v := range violations {
		sb.WriteString(fmt.Sprintf("[%d] %s (%s) on %s - %s [CVSS: %.1f]\n",
			i+1, v.RuleID, v.Severity, v.InterfaceName, v.Title, v.CVSSScore))
		sb.WriteString(fmt.Sprintf("    Details: %s\n", v.Description))
		sb.WriteString(fmt.Sprintf("    Remediation: %s\n", v.Remediation))
	}
	return sb.String()
}
