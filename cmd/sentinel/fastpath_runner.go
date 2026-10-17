package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgfastpath"
)

// runFastPathAudit coordinates WireGuard eBPF fast-path and cryptographic performance auditing.
func runFastPathAudit(
	manifestPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]wgfastpath.WGFastPathViolation, *wgfastpath.WGFastPathSummary, []wgfastpath.FastPathTelemetry, []wgfastpath.CryptoBenchmarkTelemetry) {
	if manifestPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil, nil
	}

	report, err := wgfastpath.ScanFastPath(manifestPath, telemetryPath, strictMode, feed)
	if err != nil {
		logErr("[-] Failed to audit WireGuard fast-path manifests/telemetry: %v\n", err)
		os.Exit(1)
	}

	if manifestPath != "" {
		logInfo("[+] Audited WireGuard Fast-Path Manifests: %s (%d interfaces scanned)\n", manifestPath, len(report.Configurations))
	}

	if telemetryPath != "" {
		logInfo("[+] Reconciled WireGuard Fast-Path & Crypto Telemetry: %s (%d telemetry samples)\n", telemetryPath, len(report.Telemetry)+len(report.CryptoTelemetry))
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d WireGuard fast-path & cryptographic performance violations:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.InterfaceName, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero WireGuard fast-path or cryptographic performance violations detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened WireGuard Fast-Path & eBPF XDP Policies into: %s\n", synthOut)
		defaultCfg := wgfastpath.WireGuardInterfaceFastPathConfig{
			InterfaceName:   "wg0",
			MTU:             1420,
			FastPathMode:    wgfastpath.ModeNativeXDP,
			RingBufferSize:  4096,
			HardwareOffload: true,
			QueueCount:      16,
			CryptoVector:    wgfastpath.VectorAVX512,
		}
		if len(report.Configurations) > 0 {
			defaultCfg = report.Configurations[0]
			defaultCfg.FastPathMode = wgfastpath.ModeNativeXDP
			defaultCfg.CryptoVector = wgfastpath.VectorAVX512
			defaultCfg.HardwareOffload = true
			if defaultCfg.RingBufferSize < 4096 {
				defaultCfg.RingBufferSize = 4096
			}
			if defaultCfg.MTU != 1420 && defaultCfg.MTU != 8920 {
				defaultCfg.MTU = 1420
			}
		}

		if err := wgfastpath.WriteSynthesizedPolicies(synthOut, defaultCfg); err != nil {
			logErr("[-] Failed to synthesize fast-path policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated NixOS fast-path module, eBPF XDP program, and Kubernetes CiliumNodeConfig.\n")
	}

	logInfo("[+] WireGuard Fast-Path Posture: Compliance Score: %.1f%% (AVX-512: %t, ARM Neon: %t, Bottlenecks: %d)\n",
		report.Summary.ComplianceScore, report.Summary.AVX512Accelerated, report.Summary.ARMNeonAccelerated, len(report.Summary.BottleneckInterfaces))

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 70.0) {
		logErr("[-] FATAL: WireGuard Fast-Path posture NON_COMPLIANT in strict mode (Critical violation or Score < 70%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry, report.CryptoTelemetry
}
