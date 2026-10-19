package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/flow"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runFlowAudit coordinates Cluster-Wide eBPF Network Flow & DNS Exfiltration Anomaly Profiler.
func runFlowAudit(
	targetPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]flow.FlowViolation, *flow.FlowSummary, *flow.FlowTelemetryReport) {
	if targetPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := flow.NewFlowScanner()
	report, err := scanner.ScanFlowTarget(targetPath, telemetryPath, feed)
	if err != nil {
		logErr("[-] Failed to audit eBPF network flow and DNS configurations: %v\n", err)
		os.Exit(1)
	}

	if targetPath != "" {
		logInfo("[+] Audited Network Flow & Cilium DNS Policies: %s (%d configurations scanned)\n",
			targetPath, report.Summary.TotalScanned)
	}

	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled eBPF Network Flow & DNS Telemetry: %s (Cluster: %s, Host: %s, Queries: %d, NXDOMAIN: %.1f%%, PeakSocketRate: %d conn/s)\n",
			telemetryPath,
			report.Telemetry.ClusterName,
			report.Telemetry.HostName,
			report.Telemetry.TotalDNSQueries,
			report.Telemetry.NXDomainRatePercent,
			report.Telemetry.PeakSocketConnectRate,
		)
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d network flow & DNS exfiltration vulnerabilities:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.FilePath, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero network flow or DNS tunneling vulnerabilities detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened Cilium Network Policies & NixOS Flow Profiler into: %s\n", synthOut)
		var ciliumCfg *flow.CiliumNetworkPolicyConfig
		if len(report.CiliumConfigs) > 0 {
			ciliumCfg = report.CiliumConfigs[0]
		}
		written, err := flow.WriteSynthesizedPolicies(synthOut, ciliumCfg)
		if err != nil {
			logErr("[-] Failed to synthesize network flow policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated %d hardened configuration files in %s.\n", len(written), synthOut)
	}

	logInfo("[+] Network Flow & DNS Exfiltration Posture: Compliance Score: %.1f%% (Critical: %d, High: %d, Med: %d)\n",
		report.Summary.ComplianceScore,
		report.Summary.CriticalCount,
		report.Summary.HighCount,
		report.Summary.MediumCount,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 75.0) {
		logErr("[-] FATAL: Network flow & DNS exfiltration posture NON_COMPLIANT in strict mode (Critical violation or Score < 75%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry
}
