package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/clustermesh"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runClusterMeshAudit coordinates Multi-Tenant Cilium ClusterMesh & Global Service Discovery audits.
func runClusterMeshAudit(
	targetPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]clustermesh.MeshViolation, *clustermesh.MeshSummary, *clustermesh.ClusterMeshTelemetryReport) {
	if targetPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := clustermesh.NewClusterMeshScanner()
	report, err := scanner.ScanClusterMeshTarget(targetPath, telemetryPath, feed)
	if err != nil {
		logErr("[-] Failed to audit Cilium ClusterMesh and Global Services: %v\n", err)
		os.Exit(1)
	}

	if targetPath != "" {
		logInfo("[+] Audited Cilium ClusterMesh & Global Services: %s (%d configs, %d services, %d policies scanned)\n",
			targetPath, len(report.Configs), len(report.Services), len(report.Policies))
	}

	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled ClusterMesh Runtime Telemetry: %s (Cluster: %s, ID: %d, State: %s, Latency: %.1f ms, Connected: %d, Disconnected: %d)\n",
			telemetryPath,
			report.Telemetry.LocalClusterName,
			report.Telemetry.LocalClusterID,
			report.Telemetry.SyncState,
			report.Telemetry.SyncLatencyMs,
			len(report.Telemetry.ConnectedClusters),
			len(report.Telemetry.DisconnectedClusters),
		)
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d ClusterMesh & Global Service Discovery vulnerabilities:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.FilePath, cveTag, v.Message, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero ClusterMesh routing or cross-cluster security vulnerabilities detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened ClusterMesh Configurations & Network Policies into: %s\n", synthOut)
		var meshCfg *clustermesh.ClusterMeshConfig
		if len(report.Configs) > 0 {
			meshCfg = &report.Configs[0]
		}
		written, err := clustermesh.WriteSynthesizedPolicies(synthOut, meshCfg)
		if err != nil {
			logErr("[-] Failed to synthesize ClusterMesh policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated %d hardened configuration files in %s.\n", len(written), synthOut)
	}

	logInfo("[+] ClusterMesh Security Posture: Compliance Score: %.1f%% (Critical: %d, High: %d, Med: %d, Healthy: %v)\n",
		report.Summary.ComplianceScore,
		report.Summary.CriticalCount,
		report.Summary.HighCount,
		report.Summary.MediumCount,
		report.Summary.MeshHealthy,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 75.0) {
		logErr("[-] FATAL: ClusterMesh posture NON_COMPLIANT in strict mode (Critical violation or Score < 75%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry
}
