package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bgp"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runBGPAudit coordinates Kubernetes Service Mesh Dual-Stack IPv6 & Cilium BGP Peering Radar auditing.
func runBGPAudit(
	targetPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]bgp.BGPViolation, *bgp.BGPSummary, *bgp.BGPTelemetryReport) {
	if targetPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := bgp.NewBGPScanner()
	report, err := scanner.ScanTarget(targetPath, telemetryPath)
	if err != nil {
		logErr("[-] Failed to audit Cilium BGP peering configurations: %v\n", err)
		os.Exit(1)
	}

	if targetPath != "" {
		logInfo("[+] Audited Cilium BGP & Network Manifests: %s (%d policies, %d IP pools, %d NixOS hosts scanned)\n",
			targetPath, len(report.Policies), len(report.IPPools), len(report.NixOSHosts))
	}

	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled BGP Peering Telemetry: %s (%d neighbors, %d IPAM pools reporting)\n",
			telemetryPath, len(report.Telemetry.Peers), len(report.Telemetry.IPAMPools))
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d Cilium BGP peering & routing vulnerabilities:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			target := v.PolicyName
			if v.PeerAddress != "" {
				target = v.PolicyName + " (" + v.PeerAddress + ")"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, target, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero BGP peering or dual-stack routing vulnerabilities detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened Cilium BGP Policies into: %s\n", synthOut)
		polName := "cilium-bgp-hardened"
		localASN := 65001
		peerASN := 65000
		peerAddr := "192.168.100.1/32"
		authSecret := "cilium-bgp-auth-secret"

		if len(report.Policies) > 0 && len(report.Policies[0].VirtualRouters) > 0 {
			vr := report.Policies[0].VirtualRouters[0]
			polName = report.Policies[0].PolicyName
			if vr.LocalASN != 0 {
				localASN = vr.LocalASN
			}
			if len(vr.Neighbors) > 0 {
				if vr.Neighbors[0].PeerASN != 0 {
					peerASN = vr.Neighbors[0].PeerASN
				}
				if vr.Neighbors[0].PeerAddress != "" {
					peerAddr = vr.Neighbors[0].PeerAddress
				}
				if vr.Neighbors[0].AuthSecret != "" {
					authSecret = vr.Neighbors[0].AuthSecret
				}
			}
		}

		written, err := bgp.WriteSynthesizedPolicies(synthOut, polName, localASN, peerASN, peerAddr, authSecret)
		if err != nil {
			logErr("[-] Failed to synthesize BGP policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated %d hardened policy files in %s.\n", len(written), synthOut)
	}

	logInfo("[+] BGP Radar Posture: Compliance Score: %.1f%% (Dual-Stack: %t, Total Peers: %d, Critical: %d, High: %d)\n",
		report.Summary.ComplianceScore,
		report.Summary.DualStackCompliant,
		report.Summary.TotalPeers,
		report.Summary.CriticalCount,
		report.Summary.HighCount,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 75.0) {
		logErr("[-] FATAL: Cilium BGP Peering Radar posture NON_COMPLIANT in strict mode (Critical violation or Score < 75%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry
}
