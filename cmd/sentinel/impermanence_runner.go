package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/impermanence"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runImpermanenceAudit coordinates NixOS Immutable Root & Impermanence Ephemerality Radar auditing.
func runImpermanenceAudit(
	targetPath, k8sPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]impermanence.ImpermanenceViolation, *impermanence.ImpermanenceSummary, *impermanence.EphemeralStorageTelemetry) {
	if targetPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := impermanence.NewScanner()
	report, err := scanner.Scan(targetPath, k8sPath, telemetryPath)
	if err != nil {
		logErr("[-] Failed to audit NixOS impermanence configurations: %v\n", err)
		os.Exit(1)
	}

	if targetPath != "" {
		logInfo("[+] Audited NixOS Impermanence Hosts: %s (%d hosts scanned)\n", targetPath, len(report.Hosts))
	}

	var firstNodeTele *impermanence.EphemeralStorageTelemetry
	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled Ephemeral Storage Telemetry: %s (%d nodes reporting)\n", telemetryPath, len(report.Telemetry.Nodes))
		if len(report.Telemetry.Nodes) > 0 {
			firstNodeTele = &report.Telemetry.Nodes[0]
		}
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d NixOS impermanence & ephemeral storage violations:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.HostName, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero NixOS impermanence violations detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened NixOS Impermanence Policies into: %s\n", synthOut)
		hostName := "k8s-node-nixos-hardened"
		persistRoot := "/persist"
		if len(report.Hosts) > 0 {
			hostName = report.Hosts[0].HostName
			if report.Hosts[0].PersistenceRoot != "" {
				persistRoot = report.Hosts[0].PersistenceRoot
			}
		}

		synth := impermanence.NewSynthesizer()
		if err := synth.WriteSynthesizedPolicies(synthOut, hostName, persistRoot); err != nil {
			logErr("[-] Failed to synthesize impermanence policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated impermanence-hardened.nix, wipe-on-reboot-zfs.nix, and impermanence-alerts.yaml.\n")
	}

	logInfo("[+] Impermanence Posture: Compliance Score: %.1f%% (Compliant Hosts: %d/%d, Ephemeral Roots: %d, Unencrypted Swap: %d, Missing Wipe Hooks: %d)\n",
		report.Summary.ComplianceScore,
		report.Summary.CompliantHosts,
		report.Summary.TotalHostsScanned,
		report.Summary.EphemeralRootCount,
		report.Summary.UnencryptedSwapCount,
		report.Summary.WipeHookMissingCount,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 75.0) {
		logErr("[-] FATAL: NixOS Impermanence posture NON_COMPLIANT in strict mode (Critical violation or Score < 75%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, firstNodeTele
}
