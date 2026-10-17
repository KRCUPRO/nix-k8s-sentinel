package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/lsm"
)

// runLSMAudit coordinates eBPF Linux Security Module (LSM) auditing and Kernel MAC policy synthesis.
func runLSMAudit(manifestPath, telemetryPath, synthOut string, lsmStrict bool, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]lsm.LSMViolation, *lsm.LSMSummary) {
	if manifestPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil
	}

	scanner := lsm.NewLSMScanner(feed)
	scanner.StrictMode = lsmStrict

	var allViolations []lsm.LSMViolation
	var allConfigs []lsm.NixOSLSMConfig
	var allProfiles []lsm.ContainerMACProfile
	var allTelemetry []lsm.LSMTelemetryEvent

	// 1. Declarative Manifest Audit (NixOS & Kubernetes)
	if manifestPath != "" {
		logInfo("[+] Auditing Declarative Host & Workload Manifests for eBPF LSM MAC: %s\n", manifestPath)
		rep, err := scanner.ScanManifestPath(manifestPath)
		if err != nil {
			logErr("[-] Failed to audit manifests at %s: %v\n", manifestPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		allConfigs = append(allConfigs, rep.Configs...)
		allProfiles = append(allProfiles, rep.Profiles...)

		logInfo("[+] Evaluated declarative definitions: %d NixOS configs, %d container MAC profiles (%d violations identified)\n",
			len(rep.Configs), len(rep.Profiles), len(rep.Violations))

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Resource, cveSuffix, v.Message, v.Severity, v.CVSSScore)
		}
	}

	// 2. Runtime eBPF LSM Denial Telemetry Audit
	if telemetryPath != "" {
		logInfo("[+] Reconciling Runtime eBPF LSM Denial Telemetry: %s\n", telemetryPath)
		events, err := scanner.ScanTelemetryPath(telemetryPath)
		if err != nil {
			logErr("[-] Failed to audit lsm telemetry at %s: %v\n", telemetryPath, err)
			os.Exit(1)
		}

		allTelemetry = append(allTelemetry, events...)
		tv := lsm.AuditTelemetry(events, telemetryPath, feed)
		allViolations = append(allViolations, tv...)

		logInfo("[+] Evaluated %d runtime telemetry events (%d denied / blocked attempts)\n",
			len(events), len(tv))

		for j, v := range tv {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				j+1, v.RuleID, v.Resource, cveSuffix, v.Message, v.Severity, v.CVSSScore)
		}
	}

	// 3. Synthesize Hardened eBPF LSM & Kernel MAC Policies to Disk
	if synthOut != "" {
		logInfo("[+] Writing Synthesized eBPF LSM & Kernel MAC Artifacts into: %s\n", synthOut)
		nixMod := lsm.SynthesizeNixOSLSMModule(allProfiles)
		var sampleProfile *lsm.ContainerMACProfile
		if len(allProfiles) > 0 {
			sampleProfile = &allProfiles[0]
		}
		bpfCode := lsm.SynthesizeBPFLSMCode(sampleProfile)
		k8sPolicy := lsm.SynthesizeK8sMACPolicy(sampleProfile)

		written, err := lsm.WriteLSMArtifacts(synthOut, nixMod, bpfCode, k8sPolicy)
		if err != nil {
			logErr("[-] Failed to write lsm artifacts: %v\n", err)
			os.Exit(1)
		}
		for key, path := range written {
			logInfo("  -> Generated %s: %s\n", key, path)
		}
	}

	summary := scanner.ComputeSummary(allViolations, allConfigs, allProfiles, allTelemetry)
	activeStr := "INACTIVE"
	if summary.BPFLSMActive {
		activeStr = "ACTIVE"
	}
	logInfo("[+] eBPF LSM Audit Complete: Score %.1f%% (Status: %s, Kernel LSM: %s) | %d MAC Profiles | %d Blocked Telemetry Syscalls\n",
		summary.LSMScore, summary.Status, activeStr, summary.MACProfileCount, summary.BlockedTelemetryCount)

	return allViolations, &summary
}
