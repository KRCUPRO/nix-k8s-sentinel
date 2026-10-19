package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/report"
)

// runBriefingExport handles Threat Briefing markdown generation and file persistence.
func runBriefingExport(cfg SentinelConfig, briefingOpts report.BriefingOptions, logInfo func(string, ...any), logErr func(string, ...any)) {
	rep, err := report.GenerateBriefing(briefingOpts)
	if err != nil {
		logErr("[-] Failed to generate threat briefing: %v\n", err)
		os.Exit(1)
	}

	savedPath, err := report.WriteBriefingToFile(rep, cfg.BriefingDir, cfg.BriefingFile)
	if err != nil {
		logErr("[-] Failed to save briefing file: %v\n", err)
		os.Exit(1)
	}

	logInfo("[+] Threat Briefing written to: %s\n", savedPath)
	logInfo("    Telemetry: Total=%d | Critical=%d | High=%d | Medium=%d | Low=%d\n",
		rep.Telemetry.TotalThreats, rep.Telemetry.CriticalCount, rep.Telemetry.HighCount, rep.Telemetry.MediumCount, rep.Telemetry.LowCount)
	logInfo("    Fleet Risk: Peak CVSS=%.1f | Avg CVSS=%.1f\n", rep.Telemetry.MaxCVSS, rep.Telemetry.AverageCVSS)
}
