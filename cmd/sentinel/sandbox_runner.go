package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sandbox"
)

// runSandboxAudit coordinates Ephemeral MicroVM Sandbox & Honeypot Detonation execution.
func runSandboxAudit(sandboxPath, telemetryPath, synthOut string, quarantineStrict bool, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]sandbox.SandboxViolation, *sandbox.SandboxSummary) {
	if sandboxPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil
	}

	scanner := sandbox.NewSandboxScanner(feed)
	var allViolations []sandbox.SandboxViolation
	totalVMs := 0
	totalDetonations := 0
	totalHits := 0
	quarantined := 0
	clean := 0

	// 1. Declarative Manifest Audit (NixOS MicroVM & Kubernetes Detonation Job)
	if sandboxPath != "" {
		logInfo("[+] Auditing Ephemeral MicroVM & Detonation Manifests: %s\n", sandboxPath)
		rep, err := scanner.ScanPath(sandboxPath)
		if err != nil {
			logErr("[-] Failed to audit sandbox manifests at %s: %v\n", sandboxPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalVMs += rep.Summary.TotalMicroVMsScanned

		logInfo("[+] Evaluated %d MicroVM specifications: %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalMicroVMsScanned, rep.Summary.ViolationsCount, rep.Summary.SandboxSecurityScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// 2. Runtime Detonation & Intercepted Honeypot Telemetry Audit
	if telemetryPath != "" {
		logInfo("[+] Inspecting Runtime MicroVM Detonation & Honeypot Telemetry: %s\n", telemetryPath)
		rep, err := scanner.ScanTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to audit detonation telemetry at %s: %v\n", telemetryPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalDetonations += rep.Summary.TotalDetonations
		totalHits += rep.Summary.TotalHoneypotHits
		quarantined += rep.Summary.QuarantinedCount
		clean += rep.Summary.CleanCount

		logInfo("[+] Evaluated %d payload detonations (%d honeypot hits, %d quarantined): %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalDetonations, rep.Summary.TotalHoneypotHits, rep.Summary.QuarantinedCount, rep.Summary.ViolationsCount, rep.Summary.SandboxSecurityScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// 3. Declarative Policy & Honeypot Lure Synthesis
	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened NixOS MicroVM, Detonation Job, and Honeypot Lures into: %s\n", synthOut)
		written, err := sandbox.WriteSynthesizedSandboxConfigs(synthOut)
		if err != nil {
			logErr("[-] Failed to synthesize sandbox policies: %v\n", err)
			os.Exit(1)
		}
		for key, path := range written {
			logInfo("  -> Generated %s: %s\n", key, path)
		}
	}

	summary := sandbox.ComputeSandboxSummary(totalVMs, totalDetonations, totalHits, allViolations, quarantined, clean)
	return allViolations, &summary
}
