package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/lockdown"
)

// runLockdownAudit coordinates Linux Kernel Lockdown & UEFI Secure Boot DBX Revocation List Auditor.
func runLockdownAudit(
	targetPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]lockdown.LockdownViolation, *lockdown.LockdownSummary, *lockdown.LockdownTelemetryReport) {
	if targetPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := lockdown.NewLockdownScanner()
	report, err := scanner.ScanLockdownTarget(targetPath, telemetryPath, feed)
	if err != nil {
		logErr("[-] Failed to audit kernel lockdown and UEFI DBX configurations: %v\n", err)
		os.Exit(1)
	}

	if targetPath != "" {
		logInfo("[+] Audited Kernel Lockdown & Secure Boot Configurations: %s (%d host configurations scanned)\n",
			targetPath, report.Summary.TotalScanned)
	}

	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled Kernel Lockdown & UEFI Telemetry: %s (Host: %s, Mode: %s, SecureBoot: %s, DBX: %s with %d revocations)\n",
			telemetryPath,
			report.Telemetry.HostName,
			report.Telemetry.LiveLockdownMode,
			report.Telemetry.SecureBootStatus,
			report.Telemetry.DBXVersion,
			report.Telemetry.DBXTotalRevocations,
		)
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d kernel lockdown & Secure Boot vulnerabilities:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.FilePath, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero kernel lockdown or UEFI DBX vulnerabilities detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened Kernel Lockdown & Lanzaboote Policies into: %s\n", synthOut)
		written, err := lockdown.WriteSynthesizedPolicies(synthOut, report.Config)
		if err != nil {
			logErr("[-] Failed to synthesize kernel lockdown policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated %d hardened configuration files in %s.\n", len(written), synthOut)
	}

	logInfo("[+] Kernel Lockdown & Secure Boot Posture: Compliance Score: %.1f%% (Critical: %d, High: %d, Med: %d)\n",
		report.Summary.ComplianceScore,
		report.Summary.CriticalCount,
		report.Summary.HighCount,
		report.Summary.MediumCount,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 75.0) {
		logErr("[-] FATAL: Kernel Lockdown & UEFI DBX posture NON_COMPLIANT in strict mode (Critical violation or Score < 75%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry
}
