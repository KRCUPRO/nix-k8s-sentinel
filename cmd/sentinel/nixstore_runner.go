package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nixstore"
)

// runNixStoreAudit coordinates Multi-Tenant Nix Store Signature & Binary Cache Isolation Gate auditing.
func runNixStoreAudit(
	targetPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]nixstore.StoreViolation, *nixstore.StoreSummary, *nixstore.NixStoreTelemetryReport) {
	if targetPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := nixstore.NewNixStoreScanner()
	report, err := scanner.ScanTarget(targetPath, telemetryPath)
	if err != nil {
		logErr("[-] Failed to audit Nix store and binary cache configurations: %v\n", err)
		os.Exit(1)
	}

	if targetPath != "" {
		logInfo("[+] Audited Nix Store & Daemon Configurations: %s (%d host configurations scanned)\n",
			targetPath, len(report.Configs))
	}

	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled Nix Store Telemetry: %s (Host: %s, %d store paths, %.1f%% used, %d signatures verified)\n",
			telemetryPath,
			report.Telemetry.HostName,
			report.Telemetry.StorePathCount,
			report.Telemetry.StoreUsagePercent,
			report.Telemetry.SignatureVerificationsTotal,
		)
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d Nix store signature & binary cache vulnerabilities:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.ConfigTarget, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero Nix store signature or binary cache vulnerabilities detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened Nix Store Configurations into: %s\n", synthOut)
		trustedKeys := make([]string, 0)
		substituters := make([]string, 0)
		trustedUsers := []string{"root"}

		if len(report.Configs) > 0 {
			for _, k := range report.Configs[0].TrustedPublicKeys {
				if k.ValidFormat {
					trustedKeys = append(trustedKeys, k.RawString)
				}
			}
			for _, s := range report.Configs[0].Substituters {
				if s.IsHTTPS {
					substituters = append(substituters, s.URL)
				}
			}
		}

		written, err := nixstore.WriteSynthesizedPolicies(synthOut, trustedKeys, substituters, trustedUsers)
		if err != nil {
			logErr("[-] Failed to synthesize Nix store policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated %d hardened configuration files in %s.\n", len(written), synthOut)
	}

	logInfo("[+] Nix Store Gate Posture: Compliance Score: %.1f%% (Sandboxing: %t, Signatures: %t, Critical: %d, High: %d)\n",
		report.Summary.ComplianceScore,
		report.Summary.SandboxingEnforced,
		report.Summary.SignaturesEnforced,
		report.Summary.CriticalCount,
		report.Summary.HighCount,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 75.0) {
		logErr("[-] FATAL: Nix Store Signature & Binary Cache Gate posture NON_COMPLIANT in strict mode (Critical violation or Score < 75%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry
}
