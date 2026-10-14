package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runCISAudit coordinates CIS Kubernetes Benchmark auditing across NixOS modules and Kubernetes manifests.
func runCISAudit(cisPath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]bench.CISViolation, *bench.CISSummary) {
	if cisPath == "" {
		return nil, nil
	}

	logInfo("[+] Auditing CIS Kubernetes Benchmark Compliance: %s\n", cisPath)
	fileInfo, err := os.Stat(cisPath)
	if err != nil {
		logErr("[-] Failed to inspect CIS benchmark target path: %v\n", err)
		os.Exit(1)
	}

	scanner := bench.NewCISScanner(feed)
	var report *bench.CISAuditReport

	if fileInfo.IsDir() {
		rep, err := scanner.ScanDirectory(cisPath)
		if err != nil {
			logErr("[-] Failed to scan directory against CIS benchmark: %v\n", err)
			os.Exit(1)
		}
		report = rep
	} else {
		rep, err := scanner.ScanFile(cisPath)
		if err != nil {
			logErr("[-] Failed to scan file against CIS benchmark: %v\n", err)
			os.Exit(1)
		}
		report = rep
	}

	logInfo("[+] CIS Benchmark Scan Complete across %d files (%d component blocks evaluated)\n",
		report.TotalFiles, len(report.Components))
	logInfo("    Compliance Score: %.1f%% (%d Passed / %d Total Checks)\n",
		report.Summary.ComplianceScore, report.Summary.PassedChecks, report.Summary.TotalChecks)
	logInfo("    Severity Breakdown: Critical=%d | High=%d | Medium=%d | Low=%d\n",
		report.Summary.CriticalCount, report.Summary.HighCount, report.Summary.MediumCount, report.Summary.LowCount)

	if len(report.Violations) == 0 {
		logInfo("[+] Zero CIS benchmark violations detected. Cluster control plane and workers are fully hardened.\n")
	} else {
		logInfo("[-] WARNING: %d CIS benchmark configuration violations identified!\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Component: %s (Flag: %s | Current: %s | Expected: %s)\n",
				v.Component, v.FlagName, v.ActualValue, v.ExpectedValue)
			logInfo("      Source: %s (Line: %d)\n", v.FilePath, v.StartLine)
			if v.RemediationNix != "" {
				logInfo("      Remediation: %s\n", v.RemediationNix)
			}
		}
	}

	return report.Violations, &report.Summary
}
