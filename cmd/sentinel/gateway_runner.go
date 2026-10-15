package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runGatewayAudit coordinates Gateway API and EnvoyFilter route threat radar analysis.
func runGatewayAudit(gwPath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]gateway.GatewayViolation, *gateway.GatewaySummary) {
	if gwPath == "" {
		return nil, nil
	}

	logInfo("[+] Auditing Kubernetes Gateway API & EnvoyFilter Route Threat Radar: %s\n", gwPath)
	fileInfo, err := os.Stat(gwPath)
	if err != nil {
		logErr("[-] Failed to inspect Gateway API target path: %v\n", err)
		os.Exit(1)
	}

	scanner := gateway.NewGatewayScanner(feed)
	var report *gateway.GatewayAuditReport

	if fileInfo.IsDir() {
		rep, err := scanner.ScanDirectory(gwPath)
		if err != nil {
			logErr("[-] Failed to audit Gateway API directory: %v\n", err)
			os.Exit(1)
		}
		report = rep
		logInfo("[+] Scanned %d files (%d Gateway/Route resources evaluated)\n", rep.TotalFiles, rep.TotalResources)
	} else {
		rep, err := scanner.ScanFile(gwPath)
		if err != nil {
			logErr("[-] Failed to audit Gateway API file: %v\n", err)
			os.Exit(1)
		}
		report = rep
		logInfo("[+] Scanned file %s (%d Gateway/Route resources evaluated)\n", gwPath, rep.TotalResources)
	}

	logInfo("    Compliance Score: %.1f%% (%d Passed / %d Total Checks)\n",
		report.Summary.ComplianceScore, report.Summary.PassedChecks, report.Summary.TotalChecks)
	logInfo("    Severity Breakdown: Critical=%d | High=%d | Medium=%d | Low=%d\n",
		report.Summary.CriticalCount, report.Summary.HighCount, report.Summary.MediumCount, report.Summary.LowCount)
	logInfo("    ReferenceGrants Active: %d registered\n", len(report.ReferenceGrants))

	if len(report.Violations) == 0 {
		logInfo("[+] Zero Gateway API or EnvoyFilter routing violations detected. All route boundaries are strictly enforced.\n")
	} else {
		logInfo("[-] WARNING: %d Gateway API & EnvoyFilter routing violations identified!\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Target: %s/%s (Namespace: %s | Line: %d)\n", v.ResourceKind, v.ResourceName, v.Namespace, v.StartLine)
			logInfo("      Details: %s\n", v.Message)
			logInfo("      Remediation: %s\n", v.Remediation)
		}
	}

	return report.Violations, &report.Summary
}
