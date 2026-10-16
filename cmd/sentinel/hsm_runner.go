package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/hsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runHSMAudit coordinates Hardware Security Module (HSM), KMS v2, and PKCS#11 security audits.
func runHSMAudit(hsmPath, telemetryPath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]hsm.HSMViolation, *hsm.HSMSummary) {
	if hsmPath == "" && telemetryPath == "" {
		return nil, nil
	}

	scanner := hsm.NewHSMScanner(feed)
	var allViolations []hsm.HSMViolation
	totalConfigs := 0
	totalKeys := 0

	// 1. Declarative Manifest Audit (Kubernetes EncryptionConfiguration & NixOS Host)
	if hsmPath != "" {
		logInfo("[+] Auditing Hardware Security Module (HSM) & KMS v2 Manifests: %s\n", hsmPath)
		rep, err := scanner.ScanPath(hsmPath)
		if err != nil {
			logErr("[-] Failed to audit HSM manifests at %s: %v\n", hsmPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalConfigs += rep.Summary.TotalConfigsScanned
		logInfo("[+] Evaluated %d HSM/KMS configurations: %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalConfigsScanned, rep.Summary.ViolationsCount, rep.Summary.ComplianceScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// 2. Runtime HSM & KMS Plugin Telemetry Audit
	if telemetryPath != "" {
		logInfo("[+] Inspecting HSM, PKCS#11 & KMS Plugin Runtime Telemetry: %s\n", telemetryPath)
		rep, err := scanner.ScanTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to audit HSM telemetry at %s: %v\n", telemetryPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalKeys += rep.Summary.TotalKeysAudited
		logInfo("[+] Reconciled %d active Key Encryption Keys (KEK): %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalKeysAudited, rep.Summary.ViolationsCount, rep.Summary.ComplianceScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// Recompute combined summary
	summary := &hsm.HSMSummary{
		TotalConfigsScanned: totalConfigs,
		TotalKeysAudited:    totalKeys,
		ViolationsCount:     len(allViolations),
	}

	for _, v := range allViolations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
		case intel.SeverityHigh:
			summary.HighCount++
		case intel.SeverityMedium:
			summary.MediumCount++
		case intel.SeverityLow:
			summary.LowCount++
		}
	}

	deductions := float64(summary.CriticalCount)*25.0 +
		float64(summary.HighCount)*12.0 +
		float64(summary.MediumCount)*5.0 +
		float64(summary.LowCount)*2.0

	score := 100.0 - deductions
	if score < 0.0 {
		score = 0.0
	}
	summary.ComplianceScore = score

	switch {
	case summary.CriticalCount > 0:
		summary.AuditStatus = "CRITICAL_DEFECTS_DETECTED"
	case summary.HighCount > 0:
		summary.AuditStatus = "HIGH_RISK_DEFECTS_DETECTED"
	case summary.ViolationsCount > 0:
		summary.AuditStatus = "WARNINGS_DETECTED"
	default:
		summary.AuditStatus = "COMPLIANT"
	}

	return allViolations, summary
}
