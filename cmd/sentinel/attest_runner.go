package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runAttestAudit coordinates Confidential Computing & Measured Boot attestation verifications.
func runAttestAudit(attestPath, telemetryPath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]attest.AttestationViolation, *attest.AttestationSummary) {
	if attestPath == "" && telemetryPath == "" {
		return nil, nil
	}

	var allViolations []attest.AttestationViolation
	totalChecks := 0
	passedChecks := 0
	nodesAttested := 0
	nodesVerified := 0
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	// 1. Audit Declarative NixOS Confidential Computing Configurations
	if attestPath != "" {
		logInfo("[+] Auditing Confidential Computing & Measured Boot Configurations: %s\n", attestPath)
		fileInfo, err := os.Stat(attestPath)
		if err != nil {
			logErr("[-] Failed to inspect attestation configuration path: %v\n", err)
			os.Exit(1)
		}

		scanner := attest.NewAttestationScanner(feed)
		var rep *attest.AttestationAuditReport
		if fileInfo.IsDir() {
			r, err := scanner.ScanDirectory(attestPath)
			if err != nil {
				logErr("[-] Failed to audit attestation configuration directory: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned %d files (%d hosts/configurations evaluated)\n", rep.TotalFiles, rep.TotalNodes)
		} else {
			r, err := scanner.ScanFile(attestPath)
			if err != nil {
				logErr("[-] Failed to audit attestation configuration file: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned file %s (1 host configuration evaluated)\n", attestPath)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalChecks += rep.Summary.TotalChecks
		passedChecks += rep.Summary.PassedChecks
		nodesAttested += rep.Summary.NodesAttested
		nodesVerified += rep.Summary.NodesVerified
		critCount += rep.Summary.CriticalCount
		highCount += rep.Summary.HighCount
		medCount += rep.Summary.MediumCount
		lowCount += rep.Summary.LowCount
	}

	// 2. Verify Remote Attestation Telemetry and TPM 2.0 PCR Quotations
	if telemetryPath != "" {
		logInfo("[+] Verifying TPM 2.0 PCR Quotations & Remote Attestation Telemetry: %s\n", telemetryPath)
		verifier := attest.NewAttestationVerifier(feed)
		rep, err := verifier.VerifyTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to verify attestation telemetry file: %v\n", err)
			os.Exit(1)
		}

		logInfo("[+] Verified attestation quotes across %d cluster worker nodes\n", rep.TotalNodes)
		allViolations = append(allViolations, rep.Violations...)
		totalChecks += rep.Summary.TotalChecks
		passedChecks += rep.Summary.PassedChecks
		nodesAttested += rep.Summary.NodesAttested
		nodesVerified += rep.Summary.NodesVerified
		critCount += rep.Summary.CriticalCount
		highCount += rep.Summary.HighCount
		medCount += rep.Summary.MediumCount
		lowCount += rep.Summary.LowCount
	}

	score := 100.0
	if totalChecks > 0 {
		score = float64(passedChecks) / float64(totalChecks) * 100.0
	}

	summary := &attest.AttestationSummary{
		TotalChecks:     totalChecks,
		PassedChecks:    passedChecks,
		ComplianceScore: score,
		CriticalCount:   critCount,
		HighCount:       highCount,
		MediumCount:     medCount,
		LowCount:        lowCount,
		NodesAttested:   nodesAttested,
		NodesVerified:   nodesVerified,
	}

	logInfo("    Compliance Score: %.1f%% (%d Passed / %d Total Checks)\n", summary.ComplianceScore, summary.PassedChecks, summary.TotalChecks)
	logInfo("    Node Verification: %d Verified Safe / %d Attested\n", summary.NodesVerified, summary.NodesAttested)
	logInfo("    Severity Breakdown: Critical=%d | High=%d | Medium=%d | Low=%d\n", summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount)

	if len(allViolations) == 0 {
		logInfo("[+] Zero Confidential Computing or Measured Boot anomalies detected. All hardware enclave boundaries verified.\n")
	} else {
		logInfo("[-] WARNING: %d Confidential Computing & Measured Boot violations identified!\n", len(allViolations))
		for i, v := range allViolations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Target: %s (%s | Line: %d)\n", v.Target, v.Technology, v.StartLine)
			logInfo("      Details: %s\n", v.Message)
			logInfo("      Remediation: %s\n", v.Remediation)
		}
	}

	return allViolations, summary
}
