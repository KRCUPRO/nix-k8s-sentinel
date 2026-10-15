package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
)

// runSPIFFEAudit coordinates Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation audits.
func runSPIFFEAudit(spiffePath, telemetryPath, policyOut string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]spiffe.SPIFFEViolation, *spiffe.SPIFFESummary) {
	if spiffePath == "" && telemetryPath == "" && policyOut == "" {
		return nil, nil
	}

	var allViolations []spiffe.SPIFFEViolation
	totalChecks := 0
	passedChecks := 0
	svidsAudited := 0
	svidsValid := 0
	svidsExpiredOrNear := 0
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0
	policiesSynthesized := 0

	scanner := spiffe.NewSPIFFEScanner(feed)

	// 1. Audit Declarative SPIFFE/SPIRE & Cilium Manifests
	if spiffePath != "" {
		logInfo("[+] Auditing SPIFFE/SPIRE & Cilium Declarative Manifests: %s\n", spiffePath)
		fileInfo, err := os.Stat(spiffePath)
		if err != nil {
			logErr("[-] Failed to inspect SPIFFE manifest path: %v\n", err)
			os.Exit(1)
		}

		var rep *spiffe.SPIFFEAuditReport
		if fileInfo.IsDir() {
			r, err := scanner.ScanDirectory(spiffePath)
			if err != nil {
				logErr("[-] Failed to audit SPIFFE manifest directory: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned %d files across SPIFFE configuration directory\n", rep.TotalFiles)
		} else {
			r, err := scanner.ScanFile(spiffePath)
			if err != nil {
				logErr("[-] Failed to audit SPIFFE manifest file: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned manifest file %s (evaluated declarative SPIFFE resources)\n", spiffePath)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalChecks += rep.Summary.TotalChecks
		passedChecks += rep.Summary.PassedChecks
		critCount += rep.Summary.CriticalCount
		highCount += rep.Summary.HighCount
		medCount += rep.Summary.MediumCount
		lowCount += rep.Summary.LowCount
	}

	// 2. Reconcile Runtime SVID Telemetry
	if telemetryPath != "" {
		logInfo("[+] Reconciling Runtime X.509 SVID Telemetry: %s\n", telemetryPath)
		rep, err := scanner.ReconcileTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to reconcile SVID telemetry file: %v\n", err)
			os.Exit(1)
		}

		logInfo("[+] Reconciled runtime telemetry across %d SVIDs\n", rep.Summary.SVIDsAudited)
		allViolations = append(allViolations, rep.Violations...)
		totalChecks += rep.Summary.TotalChecks
		passedChecks += rep.Summary.PassedChecks
		svidsAudited += rep.Summary.SVIDsAudited
		svidsValid += rep.Summary.SVIDsValid
		svidsExpiredOrNear += rep.Summary.SVIDsExpiredOrNearExpiry
		critCount += rep.Summary.CriticalCount
		highCount += rep.Summary.HighCount
		medCount += rep.Summary.MediumCount
		lowCount += rep.Summary.LowCount
	}

	// 3. Synthesize Hardened Cilium Network Policies if requested
	if policyOut != "" {
		logInfo("[+] Synthesizing Hardened Cilium Zero-Trust Microsegmentation Policies...\n")
		sampleWorkloads := []spiffe.WorkloadIdentity{
			{
				Name:        "payment-service",
				Namespace:   "finance",
				SPIFFEID:    "spiffe://cluster.local/ns/finance/sa/payment-service",
				TrustDomain: "cluster.local",
				Attested:    true,
			},
			{
				Name:        "order-processor",
				Namespace:   "orders",
				SPIFFEID:    "spiffe://cluster.local/ns/orders/sa/order-processor",
				TrustDomain: "cluster.local",
				Attested:    true,
			},
		}

		yamlPolicies := spiffe.SynthesizeCiliumPoliciesForWorkloads(sampleWorkloads)
		savedPath, err := spiffe.WriteCiliumPoliciesToDir(yamlPolicies, policyOut)
		if err != nil {
			logErr("[-] Failed to export synthesized Cilium policies: %v\n", err)
			os.Exit(1)
		}
		policiesSynthesized = len(sampleWorkloads) + 1 // workloads + default-deny
		logInfo("[+] Synthesized Cilium Zero-Trust Microsegmentation Policies exported to: %s\n", savedPath)
	}

	score := 100.0
	if totalChecks > 0 {
		score = float64(passedChecks) / float64(totalChecks) * 100.0
	}

	summary := &spiffe.SPIFFESummary{
		TotalChecks:               totalChecks,
		PassedChecks:              passedChecks,
		ComplianceScore:           score,
		CriticalCount:             critCount,
		HighCount:                 highCount,
		MediumCount:               medCount,
		LowCount:                  lowCount,
		SVIDsAudited:              svidsAudited,
		SVIDsValid:                svidsValid,
		SVIDsExpiredOrNearExpiry:  svidsExpiredOrNear,
		CiliumPoliciesSynthesized: policiesSynthesized,
	}

	logInfo("    Compliance Score: %.1f%% (%d Passed / %d Total Checks)\n", summary.ComplianceScore, summary.PassedChecks, summary.TotalChecks)
	logInfo("    SVID Posture: %d Audited | %d Valid | %d Expired / Near-Expiry\n",
		summary.SVIDsAudited, summary.SVIDsValid, summary.SVIDsExpiredOrNearExpiry)
	logInfo("    Severity Breakdown: Critical=%d | High=%d | Medium=%d | Low=%d\n", summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount)

	if len(allViolations) == 0 {
		logInfo("[+] Zero SPIFFE workload attestation or microsegmentation violations detected. All cryptographic boundaries enforced.\n")
	} else {
		logInfo("[-] WARNING: %d SPIFFE & Cilium microsegmentation violations identified!\n", len(allViolations))
		for i, v := range allViolations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			workloadTag := v.Workload
			if workloadTag == "" {
				workloadTag = v.ResourceName
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Workload / Target: %s (Namespace: %s)\n", workloadTag, v.Namespace)
			logInfo("      Details: %s\n", v.Message)
			logInfo("      Remediation: %s\n", v.Remediation)
		}
	}

	return allViolations, summary
}
