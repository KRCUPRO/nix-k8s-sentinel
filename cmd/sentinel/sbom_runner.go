package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sbom"
)

// runSBOMAudit coordinates Software Bill of Materials (SBOM) and In-Toto Supply Chain Attestation audits.
func runSBOMAudit(sbomPath, attestPath, runtimePath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]sbom.SBOMViolation, *sbom.SBOMSummary, []sbom.SBOMDeltaItem) {
	if sbomPath == "" && attestPath == "" && runtimePath == "" {
		return nil, nil, nil
	}

	scanner := sbom.NewSBOMScanner(feed)
	var allViolations []sbom.SBOMViolation
	var allDeltaItems []sbom.SBOMDeltaItem
	totalPackages := 0
	totalDocuments := 0
	evaluatedSLSA := sbom.SLSALevel0
	attestVerified := false
	driftingCount := 0
	undeclaredCount := 0

	// 1. Declarative vs. Runtime State Reconciliation
	if sbomPath != "" && runtimePath != "" {
		logInfo("[+] Reconciling Declarative SBOM (%s) Against Cluster Runtime State (%s)...\n", sbomPath, runtimePath)
		rep, err := scanner.ReconcileRuntimeState(sbomPath, runtimePath)
		if err != nil {
			logErr("[-] Failed to reconcile SBOM against runtime state: %v\n", err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		allDeltaItems = append(allDeltaItems, rep.DeltaItems...)
		totalPackages += rep.Summary.TotalPackages
		totalDocuments += rep.Summary.TotalDocuments
		driftingCount += rep.Summary.DriftingPackages
		undeclaredCount += rep.Summary.UndeclaredPackages

		logInfo("[+] Reconciled %d packages: %d drifting, %d undeclared runtime injections (Score: %.1f%%)\n",
			rep.Summary.TotalPackages, rep.Summary.DriftingPackages, rep.Summary.UndeclaredPackages, rep.Summary.ComplianceScore)

		for i, d := range rep.DeltaItems {
			if d.Status != sbom.DeltaMatch {
				logInfo("  [%d] [%s] %s: %s (Severity: %s)\n", i+1, d.Status, d.PackageName, d.Message, d.Severity)
			}
		}
	} else if sbomPath != "" {
		// 2. Standalone Declarative SBOM Scan
		logInfo("[+] Auditing Declarative Software Bill of Materials (SBOM): %s\n", sbomPath)
		info, err := os.Stat(sbomPath)
		if err != nil {
			logErr("[-] Failed to inspect SBOM path: %v\n", err)
			os.Exit(1)
		}

		var rep *sbom.SBOMAuditReport
		if info.IsDir() {
			r, err := scanner.ScanDirectory(sbomPath)
			if err != nil {
				logErr("[-] Failed to scan SBOM directory: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned %d files across SBOM manifest directory\n", rep.TotalFiles)
		} else {
			r, err := scanner.ScanFile(sbomPath)
			if err != nil {
				logErr("[-] Failed to scan SBOM file: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned SBOM file %s (%d components evaluated)\n", sbomPath, rep.Summary.TotalPackages)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalPackages += rep.Summary.TotalPackages
		totalDocuments += rep.Summary.TotalDocuments
	}

	// 3. In-Toto Attestation & SLSA Provenance Verification
	if attestPath != "" {
		logInfo("[+] Verifying In-Toto Attestation & SLSA Provenance: %s\n", attestPath)
		attest, vios, err := sbom.ParseInTotoAttestationFile(attestPath)
		if err != nil {
			logErr("[-] Failed to parse In-Toto attestation file: %v\n", err)
			os.Exit(1)
		}

		allViolations = append(allViolations, vios...)
		evaluatedSLSA = attest.EvaluatedSLSALevel
		attestVerified = attest.VerifiedSignature

		logInfo("[+] In-Toto Envelope Verified: Builder '%s' (Hermetic: %v, Signature: %v) -> %s\n",
			attest.BuilderID, attest.Hermetic, attest.VerifiedSignature, attest.EvaluatedSLSALevel)
	}

	// Calculate consolidated summary
	crit := 0
	high := 0
	med := 0
	low := 0
	for _, v := range allViolations {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	score := 100.0 - (float64(crit)*15.0 + float64(high)*7.5 + float64(med)*3.0 + float64(low)*1.0)
	if score < 0.0 {
		score = 0.0
	}

	summary := &sbom.SBOMSummary{
		TotalPackages:       totalPackages,
		TotalDocuments:      totalDocuments,
		TotalViolations:     len(allViolations),
		CriticalCount:       crit,
		HighCount:           high,
		MediumCount:         med,
		LowCount:            low,
		AttestationVerified: attestVerified,
		EvaluatedSLSALevel:  evaluatedSLSA,
		DriftingPackages:    driftingCount,
		UndeclaredPackages:  undeclaredCount,
		ComplianceScore:     score,
	}

	if len(allViolations) == 0 {
		logInfo("[+] Zero supply chain vulnerabilities or SBOM violations identified.\n")
	} else {
		logInfo("[-] WARNING: %d supply chain / SBOM violations identified (Score: %.1f%%)!\n", len(allViolations), score)
		for i, v := range allViolations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Component/Resource: %s\n", v.ResourceURI)
			logInfo("      Details: %s\n", v.Description)
			logInfo("      Remediation: %s\n", v.Remediation)
		}
	}

	return allViolations, summary, allDeltaItems
}
