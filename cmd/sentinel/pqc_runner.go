package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/pqc"
)

// runPQCAudit coordinates Post-Quantum Cryptography & CNSA 2.0 TLS audit engine execution.
func runPQCAudit(pqcPath, telemetryPath, synthOut string, cnsaStrict bool, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]pqc.PQCViolation, *pqc.PQCSummary) {
	if pqcPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil
	}

	scanner := pqc.NewPQCScanner(feed)
	var allViolations []pqc.PQCViolation
	totalConfigs := 0
	totalEndpoints := 0
	totalEvents := 0
	hybridPct := 0.0
	tls13Pct := 0.0

	// 1. Declarative Manifest Audit (Kubernetes Control Plane & NixOS Crypto Policy)
	if pqcPath != "" {
		logInfo("[+] Auditing Post-Quantum Cryptography & CNSA 2.0 Manifests: %s\n", pqcPath)
		rep, err := scanner.ScanPath(pqcPath)
		if err != nil {
			logErr("[-] Failed to audit PQC manifests at %s: %v\n", pqcPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalConfigs += rep.Summary.TotalConfigsScanned
		totalEndpoints += rep.Summary.TotalEndpointsScanned

		logInfo("[+] Evaluated %d PQC control plane configs: %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalConfigsScanned, rep.Summary.ViolationsCount, rep.Summary.CNSAComplianceScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// 2. Runtime TLS Handshake Telemetry Audit
	if telemetryPath != "" {
		logInfo("[+] Inspecting Runtime Post-Quantum TLS Handshake Telemetry: %s\n", telemetryPath)
		rep, err := scanner.ScanTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to audit PQC runtime telemetry at %s: %v\n", telemetryPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalEvents += rep.Summary.TotalTelemetryEvents
		hybridPct = rep.Summary.HybridKEMPercentage
		tls13Pct = rep.Summary.TLS13Percentage

		logInfo("[+] Evaluated %d runtime TLS handshakes: %d violations found (Hybrid KEM: %.1f%%, TLS 1.3: %.1f%%, Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalTelemetryEvents, rep.Summary.ViolationsCount, rep.Summary.HybridKEMPercentage, rep.Summary.TLS13Percentage, rep.Summary.CNSAComplianceScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// 3. Declarative Policy Synthesis
	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened NixOS & Kubernetes PQC / CNSA 2.0 Policies into: %s\n", synthOut)
		written, err := pqc.WriteSynthesizedPQCConfig(synthOut)
		if err != nil {
			logErr("[-] Failed to synthesize PQC policies: %v\n", err)
			os.Exit(1)
		}
		for key, path := range written {
			logInfo("  -> Generated %s: %s\n", key, path)
		}
	}

	summary := pqc.ComputePQCSummary(totalConfigs, totalEndpoints, totalEvents, allViolations, hybridPct, tls13Pct)
	return allViolations, &summary
}
