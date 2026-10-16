package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bpf"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runBPFAudit coordinates Dynamic Kernel Runtime Threat Profiling, Syscall BPF Filtering, and policy synthesis.
func runBPFAudit(bpfPath, telemetryPath, synthOut, serviceName string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]bpf.BPFViolation, *bpf.BPFSummary) {
	if bpfPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil
	}

	scanner := bpf.NewBPFScanner(feed)
	var allViolations []bpf.BPFViolation
	totalProfiles := 0
	totalEvents := 0

	// 1. Declarative Manifest Audit (Kubernetes Seccomp & NixOS Host BPF)
	if bpfPath != "" {
		logInfo("[+] Auditing Kernel Runtime Threat & Seccomp Manifests: %s\n", bpfPath)
		rep, err := scanner.ScanPath(bpfPath)
		if err != nil {
			logErr("[-] Failed to audit BPF/seccomp manifests at %s: %v\n", bpfPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalProfiles += rep.Summary.TotalProfilesScanned
		logInfo("[+] Evaluated %d BPF/seccomp profiles: %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalProfilesScanned, rep.Summary.ViolationsCount, rep.Summary.ComplianceScore, rep.Summary.AuditStatus)

		for i, v := range rep.Violations {
			cveSuffix := ""
			if v.MatchedCVE != "" {
				cveSuffix = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.Title, cveSuffix, v.Description, v.Severity, v.CVSSScore)
		}
	}

	// 2. Runtime Kernel Telemetry & Syscall Audit
	if telemetryPath != "" {
		logInfo("[+] Inspecting Kernel BPF & Syscall Runtime Telemetry: %s\n", telemetryPath)
		rep, err := scanner.ScanTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to audit BPF runtime telemetry at %s: %v\n", telemetryPath, err)
			os.Exit(1)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalEvents += rep.Summary.TotalTelemetryEvents
		logInfo("[+] Evaluated %d runtime kernel events: %d violations found (Score: %.1f%%, Status: %s)\n",
			rep.Summary.TotalTelemetryEvents, rep.Summary.ViolationsCount, rep.Summary.ComplianceScore, rep.Summary.AuditStatus)

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
		logInfo("[+] Synthesizing Hardened Seccomp & eBPF LSM Policies into: %s\n", synthOut)
		written, err := bpf.WriteSynthesizedPolicies(synthOut, serviceName)
		if err != nil {
			logErr("[-] Failed to synthesize BPF policies: %v\n", err)
			os.Exit(1)
		}
		for key, path := range written {
			logInfo("  -> Generated %s: %s\n", key, path)
		}
	}

	// Recompute combined summary
	summary := bpf.ComputeBPFSummary(totalProfiles, totalEvents, allViolations)
	return allViolations, &summary
}
