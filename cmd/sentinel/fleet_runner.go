package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// runFleetAudit coordinates Multi-Cluster Fleet Synchronization & OIDC Token Radar audits.
func runFleetAudit(fleetPath, telemetryPath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]fleet.FleetViolation, *fleet.FleetSummary) {
	if fleetPath == "" && telemetryPath == "" {
		return nil, nil
	}

	var allViolations []fleet.FleetViolation
	totalChecks := 0
	passedChecks := 0
	clustersAudited := 0
	clustersInSync := 0
	driftingApps := 0
	oidcVerified := 0
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	scanner := fleet.NewFleetScanner(feed)

	// 1. Audit Declarative Multi-Cluster RBAC & GitOps Manifests
	if fleetPath != "" {
		logInfo("[+] Auditing Multi-Cluster Fleet & GitOps Manifests: %s\n", fleetPath)
		fileInfo, err := os.Stat(fleetPath)
		if err != nil {
			logErr("[-] Failed to inspect fleet manifest path: %v\n", err)
			os.Exit(1)
		}

		var rep *fleet.FleetAuditReport
		if fileInfo.IsDir() {
			r, err := scanner.ScanDirectory(fleetPath)
			if err != nil {
				logErr("[-] Failed to audit fleet manifest directory: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned %d files across fleet configuration directory\n", rep.TotalFiles)
		} else {
			r, err := scanner.ScanFile(fleetPath)
			if err != nil {
				logErr("[-] Failed to audit fleet manifest file: %v\n", err)
				os.Exit(1)
			}
			rep = r
			logInfo("[+] Scanned manifest file %s (evaluated declarative fleet resources)\n", fleetPath)
		}

		allViolations = append(allViolations, rep.Violations...)
		totalChecks += rep.Summary.TotalChecks
		passedChecks += rep.Summary.PassedChecks
		clustersAudited += rep.Summary.ClustersAudited
		clustersInSync += rep.Summary.ClustersInSync
		driftingApps += rep.Summary.DriftingApps
		oidcVerified += rep.Summary.OIDCTokensVerified
		critCount += rep.Summary.CriticalCount
		highCount += rep.Summary.HighCount
		medCount += rep.Summary.MediumCount
		lowCount += rep.Summary.LowCount
	}

	// 2. Reconcile Live Multi-Cluster Fleet Telemetry & OIDC Tokens
	if telemetryPath != "" {
		logInfo("[+] Reconciling Runtime Fleet Telemetry & OIDC Tokens: %s\n", telemetryPath)
		rep, err := scanner.ReconcileTelemetryFile(telemetryPath)
		if err != nil {
			logErr("[-] Failed to reconcile fleet telemetry file: %v\n", err)
			os.Exit(1)
		}

		logInfo("[+] Reconciled runtime telemetry across %d geographically distributed clusters\n", rep.Summary.ClustersAudited)
		allViolations = append(allViolations, rep.Violations...)
		totalChecks += rep.Summary.TotalChecks
		passedChecks += rep.Summary.PassedChecks
		clustersAudited += rep.Summary.ClustersAudited
		clustersInSync += rep.Summary.ClustersInSync
		driftingApps += rep.Summary.DriftingApps
		oidcVerified += rep.Summary.OIDCTokensVerified
		critCount += rep.Summary.CriticalCount
		highCount += rep.Summary.HighCount
		medCount += rep.Summary.MediumCount
		lowCount += rep.Summary.LowCount
	}

	score := 100.0
	if totalChecks > 0 {
		score = float64(passedChecks) / float64(totalChecks) * 100.0
	}

	summary := &fleet.FleetSummary{
		TotalChecks:        totalChecks,
		PassedChecks:       passedChecks,
		ComplianceScore:    score,
		CriticalCount:      critCount,
		HighCount:          highCount,
		MediumCount:        medCount,
		LowCount:           lowCount,
		ClustersAudited:    clustersAudited,
		ClustersInSync:     clustersInSync,
		DriftingApps:       driftingApps,
		OIDCTokensVerified: oidcVerified,
	}

	logInfo("    Compliance Score: %.1f%% (%d Passed / %d Total Checks)\n", summary.ComplianceScore, summary.PassedChecks, summary.TotalChecks)
	logInfo("    Fleet Topology: %d Clusters Audited | %d In Sync | %d Drifting Apps | %d OIDC Tokens Verified\n",
		summary.ClustersAudited, summary.ClustersInSync, summary.DriftingApps, summary.OIDCTokensVerified)
	logInfo("    Severity Breakdown: Critical=%d | High=%d | Medium=%d | Low=%d\n", summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount)

	if len(allViolations) == 0 {
		logInfo("[+] Zero fleet synchronization drift or OIDC token vulnerabilities detected. All cluster boundaries aligned.\n")
	} else {
		logInfo("[-] WARNING: %d Multi-Cluster Fleet & OIDC violations identified!\n", len(allViolations))
		for i, v := range allViolations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			clusterTag := v.ClusterID
			if clusterTag == "" {
				clusterTag = "fleet-wide"
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Resource: %s/%s (Cluster: %s | Line: %d)\n", v.ResourceKind, v.ResourceName, clusterTag, v.StartLine)
			logInfo("      Impact: %s\n", v.Message)
			logInfo("      Remediation: %s\n", v.Remediation)
		}
	}

	return allViolations, summary
}
