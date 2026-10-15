package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
)

// runFlakeAudit audits a NixOS flake.lock against known CVE feeds.
func runFlakeAudit(flakePath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) []nix.FlakeVulnerabilityMatch {
	if flakePath == "" {
		return nil
	}

	logInfo("[+] Auditing Nix Flake Lockfile: %s\n", flakePath)
	lock, err := nix.ParseFlakeLockFile(flakePath)
	if err != nil {
		logErr("[-] Failed to parse flake.lock: %v\n", err)
		os.Exit(1)
	}

	deps, err := lock.ResolveDependencies(lock.Root)
	if err != nil {
		logErr("[-] Failed to resolve flake dependencies: %v\n", err)
		os.Exit(1)
	}

	logInfo("[+] Resolved %d pinned flake dependencies.\n", len(deps))
	matches, err := nix.ScanFlakeAgainstFeed(lock, feed)
	if err != nil {
		logErr("[-] Error scanning flake against feed: %v\n", err)
		os.Exit(1)
	}

	if len(matches) == 0 {
		logInfo("[+] Zero matching CVEs detected in flake.lock inputs.\n")
	} else {
		logInfo("[-] WARNING: %d vulnerable flake inputs identified!\n", len(matches))
		for i, m := range matches {
			logInfo("  [%d] %s (%s) - %s [CVSS: %.1f]\n", i+1, m.AdvisoryID, m.Severity, m.Title, m.CVSSScore)
			logInfo("      Input: %s (Node: %s) | Rev: %s\n", m.DependencyName, m.NodeKey, m.InstalledRev)
			logInfo("      Mitigation: %s\n", m.Mitigation)
		}
	}

	return matches
}

// runK8sAudit audits declarative Kubernetes manifests against security rules and CVE feeds.
func runK8sAudit(k8sPath string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) *k8s.ManifestAuditReport {
	if k8sPath == "" {
		return nil
	}

	logInfo("[+] Auditing Kubernetes Manifests: %s\n", k8sPath)
	manifestScanner := k8s.NewManifestScanner(feed)

	fileInfo, err := os.Stat(k8sPath)
	if err != nil {
		logErr("[-] Failed to inspect manifest path: %v\n", err)
		os.Exit(1)
	}

	var k8sReport *k8s.ManifestAuditReport
	if fileInfo.IsDir() {
		k8sReport, err = manifestScanner.ScanDirectory(k8sPath)
	} else {
		k8sReport, err = manifestScanner.ScanFile(k8sPath)
	}

	if err != nil {
		logErr("[-] Failed to audit Kubernetes manifest: %v\n", err)
		os.Exit(1)
	}

	logInfo("[+] Scanned %d files across %d declarative resources.\n", k8sReport.TotalFiles, k8sReport.TotalResources)
	if len(k8sReport.Violations) == 0 {
		logInfo("[+] Zero security violations detected in Kubernetes manifests.\n")
	} else {
		logInfo("[-] WARNING: %d security violations identified!\n", len(k8sReport.Violations))
		for i, v := range k8sReport.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
			}
			logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
			logInfo("      Target: %s/%s (Namespace: %s)\n", v.ResourceKind, v.ResourceName, v.Namespace)
			logInfo("      Details: %s\n", v.Description)
			logInfo("      Remediation: %s\n", v.Remediation)
		}
	}

	return k8sReport
}
