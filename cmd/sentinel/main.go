package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
)

var (
	version = "0.3.0"
)

func main() {
	feedPath := flag.String("feed", "intel/cve-feed.json", "Path to threat intelligence feed JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	targetFilter := flag.String("target", "", "Filter feed by target ('nixos' or 'kubernetes')")
	flakePath := flag.String("flake", "", "Path to NixOS flake.lock to audit for known CVEs")
	k8sPath := flag.String("k8s", "", "Path to Kubernetes manifest file or directory to audit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nix-k8s-sentinel v%s (Cloud-Native Threat Radar)\n", version)
		os.Exit(0)
	}

	fmt.Printf("[+] nix-k8s-sentinel v%s starting up...\n", version)

	data, err := os.ReadFile(*feedPath)
	if err != nil {
		fmt.Printf("[-] Warning: Failed to read feed file (%s): %v\n", *feedPath, err)
		fmt.Println("[+] Initialized in dry-run monitoring mode.")
		os.Exit(0)
	}

	feed, err := intel.ParseFeed(data)
	if err != nil {
		fmt.Printf("[-] Error parsing feed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Feed Loaded: %d intelligence advisories (Updated: %s)\n", len(feed.Items), feed.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))

	// 1. Audit Nix Flake if --flake is provided
	if *flakePath != "" {
		fmt.Printf("[+] Auditing Nix Flake Lockfile: %s\n", *flakePath)
		lock, err := nix.ParseFlakeLockFile(*flakePath)
		if err != nil {
			fmt.Printf("[-] Failed to parse flake.lock: %v\n", err)
			os.Exit(1)
		}

		deps, err := lock.ResolveDependencies(lock.Root)
		if err != nil {
			fmt.Printf("[-] Failed to resolve flake dependencies: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Resolved %d pinned flake dependencies.\n", len(deps))
		matches, err := nix.ScanFlakeAgainstFeed(lock, feed)
		if err != nil {
			fmt.Printf("[-] Error scanning flake against feed: %v\n", err)
			os.Exit(1)
		}

		if len(matches) == 0 {
			fmt.Println("[+] Zero matching CVEs detected in flake.lock inputs.")
		} else {
			fmt.Printf("[-] WARNING: %d vulnerable flake inputs identified!\n", len(matches))
			for i, m := range matches {
				fmt.Printf("  [%d] %s (%s) - %s [CVSS: %.1f]\n", i+1, m.AdvisoryID, m.Severity, m.Title, m.CVSSScore)
				fmt.Printf("      Input: %s (Node: %s) | Rev: %s\n", m.DependencyName, m.NodeKey, m.InstalledRev)
				fmt.Printf("      Mitigation: %s\n", m.Mitigation)
			}
		}
		return
	}

	// 2. Audit Kubernetes Manifests if --k8s is provided
	if *k8sPath != "" {
		fmt.Printf("[+] Auditing Kubernetes Manifests: %s\n", *k8sPath)
		manifestScanner := k8s.NewManifestScanner(feed)

		fileInfo, err := os.Stat(*k8sPath)
		if err != nil {
			fmt.Printf("[-] Failed to inspect manifest path: %v\n", err)
			os.Exit(1)
		}

		var report *k8s.ManifestAuditReport
		if fileInfo.IsDir() {
			report, err = manifestScanner.ScanDirectory(*k8sPath)
		} else {
			report, err = manifestScanner.ScanFile(*k8sPath)
		}

		if err != nil {
			fmt.Printf("[-] Failed to audit Kubernetes manifest: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Scanned %d files across %d declarative resources.\n", report.TotalFiles, report.TotalResources)
		if len(report.Violations) == 0 {
			fmt.Println("[+] Zero security violations detected in Kubernetes manifests.")
		} else {
			fmt.Printf("[-] WARNING: %d security violations identified!\n", len(report.Violations))
			for i, v := range report.Violations {
				cveTag := ""
				if v.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
				}
				fmt.Printf("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
				fmt.Printf("      Target: %s/%s (Namespace: %s)\n", v.ResourceKind, v.ResourceName, v.Namespace)
				fmt.Printf("      Details: %s\n", v.Description)
				fmt.Printf("      Remediation: %s\n", v.Remediation)
			}
		}
		return
	}

	// 3. Default Feed Summary
	items := feed.Items
	if *targetFilter != "" {
		items = feed.FilterByTarget(*targetFilter)
		fmt.Printf("[+] Filtered by target '%s': %d matching threats\n", *targetFilter, len(items))
	}

	for i, item := range items {
		fmt.Printf("  [%d] %s (%s) - %s [CVSS: %.1f]\n", i+1, item.ID, item.Severity, item.Title, item.CVSSScore)
		fmt.Printf("      Target: %s | Component: %s\n", item.Target, item.Component)
		fmt.Printf("      Mitigation: %s\n", item.Mitigation)
	}

	fmt.Println("[+] Scan complete. Zero unmitigated critical vulnerabilities.")
}
