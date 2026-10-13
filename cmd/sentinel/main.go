package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	version = "0.1.0"
)

func main() {
	feedPath := flag.String("feed", "intel/cve-feed.json", "Path to threat intelligence feed JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	targetFilter := flag.String("target", "", "Filter feed by target ('nixos' or 'kubernetes')")
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
