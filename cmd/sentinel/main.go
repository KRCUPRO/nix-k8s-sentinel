package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/policy"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/report"
)

var (
	version = "0.7.0"
)

func main() {
	feedPath := flag.String("feed", "intel/cve-feed.json", "Path to threat intelligence feed JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	targetFilter := flag.String("target", "", "Filter feed by target ('nixos' or 'kubernetes')")
	flakePath := flag.String("flake", "", "Path to NixOS flake.lock to audit for known CVEs")
	k8sPath := flag.String("k8s", "", "Path to Kubernetes manifest file or directory to audit")
	briefing := flag.Bool("briefing", false, "Generate automated Markdown threat intelligence briefing")
	briefingDir := flag.String("briefing-dir", "intel/briefings", "Output directory for threat briefings")
	briefingFile := flag.String("briefing-file", "", "Custom filename for threat briefing markdown")
	policyOut := flag.String("policy-out", "", "Output directory to export synthesized Falco and OPA Gatekeeper security policies")
	policyEngine := flag.String("policy-engine", "all", "Policy engines to synthesize ('all', 'falco', 'gatekeeper')")
	enforceAction := flag.String("enforce-action", "deny", "OPA Gatekeeper enforcement action ('deny', 'dryrun', 'warn')")
	probeFlag := flag.Bool("probe", false, "Execute bare-metal eBPF kernel telemetry probe analysis")
	probeFixture := flag.String("probe-fixture", "fixtures/probe-telemetry.json", "Path to bare-metal probe events fixture JSON")
	probeNodes := flag.String("probe-nodes", "nixos-control-01,nixos-worker-01,nixos-worker-02", "Comma-separated list of bare-metal cluster node names")
	format := flag.String("format", "console", "Audit report output format ('console', 'json', 'sarif')")
	outFile := flag.String("output", "", "Output destination file for formatted report (defaults to stdout)")
	outShort := flag.String("o", "", "Shorthand for --output")
	flag.Parse()

	if *outFile == "" && *outShort != "" {
		*outFile = *outShort
	}

	if *showVersion {
		fmt.Printf("nix-k8s-sentinel v%s (Cloud-Native Threat Radar & Policy Synthesizer)\n", version)
		os.Exit(0)
	}

	isStdoutFormatted := (*format == "json" || *format == "sarif") && *outFile == ""
	logInfo := func(formatStr string, a ...any) {
		if isStdoutFormatted {
			return
		}
		fmt.Printf(formatStr, a...)
	}
	logErr := func(formatStr string, a ...any) {
		fmt.Fprintf(os.Stderr, formatStr, a...)
	}

	logInfo("[+] nix-k8s-sentinel v%s starting up...\n", version)

	data, err := os.ReadFile(*feedPath)
	if err != nil {
		logInfo("[-] Warning: Failed to read feed file (%s): %v\n", *feedPath, err)
		logInfo("[+] Initialized in dry-run monitoring mode.\n")
		os.Exit(0)
	}

	feed, err := intel.ParseFeed(data)
	if err != nil {
		logErr("[-] Error parsing feed: %v\n", err)
		os.Exit(1)
	}

	logInfo("[+] Feed Loaded: %d intelligence advisories (Updated: %s)\n", len(feed.Items), feed.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))

	var flakeMatches []nix.FlakeVulnerabilityMatch
	var k8sReport *k8s.ManifestAuditReport
	var probeSnapshots []probe.TelemetryEvent

	// 1. Audit Nix Flake if --flake is provided
	if *flakePath != "" {
		logInfo("[+] Auditing Nix Flake Lockfile: %s\n", *flakePath)
		lock, err := nix.ParseFlakeLockFile(*flakePath)
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
		flakeMatches = matches

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
	}

	// 2. Audit Kubernetes Manifests if --k8s is provided
	if *k8sPath != "" {
		logInfo("[+] Auditing Kubernetes Manifests: %s\n", *k8sPath)
		manifestScanner := k8s.NewManifestScanner(feed)

		fileInfo, err := os.Stat(*k8sPath)
		if err != nil {
			logErr("[-] Failed to inspect manifest path: %v\n", err)
			os.Exit(1)
		}

		if fileInfo.IsDir() {
			k8sReport, err = manifestScanner.ScanDirectory(*k8sPath)
		} else {
			k8sReport, err = manifestScanner.ScanFile(*k8sPath)
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
	}

	// 3. Synthesize Security Policies if --policy-out is specified
	if *policyOut != "" {
		logInfo("[+] Synthesizing Declarative Security Policies (Engine: %s, Action: %s)...\n", *policyEngine, *enforceAction)
		var violations []k8s.Violation
		if k8sReport != nil {
			violations = k8sReport.Violations
		}

		policyOpts := policy.DefaultSynthesisOptions()
		policyOpts.EnforcementAction = *enforceAction
		policyOpts.TargetEngines = []string{*policyEngine}

		policySet, err := policy.SynthesizePolicies(feed, violations, policyOpts)
		if err != nil {
			logErr("[-] Failed to synthesize security policies: %v\n", err)
			os.Exit(1)
		}

		written, err := policy.WritePoliciesToDir(policySet, *policyOut)
		if err != nil {
			logErr("[-] Failed to write security policies: %v\n", err)
			os.Exit(1)
		}

		logInfo("[+] Policy Synthesis Complete (Total: %d Falco Rules, %d Gatekeeper Templates, %d Constraints)\n",
			policySet.TotalFalcoRules, policySet.TotalOPAConstraintTemplates, policySet.TotalOPAConstraints)
		for engine, p := range written {
			logInfo("    -> [%s] Policy Exported: %s\n", engine, p)
		}
	}

	// 4. Run Bare-Metal eBPF Telemetry Probes if --probe is provided
	if *probeFlag {
		logInfo("[+] Initializing Bare-Metal eBPF Telemetry Engine...\n")
		rawNodes := strings.Split(*probeNodes, ",")
		var nodeList []string
		for _, n := range rawNodes {
			trimmed := strings.TrimSpace(n)
			if trimmed != "" {
				nodeList = append(nodeList, trimmed)
			}
		}

		var rawEvents []probe.TelemetryEvent
		if *probeFixture != "" {
			if _, err := os.Stat(*probeFixture); err == nil {
				loaded, err := probe.LoadEventsFromFile(*probeFixture)
				if err != nil {
					logErr("[-] Failed to load probe fixture (%s): %v\n", *probeFixture, err)
					os.Exit(1)
				}
				rawEvents = loaded
				logInfo("[+] Loaded %d telemetry records from fixture: %s\n", len(rawEvents), *probeFixture)
			}
		}

		mgr, err := probe.SimulateMultiNodeCluster(nodeList, feed, rawEvents)
		if err != nil {
			logErr("[-] Failed to initialize multi-node cluster simulation: %v\n", err)
			os.Exit(1)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if err := mgr.Start(ctx); err != nil {
			logErr("[-] Failed to start eBPF manager: %v\n", err)
			os.Exit(1)
		}

		time.Sleep(150 * time.Millisecond)

		if err := mgr.Stop(); err != nil {
			logErr("[-] Warning during eBPF probe shutdown: %v\n", err)
		}

		stats := mgr.Stats()
		probeSnapshots = mgr.Snapshot()

		logInfo("[+] Bare-Metal eBPF Probes Completed across %d nodes (Total Events: %d)\n", mgr.ActiveProbesCount(), stats.TotalEvents)
		logInfo("    Severity: Critical=%d | High=%d | Medium=%d | Low=%d | Info=%d\n",
			stats.CriticalCount, stats.HighCount, stats.MediumCount, stats.LowCount, stats.InfoCount)

		for _, ev := range probeSnapshots {
			if ev.RiskScore >= 7.0 || ev.Severity == "CRITICAL" || ev.Severity == "HIGH" {
				logInfo("  [!] [%s] %s on node %s: %s [Risk: %.1f]\n", ev.Severity, ev.EventType, ev.NodeName, ev.Message, ev.RiskScore)
				if len(ev.ThreatTags) > 0 {
					logInfo("      Tags: %s\n", strings.Join(ev.ThreatTags, ", "))
				}
			}
		}
	}

	// 5. Generate Threat Briefing if --briefing is requested
	if *briefing {
		logInfo("[+] Synthesizing Threat Intelligence Briefing...\n")
		briefingOpts := report.BriefingOptions{
			Version:        version,
			Feed:           feed,
			K8sReport:      k8sReport,
			FlakeMatches:   flakeMatches,
			ProbeEvents:    probeSnapshots,
			OutputDir:      *briefingDir,
			CustomFilename: *briefingFile,
		}

		rep, err := report.GenerateBriefing(briefingOpts)
		if err != nil {
			logErr("[-] Failed to generate threat briefing: %v\n", err)
			os.Exit(1)
		}

		savedPath, err := report.WriteBriefingToFile(rep, *briefingDir, *briefingFile)
		if err != nil {
			logErr("[-] Failed to save briefing file: %v\n", err)
			os.Exit(1)
		}

		logInfo("[+] Threat Briefing written to: %s\n", savedPath)
		logInfo("    Telemetry: Total=%d | Critical=%d | High=%d | Medium=%d | Low=%d\n",
			rep.Telemetry.TotalThreats,
			rep.Telemetry.CriticalCount,
			rep.Telemetry.HighCount,
			rep.Telemetry.MediumCount,
			rep.Telemetry.LowCount,
		)
		logInfo("    Fleet Risk: Peak CVSS=%.1f | Avg CVSS=%.1f\n", rep.Telemetry.MaxCVSS, rep.Telemetry.AverageCVSS)
		return
	}

	// 6. Handle Structured Formats (SARIF / JSON)
	if *format == "sarif" || *format == "json" {
		reportOpts := report.ReportOptions{
			Version:      version,
			Feed:         feed,
			K8sReport:    k8sReport,
			FlakeMatches: flakeMatches,
			ProbeEvents:  probeSnapshots,
			FlakePath:    *flakePath,
			K8sPath:      *k8sPath,
			TargetFilter: *targetFilter,
			Pretty:       true,
		}

		if *format == "sarif" {
			sarifLog, err := report.BuildSARIFReport(reportOpts)
			if err != nil {
				logErr("[-] Failed to build SARIF report: %v\n", err)
				os.Exit(1)
			}

			if *outFile != "" {
				if err := report.WriteSARIFToFile(sarifLog, *outFile, true); err != nil {
					logErr("[-] Failed to write SARIF report to %s: %v\n", *outFile, err)
					os.Exit(1)
				}
				fmt.Printf("[+] SARIF v2.1.0 security report written to: %s (Total Findings: %d)\n", *outFile, len(sarifLog.Runs[0].Results))
			} else {
				data, err := report.FormatSARIF(sarifLog, true)
				if err != nil {
					logErr("[-] Failed to format SARIF report: %v\n", err)
					os.Exit(1)
				}
				fmt.Println(string(data))
			}
			return
		}

		if *format == "json" {
			jsonReport, err := report.BuildJSONReport(reportOpts)
			if err != nil {
				logErr("[-] Failed to build JSON report: %v\n", err)
				os.Exit(1)
			}

			if *outFile != "" {
				if err := report.WriteJSONToFile(jsonReport, *outFile, true); err != nil {
					logErr("[-] Failed to write JSON report to %s: %v\n", *outFile, err)
					os.Exit(1)
				}
				fmt.Printf("[+] JSON security report written to: %s\n", *outFile)
			} else {
				data, err := report.FormatJSON(jsonReport, true)
				if err != nil {
					logErr("[-] Failed to format JSON report: %v\n", err)
					os.Exit(1)
				}
				fmt.Println(string(data))
			}
			return
		}
	}

	// 7. Default feed summary (when neither flake nor k8s nor policy nor probe was requested)
	if *flakePath == "" && *k8sPath == "" && *policyOut == "" && !*probeFlag {
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
}
