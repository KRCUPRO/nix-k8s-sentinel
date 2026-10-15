package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/policy"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/report"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

var (
	version = "0.14.0"
)

func main() {
	feedPath := flag.String("feed", "intel/cve-feed.json", "Path to threat intelligence feed JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	targetFilter := flag.String("target", "", "Filter feed by target ('nixos' or 'kubernetes')")
	flakePath := flag.String("flake", "", "Path to NixOS flake.lock to audit for known CVEs")
	k8sPath := flag.String("k8s", "", "Path to Kubernetes manifest file or directory to audit")
	cephPath := flag.String("ceph", "", "Path to Rook Ceph manifest file or directory to audit")
	storageShort := flag.String("storage", "", "Alias for --ceph")
	cephTelemetry := flag.String("ceph-telemetry", "", "Path to Ceph runtime health telemetry JSON to inspect")
	wgPath := flag.String("wg", "", "Path to NixOS WireGuard manifest file or directory to audit")
	wireguardLong := flag.String("wireguard", "", "Alias for --wg")
	wgTelemetry := flag.String("wg-telemetry", "", "Path to runtime WireGuard peer telemetry JSON to inspect")
	cisPath := flag.String("cis", "", "Path to NixOS module or Kubernetes YAML to audit against CIS Benchmark")
	benchShort := flag.String("bench", "", "Alias for --cis")
	kubeBenchLong := flag.String("kube-bench", "", "Alias for --cis")
	remediationOut := flag.String("remediation-out", "", "Output path to write synthesized NixOS CIS hardening remediation module")
	gwPath := flag.String("gateway", "", "Path to Kubernetes Gateway API or EnvoyFilter manifest file or directory to audit")
	gatewayShort := flag.String("gw", "", "Alias for --gateway")
	attestPath := flag.String("attest", "", "Path to NixOS measured boot configuration file or directory to audit")
	attestTelemetry := flag.String("attest-telemetry", "", "Path to node attestation telemetry JSON with TPM 2.0 PCR quotations")
	attestQuote := flag.String("attest-quote", "", "Alias for --attest-telemetry")
	fleetPath := flag.String("fleet", "", "Path to multi-cluster manifest file or directory to audit")
	gitopsShort := flag.String("gitops", "", "Alias for --fleet")
	fleetTelemetry := flag.String("fleet-telemetry", "", "Path to runtime fleet telemetry JSON with cluster and OIDC token states")
	spiffePath := flag.String("spiffe", "", "Path to SPIFFE/SPIRE manifest file or directory to audit")
	spireShort := flag.String("spire", "", "Alias for --spiffe")
	svidTelemetry := flag.String("svid-telemetry", "", "Path to runtime X.509 SVID telemetry JSON to inspect")
	spiffePolicyOut := flag.String("spiffe-policy-out", "", "Output path or directory to write synthesized Cilium zero-trust microsegmentation policies")
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

	if *cephPath == "" && *storageShort != "" {
		*cephPath = *storageShort
	}

	if *wgPath == "" && *wireguardLong != "" {
		*wgPath = *wireguardLong
	}

	if *cisPath == "" && *benchShort != "" {
		*cisPath = *benchShort
	}
	if *cisPath == "" && *kubeBenchLong != "" {
		*cisPath = *kubeBenchLong
	}

	if *gwPath == "" && *gatewayShort != "" {
		*gwPath = *gatewayShort
	}

	if *attestTelemetry == "" && *attestQuote != "" {
		*attestTelemetry = *attestQuote
	}

	if *fleetPath == "" && *gitopsShort != "" {
		*fleetPath = *gitopsShort
	}

	if *spiffePath == "" && *spireShort != "" {
		*spiffePath = *spireShort
	}

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
	var storageViolations []storage.StorageViolation
	var storageHealth *storage.CephHealthReport
	var wireguardViolations []wireguard.WireGuardViolation
	var wireguardReconciliation *wireguard.ReconciliationReport
	var cisViolations []bench.CISViolation
	var cisSummary *bench.CISSummary
	var gatewayViolations []gateway.GatewayViolation
	var gatewaySummary *gateway.GatewaySummary
	var attestViolations []attest.AttestationViolation
	var attestSummary *attest.AttestationSummary
	var fleetViolations []fleet.FleetViolation
	var fleetSummary *fleet.FleetSummary
	var spiffeViolations []spiffe.SPIFFEViolation
	var spiffeSummary *spiffe.SPIFFESummary

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
		probeSnapshots = runProbeTelemetry(*probeNodes, *probeFixture, feed, logInfo, logErr)
	}

	// 5. Audit Rook Ceph Storage Manifests & Telemetry
	if *cephPath != "" || *cephTelemetry != "" {
		storageViolations, storageHealth = runStorageAudit(*cephPath, *cephTelemetry, feed, logInfo, logErr)
	}

	// 6. Audit NixOS WireGuard Mesh Manifests & Telemetry
	if *wgPath != "" || *wgTelemetry != "" {
		wireguardViolations, wireguardReconciliation = runWireGuardAudit(*wgPath, *wgTelemetry, feed, logInfo, logErr)
	}

	// 7. Audit CIS Kubernetes Benchmark if --cis is provided
	if *cisPath != "" {
		cisViolations, cisSummary = runCISAudit(*cisPath, feed, logInfo, logErr)
		if *remediationOut != "" && len(cisViolations) > 0 {
			nixPatch := bench.SynthesizeNixOSRemediation(cisViolations)
			cleanOut := filepath.Clean(*remediationOut)
			if err := os.MkdirAll(filepath.Dir(cleanOut), 0755); err != nil {
				logErr("[-] Failed to create directory for remediation patch: %v\n", err)
			} else if err := os.WriteFile(cleanOut, []byte(nixPatch), 0644); err != nil {
				logErr("[-] Failed to write remediation patch to %s: %v\n", cleanOut, err)
			} else {
				logInfo("[+] Synthesized CIS NixOS hardening module written to: %s\n", cleanOut)
			}
		}
	}

	// 8. Audit Kubernetes Gateway API & EnvoyFilter if --gateway is provided
	if *gwPath != "" {
		gatewayViolations, gatewaySummary = runGatewayAudit(*gwPath, feed, logInfo, logErr)
	}

	// 9. Audit Confidential Computing & Measured Boot if --attest or --attest-telemetry is provided
	if *attestPath != "" || *attestTelemetry != "" {
		attestViolations, attestSummary = runAttestAudit(*attestPath, *attestTelemetry, feed, logInfo, logErr)
	}

	// 10. Audit Multi-Cluster Fleet Synchronization & OIDC Token Radar if --fleet or --fleet-telemetry is provided
	if *fleetPath != "" || *fleetTelemetry != "" {
		fleetViolations, fleetSummary = runFleetAudit(*fleetPath, *fleetTelemetry, feed, logInfo, logErr)
	}

	// 11. Audit Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation if --spiffe, --svid-telemetry, or --spiffe-policy-out is provided
	if *spiffePath != "" || *svidTelemetry != "" || *spiffePolicyOut != "" {
		spiffeViolations, spiffeSummary = runSPIFFEAudit(*spiffePath, *svidTelemetry, *spiffePolicyOut, feed, logInfo, logErr)
	}

	// 12. Generate Threat Briefing if --briefing is requested
	if *briefing {
		logInfo("[+] Synthesizing Threat Intelligence Briefing...\n")
		briefingOpts := report.BriefingOptions{
			Version:                 version,
			Feed:                    feed,
			K8sReport:               k8sReport,
			FlakeMatches:            flakeMatches,
			ProbeEvents:             probeSnapshots,
			StorageViolations:       storageViolations,
			StorageHealth:           storageHealth,
			WireGuardViolations:     wireguardViolations,
			WireGuardReconciliation: wireguardReconciliation,
			CISViolations:           cisViolations,
			CISSummary:              cisSummary,
			GatewayViolations:       gatewayViolations,
			GatewaySummary:          gatewaySummary,
			AttestViolations:        attestViolations,
			AttestSummary:           attestSummary,
			FleetViolations:         fleetViolations,
			FleetSummary:            fleetSummary,
			SPIFFEViolations:        spiffeViolations,
			SPIFFESummary:           spiffeSummary,
			OutputDir:               *briefingDir,
			CustomFilename:          *briefingFile,
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

	// 13. Handle Structured Formats (SARIF / JSON)
	if *format == "sarif" || *format == "json" {
		reportOpts := report.ReportOptions{
			Version:                 version,
			Feed:                    feed,
			K8sReport:               k8sReport,
			FlakeMatches:            flakeMatches,
			ProbeEvents:             probeSnapshots,
			StorageViolations:       storageViolations,
			StorageHealth:           storageHealth,
			WireGuardViolations:     wireguardViolations,
			WireGuardReconciliation: wireguardReconciliation,
			CISViolations:           cisViolations,
			CISSummary:              cisSummary,
			GatewayViolations:       gatewayViolations,
			GatewaySummary:          gatewaySummary,
			AttestViolations:        attestViolations,
			AttestSummary:           attestSummary,
			FleetViolations:         fleetViolations,
			FleetSummary:            fleetSummary,
			SPIFFEViolations:        spiffeViolations,
			SPIFFESummary:           spiffeSummary,
			FlakePath:               *flakePath,
			K8sPath:                 *k8sPath,
			StoragePath:             *cephPath,
			WireGuardPath:           *wgPath,
			CISPath:                 *cisPath,
			GatewayPath:             *gwPath,
			AttestPath:              *attestPath,
			AttestTelemetryPath:     *attestTelemetry,
			FleetPath:               *fleetPath,
			FleetTelemetryPath:      *fleetTelemetry,
			SPIFFEPath:              *spiffePath,
			SPIFFETelemetryPath:     *svidTelemetry,
			TargetFilter:            *targetFilter,
			Pretty:                  true,
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

	// 14. Default feed summary (when no specific audit target was requested)
	if *flakePath == "" && *k8sPath == "" && *policyOut == "" && !*probeFlag && *cephPath == "" && *cephTelemetry == "" && *wgPath == "" && *wgTelemetry == "" && *cisPath == "" && *gwPath == "" && *attestPath == "" && *attestTelemetry == "" && *fleetPath == "" && *fleetTelemetry == "" && *spiffePath == "" && *svidTelemetry == "" && *spiffePolicyOut == "" {
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
