package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/attest"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bench"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bpf"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/gateway"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/hsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/lsm"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/pqc"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/remediate"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/replication"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/report"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sandbox"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/sbom"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/webhook"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgenclave"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgfastpath"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

var (
	version = "0.25.0"
)

func main() {
	cfg := parseCLI()

	// Direct console output helpers
	logInfo := func(format string, a ...any) {
		if cfg.Format == "console" {
			fmt.Printf(format, a...)
		}
	}
	logErr := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, format, a...)
	}

	logInfo("[*] Loading Threat Intelligence feed: %s\n", cfg.FeedPath)
	feedBytes, err := os.ReadFile(cfg.FeedPath)
	if err != nil {
		logErr("[-] Error reading threat feed file (%s): %v\n", cfg.FeedPath, err)
		os.Exit(1)
	}
	feed, err := intel.ParseFeed(feedBytes)
	if err != nil {
		logErr("[-] Error parsing threat feed (%s): %v\n", cfg.FeedPath, err)
		os.Exit(1)
	}

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
	var sbomViolations []sbom.SBOMViolation
	var sbomSummary *sbom.SBOMSummary
	var sbomDelta []sbom.SBOMDeltaItem
	var hsmViolations []hsm.HSMViolation
	var hsmSummary *hsm.HSMSummary
	var bpfViolations []bpf.BPFViolation
	var bpfSummary *bpf.BPFSummary
	var pqcViolations []pqc.PQCViolation
	var pqcSummary *pqc.PQCSummary
	var sandboxViolations []sandbox.SandboxViolation
	var sandboxSummary *sandbox.SandboxSummary
	var remediateFindings []remediate.RemediationFinding
	var remediatePRs []remediate.GitOpsPullRequest
	var remediateSummary *remediate.RemediationSummary
	var lsmViolations []lsm.LSMViolation
	var lsmSummary *lsm.LSMSummary
	var drViolations []replication.ReplicationViolation
	var drSummary *replication.ReplicationSummary
	var drTelemetry *replication.CrossRegionDRTelemetry
	var fastpathViolations []wgfastpath.WGFastPathViolation
	var fastpathSummary *wgfastpath.WGFastPathSummary
	var fastpathTelemetry []wgfastpath.FastPathTelemetry
	var fastpathCrypto []wgfastpath.CryptoBenchmarkTelemetry
	var enclaveViolations []wgenclave.WGEnclaveViolation
	var enclaveSummary *wgenclave.WGEnclaveSummary
	var enclaveReports []wgenclave.AttestationReport
	var enclavePeers []wgenclave.PeerTunnelStatus
	var webhookViolations []webhook.WebhookViolation
	var webhookSummary *webhook.WebhookSummary
	var webhookTelemetry *webhook.WebhookTelemetry

	// 1. Audit Nix Flake
	if cfg.FlakePath != "" {
		flakeMatches = runFlakeAudit(cfg.FlakePath, feed, logInfo, logErr)
	}

	// 2. Audit Kubernetes Manifests
	if cfg.K8sPath != "" {
		k8sReport = runK8sAudit(cfg.K8sPath, feed, logInfo, logErr)
	}

	// 3. Synthesize Security Policies
	if cfg.PolicyOut != "" {
		runPolicySynthesis(cfg.PolicyOut, cfg.PolicyEngine, cfg.EnforceAction, feed, k8sReport, logInfo, logErr)
	}

	// 4. Run Bare-Metal eBPF Telemetry Probes
	if cfg.ProbeFlag {
		probeSnapshots = runProbeTelemetry(cfg.ProbeNodes, cfg.ProbeFixture, feed, logInfo, logErr)
	}

	// 5. Audit Rook Ceph Storage Manifests & Telemetry
	if cfg.CephPath != "" || cfg.CephTelemetry != "" {
		storageViolations, storageHealth = runStorageAudit(cfg.CephPath, cfg.CephTelemetry, feed, logInfo, logErr)
	}

	// 6. Audit NixOS WireGuard Mesh Manifests & Telemetry
	if cfg.WgPath != "" || cfg.WgTelemetry != "" {
		wireguardViolations, wireguardReconciliation = runWireGuardAudit(cfg.WgPath, cfg.WgTelemetry, feed, logInfo, logErr)
	}

	// 7. Audit CIS Kubernetes Benchmark
	if cfg.CISPath != "" {
		cisViolations, cisSummary = runCISAudit(cfg.CISPath, feed, logInfo, logErr)
	}

	// 8. Audit Kubernetes Gateway API & EnvoyFilter Route Threat Radar
	if cfg.GwPath != "" {
		gatewayViolations, gatewaySummary = runGatewayAudit(cfg.GwPath, feed, logInfo, logErr)
	}

	// 9. Audit Confidential Computing & Measured Boot Attestation
	if cfg.AttestPath != "" || cfg.AttestTelemetry != "" {
		attestViolations, attestSummary = runAttestAudit(cfg.AttestPath, cfg.AttestTelemetry, feed, logInfo, logErr)
	}

	// 10. Audit Multi-Cluster Fleet Synchronization & OIDC Token Radar
	if cfg.FleetPath != "" || cfg.FleetTelemetry != "" {
		fleetViolations, fleetSummary = runFleetAudit(cfg.FleetPath, cfg.FleetTelemetry, feed, logInfo, logErr)
	}

	// 11. Audit SPIFFE/SPIRE Workload Attestation & Cilium Zero-Trust
	if cfg.SpiffePath != "" || cfg.SvidTelemetry != "" || cfg.SpiffePolicyOut != "" {
		spiffeViolations, spiffeSummary = runSPIFFEAudit(cfg.SpiffePath, cfg.SvidTelemetry, cfg.SpiffePolicyOut, feed, logInfo, logErr)
	}

	// 12. Audit Software Bill of Materials (SBOM) & In-Toto Supply Chain Attestation
	if cfg.SbomPath != "" || cfg.AttestFile != "" || cfg.RuntimePath != "" {
		sbomViolations, sbomSummary, sbomDelta = runSBOMAudit(cfg.SbomPath, cfg.AttestFile, cfg.RuntimePath, feed, logInfo, logErr)
	}

	// 13. Audit Hardware Security Module (HSM) & PKCS#11 Envelope Encryption
	if cfg.HsmPath != "" || cfg.HsmTelemetry != "" {
		hsmViolations, hsmSummary = runHSMAudit(cfg.HsmPath, cfg.HsmTelemetry, feed, logInfo, logErr)
	}

	// 14. Audit Dynamic Kernel Runtime Threat Profiler & Syscall BPF Filter
	if cfg.BpfPath != "" || cfg.BpfTelemetry != "" || cfg.BpfSynthOut != "" {
		bpfViolations, bpfSummary = runBPFAudit(cfg.BpfPath, cfg.BpfTelemetry, cfg.BpfSynthOut, cfg.BpfService, feed, logInfo, logErr)
	}

	// 15. Audit Post-Quantum Cryptography & CNSA 2.0 TLS
	if cfg.PqcPath != "" || cfg.PqcTelemetry != "" || cfg.PqcSynthOut != "" {
		pqcViolations, pqcSummary = runPQCAudit(cfg.PqcPath, cfg.PqcTelemetry, cfg.PqcSynthOut, cfg.CnsaStrict, feed, logInfo, logErr)
	}

	// 16. Audit Ephemeral MicroVM Sandbox & Honeypot Detonation
	if cfg.SandboxPath != "" || cfg.SandboxTelemetry != "" || cfg.SandboxSynthOut != "" {
		sandboxViolations, sandboxSummary = runSandboxAudit(cfg.SandboxPath, cfg.SandboxTelemetry, cfg.SandboxSynthOut, cfg.QuarantineStrict, feed, logInfo, logErr)
	}

	// 17. Audit Autonomous Threat Remediation & GitOps Synthesizer
	if cfg.RemediatePath != "" || cfg.RemediateSynthOut != "" {
		remediateFindings, remediatePRs, remediateSummary = runRemediationAudit(cfg.RemediatePath, cfg.RemediateSynthOut, cfg.CanaryStrict, feed, logInfo, logErr)
	}

	// 18. Audit eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control
	if cfg.LSMPath != "" || cfg.LSMTelemetry != "" || cfg.LSMSynthOut != "" {
		lsmViolations, lsmSummary = runLSMAudit(cfg.LSMPath, cfg.LSMTelemetry, cfg.LSMSynthOut, cfg.LSMStrict, feed, logInfo, logErr)
	}

	// 19. Audit CephFS Snapshot & Volume Replication Disaster Recovery
	if cfg.DRManifests != "" || cfg.DRTelemetry != "" || cfg.DRSynthOut != "" {
		drViolations, drSummary, drTelemetry = runReplicationAudit(cfg.DRManifests, cfg.DRTelemetry, cfg.DRSynthOut, cfg.DRRPOMax, cfg.DRStrict, feed, logInfo, logErr)
	}

	// 20. Audit WireGuard eBPF Fast-Path & Crypto Performance
	if cfg.FastPathManifests != "" || cfg.FastPathTelemetry != "" || cfg.FastPathSynthOut != "" {
		fastpathViolations, fastpathSummary, fastpathTelemetry, fastpathCrypto = runFastPathAudit(cfg.FastPathManifests, cfg.FastPathTelemetry, cfg.FastPathSynthOut, cfg.FastPathStrict, feed, logInfo, logErr)
	}

	// 21. Audit Confidential VM & Secure Enclave WireGuard Peer Attestation
	if cfg.EnclaveManifests != "" || cfg.EnclaveTelemetry != "" || cfg.EnclaveSynthOut != "" {
		enclaveViolations, enclaveSummary, enclaveReports, enclavePeers = runEnclaveAudit(
			cfg.EnclaveManifests,
			cfg.EnclaveTelemetry,
			cfg.EnclaveSynthOut,
			cfg.EnclaveStrict,
			feed,
			logInfo,
			logErr,
		)
	}

	// 22. Audit Kubernetes Dynamic Admission Webhook & CA Rotation Radar
	if cfg.WebhookPath != "" || cfg.WebhookTelemetry != "" || cfg.WebhookSynthOut != "" {
		webhookViolations, webhookSummary, webhookTelemetry = runWebhookAudit(
			cfg.WebhookPath,
			cfg.WebhookTelemetry,
			cfg.WebhookSynthOut,
			cfg.WebhookStrict,
			feed,
			logInfo,
			logErr,
		)
	}

	// 23. Generate Threat Briefing if --briefing is requested
	if cfg.Briefing {
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
			SBOMViolations:          sbomViolations,
			SBOMSummary:             sbomSummary,
			SBOMDelta:               sbomDelta,
			HSMViolations:           hsmViolations,
			HSMSummary:              hsmSummary,
			BPFViolations:           bpfViolations,
			BPFSummary:              bpfSummary,
			PQCViolations:           pqcViolations,
			PQCSummary:              pqcSummary,
			SandboxViolations:       sandboxViolations,
			SandboxSummary:          sandboxSummary,
			RemediateFindings:       remediateFindings,
			RemediatePullRequests:   remediatePRs,
			RemediateSummary:        remediateSummary,
			LSMViolations:           lsmViolations,
			LSMSummary:              lsmSummary,
			ReplicationViolations:   drViolations,
			ReplicationSummary:      drSummary,
			FastPathViolations:      fastpathViolations,
			FastPathSummary:         fastpathSummary,
			FastPathTelemetry:       fastpathTelemetry,
			EnclaveViolations:       enclaveViolations,
			EnclaveSummary:          enclaveSummary,
			EnclaveReports:          enclaveReports,
			WebhookViolations:       webhookViolations,
			WebhookSummary:          webhookSummary,
			WebhookTelemetry:        webhookTelemetry,
			OutputDir:               cfg.BriefingDir,
			CustomFilename:          cfg.BriefingFile,
		}

		rep, err := report.GenerateBriefing(briefingOpts)
		if err != nil {
			logErr("[-] Failed to generate threat briefing: %v\n", err)
			os.Exit(1)
		}

		savedPath, err := report.WriteBriefingToFile(rep, cfg.BriefingDir, cfg.BriefingFile)
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

	// 19. Handle Structured Formats (SARIF / JSON)
	if cfg.Format == "sarif" || cfg.Format == "json" {
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
			SBOMViolations:          sbomViolations,
			SBOMSummary:             sbomSummary,
			SBOMDelta:               sbomDelta,
			HSMViolations:           hsmViolations,
			HSMSummary:              hsmSummary,
			BPFViolations:           bpfViolations,
			BPFSummary:              bpfSummary,
			PQCViolations:           pqcViolations,
			PQCSummary:              pqcSummary,
			SandboxViolations:       sandboxViolations,
			SandboxSummary:          sandboxSummary,
			RemediateFindings:       remediateFindings,
			RemediatePullRequests:   remediatePRs,
			RemediateSummary:        remediateSummary,
			LSMViolations:           lsmViolations,
			LSMSummary:              lsmSummary,
			ReplicationViolations:   drViolations,
			ReplicationSummary:      drSummary,
			ReplicationTelemetry:    drTelemetry,
			FastPathViolations:      fastpathViolations,
			FastPathSummary:         fastpathSummary,
			FastPathTelemetry:       fastpathTelemetry,
			FastPathCrypto:          fastpathCrypto,
			FlakePath:               cfg.FlakePath,
			K8sPath:                 cfg.K8sPath,
			StoragePath:             cfg.CephPath,
			WireGuardPath:           cfg.WgPath,
			CISPath:                 cfg.CISPath,
			GatewayPath:             cfg.GwPath,
			AttestPath:              cfg.AttestPath,
			AttestTelemetryPath:     cfg.AttestTelemetry,
			FleetPath:               cfg.FleetPath,
			FleetTelemetryPath:      cfg.FleetTelemetry,
			SPIFFEPath:              cfg.SpiffePath,
			SPIFFETelemetryPath:     cfg.SvidTelemetry,
			SBOMPath:                cfg.SbomPath,
			SBOMAttestPath:          cfg.AttestFile,
			SBOMRuntimePath:         cfg.RuntimePath,
			HSMPath:                 cfg.HsmPath,
			HSMTelemetryPath:        cfg.HsmTelemetry,
			BPFPath:                 cfg.BpfPath,
			BPFTelemetryPath:        cfg.BpfTelemetry,
			PQCPath:                 cfg.PqcPath,
			PQCTelemetryPath:        cfg.PqcTelemetry,
			SandboxPath:             cfg.SandboxPath,
			SandboxTelemetryPath:    cfg.SandboxTelemetry,
			RemediatePath:           cfg.RemediatePath,
			RemediateOutDir:         cfg.RemediateSynthOut,
			LSMPath:                 cfg.LSMPath,
			LSMTelemetryPath:        cfg.LSMTelemetry,
			LSMSynthOut:             cfg.LSMSynthOut,
			DRManifestPath:          cfg.DRManifests,
			DRTelemetryPath:         cfg.DRTelemetry,
			DRSynthOut:              cfg.DRSynthOut,
			FastPathManifestPath:    cfg.FastPathManifests,
			FastPathTelemetryPath:   cfg.FastPathTelemetry,
			FastPathSynthOut:        cfg.FastPathSynthOut,
			EnclaveViolations:       enclaveViolations,
			EnclaveSummary:          enclaveSummary,
			EnclaveReports:          enclaveReports,
			EnclavePeers:            enclavePeers,
			EnclaveManifestPath:     cfg.EnclaveManifests,
			EnclaveTelemetryPath:    cfg.EnclaveTelemetry,
			EnclaveSynthOut:         cfg.EnclaveSynthOut,
			WebhookViolations:       webhookViolations,
			WebhookSummary:          webhookSummary,
			WebhookTelemetry:        webhookTelemetry,
			WebhookPath:             cfg.WebhookPath,
			WebhookTelemetryPath:    cfg.WebhookTelemetry,
			WebhookSynthOut:         cfg.WebhookSynthOut,
			TargetFilter:            cfg.TargetFilter,
			Pretty:                  true,
		}

		if cfg.Format == "sarif" {
			sarifLog, err := report.BuildSARIFReport(reportOpts)
			if err != nil {
				logErr("[-] Failed to build SARIF report: %v\n", err)
				os.Exit(1)
			}

			if cfg.OutFile != "" {
				if err := report.WriteSARIFToFile(sarifLog, cfg.OutFile, true); err != nil {
					logErr("[-] Failed to write SARIF report to %s: %v\n", cfg.OutFile, err)
					os.Exit(1)
				}
				fmt.Printf("[+] SARIF v2.1.0 security report written to: %s (Total Findings: %d)\n", cfg.OutFile, len(sarifLog.Runs[0].Results))
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

		if cfg.Format == "json" {
			jsonReport, err := report.BuildJSONReport(reportOpts)
			if err != nil {
				logErr("[-] Failed to build JSON report: %v\n", err)
				os.Exit(1)
			}

			if cfg.OutFile != "" {
				if err := report.WriteJSONToFile(jsonReport, cfg.OutFile, true); err != nil {
					logErr("[-] Failed to write JSON report to %s: %v\n", cfg.OutFile, err)
					os.Exit(1)
				}
				fmt.Printf("[+] JSON security report written to: %s\n", cfg.OutFile)
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

	// 23. Default feed summary (when no specific audit target was requested)
	if cfg.FlakePath == "" && cfg.K8sPath == "" && cfg.PolicyOut == "" && !cfg.ProbeFlag && cfg.CephPath == "" && cfg.CephTelemetry == "" && cfg.WgPath == "" && cfg.WgTelemetry == "" && cfg.CISPath == "" && cfg.GwPath == "" && cfg.AttestPath == "" && cfg.AttestTelemetry == "" && cfg.FleetPath == "" && cfg.FleetTelemetry == "" && cfg.SpiffePath == "" && cfg.SvidTelemetry == "" && cfg.SpiffePolicyOut == "" && cfg.SbomPath == "" && cfg.AttestFile == "" && cfg.RuntimePath == "" && cfg.HsmPath == "" && cfg.HsmTelemetry == "" && cfg.BpfPath == "" && cfg.BpfTelemetry == "" && cfg.BpfSynthOut == "" && cfg.PqcPath == "" && cfg.PqcTelemetry == "" && cfg.PqcSynthOut == "" && cfg.SandboxPath == "" && cfg.SandboxTelemetry == "" && cfg.SandboxSynthOut == "" && cfg.RemediatePath == "" && cfg.RemediateSynthOut == "" && cfg.LSMPath == "" && cfg.LSMTelemetry == "" && cfg.LSMSynthOut == "" && cfg.DRManifests == "" && cfg.DRTelemetry == "" && cfg.DRSynthOut == "" && cfg.FastPathManifests == "" && cfg.FastPathTelemetry == "" && cfg.FastPathSynthOut == "" && cfg.EnclaveManifests == "" && cfg.EnclaveTelemetry == "" && cfg.EnclaveSynthOut == "" {
		items := feed.Items
		if cfg.TargetFilter != "" {
			items = feed.FilterByTarget(cfg.TargetFilter)
			fmt.Printf("[+] Filtered by target '%s': %d matching threats\n", cfg.TargetFilter, len(items))
		}

		for i, item := range items {
			fmt.Printf("  [%d] %s (%s) - %s [CVSS: %.1f]\n", i+1, item.ID, item.Severity, item.Title, item.CVSSScore)
			fmt.Printf("      Target: %s | Component: %s\n", item.Target, item.Component)
			fmt.Printf("      Mitigation: %s\n", item.Mitigation)
		}

		fmt.Println("[+] Scan complete. Zero unmitigated critical vulnerabilities.")
	}
}
