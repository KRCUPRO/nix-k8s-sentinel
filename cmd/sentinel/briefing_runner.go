package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/report"
)

// runBriefingExport handles Threat Briefing markdown generation and file persistence.
func runBriefingExport(cfg SentinelConfig, reportOpts report.ReportOptions, logInfo func(string, ...any), logErr func(string, ...any)) {
	logInfo("[+] Synthesizing Threat Intelligence Briefing...\n")
	briefingOpts := report.BriefingOptions{
		Version:                 reportOpts.Version,
		Feed:                    reportOpts.Feed,
		K8sReport:               reportOpts.K8sReport,
		FlakeMatches:            reportOpts.FlakeMatches,
		ProbeEvents:             reportOpts.ProbeEvents,
		StorageViolations:       reportOpts.StorageViolations,
		StorageHealth:           reportOpts.StorageHealth,
		WireGuardViolations:     reportOpts.WireGuardViolations,
		WireGuardReconciliation: reportOpts.WireGuardReconciliation,
		CISViolations:           reportOpts.CISViolations,
		CISSummary:              reportOpts.CISSummary,
		GatewayViolations:       reportOpts.GatewayViolations,
		GatewaySummary:          reportOpts.GatewaySummary,
		AttestViolations:        reportOpts.AttestViolations,
		AttestSummary:           reportOpts.AttestSummary,
		FleetViolations:         reportOpts.FleetViolations,
		FleetSummary:            reportOpts.FleetSummary,
		SPIFFEViolations:        reportOpts.SPIFFEViolations,
		SPIFFESummary:           reportOpts.SPIFFESummary,
		SBOMViolations:          reportOpts.SBOMViolations,
		SBOMSummary:             reportOpts.SBOMSummary,
		SBOMDelta:               reportOpts.SBOMDelta,
		HSMViolations:           reportOpts.HSMViolations,
		HSMSummary:              reportOpts.HSMSummary,
		BPFViolations:           reportOpts.BPFViolations,
		BPFSummary:              reportOpts.BPFSummary,
		PQCViolations:           reportOpts.PQCViolations,
		PQCSummary:              reportOpts.PQCSummary,
		SandboxViolations:       reportOpts.SandboxViolations,
		SandboxSummary:          reportOpts.SandboxSummary,
		RemediateFindings:       reportOpts.RemediateFindings,
		RemediatePullRequests:   reportOpts.RemediatePullRequests,
		RemediateSummary:        reportOpts.RemediateSummary,
		LSMViolations:           reportOpts.LSMViolations,
		LSMSummary:              reportOpts.LSMSummary,
		ReplicationViolations:   reportOpts.ReplicationViolations,
		ReplicationSummary:      reportOpts.ReplicationSummary,
		FastPathViolations:      reportOpts.FastPathViolations,
		FastPathSummary:         reportOpts.FastPathSummary,
		FastPathTelemetry:       reportOpts.FastPathTelemetry,
		EnclaveViolations:       reportOpts.EnclaveViolations,
		EnclaveSummary:          reportOpts.EnclaveSummary,
		EnclaveReports:          reportOpts.EnclaveReports,
		WebhookViolations:       reportOpts.WebhookViolations,
		WebhookSummary:          reportOpts.WebhookSummary,
		WebhookTelemetry:        reportOpts.WebhookTelemetry,
		ImpermanenceViolations:  reportOpts.ImpermanenceViolations,
		ImpermanenceSummary:     reportOpts.ImpermanenceSummary,
		ImpermanenceTelemetry:   reportOpts.ImpermanenceTelemetry,
		BGPViolations:           reportOpts.BGPViolations,
		BGPSummary:              reportOpts.BGPSummary,
		BGPTelemetry:            reportOpts.BGPTelemetry,
		StoreViolations:         reportOpts.StoreViolations,
		StoreSummary:            reportOpts.StoreSummary,
		StoreTelemetry:          reportOpts.StoreTelemetry,
		LockdownViolations:      reportOpts.LockdownViolations,
		LockdownSummary:         reportOpts.LockdownSummary,
		LockdownTelemetry:       reportOpts.LockdownTelemetry,
		FlowViolations:          reportOpts.FlowViolations,
		FlowSummary:             reportOpts.FlowSummary,
		FlowTelemetry:           reportOpts.FlowTelemetry,
		MeshViolations:          reportOpts.MeshViolations,
		MeshSummary:             reportOpts.MeshSummary,
		MeshTelemetry:           reportOpts.MeshTelemetry,
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
		rep.Telemetry.TotalThreats, rep.Telemetry.CriticalCount, rep.Telemetry.HighCount, rep.Telemetry.MediumCount, rep.Telemetry.LowCount)
	logInfo("    Fleet Risk: Peak CVSS=%.1f | Avg CVSS=%.1f\n", rep.Telemetry.MaxCVSS, rep.Telemetry.AverageCVSS)
}
