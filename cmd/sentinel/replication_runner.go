package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/replication"
)

// runReplicationAudit coordinates CephFS snapshot scheduling, volume replication, and cross-region DR auditing.
func runReplicationAudit(manifestPath, telemetryPath, synthOut string, rpoMax int, drStrict bool, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]replication.ReplicationViolation, *replication.ReplicationSummary, *replication.CrossRegionDRTelemetry) {
	if manifestPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := replication.NewReplicationScanner(feed)
	rep, err := scanner.AuditAll(manifestPath, telemetryPath)
	if err != nil {
		logErr("[-] Failed to audit CephFS DR manifests/telemetry: %v\n", err)
		os.Exit(1)
	}

	if manifestPath != "" {
		logInfo("[+] Audited CephFS & Volume Replication Manifests: %s (%d files scanned)\n", manifestPath, rep.TotalFiles)
	}

	if telemetryPath != "" {
		logInfo("[+] Reconciled Cross-Region DR Telemetry: %s\n", telemetryPath)
		if rep.Telemetry != nil {
			logInfo("    Primary: %s (%s) <-> Peer: %s (%s) | Total Volumes: %d (In-Sync: %d, Lagging: %d)\n",
				rep.Telemetry.PrimaryClusterID, rep.Telemetry.PrimaryRegion, rep.Telemetry.PeerClusterID, rep.Telemetry.PeerRegion,
				rep.Telemetry.TotalVolumes, rep.Telemetry.InSyncCount, rep.Telemetry.LaggingCount)
		}
	}

	if len(rep.Violations) > 0 {
		logInfo("[-] Identified %d CephFS DR & Volume Replication posture violations:\n", len(rep.Violations))
		for i, v := range rep.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s/%s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.ResourceKind, v.ResourceName, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero CephFS snapshot or volume replication DR violations detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened CephFS Snapshot & VolumeReplication Policies into: %s\n", synthOut)
		if err := replication.WriteSyntheticPoliciesToDir(synthOut); err != nil {
			logErr("[-] Failed to synthesize DR policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated VolumeSnapshotClass, CephFilesystemSubVolumeGroup, and VolumeReplication pairs.\n")
	}

	if rep.Summary != nil {
		splitBadge := "CLEAN"
		if rep.Summary.SplitBrainDetected {
			splitBadge = "SPLIT-BRAIN DETECTED"
		}
		logInfo("[+] CephFS DR Posture: %s (Score: %.1f%% | Split-Brain: %s | Max Lag: %ds)\n",
			rep.Summary.Status, rep.Summary.Score, splitBadge, rep.Summary.MaxDeltaLagSeconds)

		if drStrict && rep.Summary.Status == "NON_COMPLIANT" {
			logErr("[-] FATAL: CephFS DR posture NON_COMPLIANT in strict mode (Split-Brain or Critical RPO violation)\n")
			os.Exit(1)
		}
	}

	return rep.Violations, rep.Summary, rep.Telemetry
}
