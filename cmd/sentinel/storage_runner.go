package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/storage"
)

// runStorageAudit coordinates Rook Ceph manifest inspection and runtime telemetry analysis.
func runStorageAudit(cephPath string, cephTelemetry string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]storage.StorageViolation, *storage.CephHealthReport) {
	var storageViolations []storage.StorageViolation
	var storageHealth *storage.CephHealthReport

	if cephPath != "" {
		logInfo("[+] Auditing Rook Ceph Storage Manifests: %s\n", cephPath)
		storageScanner := storage.NewStorageScanner(feed)
		fileInfo, err := os.Stat(cephPath)
		if err != nil {
			logErr("[-] Failed to inspect Ceph manifest path: %v\n", err)
			os.Exit(1)
		}

		var findings []storage.StorageViolation
		if fileInfo.IsDir() {
			rep, err := storageScanner.ScanDirectory(cephPath)
			if err != nil {
				logErr("[-] Failed to audit Ceph directory: %v\n", err)
				os.Exit(1)
			}
			findings = rep.Violations
			logInfo("[+] Scanned %d files for Rook Ceph storage configurations.\n", rep.TotalFiles)
		} else {
			findings, err = storageScanner.ScanFile(cephPath)
			if err != nil {
				logErr("[-] Failed to audit Ceph file: %v\n", err)
				os.Exit(1)
			}
		}

		storageViolations = append(storageViolations, findings...)
		if len(findings) == 0 {
			logInfo("[+] Zero integrity or security violations detected in Rook Ceph manifests.\n")
		} else {
			logInfo("[-] WARNING: %d Rook Ceph storage violations identified!\n", len(findings))
			for i, v := range findings {
				cveTag := ""
				if v.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
				}
				logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, cveTag, v.CVSSScore)
				logInfo("      Target: %s/%s\n", v.ResourceKind, v.ResourceName)
				logInfo("      Details: %s\n", v.Description)
				logInfo("      Remediation: %s\n", v.Remediation)
			}
		}
	}

	if cephTelemetry != "" {
		logInfo("[+] Ingesting Ceph Runtime Health Telemetry: %s\n", cephTelemetry)
		detector := storage.NewCephAnomalyDetector(feed)
		health, anomalies, err := detector.AnalyzeHealthFile(cephTelemetry)
		if err != nil {
			logErr("[-] Failed to analyze Ceph health telemetry: %v\n", err)
			os.Exit(1)
		}
		storageHealth = health
		storageViolations = append(storageViolations, anomalies...)

		logInfo("[+] Ceph Cluster Status: %s (Monitors: %d | OSDs: %d Up/%d Total | PGs: %d ActiveClean/%d Total)\n",
			health.Status, len(health.MonQuorum), health.OSDStats.Up, health.OSDStats.Total, health.PGStats.ActiveClean, health.PGStats.Total)

		if len(anomalies) == 0 {
			logInfo("[+] Zero storage runtime anomalies detected.\n")
		} else {
			logInfo("[-] WARNING: %d Ceph storage anomalies identified!\n", len(anomalies))
			for i, a := range anomalies {
				cveTag := ""
				if a.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" [%s]", a.MatchedCVE)
				}
				logInfo("  [%d] [%s] %s (%s)%s [CVSS: %.1f]\n", i+1, a.RuleID, a.Title, a.Severity, cveTag, a.CVSSScore)
				logInfo("      Details: %s\n", a.Description)
				logInfo("      Remediation: %s\n", a.Remediation)
			}
		}
	}

	return storageViolations, storageHealth
}
