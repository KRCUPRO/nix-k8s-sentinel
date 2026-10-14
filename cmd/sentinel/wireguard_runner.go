package main

import (
	"fmt"
	"os"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wireguard"
)

// runWireGuardAudit coordinates declarative NixOS manifest scanning, key rotation auditing, and telemetry reconciliation.
func runWireGuardAudit(wgPath string, wgTelemetry string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]wireguard.WireGuardViolation, *wireguard.ReconciliationReport) {
	var violations []wireguard.WireGuardViolation
	var declaredIfaces []wireguard.InterfaceDeclaration
	var reconciliation *wireguard.ReconciliationReport

	scanner := wireguard.NewWireGuardScanner(feed)
	reconciler := wireguard.NewReconciler(feed)

	// 1. Audit Declarative NixOS Configurations
	if wgPath != "" {
		logInfo("[+] Auditing NixOS WireGuard Mesh Declarations: %s\n", wgPath)
		fileInfo, err := os.Stat(wgPath)
		if err != nil {
			logErr("[-] Failed to inspect WireGuard path: %v\n", err)
			os.Exit(1)
		}

		var scanViolations []wireguard.WireGuardViolation
		if fileInfo.IsDir() {
			ifaces, viols, err := scanner.ScanDirectory(wgPath)
			if err != nil {
				logErr("[-] Failed to audit WireGuard directory: %v\n", err)
				os.Exit(1)
			}
			declaredIfaces = ifaces
			scanViolations = viols
		} else {
			ifaces, viols, err := scanner.ScanFile(wgPath)
			if err != nil {
				logErr("[-] Failed to audit WireGuard file: %v\n", err)
				os.Exit(1)
			}
			declaredIfaces = ifaces
			scanViolations = viols
		}

		violations = append(violations, scanViolations...)
		logInfo("[+] Identified %d declarative WireGuard interfaces across scanned files.\n", len(declaredIfaces))

		if len(scanViolations) == 0 {
			logInfo("[+] Zero cryptographic or security violations detected in WireGuard declarations.\n")
		} else {
			logInfo("[-] WARNING: %d WireGuard declarative security violations identified!\n", len(scanViolations))
			for i, v := range scanViolations {
				cveTag := ""
				if v.MatchedCVE != "" {
					cveTag = fmt.Sprintf(" [%s]", v.MatchedCVE)
				}
				peerTag := ""
				if v.PeerPublicKey != "" {
					peerTag = fmt.Sprintf(" (Peer: %s)", v.PeerPublicKey)
				}
				logInfo("  [%d] [%s] %s (%s)%s%s [CVSS: %.1f]\n", i+1, v.RuleID, v.Title, v.Severity, peerTag, cveTag, v.CVSSScore)
				logInfo("      Target: %s (Line: %d)\n", v.InterfaceName, v.StartLine)
				logInfo("      Details: %s\n", v.Description)
				logInfo("      Remediation: %s\n", v.Remediation)
			}
		}
	}

	// 2. Audit Runtime Telemetry & Reconcile
	if wgTelemetry != "" {
		logInfo("[+] Ingesting WireGuard Runtime Mesh Telemetry: %s\n", wgTelemetry)
		runtimeTelemetry, err := reconciler.ParseTelemetryFile(wgTelemetry)
		if err != nil {
			logErr("[-] Failed to parse WireGuard telemetry: %v\n", err)
			os.Exit(1)
		}

		reconciliation = reconciler.Reconcile(declaredIfaces, runtimeTelemetry, time.Now().UTC())
		violations = append(violations, reconciliation.Violations...)

		logInfo("[+] WireGuard Mesh Telemetry Reconciled across %d interfaces (Total Runtime Peers: %d)\n",
			reconciliation.InterfaceCount, reconciliation.RuntimePeersCount)
		logInfo("    Drift: Unmanaged Peers=%d | Missing Peers=%d | Stale Handshakes=%d\n",
			reconciliation.UnmanagedPeersCount, reconciliation.MissingPeersCount, reconciliation.StaleHandshakeCount)
		logInfo("    Key Rotation: Active=%d | Needs Rotation=%d | Expired=%d (Oldest Key Age: %d days)\n",
			reconciliation.KeyRotation.ActiveKeys, reconciliation.KeyRotation.NeedsRotationKeys, reconciliation.KeyRotation.ExpiredKeys, reconciliation.KeyRotation.OldestKeyAgeDays)

		for _, v := range reconciliation.Violations {
			if v.Severity == intel.SeverityCritical || v.Severity == intel.SeverityHigh {
				peerTag := ""
				if v.PeerPublicKey != "" {
					peerTag = fmt.Sprintf(" (Peer: %s)", v.PeerPublicKey)
				}
				logInfo("  [!] [%s] %s%s: %s [CVSS: %.1f]\n", v.Severity, v.RuleID, peerTag, v.Description, v.CVSSScore)
			}
		}
	}

	return violations, reconciliation
}
