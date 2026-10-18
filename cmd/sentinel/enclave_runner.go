package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/wgenclave"
)

// runEnclaveAudit coordinates Confidential VM & Secure Enclave WireGuard Peer Attestation auditing.
func runEnclaveAudit(
	manifestPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]wgenclave.WGEnclaveViolation, *wgenclave.WGEnclaveSummary, []wgenclave.AttestationReport, []wgenclave.PeerTunnelStatus) {
	if manifestPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil, nil
	}

	report, err := wgenclave.ScanEnclavePeers(manifestPath, telemetryPath, strictMode, feed)
	if err != nil {
		logErr("[-] Failed to audit WireGuard enclave peer manifests/telemetry: %v\n", err)
		os.Exit(1)
	}

	if manifestPath != "" {
		logInfo("[+] Audited WireGuard Enclave Peer Manifests: %s (%d peers configured)\n", manifestPath, len(report.Configurations))
	}

	if telemetryPath != "" {
		logInfo("[+] Reconciled Enclave Attestation Telemetry: %s (%d reports, %d tunnels)\n", telemetryPath, len(report.Reports), len(report.Peers))
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d WireGuard confidential enclave peer attestation violations:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.PeerName, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero WireGuard confidential enclave peer attestation violations detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened WireGuard Enclave Policies into: %s\n", synthOut)
		defaultCfg := wgenclave.EnclavePeerConfig{
			InterfaceName:       "wg0",
			PeerName:            "confidential-peer-01",
			PublicKey:           "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
			Endpoint:            "192.168.100.10:51820",
			Platform:            wgenclave.PlatformSEVSNP,
			MinTCBSVN:           4,
			RequireHardwareRoot: true,
			SessionKeyBinding:   true,
			AllowDebug:          false,
			GoldenImageDigest:   "sha256:4a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b",
			RequiredPCRs: map[int]string{
				0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				2: "c24f6e4a8b1c9d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
				4: "b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
				7: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
			},
		}
		if len(report.Configurations) > 0 {
			defaultCfg = report.Configurations[0]
			defaultCfg.RequireHardwareRoot = true
			defaultCfg.SessionKeyBinding = true
			defaultCfg.AllowDebug = false
			if defaultCfg.MinTCBSVN < 4 {
				defaultCfg.MinTCBSVN = 4
			}
		}

		if err := wgenclave.WriteSynthesizedPolicies(synthOut, defaultCfg); err != nil {
			logErr("[-] Failed to synthesize enclave peer policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated NixOS enclave module, Kubernetes CRD, and pre-handshake gate script.\n")
	}

	logInfo("[+] WireGuard Enclave Peer Posture: Compliance Score: %.1f%% (SEV-SNP: %t, TDX: %t, Rejected Tunnels: %d, PCR Deviations: %d)\n",
		report.Summary.ComplianceScore, report.Summary.SEVSNPVerified, report.Summary.TDXVerified, report.Summary.RejectedPeers, report.Summary.PCRDeviationsDetected)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 70.0) {
		logErr("[-] FATAL: WireGuard Enclave Peer posture NON_COMPLIANT in strict mode (Critical violation or Score < 70%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Reports, report.Peers
}
