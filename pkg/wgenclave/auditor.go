package wgenclave

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditEnclavePeerConfig statically evaluates declarative WireGuard peer configurations.
func AuditEnclavePeerConfig(cfg EnclavePeerConfig, violations *[]WGEnclaveViolation) {
	peerName := cfg.PeerName
	if peerName == "" {
		peerName = "unnamed-peer"
	}

	// WG-ENC-001: Missing hardware root-of-trust platform
	if cfg.Platform == "" || (!cfg.RequireHardwareRoot && cfg.Platform == PlatformTPM) {
		addViolation(violations, "WG-ENC-001", peerName, cfg.InterfaceName, cfg.Platform, cfg.FilePath, cfg.StartLine,
			fmt.Sprintf("WireGuard peer '%s' is configured without binding to hardware enclave attestation", peerName))
	}

	// WG-ENC-005: Missing session key binding requirement
	if !cfg.SessionKeyBinding {
		addViolation(violations, "WG-ENC-005", peerName, cfg.InterfaceName, cfg.Platform, cfg.FilePath, cfg.StartLine,
			fmt.Sprintf("WireGuard peer '%s' does not enforce cryptographic binding of ephemeral session keys to enclave REPORT_DATA", peerName))
	}

	// WG-ENC-006: Insecure hypervisor debugging allowed
	if cfg.AllowDebug {
		addViolation(violations, "WG-ENC-006", peerName, cfg.InterfaceName, cfg.Platform, cfg.FilePath, cfg.StartLine,
			fmt.Sprintf("WireGuard confidential peer '%s' permits insecure hypervisor memory inspection (allowDebug = true)", peerName))
	}

	// WG-ENC-010: TCB SVN below minimum
	if cfg.MinTCBSVN > 0 && cfg.MinTCBSVN < DefaultMinTCBSVN {
		addViolation(violations, "WG-ENC-010", peerName, cfg.InterfaceName, cfg.Platform, cfg.FilePath, cfg.StartLine,
			fmt.Sprintf("WireGuard peer '%s' requires TCB SVN %d, which is below cluster minimum security baseline %d", peerName, cfg.MinTCBSVN, DefaultMinTCBSVN))
	}

	// WG-ENC-004: Missing mandatory measured boot PCR declarations
	if cfg.Platform == PlatformSEVSNP || cfg.Platform == PlatformTDX {
		if len(cfg.RequiredPCRs) == 0 && cfg.GoldenImageDigest == "" {
			addViolation(violations, "WG-ENC-004", peerName, cfg.InterfaceName, cfg.Platform, cfg.FilePath, cfg.StartLine,
				fmt.Sprintf("WireGuard confidential peer '%s' lacks declarative golden PCR references for measured boot attestation", peerName))
		}
	}
}

// AuditAttestationReport verifies runtime cryptographic attestation quotes and reports.
func AuditAttestationReport(report AttestationReport, cfg *EnclavePeerConfig, now time.Time, violations *[]WGEnclaveViolation, summary *WGEnclaveSummary) {
	peerName := report.NodeID
	if cfg != nil && cfg.PeerName != "" {
		peerName = cfg.PeerName
	}
	iface := "wg0"
	if cfg != nil && cfg.InterfaceName != "" {
		iface = cfg.InterfaceName
	}

	// WG-ENC-002: AMD SEV-SNP VCEK verification
	if report.Platform == PlatformSEVSNP {
		if !report.VCEKCertChainValid {
			addViolation(violations, "WG-ENC-002", peerName, iface, report.Platform, "", 0,
				fmt.Sprintf("Node '%s' AMD SEV-SNP VCEK endorsement certificate chain validation failed or revoked", report.NodeID))
		} else {
			summary.SEVSNPVerified = true
		}
	}

	// WG-ENC-003: Intel TDX Quote verification
	if report.Platform == PlatformTDX {
		if !report.TDXQuoteValid {
			addViolation(violations, "WG-ENC-003", peerName, iface, report.Platform, "", 0,
				fmt.Sprintf("Node '%s' Intel TDX Quote cryptographic signature verification failed", report.NodeID))
		} else {
			summary.TDXVerified = true
		}
	}

	// WG-ENC-006: Runtime debug flag
	if report.DebugAllowed {
		addViolation(violations, "WG-ENC-006", peerName, iface, report.Platform, "", 0,
			fmt.Sprintf("Node '%s' enclave report attests that guest debugging is enabled by hypervisor", report.NodeID))
	}

	// WG-ENC-007: Stale report age
	if !report.Timestamp.IsZero() {
		age := now.Sub(report.Timestamp)
		maxAge := MaxAttestationAge
		if cfg != nil && cfg.MaxAttestationAgeSec > 0 {
			maxAge = time.Duration(cfg.MaxAttestationAgeSec) * time.Second
		}
		if age > maxAge {
			addViolation(violations, "WG-ENC-007", peerName, iface, report.Platform, "", 0,
				fmt.Sprintf("Node '%s' attestation report age (%.0fs) exceeds maximum allowable freshness window (%.0fs)", report.NodeID, age.Seconds(), maxAge.Seconds()))
		}
	}

	// WG-ENC-010: TCB SVN degradation
	minSVN := DefaultMinTCBSVN
	if cfg != nil && cfg.MinTCBSVN > 0 {
		minSVN = cfg.MinTCBSVN
	}
	if report.TCBSVN < minSVN {
		addViolation(violations, "WG-ENC-010", peerName, iface, report.Platform, "", 0,
			fmt.Sprintf("Node '%s' attestation report TCB SVN (%d) is lower than required minimum (%d)", report.NodeID, report.TCBSVN, minSVN))
	}

	// WG-ENC-004: Measured Boot PCR deviation
	if cfg != nil && len(cfg.RequiredPCRs) > 0 {
		for pcrIdx, expectedDigest := range cfg.RequiredPCRs {
			actualDigest, found := report.MeasuredPCRs[pcrIdx]
			if !found || !strings.EqualFold(expectedDigest, actualDigest) {
				summary.PCRDeviationsDetected++
				addViolation(violations, "WG-ENC-004", peerName, iface, report.Platform, cfg.FilePath, cfg.StartLine,
					fmt.Sprintf("Node '%s' measured boot PCR %d (%s) deviates from golden reference (%s)", report.NodeID, pcrIdx, actualDigest, expectedDigest))
			}
		}
	}

	// WG-ENC-008: Intel TDX RTMR workload deviation
	if cfg != nil && len(cfg.RequiredRTMRs) > 0 {
		for rtmrIdx, expectedDigest := range cfg.RequiredRTMRs {
			actualDigest, found := report.MeasuredRTMRs[rtmrIdx]
			if !found || !strings.EqualFold(expectedDigest, actualDigest) {
				addViolation(violations, "WG-ENC-008", peerName, iface, report.Platform, cfg.FilePath, cfg.StartLine,
					fmt.Sprintf("Node '%s' Intel TDX RTMR %d (%s) does not match expected workload container image (%s)", report.NodeID, rtmrIdx, actualDigest, expectedDigest))
			}
		}
	}
}

// ReconcilePeerTunnels reconciles active WireGuard peer connections against enclave reports and policies.
func ReconcilePeerTunnels(
	peers []PeerTunnelStatus,
	reports []AttestationReport,
	configs []EnclavePeerConfig,
	now time.Time,
	violations *[]WGEnclaveViolation,
	summary *WGEnclaveSummary,
) []PeerTunnelStatus {
	reportMap := make(map[string]AttestationReport)
	reportByPubKey := make(map[string]AttestationReport)
	for _, r := range reports {
		if r.ReportID != "" {
			reportMap[r.ReportID] = r
		}
		if r.PeerPublicKey != "" {
			reportByPubKey[r.PeerPublicKey] = r
		}
	}

	configMap := make(map[string]EnclavePeerConfig)
	for _, c := range configs {
		if c.PublicKey != "" {
			configMap[c.PublicKey] = c
		}
		if c.PeerName != "" {
			configMap[c.PeerName] = c
		}
	}

	reconciled := make([]PeerTunnelStatus, len(peers))
	copy(reconciled, peers)

	for i := range reconciled {
		peer := &reconciled[i]
		summary.TotalPeersScanned++

		cfg, hasCfg := configMap[peer.PeerPublicKey]
		if !hasCfg {
			cfg, hasCfg = configMap[peer.PeerName]
		}

		rep, hasRep := reportMap[peer.BoundReportID]
		if !hasRep {
			rep, hasRep = reportByPubKey[peer.PeerPublicKey]
		}

		// Reconcile tunnel state
		if peer.TunnelState == TunnelEstablished {
			if !hasRep {
				peer.TunnelState = TunnelRejected
				peer.RejectionReason = "Missing hardware enclave attestation report"
				summary.RejectedPeers++
				summary.RejectedPeerIDs = append(summary.RejectedPeerIDs, peer.PeerName)
				addViolation(violations, "WG-ENC-001", peer.PeerName, peer.InterfaceName, PlatformTPM, "", 0,
					fmt.Sprintf("Established WireGuard peer '%s' lacks valid attestation report; rejecting tunnel", peer.PeerName))
			} else {
				// WG-ENC-005: Ephemeral session key binding check
				if cfg.SessionKeyBinding && peer.ActiveSessionKeyHash != "" {
					if rep.ReportDataHash == "" || !strings.EqualFold(rep.ReportDataHash, peer.ActiveSessionKeyHash) {
						peer.TunnelState = TunnelRejected
						peer.RejectionReason = "Session key hash not cryptographically bound to enclave REPORT_DATA"
						summary.RejectedPeers++
						summary.RejectedPeerIDs = append(summary.RejectedPeerIDs, peer.PeerName)
						addViolation(violations, "WG-ENC-005", peer.PeerName, peer.InterfaceName, rep.Platform, "", 0,
							fmt.Sprintf("Peer '%s' active session key hash (%s) does not match enclave REPORT_DATA (%s)", peer.PeerName, peer.ActiveSessionKeyHash, rep.ReportDataHash))
					}
				}

				if peer.TunnelState == TunnelEstablished {
					summary.CompliantPeers++
					peer.AttestationValid = true
				}
			}
		} else if peer.TunnelState == TunnelPending {
			summary.PendingPeers++
		} else if peer.TunnelState == TunnelRejected || peer.TunnelState == TunnelRevoked {
			summary.RejectedPeers++
			summary.RejectedPeerIDs = append(summary.RejectedPeerIDs, peer.PeerName)
		}
	}

	return reconciled
}

// CalculateComplianceScore derives the deterministic security score (0.0% to 100.0%).
func CalculateComplianceScore(summary *WGEnclaveSummary, violations []WGEnclaveViolation) {
	crit, high, med, low := 0, 0, 0, 0
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	summary.CriticalCount = crit
	summary.HighCount = high
	summary.MediumCount = med
	summary.LowCount = low

	penalty := float64(crit)*25.0 + float64(high)*15.0 + float64(med)*5.0 + float64(low)*2.0
	score := 100.0 - penalty
	if score < 0.0 {
		score = 0.0
	}
	summary.ComplianceScore = math.Round(score*10.0) / 10.0
}

func addViolation(
	violations *[]WGEnclaveViolation,
	ruleID, peerName, iface string,
	platform EnclavePlatform,
	filePath string,
	startLine int,
	desc string,
) {
	rule, found := GetRule(ruleID)
	if !found {
		rule = WGEnclaveRule{
			ID:          ruleID,
			Title:       ruleID,
			Severity:    intel.SeverityHigh,
			CVSSScore:   7.5,
			Remediation: "Enforce enclave peer attestation policy.",
		}
	}

	*violations = append(*violations, WGEnclaveViolation{
		RuleID:        rule.ID,
		PeerName:      peerName,
		InterfaceName: iface,
		Platform:      platform,
		Severity:      rule.Severity,
		CVSSScore:     rule.CVSSScore,
		Title:         rule.Title,
		Description:   desc,
		Remediation:   rule.Remediation,
		MatchedCVE:    rule.MatchedCVE,
		FilePath:      filePath,
		StartLine:     startLine,
	})
}
