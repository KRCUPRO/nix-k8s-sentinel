package bgp

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditCiliumBGPPeeringPolicies audits static declarations against canonical BGP radar rules.
func AuditCiliumBGPPeeringPolicies(policies []CiliumBGPPeeringPolicyConfig) []BGPViolation {
	var violations []BGPViolation

	for _, pol := range policies {
		for _, vr := range pol.VirtualRouters {
			// Rule BGP-RADAR-004: Unrestricted BGP route export
			if (vr.ExportPodCIDR || vr.ExportServiceCIDR) && len(vr.PrefixFilters) == 0 {
				r := FindRule("BGP-RADAR-004")
				violations = append(violations, BGPViolation{
					RuleID:      r.ID,
					Severity:    r.Severity,
					CVSSScore:   r.CVSSScore,
					Title:       r.Title,
					Description: fmt.Sprintf("Virtual router ASN %d in policy '%s' exports CIDRs without explicit prefix filters, risking route leaks.", vr.LocalASN, pol.PolicyName),
					Remediation: r.Remediation,
					PolicyName:  pol.PolicyName,
					FilePath:    pol.SourceFile,
					StartLine:   pol.StartLine,
					MatchedCVE:  r.MatchedCVE,
				})
			} else {
				for _, pf := range vr.PrefixFilters {
					if pf == "0.0.0.0/0" || pf == "::/0" {
						r := FindRule("BGP-RADAR-004")
						violations = append(violations, BGPViolation{
							RuleID:      r.ID,
							Severity:    r.Severity,
							CVSSScore:   r.CVSSScore,
							Title:       r.Title,
							Description: fmt.Sprintf("Virtual router ASN %d in policy '%s' declares catch-all default route '%s' in prefix filters.", vr.LocalASN, pol.PolicyName, pf),
							Remediation: r.Remediation,
							PolicyName:  pol.PolicyName,
							FilePath:    pol.SourceFile,
							StartLine:   pol.StartLine,
							MatchedCVE:  r.MatchedCVE,
						})
					}
				}
			}

			for _, n := range vr.Neighbors {
				// Rule BGP-RADAR-001: Unauthenticated BGP peering session
				if !n.HasMD5 && !n.HasTCPAO && n.AuthSecret == "" {
					r := FindRule("BGP-RADAR-001")
					violations = append(violations, BGPViolation{
						RuleID:      r.ID,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						Title:       r.Title,
						Description: fmt.Sprintf("BGP peer '%s' (ASN %d) in policy '%s' has zero TCP MD5 or TCP-AO password authentication.", n.PeerAddress, n.PeerASN, pol.PolicyName),
						Remediation: r.Remediation,
						PeerAddress: n.PeerAddress,
						PolicyName:  pol.PolicyName,
						FilePath:    pol.SourceFile,
						StartLine:   pol.StartLine,
						MatchedCVE:  r.MatchedCVE,
					})
				}

				// Rule BGP-RADAR-002: Missing dual-stack IPv6 route announcements
				hasIPv6 := false
				for _, f := range n.Families {
					fLower := strings.ToLower(f)
					if strings.Contains(fLower, "ipv6") || fLower == "dualstack" {
						hasIPv6 = true
						break
					}
				}
				if !hasIPv6 {
					r := FindRule("BGP-RADAR-002")
					violations = append(violations, BGPViolation{
						RuleID:      r.ID,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						Title:       r.Title,
						Description: fmt.Sprintf("BGP peer '%s' (ASN %d) lacks IPv6 address family in route advertisements.", n.PeerAddress, n.PeerASN),
						Remediation: r.Remediation,
						PeerAddress: n.PeerAddress,
						PolicyName:  pol.PolicyName,
						FilePath:    pol.SourceFile,
						StartLine:   pol.StartLine,
					})
				}

				// Rule BGP-RADAR-005: eBGP multihop TTL vulnerability
				if vr.LocalASN != 0 && n.PeerASN != 0 && vr.LocalASN != n.PeerASN {
					if n.MultihopTTL <= 1 {
						r := FindRule("BGP-RADAR-005")
						violations = append(violations, BGPViolation{
							RuleID:      r.ID,
							Severity:    r.Severity,
							CVSSScore:   r.CVSSScore,
							Title:       r.Title,
							Description: fmt.Sprintf("eBGP neighbor '%s' (local ASN %d, peer ASN %d) has multihop TTL <= 1 without GTSM protection.", n.PeerAddress, vr.LocalASN, n.PeerASN),
							Remediation: r.Remediation,
							PeerAddress: n.PeerAddress,
							PolicyName:  pol.PolicyName,
							FilePath:    pol.SourceFile,
							StartLine:   pol.StartLine,
						})
					}
				}

				// Rule BGP-RADAR-006: BGP Graceful Restart disabled
				if !n.GracefulRestart || n.GracefulRestartTime <= 0 {
					r := FindRule("BGP-RADAR-006")
					violations = append(violations, BGPViolation{
						RuleID:      r.ID,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						Title:       r.Title,
						Description: fmt.Sprintf("BGP peer '%s' does not enable RFC 4724 Graceful Restart.", n.PeerAddress),
						Remediation: r.Remediation,
						PeerAddress: n.PeerAddress,
						PolicyName:  pol.PolicyName,
						FilePath:    pol.SourceFile,
						StartLine:   pol.StartLine,
					})
				}

				// Rule BGP-RADAR-009: BGP HoldTime timer misconfiguration
				if n.HoldTime > 90 || (n.HoldTime > 0 && n.HoldTime < 9) {
					r := FindRule("BGP-RADAR-009")
					violations = append(violations, BGPViolation{
						RuleID:      r.ID,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						Title:       r.Title,
						Description: fmt.Sprintf("BGP peer '%s' holdTime (%d seconds) is outside recommended range (9-90s).", n.PeerAddress, n.HoldTime),
						Remediation: r.Remediation,
						PeerAddress: n.PeerAddress,
						PolicyName:  pol.PolicyName,
						FilePath:    pol.SourceFile,
						StartLine:   pol.StartLine,
					})
				}

				// Rule BGP-RADAR-011: Missing community tags
				if len(n.CommunityTags) == 0 {
					r := FindRule("BGP-RADAR-011")
					violations = append(violations, BGPViolation{
						RuleID:      r.ID,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						Title:       r.Title,
						Description: fmt.Sprintf("BGP peer '%s' does not specify routing community tags for egress traffic segregation.", n.PeerAddress),
						Remediation: r.Remediation,
						PeerAddress: n.PeerAddress,
						PolicyName:  pol.PolicyName,
						FilePath:    pol.SourceFile,
						StartLine:   pol.StartLine,
					})
				}
			}
		}
	}

	return violations
}

// AuditCiliumLoadBalancerIPPools checks IP pool dual-stack allocation.
func AuditCiliumLoadBalancerIPPools(pools []CiliumLoadBalancerIPPoolConfig) []BGPViolation {
	var violations []BGPViolation
	hasIPv6Pool := false

	for _, pool := range pools {
		if pool.Disabled {
			continue
		}
		for _, cidr := range pool.CIDRs {
			if strings.Contains(cidr, ":") {
				hasIPv6Pool = true
				break
			}
		}
	}

	if len(pools) > 0 && !hasIPv6Pool {
		r := FindRule("BGP-RADAR-002")
		violations = append(violations, BGPViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Title,
			Description: "Active CiliumLoadBalancerIPPools contain only IPv4 CIDRs with zero IPv6 pool declarations.",
			Remediation: r.Remediation,
			FilePath:    pools[0].SourceFile,
			StartLine:   pools[0].StartLine,
		})
	}

	return violations
}

// AuditNixOSBGP audits host network and firewall configurations.
func AuditNixOSBGP(cfg *NixOSBGPConfig) []BGPViolation {
	if cfg == nil {
		return nil
	}

	var violations []BGPViolation

	// Rule BGP-RADAR-007: Unrestricted TCP 179 exposure
	if cfg.TCP179Allowed && !cfg.FirewallRestricted {
		r := FindRule("BGP-RADAR-007")
		violations = append(violations, BGPViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Title,
			Description: fmt.Sprintf("NixOS host '%s' opens TCP port 179 in allowedTCPPorts without subnet restriction in firewall rules.", cfg.HostName),
			Remediation: r.Remediation,
			FilePath:    cfg.SourceFile,
			StartLine:   cfg.StartLine,
		})
	}

	// Rule BGP-RADAR-008: IPv6 RA spoofing vulnerability
	if cfg.IPv6AcceptRA > 0 {
		r := FindRule("BGP-RADAR-008")
		violations = append(violations, BGPViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Title,
			Description: fmt.Sprintf("NixOS host '%s' sets net.ipv6.conf.all.accept_ra = %d allowing rogue router advertisement overrides.", cfg.HostName, cfg.IPv6AcceptRA),
			Remediation: r.Remediation,
			FilePath:    cfg.SourceFile,
			StartLine:   cfg.StartLine,
		})
	}

	return violations
}

// AuditBGPTelemetry audits runtime BGP session and IPAM telemetry.
func AuditBGPTelemetry(tel *BGPTelemetryReport, configuredPeers map[string]bool) []BGPViolation {
	if tel == nil {
		return nil
	}

	var violations []BGPViolation
	now := time.Now().UTC()

	// Rule BGP-RADAR-012: Stale telemetry timestamp
	if !tel.Timestamp.IsZero() && now.Sub(tel.Timestamp) > 300*time.Second {
		r := FindRule("BGP-RADAR-012")
		violations = append(violations, BGPViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Title,
			Description: fmt.Sprintf("BGP telemetry timestamp is stale (%s ago, threshold: 300s).", now.Sub(tel.Timestamp).Round(time.Second)),
			Remediation: r.Remediation,
		})
	}

	// Rule BGP-RADAR-003: IPAM pool exhaustion
	for _, pool := range tel.IPAMPools {
		if pool.UsagePercent > 85.0 {
			r := FindRule("BGP-RADAR-003")
			violations = append(violations, BGPViolation{
				RuleID:      r.ID,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				Title:       r.Title,
				Description: fmt.Sprintf("IPAM pool '%s' (%s, %s) utilization at %.1f%% exceeds critical 85%% high-watermark.", pool.PoolName, pool.CIDR, pool.Family, pool.UsagePercent),
				Remediation: r.Remediation,
			})
		}
	}

	// Rule BGP-RADAR-010: Route flapping and resets
	for _, p := range tel.Peers {
		if p.ResetCount > 5 || p.FlapDampingActive {
			r := FindRule("BGP-RADAR-010")
			violations = append(violations, BGPViolation{
				RuleID:      r.ID,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				Title:       r.Title,
				Description: fmt.Sprintf("BGP peer '%s' experienced %d resets with flap damping active: %t (reason: %s).", p.PeerAddress, p.ResetCount, p.FlapDampingActive, p.LastResetReason),
				Remediation: r.Remediation,
				PeerAddress: p.PeerAddress,
			})
		}

		if p.State != StateEstablished && p.LastUpdateSeconds > 300 {
			r := FindRule("BGP-RADAR-012")
			violations = append(violations, BGPViolation{
				RuleID:      r.ID,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				Title:       r.Title,
				Description: fmt.Sprintf("BGP peer '%s' is in non-established state '%s' for > 300 seconds.", p.PeerAddress, p.State),
				Remediation: r.Remediation,
				PeerAddress: p.PeerAddress,
			})
		}
	}

	return violations
}

// ComputeBGPSummary computes deterministic summary statistics and compliance score.
func ComputeBGPSummary(policies []CiliumBGPPeeringPolicyConfig, pools []CiliumLoadBalancerIPPoolConfig, tel *BGPTelemetryReport, violations []BGPViolation) BGPSummary {
	summary := BGPSummary{
		TotalPolicies:   len(policies),
		TotalIPAMPools:  len(pools),
		TotalViolations: len(violations),
	}

	peerSet := make(map[string]bool)
	for _, pol := range policies {
		for _, vr := range pol.VirtualRouters {
			for _, n := range vr.Neighbors {
				peerSet[n.PeerAddress] = true
			}
		}
	}
	summary.TotalPeers = len(peerSet)

	hasIPv6Policy := false
	for _, pol := range policies {
		for _, vr := range pol.VirtualRouters {
			for _, n := range vr.Neighbors {
				for _, f := range n.Families {
					if strings.Contains(strings.ToLower(f), "ipv6") || strings.ToLower(f) == "dualstack" {
						hasIPv6Policy = true
					}
				}
			}
		}
	}
	summary.DualStackCompliant = hasIPv6Policy

	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
		case intel.SeverityHigh:
			summary.HighCount++
		case intel.SeverityMedium:
			summary.MediumCount++
		case intel.SeverityLow:
			summary.LowCount++
		}
	}

	penalty := float64(summary.CriticalCount)*25.0 +
		float64(summary.HighCount)*10.0 +
		float64(summary.MediumCount)*5.0 +
		float64(summary.LowCount)*2.0

	score := 100.0 - penalty
	if score < 0.0 {
		score = 0.0
	}
	summary.ComplianceScore = math.Round(score*10) / 10

	return summary
}
