package flow

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditCiliumPolicy evaluates declarative CiliumNetworkPolicies against canonical flow rules.
func AuditCiliumPolicy(config *CiliumNetworkPolicyConfig) []FlowViolation {
	if config == nil {
		return nil
	}

	var violations []FlowViolation

	// Rule 1: FLOW-RADAR-008 - Cilium DNS proxy disabled
	if config.EnableDNSProxy != nil && !*config.EnableDNSProxy {
		rule := LookupFlowRule("FLOW-RADAR-008")
		line := config.LineNumbers["enable_dns_proxy"]
		if line <= 0 {
			line = 1
		}
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("[%s/%s] %s", config.Namespace, config.Name, rule.Description),
			Remediation: rule.Remediation,
			FilePath:    config.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	for _, egress := range config.EgressRules {
		// Rule 2: FLOW-RADAR-001 - Unrestricted DNS Egress without Layer 7 DNS inspection
		for _, portRule := range egress.ToPorts {
			if portRule.Port == 53 {
				if len(portRule.DNSRules) == 0 {
					rule := LookupFlowRule("FLOW-RADAR-001")
					line := portRule.LineNumber
					if line <= 0 {
						line = egress.LineNumber
					}
					violations = append(violations, FlowViolation{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						CVSSScore:   rule.CVSSScore,
						Title:       rule.Name,
						Description: fmt.Sprintf("[%s/%s] Egress allows direct port 53 traffic without Layer 7 DNS proxy rules.", config.Namespace, config.Name),
						Remediation: rule.Remediation,
						FilePath:    config.FilePath,
						StartLine:   line,
						EndLine:     line,
						MatchedCVE:  rule.MatchedCVE,
					})
				}
			}

			// Rule 3: FLOW-RADAR-007 - Direct external IP egress on non-standard ports
			if portRule.Port != 53 && portRule.Port != 80 && portRule.Port != 443 && portRule.Port != 8080 && portRule.Port != 8443 {
				for _, cidr := range egress.ToCIDRs {
					if cidr == "0.0.0.0/0" || strings.HasPrefix(cidr, "0.0.0.0/") {
						rule := LookupFlowRule("FLOW-RADAR-007")
						line := portRule.LineNumber
						violations = append(violations, FlowViolation{
							RuleID:      rule.ID,
							Severity:    rule.Severity,
							CVSSScore:   rule.CVSSScore,
							Title:       rule.Name,
							Description: fmt.Sprintf("[%s/%s] Direct unrestricted 0.0.0.0/0 egress allowed on non-standard port %d.", config.Namespace, config.Name, portRule.Port),
							Remediation: rule.Remediation,
							FilePath:    config.FilePath,
							StartLine:   line,
							EndLine:     line,
							MatchedCVE:  rule.MatchedCVE,
						})
					}
				}
			}
		}

		// Rule 4: FLOW-RADAR-002 - Wildcard or empty FQDN patterns allowed
		for _, fqdn := range egress.ToFQDNs {
			pat := strings.TrimSpace(fqdn.MatchPattern)
			name := strings.TrimSpace(fqdn.MatchName)
			if pat == "*" || pat == "*.*" || (pat == "" && name == "") {
				rule := LookupFlowRule("FLOW-RADAR-002")
				line := fqdn.LineNumber
				if line <= 0 {
					line = egress.LineNumber
				}
				violations = append(violations, FlowViolation{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					CVSSScore:   rule.CVSSScore,
					Title:       rule.Name,
					Description: fmt.Sprintf("[%s/%s] Overly permissive wildcard FQDN pattern '%s' permits arbitrary external domains.", config.Namespace, config.Name, pat),
					Remediation: rule.Remediation,
					FilePath:    config.FilePath,
					StartLine:   line,
					EndLine:     line,
					MatchedCVE:  rule.MatchedCVE,
				})
			}
		}

		// Rule 5: FLOW-RADAR-011 - Cross-namespace unauthenticated egress
		if config.Namespace != "" && len(egress.ToCIDRs) > 0 && len(config.EndpointSelector) == 0 {
			rule := LookupFlowRule("FLOW-RADAR-011")
			line := egress.LineNumber
			violations = append(violations, FlowViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Name,
				Description: fmt.Sprintf("[%s/%s] Policy permits egress across namespaces without tenant endpoint isolation.", config.Namespace, config.Name),
				Remediation: rule.Remediation,
				FilePath:    config.FilePath,
				StartLine:   line,
				EndLine:     line,
				MatchedCVE:  rule.MatchedCVE,
			})
		}
	}

	return violations
}

// AuditNixOSFlow evaluates NixOS host eBPF flow profiling options.
func AuditNixOSFlow(config *NixOSFlowConfig) []FlowViolation {
	if config == nil {
		return nil
	}

	var violations []FlowViolation

	// Rule 1: FLOW-RADAR-006 - Kernel BPF connect monitoring disabled or unconfigured
	if config.BPFConnectMonitoring != nil && !*config.BPFConnectMonitoring {
		rule := LookupFlowRule("FLOW-RADAR-006")
		line := config.LineNumbers["bpf_connect_monitoring"]
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("NixOS host '%s' disabled kernel eBPF socket connect tracing (bpfConnectMonitoring = false).", config.HostName),
			Remediation: rule.Remediation,
			FilePath:    config.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	// Rule 2: FLOW-RADAR-008 - Cilium DNS proxy port unset
	if config.DNSProxyPort <= 0 && config.CiliumEnabled != nil && *config.CiliumEnabled {
		rule := LookupFlowRule("FLOW-RADAR-008")
		line := config.LineNumbers["dns_proxy_port"]
		if line <= 0 {
			line = config.LineNumbers["cilium_enabled"]
		}
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("NixOS host '%s' has Cilium enabled but DNS proxy port is unconfigured (dnsProxyPort = 0).", config.HostName),
			Remediation: rule.Remediation,
			FilePath:    config.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	// Rule 3: FLOW-RADAR-012 - Inadequate eBPF ring buffer size risking telemetry drops
	if config.RingBufferSizeKB > 0 && config.RingBufferSizeKB < 16384 {
		rule := LookupFlowRule("FLOW-RADAR-012")
		line := config.LineNumbers["ring_buffer_size_kb"]
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("NixOS host '%s' allocates insufficient eBPF flow ring buffer (%d KB < 16384 KB).", config.HostName, config.RingBufferSizeKB),
			Remediation: rule.Remediation,
			FilePath:    config.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	return violations
}

// AuditFlowTelemetry evaluates live runtime eBPF network flow and DNS telemetry events.
func AuditFlowTelemetry(telemetry *FlowTelemetryReport) []FlowViolation {
	if telemetry == nil {
		return nil
	}

	var violations []FlowViolation

	// Rule 1: FLOW-RADAR-005 - High runtime NXDOMAIN rate indicating DGA beaconing
	if telemetry.NXDomainRatePercent >= MaxNXDomainRatePercent {
		rule := LookupFlowRule("FLOW-RADAR-005")
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("Cluster '%s' detected critical NXDOMAIN error rate of %.1f%% (%d of %d queries), indicating active DGA beaconing.", telemetry.ClusterName, telemetry.NXDomainRatePercent, telemetry.NXDomainCount, telemetry.TotalDNSQueries),
			Remediation: rule.Remediation,
			FilePath:    "telemetry:dns_flows",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	// Rule 2: FLOW-RADAR-006 - Peak socket connect rate exceeding burst ceiling
	if telemetry.PeakSocketConnectRate >= MaxSocketConnectBurstRate {
		rule := LookupFlowRule("FLOW-RADAR-006")
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("Host '%s' recorded anomalous socket connection spike of %d conn/sec (ceiling: %d conn/sec).", telemetry.HostName, telemetry.PeakSocketConnectRate, MaxSocketConnectBurstRate),
			Remediation: rule.Remediation,
			FilePath:    "telemetry:socket_rates",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	// Rule 3: FLOW-RADAR-012 - eBPF ring buffer drops or overrun loss
	if telemetry.DropRatePercent >= 1.0 || telemetry.BufferOverruns > 0 {
		rule := LookupFlowRule("FLOW-RADAR-012")
		violations = append(violations, FlowViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Name,
			Description: fmt.Sprintf("Host '%s' experienced %.2f%% telemetry drop rate (%d buffer overruns, %d dropped packets).", telemetry.HostName, telemetry.DropRatePercent, telemetry.BufferOverruns, telemetry.DroppedPackets),
			Remediation: rule.Remediation,
			FilePath:    "telemetry:ebpf_buffer",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  rule.MatchedCVE,
		})
	}

	// Inspect individual query events
	seenEntropyExfil := false
	seenLengthExfil := false
	seenTXTExfil := false
	seenFastFlux := false

	for _, q := range telemetry.Queries {
		// Rule 4: FLOW-RADAR-003 - DNS Query Shannon Entropy threshold exceeded
		if q.Entropy >= DefaultEntropyThreshold && !seenEntropyExfil {
			seenEntropyExfil = true
			rule := LookupFlowRule("FLOW-RADAR-003")
			violations = append(violations, FlowViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Name,
				Description: fmt.Sprintf("Pod '%s/%s' dispatched high-entropy DNS query '%s' (Shannon H: %.2f > %.2f), indicating Base32/Hex tunnel exfiltration.", q.Namespace, q.ClientPod, q.QueryName, q.Entropy, DefaultEntropyThreshold),
				Remediation: rule.Remediation,
				FilePath:    fmt.Sprintf("telemetry:pod/%s/%s", q.Namespace, q.ClientPod),
				StartLine:   1,
				EndLine:     1,
				MatchedCVE:  rule.MatchedCVE,
			})
		}

		// Rule 5: FLOW-RADAR-004 - Excessive query or label length
		if (q.QueryLength >= MaxQueryLengthThreshold || q.MaxLabelLength >= MaxLabelLengthThreshold) && !seenLengthExfil {
			seenLengthExfil = true
			rule := LookupFlowRule("FLOW-RADAR-004")
			violations = append(violations, FlowViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Name,
				Description: fmt.Sprintf("Pod '%s/%s' generated oversized DNS query '%s' (QueryLen: %d, MaxLabelLen: %d).", q.Namespace, q.ClientPod, q.QueryName, q.QueryLength, q.MaxLabelLength),
				Remediation: rule.Remediation,
				FilePath:    fmt.Sprintf("telemetry:pod/%s/%s", q.Namespace, q.ClientPod),
				StartLine:   1,
				EndLine:     1,
				MatchedCVE:  rule.MatchedCVE,
			})
		}

		// Rule 6: FLOW-RADAR-009 - Abnormal high-bandwidth TXT/NULL record query
		if (q.RecordType == RecordTypeTXT || q.RecordType == RecordTypeNULL) && q.IsAnomaly && !seenTXTExfil {
			seenTXTExfil = true
			rule := LookupFlowRule("FLOW-RADAR-009")
			violations = append(violations, FlowViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Name,
				Description: fmt.Sprintf("Pod '%s/%s' queried covert TXT/NULL record '%s' with anomalous payload structure.", q.Namespace, q.ClientPod, q.QueryName),
				Remediation: rule.Remediation,
				FilePath:    fmt.Sprintf("telemetry:pod/%s/%s", q.Namespace, q.ClientPod),
				StartLine:   1,
				EndLine:     1,
				MatchedCVE:  rule.MatchedCVE,
			})
		}

		// Rule 7: FLOW-RADAR-010 - Fast-flux resolution detected
		if q.TTL > 0 && q.TTL < 10 && q.Vector == VectorFastFlux && !seenFastFlux {
			seenFastFlux = true
			rule := LookupFlowRule("FLOW-RADAR-010")
			violations = append(violations, FlowViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Name,
				Description: fmt.Sprintf("Domain '%s' resolved with ultra-low TTL of %d seconds and active IP churn.", q.QueryName, q.TTL),
				Remediation: rule.Remediation,
				FilePath:    fmt.Sprintf("telemetry:dns/%s", q.QueryName),
				StartLine:   1,
				EndLine:     1,
				MatchedCVE:  rule.MatchedCVE,
			})
		}
	}

	return violations
}

// ComputeFlowSummary aggregates violation statistics and calculates deterministic compliance score.
func ComputeFlowSummary(scannedCount int, violations []FlowViolation) FlowSummary {
	summary := FlowSummary{
		TotalScanned:    scannedCount,
		ViolationCount:  len(violations),
		ComplianceScore: 100.0,
	}

	penalty := 0.0
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
			penalty += 25.0
		case intel.SeverityHigh:
			summary.HighCount++
			penalty += 15.0
		case intel.SeverityMedium:
			summary.MediumCount++
			penalty += 8.0
		default:
			summary.LowCount++
			penalty += 4.0
		}
	}

	summary.ComplianceScore = math.Max(0.0, math.Round((100.0-penalty)*10)/10)
	if len(violations) == 0 {
		summary.CompliantCount = scannedCount
	} else {
		// Proportionally compliant items
		compliant := scannedCount - len(violations)
		if compliant < 0 {
			compliant = 0
		}
		summary.CompliantCount = compliant
	}

	return summary
}
