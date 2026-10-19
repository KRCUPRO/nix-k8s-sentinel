package flow

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// CanonicalFlowRules defines the authoritative catalog of 12 cluster-wide flow and DNS exfiltration rules.
var CanonicalFlowRules = []FlowRule{
	{
		ID:          "FLOW-RADAR-001",
		Name:        "UnrestrictedExternalDNSEgress",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.3,
		Description: "Pod egress allows unrestricted UDP/TCP port 53 traffic to external resolvers bypassing CoreDNS and Cilium DNS proxy, enabling unmonitored DNS tunneling.",
		Remediation: "Enforce CiliumNetworkPolicy restricting DNS egress exclusively to kube-system CoreDNS endpoints with Layer 7 DNS proxy inspection.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-002",
		Name:        "WildcardFQDNPatternAllowed",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.6,
		Description: "Egress toFQDNs policy uses overly permissive wildcard patterns ('*') or empty matchName rules, permitting arbitrary outbound domain resolutions.",
		Remediation: "Replace wildcard FQDN patterns with explicit, least-privilege domain whitelists and domain regex filters.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-003",
		Name:        "DNSQueryEntropyThresholdExceeded",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.9,
		Description: "Runtime DNS query Shannon entropy exceeds critical threshold (H > 3.85), indicating Base32/Base64 or Hex encoded data exfiltration inside subdomains.",
		Remediation: "Intercept high-entropy DNS tunnel sessions using eBPF socket drop filters and quarantine the originating workload container.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-004",
		Name:        "ExcessiveDNSQueryLabelLength",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.1,
		Description: "DNS query label length exceeds 50 characters or total query name exceeds 180 characters, characteristic of DNS tunnel payload staging.",
		Remediation: "Configure Cilium DNS proxy to reject queries with subdomain labels exceeding 50 characters and alert SecOps.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-005",
		Name:        "HighNXDomainRateDGABeaconing",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.4,
		Description: "Runtime NXDOMAIN error rate exceeds 25.0% of total DNS requests, indicating active Domain Generation Algorithm (DGA) Command-and-Control beaconing.",
		Remediation: "Deploy real-time Cilium network policies dropping egress traffic from pods exhibiting rapid NXDOMAIN error bursts.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-006",
		Name:        "AnomalousSocketConnectBurstRate",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.7,
		Description: "Kernel socket connect rate exceeds baseline (> 500 connections/sec per cgroup), indicating port scanning or SYN flood connection storms.",
		Remediation: "Enforce kernel eBPF cgroup/connect4 rate limiting and auto-throttle anomalous pod cgroups via NixOS systemd slice.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-007",
		Name:        "DirectExternalIPEgressUninspected",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Description: "Pod egress allows direct external IP connections on non-standard ports without Layer 7 application protocol validation.",
		Remediation: "Require all external egress to route through authenticated Cilium egress gateways or Gateway API HTTP/TLS proxies.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-008",
		Name:        "CiliumDNSProxyDisabled",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.8,
		Description: "Cilium DNS proxy inspection is disabled (enable-dns-proxy: false), preventing dynamic FQDN resolution tracking and response IP cache poisoning defenses.",
		Remediation: "Enable enable-dns-proxy: true in Cilium daemon configuration and enforce FQDN cache tracking.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-009",
		Name:        "AbnormalHighBandwidthDNSTXTQuery",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.6,
		Description: "High frequency of large TXT or NULL record queries detected from internal workloads, indicating covert DNS channel communication.",
		Remediation: "Restrict TXT record queries to authorized cluster components and monitor TXT query payload size distributions.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-010",
		Name:        "FastFluxDNSResolutionDetected",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Description: "DNS responses resolve with ultra-short TTL (< 10 seconds) combined with frequent IP address churn, indicative of Fast-Flux C2 networks.",
		Remediation: "Flag domains exhibiting rapid TTL cycling and correlate resolved destination IPs against threat intelligence feeds.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-011",
		Name:        "CrossNamespaceEgressUnauthenticated",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.2,
		Description: "Workload initiates cross-namespace egress flows without cryptographic SPIFFE identity attestation or tenant network boundary checks.",
		Remediation: "Enforce tenant-isolated CiliumClusterwideNetworkPolicies requiring SPIFFE mTLS authentication across namespace borders.",
		MatchedCVE:  "CVE-2026-10392",
	},
	{
		ID:          "FLOW-RADAR-012",
		Name:        "EBPFFlowRingBufferOverrunDrops",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.8,
		Description: "eBPF kernel flow profiler ring buffer drops or event loss exceeds 1.0%, creating blind spots in network exfiltration telemetry.",
		Remediation: "Increase NixOS eBPF ring buffer size (ring_buffer_size_kb >= 65536) and scale userspace telemetry consumer threads.",
		MatchedCVE:  "CVE-2026-10392",
	},
}

// LookupFlowRule retrieves a canonical rule definition by its unique identifier.
func LookupFlowRule(ruleID string) *FlowRule {
	for i := range CanonicalFlowRules {
		if CanonicalFlowRules[i].ID == ruleID {
			return &CanonicalFlowRules[i]
		}
	}
	return nil
}
