package bgp

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// CanonicalBGPRules provides the definitive catalog of BGP peering radar security rules.
var CanonicalBGPRules = []BGPRule{
	{
		ID:          "BGP-RADAR-001",
		Title:       "Unauthenticated BGP Peering Session Missing TCP MD5 or TCP-AO Authentication",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.3,
		Description: "BGP neighbor peering sessions configured without RFC 2385 TCP MD5 signatures or RFC 5925 TCP-AO authentication allow rogue network adjacent actors to inject forged routing announcements, hijack traffic, or execute BGP reset attacks.",
		Remediation: "Configure authSecretRef with Kubernetes secret referencing TCP MD5 or TCP-AO password in CiliumBGPPeer / FRR neighbor declarations.",
		MatchedCVE:  "CVE-2026-70192",
	},
	{
		ID:          "BGP-RADAR-002",
		Title:       "Missing Dual-Stack IPv6 Route Advertisements in BGP Peering Policy",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Description: "BGP peering configuration advertises only IPv4 unicast routes in a dual-stack Kubernetes cluster, leaving IPv6 pod traffic unrouted or routed across suboptimal non-BGP default gateways.",
		Remediation: "Enable dual-stack address families in CiliumBGPPeer (families: [IPv4, IPv6]) and associate CiliumLoadBalancerIPPool containing IPv6 CIDRs.",
	},
	{
		ID:          "BGP-RADAR-003",
		Title:       "Cilium IPAM Pool Exhaustion Threat Exceeding 85% High-Watermark",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Description: "Dynamic IP address allocation in CiliumLoadBalancerIPPool or Pod IPAM pool exceeds 85% utilization or has fewer than 10% unallocated IPv6 prefixes, risking pod eviction and service failure.",
		Remediation: "Expand IPAM pool CIDR blocks, configure secondary fallback pools, or enable dynamic subnet allocation before exhaustion.",
	},
	{
		ID:          "BGP-RADAR-004",
		Title:       "Unrestricted BGP Route Export Leaking Default Route or Missing Prefix Filters",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Description: "Exporting PodCIDR or ServiceCIDR to top-of-rack switches without explicit prefix filters risks advertising default routes (0.0.0.0/0 or ::/0) or unintended internal subnets to upstream BGP peers.",
		Remediation: "Define explicit prefix-list filters in CiliumBGPPeeringPolicy or FRR configuration restricting exported routes to allocated cluster CIDRs.",
	},
	{
		ID:          "BGP-RADAR-005",
		Title:       "BGP Autonomous System Number Conflict or Unconfigured eBGP Multihop TTL",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.5,
		Description: "eBGP peering across multi-hop L3 switches without explicit TTL or GTSM (Generalized TTL Security Mechanism) allows routing loops or spoofed BGP packet injections.",
		Remediation: "Configure explicit eBGP multihop TTL (ttl >= 2) or enable GTSM with strict TTL matching on direct ToR peer sessions.",
	},
	{
		ID:          "BGP-RADAR-006",
		Title:       "BGP Graceful Restart (RFC 4724) Disabled or Unconfigured",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Description: "Disabling BGP Graceful Restart triggers immediate route withdrawal and packet loss during Cilium agent updates, kernel live-patches, or node maintenance.",
		Remediation: "Enable gracefulRestart in CiliumBGPPeer / FRR configuration with a restart time bounded between 60 and 120 seconds.",
	},
	{
		ID:          "BGP-RADAR-007",
		Title:       "Unrestricted BGP Listen Port TCP 179 Exposed to Untrusted Interfaces",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Description: "Host nodes accepting TCP 179 connections on all network interfaces without firewall or Cilium network policy restrictions risk remote DoS and unauthenticated session fuzzing.",
		Remediation: "Restrict TCP 179 ingress in networking.firewall.extraCommands or CiliumClusterwideNetworkPolicy to verified ToR switch IP subnets.",
	},
	{
		ID:          "BGP-RADAR-008",
		Title:       "IPv6 Router Advertisement Spoofing Vulnerability on Host Interfaces",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.6,
		Description: "Host nodes with net.ipv6.conf.all.accept_ra > 0 can be tricked by rogue IPv6 Router Advertisements into overriding BGP routes or injecting rogue default routers.",
		Remediation: "Enforce boot.kernel.sysctl.\"net.ipv6.conf.all.accept_ra\" = 0 and \"net.ipv6.conf.default.accept_ra\" = 0 on all Kubernetes cluster nodes.",
	},
	{
		ID:          "BGP-RADAR-009",
		Title:       "BGP HoldTime or KeepAlive Timer Misconfiguration",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Description: "BGP HoldTime exceeding 90 seconds delays link failure convergence, while aggressive timers (< 3s) cause false-positive session drops under heavy CPU load.",
		Remediation: "Configure BGP KeepAlive to 3-10 seconds and HoldTime to 9-30 seconds for predictable bare-metal convergence.",
	},
	{
		ID:          "BGP-RADAR-010",
		Title:       "Excessive BGP Session Route Flapping or Flap Damping Penalties",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Description: "Runtime telemetry indicates frequent BGP state resets (> 5 resets/hour) or active route flap damping, causing route flapping and packet drops.",
		Remediation: "Inspect physical transceiver SFP+ link health, adjust BFD failure thresholds, and resolve underlying MTU mismatches.",
	},
	{
		ID:          "BGP-RADAR-011",
		Title:       "Missing BGP Community Tags for Multi-Tenant Egress Route Segregation",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.0,
		Description: "Multi-tenant clusters advertising routes without standard BGP community tags prevent upstream routers from applying granular route-map filtering and QoS policies.",
		Remediation: "Attach RFC 1997 / RFC 4360 BGP community tags in CiliumBGPPeeringPolicy for tenant traffic classification.",
	},
	{
		ID:          "BGP-RADAR-012",
		Title:       "Unmonitored BGP Peering Session or Stale Session Telemetry",
		Severity:    intel.SeverityLow,
		CVSSScore:   3.9,
		Description: "Declared BGP peering session lacks active telemetry tracking or telemetry timestamp is stale (> 300 seconds), creating blind spots in mesh health.",
		Remediation: "Verify Cilium BGP control plane telemetry exporters and node agent metrics collection pipelines.",
	},
}

// FindRule returns a canonical BGPRule by its identifier, or a default placeholder.
func FindRule(id string) BGPRule {
	for _, r := range CanonicalBGPRules {
		if r.ID == id {
			return r
		}
	}
	return BGPRule{
		ID:          id,
		Title:       "Unknown BGP Peering Rule",
		Severity:    intel.SeverityLow,
		CVSSScore:   1.0,
		Description: "Unrecognized BGP peering rule violation",
		Remediation: "Audit BGP configuration against production security baseline.",
	}
}
