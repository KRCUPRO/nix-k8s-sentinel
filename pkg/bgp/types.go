package bgp

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Security bounds & defensive thresholds for streaming parsers and runtime telemetry
const (
	// MaxManifestBytes restricts raw BGP and network manifest file ingestion to 10MB
	MaxManifestBytes int64 = 10 * 1024 * 1024
	// MaxTelemetryBytes restricts runtime BGP peer and IPAM telemetry files to 5MB
	MaxTelemetryBytes int64 = 5 * 1024 * 1024
	// MaxAllowedScanLines limits parser line traversal to prevent algorithmic complexity DoS
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents limits in-memory BGP session event ingestion
	MaxTelemetryEvents = 5000
)

// BGPSessionState represents the RFC 4271 BGP finite state machine state.
type BGPSessionState string

const (
	StateIdle        BGPSessionState = "IDLE"
	StateConnect     BGPSessionState = "CONNECT"
	StateActive      BGPSessionState = "ACTIVE"
	StateOpenSent    BGPSessionState = "OPENSENT"
	StateOpenConfirm BGPSessionState = "OPENCONFIRM"
	StateEstablished BGPSessionState = "ESTABLISHED"
)

// IPFamily indicates IP protocol family.
type IPFamily string

const (
	FamilyIPv4      IPFamily = "IPv4"
	FamilyIPv6      IPFamily = "IPv6"
	FamilyDualStack IPFamily = "DualStack"
)

// CiliumBGPPeerConfig defines a BGP peering neighbor configuration.
type CiliumBGPPeerConfig struct {
	PeerAddress         string   `json:"peer_address"`
	PeerASN             int      `json:"peer_asn"`
	AuthSecret          string   `json:"auth_secret,omitempty"`
	HasMD5              bool     `json:"has_md5"`
	HasTCPAO            bool     `json:"has_tcp_ao"`
	MultihopTTL         int      `json:"multihop_ttl"`
	GracefulRestart     bool     `json:"graceful_restart"`
	GracefulRestartTime int      `json:"graceful_restart_time_seconds"`
	HoldTime            int      `json:"hold_time_seconds"`
	KeepAlive           int      `json:"keepalive_seconds"`
	Families            []string `json:"families"`
	CommunityTags       []string `json:"community_tags,omitempty"`
	RouteFlapDamping    bool     `json:"route_flap_damping"`
}

// VirtualRouterConfig defines an autonomous system configuration on a node.
type VirtualRouterConfig struct {
	LocalASN         int                   `json:"local_asn"`
	ExportPodCIDR    bool                  `json:"export_pod_cidr"`
	ExportServiceCIDR bool                 `json:"export_service_cidr"`
	PrefixFilters    []string              `json:"prefix_filters,omitempty"`
	Neighbors        []CiliumBGPPeerConfig `json:"neighbors"`
}

// CiliumBGPPeeringPolicyConfig represents parsed CiliumBGPPeeringPolicy or CiliumBGPClusterConfig.
type CiliumBGPPeeringPolicyConfig struct {
	PolicyName     string                `json:"policy_name"`
	Namespace      string                `json:"namespace,omitempty"`
	NodeSelectors  map[string]string     `json:"node_selectors,omitempty"`
	VirtualRouters []VirtualRouterConfig `json:"virtual_routers"`
	SourceFile     string                `json:"source_file"`
	StartLine      int                   `json:"start_line"`
}

// CiliumLoadBalancerIPPoolConfig represents parsed CiliumLoadBalancerIPPool CRD.
type CiliumLoadBalancerIPPoolConfig struct {
	PoolName        string            `json:"pool_name"`
	CIDRs           []string          `json:"cidrs"`
	Disabled        bool              `json:"disabled"`
	ServiceSelector map[string]string `json:"service_selector,omitempty"`
	SourceFile      string            `json:"source_file"`
	StartLine       int               `json:"start_line"`
}

// NixOSBGPConfig represents parsed NixOS host BGP and network routing configuration.
type NixOSBGPConfig struct {
	HostName           string                `json:"host_name"`
	FRREnabled         bool                  `json:"frr_enabled"`
	LocalASN           int                   `json:"local_asn"`
	BGPNeighbors       []CiliumBGPPeerConfig `json:"bgp_neighbors"`
	TCP179Allowed      bool                  `json:"tcp_179_allowed"`
	FirewallRestricted bool                  `json:"firewall_restricted"`
	IPv6AcceptRA       int                   `json:"ipv6_accept_ra"`
	SourceFile         string                `json:"source_file"`
	StartLine          int                   `json:"start_line"`
}

// BGPPeerTelemetry represents runtime telemetry collected from a BGP speaker.
type BGPPeerTelemetry struct {
	PeerAddress        string          `json:"peer_address"`
	PeerASN            int             `json:"peer_asn"`
	LocalASN           int             `json:"local_asn"`
	State              BGPSessionState `json:"state"`
	UptimeSeconds      int64           `json:"uptime_seconds"`
	PrefixesReceived   int             `json:"prefixes_received"`
	PrefixesAdvertised int             `json:"prefixes_advertised"`
	ResetCount         int             `json:"reset_count"`
	FlapDampingActive  bool            `json:"flap_damping_active"`
	LastResetReason    string          `json:"last_reset_reason,omitempty"`
	HoldTimeSeconds    int             `json:"hold_time_seconds"`
	KeepAliveSeconds   int             `json:"keepalive_seconds"`
	LastUpdateSeconds  int64           `json:"last_update_seconds_ago"`
}

// IPAMPoolTelemetry represents runtime IP pool usage telemetry.
type IPAMPoolTelemetry struct {
	PoolName     string   `json:"pool_name"`
	CIDR         string   `json:"cidr"`
	Family       IPFamily `json:"family"`
	TotalIPs     int      `json:"total_ips"`
	AllocatedIPs int      `json:"allocated_ips"`
	UsagePercent float64  `json:"usage_percent"`
}

// BGPTelemetryReport encapsulates runtime BGP session and IPAM telemetry.
type BGPTelemetryReport struct {
	ClusterName string              `json:"cluster_name"`
	NodeID      string              `json:"node_id"`
	Timestamp   time.Time           `json:"timestamp"`
	Peers       []BGPPeerTelemetry  `json:"peers"`
	IPAMPools   []IPAMPoolTelemetry `json:"ipam_pools"`
}

// BGPRule defines a canonical BGP radar security check rule.
type BGPRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// BGPViolation captures a detected misconfiguration or runtime threat.
type BGPViolation struct {
	RuleID      string         `json:"rule_id"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	PeerAddress string         `json:"peer_address,omitempty"`
	PolicyName  string         `json:"policy_name,omitempty"`
	FilePath    string         `json:"file_path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// BGPSummary provides aggregate security posture metrics.
type BGPSummary struct {
	TotalPolicies       int     `json:"total_policies"`
	TotalPeers          int     `json:"total_peers"`
	TotalIPAMPools      int     `json:"total_ipam_pools"`
	TotalViolations     int     `json:"total_violations"`
	CriticalCount       int     `json:"critical_count"`
	HighCount           int     `json:"high_count"`
	MediumCount         int     `json:"medium_count"`
	LowCount            int     `json:"low_count"`
	DualStackCompliant  bool    `json:"dual_stack_compliant"`
	ComplianceScore     float64 `json:"compliance_score"`
}

// BGPAuditReport encapsulates full findings from BGP peering radar.
type BGPAuditReport struct {
	Policies   []CiliumBGPPeeringPolicyConfig   `json:"policies,omitempty"`
	IPPools    []CiliumLoadBalancerIPPoolConfig `json:"ip_pools,omitempty"`
	NixOSHosts []NixOSBGPConfig                 `json:"nixos_hosts,omitempty"`
	Telemetry  *BGPTelemetryReport              `json:"telemetry,omitempty"`
	Violations []BGPViolation                   `json:"violations"`
	Summary    BGPSummary                       `json:"summary"`
}
