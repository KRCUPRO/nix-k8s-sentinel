package flow

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes defines the 10MB memory safety ceiling for Cilium and NixOS flow configurations.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes defines the 5MB memory safety ceiling for runtime eBPF network flow & DNS telemetry.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines defines the line count ceiling for manifest scans.
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents defines the ceiling for runtime telemetry events.
	MaxTelemetryEvents = 5000
	// DefaultEntropyThreshold is the Shannon entropy threshold above which DNS queries indicate tunneling.
	DefaultEntropyThreshold = 3.85
	// MaxQueryLengthThreshold is the maximum character length for benign DNS queries.
	MaxQueryLengthThreshold = 180
	// MaxLabelLengthThreshold is the maximum character length for a single benign DNS subdomain label.
	MaxLabelLengthThreshold = 50
	// MaxSocketConnectBurstRate is the anomalous socket connection creation ceiling per cgroup (conn/sec).
	MaxSocketConnectBurstRate = 500
	// MaxNXDomainRatePercent is the threshold for active DGA beaconing detection.
	MaxNXDomainRatePercent = 25.0
)

// FlowProtocol represents the transport protocol for tracked network flows.
type FlowProtocol string

const (
	// FlowProtocolTCP represents TCP socket connections.
	FlowProtocolTCP FlowProtocol = "TCP"
	// FlowProtocolUDP represents UDP datagram flows (e.g., DNS, WireGuard).
	FlowProtocolUDP FlowProtocol = "UDP"
	// FlowProtocolICMP represents ICMP diagnostics flows.
	FlowProtocolICMP FlowProtocol = "ICMP"
	// FlowProtocolAny represents unconstrained wildcard protocols.
	FlowProtocolAny FlowProtocol = "ANY"
)

// DNSRecordType represents the DNS resource record query class.
type DNSRecordType string

const (
	// RecordTypeA represents IPv4 address queries.
	RecordTypeA DNSRecordType = "A"
	// RecordTypeAAAA represents IPv6 address queries.
	RecordTypeAAAA DNSRecordType = "AAAA"
	// RecordTypeTXT represents arbitrary text queries commonly abused for tunneling.
	RecordTypeTXT DNSRecordType = "TXT"
	// RecordTypeNULL represents experimental null record queries abused for tunneling.
	RecordTypeNULL DNSRecordType = "NULL"
	// RecordTypeCNAME represents canonical name records.
	RecordTypeCNAME DNSRecordType = "CNAME"
	// RecordTypeANY represents wildcard query types.
	RecordTypeANY DNSRecordType = "ANY"
)

// ExfiltrationVector represents the categorized data exfiltration or anomaly pattern.
type ExfiltrationVector string

const (
	// VectorTunneling indicates high-entropy DNS tunnel encapsulation.
	VectorTunneling ExfiltrationVector = "DNS_TUNNELING"
	// VectorDGA indicates Domain Generation Algorithm C2 beaconing.
	VectorDGA ExfiltrationVector = "DGA_BEACONING"
	// VectorSocketStorm indicates anomalous socket connect rate burst.
	VectorSocketStorm ExfiltrationVector = "SOCKET_CONNECT_STORM"
	// VectorUnauthorizedEgress indicates direct external egress bypassing cluster proxy.
	VectorUnauthorizedEgress ExfiltrationVector = "UNAUTHORIZED_EGRESS"
	// VectorFastFlux indicates rapid DNS IP churn with ultra-low TTL.
	VectorFastFlux ExfiltrationVector = "FAST_FLUX_RESOLUTION"
	// VectorNone indicates standard benign traffic.
	VectorNone ExfiltrationVector = "NONE"
)

// FQDNRule represents an allowed or pattern-matched Fully Qualified Domain Name rule.
type FQDNRule struct {
	MatchPattern string `json:"match_pattern,omitempty"`
	MatchName    string `json:"match_name,omitempty"`
	LineNumber   int    `json:"line_number,omitempty"`
}

// DNSRuleConfig represents DNS Layer 7 proxy filtering parameters.
type DNSRuleConfig struct {
	MatchPattern string `json:"match_pattern,omitempty"`
	MatchName    string `json:"match_name,omitempty"`
	LineNumber   int    `json:"line_number,omitempty"`
}

// PortRuleConfig represents transport port egress constraints.
type PortRuleConfig struct {
	Port       int             `json:"port"`
	Protocol   FlowProtocol    `json:"protocol"`
	DNSRules   []DNSRuleConfig `json:"dns_rules,omitempty"`
	LineNumber int             `json:"line_number,omitempty"`
}

// EgressRuleConfig models an egress policy block in a CiliumNetworkPolicy.
type EgressRuleConfig struct {
	ToPorts    []PortRuleConfig `json:"to_ports,omitempty"`
	ToCIDRs    []string         `json:"to_cidrs,omitempty"`
	ToFQDNs    []FQDNRule       `json:"to_fqdns,omitempty"`
	LineNumber int              `json:"line_number,omitempty"`
}

// CiliumNetworkPolicyConfig captures declarative Cilium network security policies.
type CiliumNetworkPolicyConfig struct {
	FilePath         string             `json:"file_path"`
	APIVersion       string             `json:"api_version"`
	Kind             string             `json:"kind"`
	Name             string             `json:"name"`
	Namespace        string             `json:"namespace"`
	EndpointSelector map[string]string  `json:"endpoint_selector,omitempty"`
	EgressRules      []EgressRuleConfig `json:"egress_rules,omitempty"`
	EnableDNSProxy   *bool              `json:"enable_dns_proxy,omitempty"`
	LineNumbers      map[string]int     `json:"line_numbers,omitempty"`
}

// NixOSFlowConfig captures declarative NixOS host eBPF flow profiling and socket tracing options.
type NixOSFlowConfig struct {
	FilePath              string         `json:"file_path"`
	HostName              string         `json:"host_name,omitempty"`
	CiliumEnabled         *bool          `json:"cilium_enabled,omitempty"`
	FlowProfilerEnabled   *bool          `json:"flow_profiler_enabled,omitempty"`
	BPFConnectMonitoring  *bool          `json:"bpf_connect_monitoring,omitempty"`
	MaxSocketRate         int            `json:"max_socket_rate,omitempty"`
	DNSProxyPort          int            `json:"dns_proxy_port,omitempty"`
	RingBufferSizeKB      int            `json:"ring_buffer_size_kb,omitempty"`
	DropThresholdPercent  float64        `json:"drop_threshold_percent,omitempty"`
	LineNumbers           map[string]int `json:"line_numbers,omitempty"`
}

// DNSQueryEvent captures an individual runtime DNS query telemetry event.
type DNSQueryEvent struct {
	Timestamp      time.Time          `json:"timestamp"`
	ClientPod      string             `json:"client_pod"`
	Namespace      string             `json:"namespace"`
	ClientIP       string             `json:"client_ip"`
	ServerIP       string             `json:"server_ip"`
	QueryName      string             `json:"query_name"`
	RecordType     DNSRecordType      `json:"record_type"`
	Entropy        float64            `json:"entropy"`
	QueryLength    int                `json:"query_length"`
	MaxLabelLength int                `json:"max_label_length"`
	ResponseCode   string             `json:"response_code"` // e.g. "NOERROR", "NXDOMAIN", "SERVFAIL"
	TTL            int                `json:"ttl"`
	Vector         ExfiltrationVector `json:"vector"`
	IsAnomaly      bool               `json:"is_anomaly"`
}

// SocketConnectEvent captures an individual kernel socket connect syscall trace.
type SocketConnectEvent struct {
	Timestamp      time.Time    `json:"timestamp"`
	SourcePod      string       `json:"source_pod"`
	Namespace      string       `json:"namespace"`
	SourceIP       string       `json:"source_ip"`
	DestIP         string       `json:"dest_ip"`
	DestPort       int          `json:"dest_port"`
	Protocol       FlowProtocol `json:"protocol"`
	ConnectsPerSec int          `json:"connects_per_sec"`
	CgroupPath     string       `json:"cgroup_path,omitempty"`
	IsAnomaly      bool         `json:"is_anomaly"`
}

// FlowTelemetryReport consolidates live eBPF socket flows, DNS tunneling metrics, and drop telemetry.
type FlowTelemetryReport struct {
	HostName               string               `json:"host_name"`
	ClusterName            string               `json:"cluster_name"`
	CollectedAt            time.Time            `json:"collected_at"`
	TotalDNSQueries        int                  `json:"total_dns_queries"`
	SuspiciousQueries      int                  `json:"suspicious_queries"`
	NXDomainCount          int                  `json:"nxdomain_count"`
	NXDomainRatePercent    float64              `json:"nxdomain_rate_percent"`
	PeakSocketConnectRate  int                  `json:"peak_socket_connect_rate"`
	DroppedPackets         int                  `json:"dropped_packets"`
	BufferOverruns         int                  `json:"buffer_overruns"`
	DropRatePercent        float64              `json:"drop_rate_percent"`
	Queries                []DNSQueryEvent      `json:"queries"`
	SocketEvents           []SocketConnectEvent `json:"socket_events"`
}

// FlowRule defines a canonical security rule for network flow and DNS exfiltration detection.
type FlowRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// FlowViolation models a detected non-compliance finding or runtime exfiltration anomaly.
type FlowViolation struct {
	RuleID      string         `json:"rule_id"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	FilePath    string         `json:"file_path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
	EndLine     int            `json:"end_line,omitempty"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// FlowSummary provides aggregate metrics and deterministic compliance scoring.
type FlowSummary struct {
	TotalScanned    int     `json:"total_scanned"`
	CompliantCount  int     `json:"compliant_count"`
	ViolationCount  int     `json:"violation_count"`
	ComplianceScore float64 `json:"compliance_score"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
}

// FlowAuditReport aggregates static manifest findings, runtime eBPF telemetry, and compliance summary.
type FlowAuditReport struct {
	HostName      string                       `json:"host_name"`
	ScannedAt     time.Time                    `json:"scanned_at"`
	CiliumConfigs []*CiliumNetworkPolicyConfig `json:"cilium_configs,omitempty"`
	NixOSConfigs  []*NixOSFlowConfig           `json:"nixos_configs,omitempty"`
	Telemetry     *FlowTelemetryReport         `json:"telemetry,omitempty"`
	Violations    []FlowViolation              `json:"violations"`
	Summary       FlowSummary                  `json:"summary"`
}
