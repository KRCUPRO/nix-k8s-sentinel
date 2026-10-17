package wgfastpath

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB upper limit to prevent memory exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes limits telemetry payload sizes to 5MB.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines prevents unbounded loop allocations on maliciously large inputs.
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents bounds the maximum telemetry records in a single audit.
	MaxTelemetryEvents = 5000

	// CriticalRingBufferSaturation flags ring buffer saturation over 85%.
	CriticalRingBufferSaturation = 85.0
	// MaxAllowedPacketDropRate sets maximum acceptable packet drops per second (1,000 drops/s).
	MaxAllowedPacketDropRate = 1000.0
	// MaxSoftIRQPercent sets the softIRQ CPU utilization threshold (70%).
	MaxSoftIRQPercent = 70.0
	// MaxContextSwitchLatencyNs sets maximum allowable SIMD context switch overhead (250ns).
	MaxContextSwitchLatencyNs = 250.0
)

// FastPathMode identifies the kernel or driver acceleration mechanism for WireGuard.
type FastPathMode string

const (
	ModeGenericBPF FastPathMode = "GENERIC_BPF"
	ModeNativeXDP  FastPathMode = "NATIVE_XDP"
	ModeOffloadXDP FastPathMode = "OFFLOAD_XDP"
	ModeTCIngress  FastPathMode = "TC_INGRESS"
	ModeNone       FastPathMode = "NONE"
)

// CryptoVector identifies the SIMD cryptographic vector acceleration engine.
type CryptoVector string

const (
	VectorAVX512  CryptoVector = "AVX512"
	VectorAVX2    CryptoVector = "AVX2"
	VectorARMNeon CryptoVector = "ARM_NEON"
	VectorScalar  CryptoVector = "GENERIC_SCALAR"
)

// WireGuardInterfaceFastPathConfig models declarative host or container fast-path network interfaces.
type WireGuardInterfaceFastPathConfig struct {
	InterfaceName   string       `json:"interface_name"`
	MTU             int          `json:"mtu"`
	FastPathMode    FastPathMode `json:"fast_path_mode"`
	XDPDriver       string       `json:"xdp_driver,omitempty"`
	RingBufferSize  int          `json:"ring_buffer_size"`
	HardwareOffload bool         `json:"hardware_offload"` // GRO, GSO, TSO
	QueueCount      int          `json:"queue_count"`
	CryptoVector    CryptoVector `json:"crypto_vector"`
	FilePath        string       `json:"file_path,omitempty"`
	StartLine       int          `json:"start_line,omitempty"`
}

// CryptoBenchmarkTelemetry represents measured kernel cryptographic throughput and latency.
type CryptoBenchmarkTelemetry struct {
	VectorEngine       CryptoVector `json:"vector_engine"`
	ChunkSizeBytes     int          `json:"chunk_size_bytes"`
	CyclesPerByte      float64      `json:"cycles_per_byte"`
	GbpsThroughput     float64      `json:"gbps_throughput"`
	SIMDRegisterWidth  int          `json:"simd_register_width"`
	ThermalThrottled   bool         `json:"thermal_throttled"`
	ContextSwitchNs    float64      `json:"context_switch_ns"`
}

// FastPathTelemetry captures live 100GbE kernel fast-path performance, packet drop, and ring buffer metrics.
type FastPathTelemetry struct {
	InterfaceName         string  `json:"interface_name"`
	RXPacketsPerSec       float64 `json:"rx_packets_per_sec"`
	TXPacketsPerSec       float64 `json:"tx_packets_per_sec"`
	RXDropsPerSec         float64 `json:"rx_drops_per_sec"`
	TXDropsPerSec         float64 `json:"tx_drops_per_sec"`
	RingBufferUtilPercent float64 `json:"ring_buffer_util_percent"`
	XDPAbortedDrops       int64   `json:"xdp_aborted_drops"`
	MemoryAllocFailures   int64   `json:"memory_alloc_failures"`
	SoftIRQCpuPercent     float64 `json:"softirq_cpu_percent"`
	ActivePeers           int     `json:"active_peers"`
}

// WGFastPathRule represents a canonical WireGuard fast-path and crypto performance security rule.
type WGFastPathRule struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// WGFastPathViolation captures a detected fast-path misconfiguration or performance bottleneck.
type WGFastPathViolation struct {
	RuleID        string         `json:"rule_id"`
	InterfaceName string         `json:"interface_name"`
	Title         string         `json:"title"`
	Severity      intel.Severity `json:"severity"`
	CVSSScore     float64        `json:"cvss_score"`
	Description   string         `json:"description"`
	Remediation   string         `json:"remediation"`
	MatchedCVE    string         `json:"matched_cve,omitempty"`
	FilePath      string         `json:"file_path,omitempty"`
	StartLine     int            `json:"start_line,omitempty"`
}

// WGFastPathSummary summarizes the WireGuard fast-path audit metrics across cluster interfaces.
type WGFastPathSummary struct {
	TotalInterfacesAudited int      `json:"total_interfaces_audited"`
	TotalTelemetrySamples  int      `json:"total_telemetry_samples"`
	ViolationsCount        int      `json:"violations_count"`
	CriticalCount          int      `json:"critical_count"`
	HighCount              int      `json:"high_count"`
	MediumCount            int      `json:"medium_count"`
	LowCount               int      `json:"low_count"`
	AVX512Accelerated      bool     `json:"avx512_accelerated"`
	ARMNeonAccelerated     bool     `json:"arm_neon_accelerated"`
	BottleneckInterfaces   []string `json:"bottleneck_interfaces"`
	ComplianceScore        float64  `json:"compliance_score"`
}

// WGFastPathAuditReport models the complete fast-path and cryptographic audit output.
type WGFastPathAuditReport struct {
	Timestamp       time.Time                          `json:"timestamp"`
	Configurations  []WireGuardInterfaceFastPathConfig `json:"configurations"`
	Telemetry       []FastPathTelemetry                `json:"telemetry"`
	CryptoTelemetry []CryptoBenchmarkTelemetry         `json:"crypto_telemetry"`
	Violations      []WGFastPathViolation              `json:"violations"`
	Summary         WGFastPathSummary                  `json:"summary"`
}
