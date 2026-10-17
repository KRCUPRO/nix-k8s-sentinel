package wgfastpath

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// CanonicalRuleCatalog defines the authoritative set of 12 WireGuard eBPF fast-path and crypto performance rules.
var CanonicalRuleCatalog = []WGFastPathRule{
	{
		ID:          "WG-FAST-001",
		Category:    "CRYPTO_ACCELERATION",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Title:       "Kernel ChaCha20-Poly1305 Scalar Fallback Without Vector Acceleration",
		Description: "The WireGuard crypto subsystem is running with generic scalar implementations lacking AVX-512 or ARM Neon hardware SIMD vector acceleration, throttling packet processing throughput to less than 15Gbps.",
		Remediation: "Ensure CPU microcode and kernel crypto modules (chacha20_simd, poly1305_simd, or neon) are explicitly enabled in NixOS boot.kernelModules and boot.kernelParams.",
	},
	{
		ID:          "WG-FAST-002",
		Category:    "FASTPATH_DRIVER",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Title:       "WireGuard Interface Missing Native XDP/eBPF Fast-Path Hook",
		Description: "The WireGuard interface is processing packets through standard kernel socket sk_buff queues rather than native eBPF/XDP driver fast-path bypass on a high-throughput network interface.",
		Remediation: "Attach a native XDP program (e.g. xdpdrv) or TC-eBPF hook to the WireGuard ingress device to handle packet encapsulation routing in driver space before socket allocation.",
	},
	{
		ID:          "WG-FAST-003",
		Category:    "RING_BUFFER_SATURATION",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.1,
		Title:       "Kernel Fast-Path Ring Buffer Saturation Exceeds Critical Threshold",
		Description: "Ring buffer utilization exceeds 85%, indicating incoming packet bursts on 100GbE interconnects are overwhelming worker queues and inducing silent packet drops.",
		Remediation: "Increase NIC ring buffer descriptors via ethtool -G rx 4096 tx 4096 and adjust sysctl net.core.netdev_max_backlog to at least 16384.",
		MatchedCVE:  "CVE-2026-31049",
	},
	{
		ID:          "WG-FAST-004",
		Category:    "PACKET_LOSS",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Title:       "Excessive Packet Drop Rate On Bare-Metal Interconnect",
		Description: "Network packet drop rate on WireGuard fast-path interface exceeds 1,000 drops per second, triggering severe TCP congestion window collapse and inter-node latency spikes.",
		Remediation: "Verify physical link integrity, tune ethtool pause parameters, increase RX ring buffer sizes, and verify interrupt affinity across CPU cores.",
	},
	{
		ID:          "WG-FAST-005",
		Category:    "HARDWARE_OFFLOAD",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.2,
		Title:       "Hardware Network Offloads Disabled on Physical Underlay NIC",
		Description: "Generic Receive Offload (GRO) or Generic Segmentation Offload (GSO) is disabled on the physical interface supporting WireGuard overlay tunnels, multiplying per-packet CPU interrupt overhead.",
		Remediation: "Enable hardware offload capabilities via ethtool -K <iface> rx-gro-hw on tso on gso on.",
	},
	{
		ID:          "WG-FAST-006",
		Category:    "CPU_STARVATION",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Title:       "SoftIRQ Budget Starvation on Cryptographic Worker Cores",
		Description: "Kernel softIRQ processing consumes greater than 70% of CPU budget on cores assigned to WireGuard crypto queues, stalling user-space workloads and scheduler threads.",
		Remediation: "Configure receive packet steering (RPS) and receive flow steering (RFS) across all NUMA nodes and pin WireGuard crypto threads to dedicated CPU cores.",
	},
	{
		ID:          "WG-FAST-007",
		Category:    "MTU_MISMATCH",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.5,
		Title:       "WireGuard Overlay MTU Mismatch Inducing IP Fragmentation",
		Description: "WireGuard interface MTU is unoptimized for the underlying fabric (e.g. non-1420 for standard 1500 Ethernet or non-8920 for 9000 Jumbo Frames), triggering kernel IP fragmentation.",
		Remediation: "Align WireGuard interface MTU to exactly underlay MTU minus 80 bytes (e.g. 1420 for MTU 1500, or 8920 for MTU 9000).",
	},
	{
		ID:          "WG-FAST-008",
		Category:    "XDP_EXCEPTION",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Title:       "eBPF XDP Program Aborted Exceptions Detected",
		Description: "The kernel driver reported XDP_ABORTED execution results, indicating memory safety faults, unhandled packet boundary violations, or verifier instruction traps inside the fast-path filter.",
		Remediation: "Inspect kernel dmesg logs for eBPF verifier warnings, recompile the XDP driver with valid bounds checks, and temporarily fall back to generic XDP.",
	},
	{
		ID:          "WG-FAST-009",
		Category:    "LATENCY_SPIKE",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.0,
		Title:       "Elevated SIMD FPU Context Switch Overhead Latency",
		Description: "SIMD register context save/restore operations exceed 250ns per batch during ChaCha20-Poly1305 encryption rounds due to high task preemption frequencies.",
		Remediation: "Increase kernel_fpu_begin/end batch granularity and configure isolcpus or thread affinity for latency-critical cryptographic pipelines.",
	},
	{
		ID:          "WG-FAST-010",
		Category:    "QUEUE_CONTENTION",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Title:       "Multi-Queue NIC Descriptors Fewer Than Active CPU Cores",
		Description: "Physical NIC hardware queues are fewer than available CPU cores on multi-socket NUMA systems, forcing packet processing threads into spinlock contention.",
		Remediation: "Configure ethtool -L <iface> combined <num_cores> to allocate one dedicated hardware RX/TX queue per logical processor.",
	},
	{
		ID:          "WG-FAST-011",
		Category:    "MEMORY_EXHAUSTION",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.4,
		Title:       "Kernel Socket Buffer Allocation Failures in Fast-Path Pipeline",
		Description: "The kernel fast-path allocator failed to provision sk_buff structures or page pool buffers under peak 100GbE traffic load.",
		Remediation: "Tune sysctl vm.min_free_kbytes, increase page pool allocations via sysctl net.core.rmem_max, and configure dedicated hugepages.",
	},
	{
		ID:          "WG-FAST-012",
		Category:    "THERMAL_THROTTLING",
		Severity:    intel.SeverityLow,
		CVSSScore:   3.8,
		Title:       "AVX-512 Execution Unit Thermal Downclocking Throttling",
		Description: "High-density AVX-512 vector operations triggered processor thermal throttling, forcing core frequency downclocking and transient throughput degradation.",
		Remediation: "Review server chassis cooling, consider AVX2 fallback profiles in thermally constrained environments, or adjust CPU energy performance bias.",
	},
}

// GetRuleByID searches CanonicalRuleCatalog by identifier and returns a copy if found.
func GetRuleByID(id string) (WGFastPathRule, bool) {
	for _, rule := range CanonicalRuleCatalog {
		if rule.ID == id {
			return rule, true
		}
	}
	return WGFastPathRule{}, false
}
