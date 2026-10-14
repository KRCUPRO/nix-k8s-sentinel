package probe

import (
	"context"
	"time"
)

// ProbeType designates the architectural domain of the kernel telemetry probe.
type ProbeType string

const (
	// ProbeTypeSyscall monitors kernel syscall dispatch (e.g., execve, ptrace, bpf).
	ProbeTypeSyscall ProbeType = "syscall"
	// ProbeTypeSocket monitors transport-layer socket lifecycle (connect, accept, bind).
	ProbeTypeSocket ProbeType = "socket"
	// ProbeTypeStorage monitors filesystem mutations and immutable store integrity.
	ProbeTypeStorage ProbeType = "storage"
	// ProbeTypeProcess monitors process lifecycle, privilege changes, and namespace transitions.
	ProbeTypeProcess ProbeType = "process"
)

// ProbeStatus represents the operational lifecycle state of an active or simulated probe.
type ProbeStatus string

const (
	StatusUninitialized ProbeStatus = "uninitialized"
	StatusRunning       ProbeStatus = "running"
	StatusStopped       ProbeStatus = "stopped"
	StatusError         ProbeStatus = "error"
)

// TelemetryEvent encapsulates a single structured telemetry record emitted from a bare-metal kernel probe.
type TelemetryEvent struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ProbeType    ProbeType `json:"probe_type"`
	NodeName     string    `json:"node_name"`
	PID          uint32    `json:"pid"`
	PPID         uint32    `json:"ppid"`
	UID          uint32    `json:"uid"`
	Comm         string    `json:"comm"`
	ContainerID  string    `json:"container_id,omitempty"`
	Namespace    string    `json:"namespace,omitempty"`
	PodName      string    `json:"pod_name,omitempty"`
	EventType    string    `json:"event_type"`
	Syscall      string    `json:"syscall,omitempty"`
	SourceAddr   string    `json:"source_addr,omitempty"`
	DestAddr     string    `json:"dest_addr,omitempty"`
	Protocol     string    `json:"protocol,omitempty"`
	Severity     string    `json:"severity"`
	RiskScore    float64   `json:"risk_score"`
	Message      string    `json:"message"`
	ThreatTags   []string  `json:"threat_tags,omitempty"`
}

// ProbeConfig defines initialization parameters for a node-level telemetry probe.
type ProbeConfig struct {
	NodeName               string   `json:"node_name"`
	TargetSyscalls         []string `json:"target_syscalls,omitempty"`
	BufferSize             int      `json:"buffer_size"`
	EnableSocketFiltering  bool     `json:"enable_socket_filtering"`
	SensitivePorts         []int    `json:"sensitive_ports,omitempty"`
	MonitoredPaths         []string `json:"monitored_paths,omitempty"`
}

// DefaultProbeConfig returns production-ready default parameters for bare-metal probes.
func DefaultProbeConfig(nodeName string) ProbeConfig {
	return ProbeConfig{
		NodeName:              nodeName,
		TargetSyscalls:        []string{"execve", "connect", "ptrace", "bpf", "openat2"},
		BufferSize:            1024,
		EnableSocketFiltering: true,
		SensitivePorts:        []int{2379, 2380, 10250, 6789},
		MonitoredPaths:        []string{"/nix/store", "/etc/kubernetes", "/proc/kcore"},
	}
}

// Probe defines the universal interface for kernel eBPF probes and multi-node mock fixtures.
type Probe interface {
	// Name returns the descriptive identifier of the probe instance.
	Name() string
	// Type returns the architectural telemetry domain.
	Type() ProbeType
	// Node returns the bare-metal node identity where the probe is attached.
	Node() string
	// Start activates telemetry stream processing.
	Start(ctx context.Context) error
	// Stop gracefully terminates the probe stream.
	Stop() error
	// Events returns the read-only telemetry channel.
	Events() <-chan TelemetryEvent
	// Status returns the current lifecycle status.
	Status() ProbeStatus
}
