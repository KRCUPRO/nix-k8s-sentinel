package bpf

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Defensive bounds and memory safety invariants
const (
	// MaxManifestBytes defines the 10MB ceiling for scanning workload and host manifests.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes defines the 5MB ceiling for runtime BPF telemetry JSON documents.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxSyscallRules limits the number of parsed syscall filter rules per profile.
	MaxSyscallRules = 2048
	// MaxSocketRateThreshold is the threshold (events/sec) exceeding normal socket creation patterns.
	MaxSocketRateThreshold = 250.0
	// MaxAllowedScanLines defines the streaming line ceiling for manifest scanners.
	MaxAllowedScanLines = 20000
)

// BPFProfileType designates the category of kernel security profile.
type BPFProfileType string

const (
	ProfileSeccomp      BPFProfileType = "seccomp"
	ProfileEBPFLSM      BPFProfileType = "ebpf_lsm"
	ProfileSyscallAudit BPFProfileType = "syscall_audit"
	ProfileTelemetry    BPFProfileType = "runtime_telemetry"
)

// SyscallAction defines seccomp filter action constants.
type SyscallAction string

const (
	ActionAllow       SyscallAction = "SCMP_ACT_ALLOW"
	ActionErrno       SyscallAction = "SCMP_ACT_ERRNO"
	ActionKillProcess SyscallAction = "SCMP_ACT_KILL_PROCESS"
	ActionLog         SyscallAction = "SCMP_ACT_LOG"
	ActionTrace       SyscallAction = "SCMP_ACT_TRACE"
)

// SyscallArg models argument filtering conditions within seccomp rules.
type SyscallArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"value_two,omitempty"`
	Op       string `json:"op"`
}

// SeccompSyscallRule represents an individual syscall rule declaration.
type SeccompSyscallRule struct {
	Names  []string      `json:"names"`
	Action SyscallAction `json:"action"`
	Args   []SyscallArg  `json:"args,omitempty"`
}

// SeccompProfile models declarative Kubernetes or Linux seccomp profile JSON structures.
type SeccompProfile struct {
	DefaultAction SyscallAction        `json:"defaultAction"`
	Architectures []string             `json:"architectures,omitempty"`
	Syscalls      []SeccompSyscallRule `json:"syscalls,omitempty"`
	Flags         []string             `json:"flags,omitempty"`
}

// BPFLSMHookDeclaration models declarative eBPF Linux Security Module (LSM) hooks.
type BPFLSMHookDeclaration struct {
	HookName      string `json:"hook_name"`
	TargetSyscall string `json:"target_syscall"`
	Action        string `json:"action"`
	Enforced      bool   `json:"enforced"`
}

// SocketTelemetryItem captures socket creation metrics and burst rates.
type SocketTelemetryItem struct {
	PID          int       `json:"pid"`
	ProcessName  string    `json:"process_name"`
	Namespace    string    `json:"namespace,omitempty"`
	PodName      string    `json:"pod_name,omitempty"`
	Domain       string    `json:"domain"`
	Type         string    `json:"type"`
	Protocol     int       `json:"protocol"`
	CreationRate float64   `json:"creation_rate"`
	AnomalyFlag  bool      `json:"anomaly_flag"`
	Timestamp    time.Time `json:"timestamp"`
}

// SyscallTelemetryEvent represents runtime syscall activity captured from kernel tracepoints.
type SyscallTelemetryEvent struct {
	PID           int       `json:"pid"`
	ProcessName   string    `json:"process_name"`
	Namespace     string    `json:"namespace,omitempty"`
	PodName       string    `json:"pod_name,omitempty"`
	SyscallName   string    `json:"syscall_name"`
	CallCount     int64     `json:"call_count"`
	FailureCount  int64     `json:"failure_count"`
	IsPrivileged  bool      `json:"is_privileged"`
	BlockedByLSM  bool      `json:"blocked_by_lsm"`
	Timestamp     time.Time `json:"timestamp"`
}

// BPFRuntimeTelemetry encapsulates live or simulated kernel runtime telemetry.
type BPFRuntimeTelemetry struct {
	ClusterID     string                  `json:"cluster_id"`
	NodeName      string                  `json:"node_name"`
	GeneratedAt   time.Time               `json:"generated_at"`
	SocketEvents  []SocketTelemetryItem   `json:"socket_events"`
	SyscallEvents []SyscallTelemetryEvent `json:"syscall_events"`
	ActiveLSMHooks []string               `json:"active_lsm_hooks"`
}

// BPFRule defines an authoritative kernel threat profiler or seccomp rule.
type BPFRule struct {
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// BPFViolation models a single security violation discovered during static or runtime audit.
type BPFViolation struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	Severity     intel.Severity `json:"severity"`
	CVSSScore    float64        `json:"cvss_score"`
	ResourceURI  string         `json:"resource_uri"`
	StartLine    int            `json:"start_line"`
	WorkloadName string         `json:"workload_name,omitempty"`
	Namespace    string         `json:"namespace,omitempty"`
	Description  string         `json:"description"`
	Remediation  string         `json:"remediation"`
	MatchedCVE   string         `json:"matched_cve,omitempty"`
}

// BPFSummary compiles compliance metrics and violation tallies.
type BPFSummary struct {
	TotalProfilesScanned int     `json:"total_profiles_scanned"`
	TotalTelemetryEvents int     `json:"total_telemetry_events"`
	ViolationsCount      int     `json:"violations_count"`
	CriticalCount        int     `json:"critical_count"`
	HighCount            int     `json:"high_count"`
	MediumCount          int     `json:"medium_count"`
	LowCount             int     `json:"low_count"`
	ComplianceScore      float64 `json:"compliance_score"`
	AuditStatus          string  `json:"audit_status"`
}

// BPFAuditReport contains the comprehensive findings of the BPF and seccomp audit.
type BPFAuditReport struct {
	ScannedPaths []string       `json:"scanned_paths"`
	Violations   []BPFViolation `json:"violations"`
	Summary      BPFSummary     `json:"summary"`
	GeneratedAt  time.Time      `json:"generated_at"`
}
