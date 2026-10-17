package lsm

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Defensive memory safety bounds and resource limits.
const (
	// MaxManifestBytes sets a strict 10MB ceiling on individual declarative manifest files.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes sets a strict 5MB ceiling on runtime eBPF LSM telemetry payloads.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines sets a strict 20,000 line scanning bound.
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents limits in-memory processing to 5,000 telemetry events per batch.
	MaxTelemetryEvents = 5000
)

// LSMHookType designates canonical Linux Security Module (LSM) hook attachment points.
type LSMHookType string

const (
	// HookBprmCheckSecurity verifies binary execution and restricts execution from writable directories.
	HookBprmCheckSecurity LSMHookType = "bprm_check_security"
	// HookFileOpen inspects file open operations for sensitive host resources.
	HookFileOpen LSMHookType = "file_open"
	// HookFilePermission enforces mandatory access controls on inode permissions.
	HookFilePermission LSMHookType = "file_permission"
	// HookSocketCreate restricts unauthorized socket creation (e.g. AF_PACKET, AF_INET raw).
	HookSocketCreate LSMHookType = "socket_create"
	// HookSocketConnect inspects and blocks egress connection attempts from container cgroups.
	HookSocketConnect LSMHookType = "socket_connect"
	// HookTaskFixSetuid prevents uncontained setuid / setgid privilege escalation within containers.
	HookTaskFixSetuid LSMHookType = "task_fix_setuid"
	// HookSecurityBPF restricts loading and verification of unprivileged eBPF programs and maps.
	HookSecurityBPF LSMHookType = "bpf"
	// HookPtraceAccessCheck prevents cross-namespace ptrace memory injection and tracing.
	HookPtraceAccessCheck LSMHookType = "ptrace_access_check"
	// HookCapable intercepts capability checks for privileged operations (e.g. CAP_SYS_ADMIN).
	HookCapable LSMHookType = "capable"
	// HookSyslog restricts kernel dmesg and syslog inspection from containers.
	HookSyslog LSMHookType = "syslog"
)

// LSMAction specifies the enforcement action executed by an eBPF LSM hook.
type LSMAction string

const (
	// ActionDeny immediately rejects the operation with -EPERM.
	ActionDeny LSMAction = "DENY"
	// ActionAudit logs the operation while permitting execution.
	ActionAudit LSMAction = "AUDIT"
	// ActionAllow explicitly permits the operation.
	ActionAllow LSMAction = "ALLOW"
	// ActionOverride forces safe default parameters.
	ActionOverride LSMAction = "OVERRIDE"
)

// NixOSLSMConfig captures declarative Linux Security Module settings for a NixOS container host.
type NixOSLSMConfig struct {
	SourceFile             string            `json:"source_file"`
	KernelParams           []string          `json:"kernel_params"`
	LSMOrder               []string          `json:"lsm_order"`
	BPFLSMEnabled          bool              `json:"bpf_lsm_enabled"`
	UnprivilegedBPFDisabled bool             `json:"unprivileged_bpf_disabled"`
	SystemdUnits           []string          `json:"systemd_units"`
	HardenedSysctls        map[string]string `json:"hardened_sysctls"`
	KernelPatches          []string          `json:"kernel_patches"`
}

// ContainerMACProfile represents a mandatory access control profile bound to a container cgroup.
type ContainerMACProfile struct {
	WorkloadName    string        `json:"workload_name"`
	Namespace       string        `json:"namespace"`
	SourceFile      string        `json:"source_file"`
	LineNumber      int           `json:"line_number"`
	CgroupPath      string        `json:"cgroup_path"`
	Privileged      bool          `json:"privileged"`
	HostPID         bool          `json:"host_pid"`
	HostIPC         bool          `json:"host_ipc"`
	Capabilities    []string      `json:"capabilities"`
	BlockedHooks    []LSMHookType `json:"blocked_hooks"`
	ProtectedPaths  []string      `json:"protected_paths"`
	AllowedSyscalls []string      `json:"allowed_syscalls"`
	MACEnforced     bool          `json:"mac_enforced"`
}

// LSMTelemetryEvent records an audit or denial event captured by runtime eBPF LSM telemetry.
type LSMTelemetryEvent struct {
	Timestamp  time.Time   `json:"timestamp"`
	Node       string      `json:"node"`
	ContainerID string     `json:"container_id"`
	Cgroup     string      `json:"cgroup"`
	Hook       LSMHookType `json:"hook"`
	Syscall    string      `json:"syscall"`
	Comm       string      `json:"comm"`
	TargetPath string      `json:"target_path"`
	ReturnCode int         `json:"return_code"`
	Blocked    bool        `json:"blocked"`
	Action     LSMAction   `json:"action"`
}

// LSMRule defines a canonical eBPF LSM and Kernel MAC security verification standard.
type LSMRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Severity    intel.Severity `json:"severity"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve"`
	CVSSScore   float64        `json:"cvss_score"`
}

// LSMViolation captures a concrete declarative deviation or runtime denial event.
type LSMViolation struct {
	RuleID      string         `json:"rule_id"`
	Severity    intel.Severity `json:"severity"`
	Resource    string         `json:"resource"`
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
	CVSSScore   float64        `json:"cvss_score"`
}

// LSMSummary provides aggregated metrics and compliance posture scoring for eBPF LSM security.
type LSMSummary struct {
	TotalInspected       int     `json:"total_inspected"`
	TotalViolations      int     `json:"total_violations"`
	CriticalCount        int     `json:"critical_count"`
	HighCount            int     `json:"high_count"`
	MediumCount          int     `json:"medium_count"`
	LowCount             int     `json:"low_count"`
	LSMScore             float64 `json:"lsm_score"`
	Status               string  `json:"status"`
	BPFLSMActive         bool    `json:"bpf_lsm_active"`
	MACProfileCount      int     `json:"mac_profile_count"`
	BlockedTelemetryCount int    `json:"blocked_telemetry_count"`
}

// LSMAuditReport represents the consolidated audit report for eBPF LSM and Kernel MAC.
type LSMAuditReport struct {
	Timestamp  time.Time             `json:"timestamp"`
	Configs    []NixOSLSMConfig      `json:"configs"`
	Profiles   []ContainerMACProfile `json:"profiles"`
	Telemetry  []LSMTelemetryEvent   `json:"telemetry"`
	Violations []LSMViolation        `json:"violations"`
	Summary    LSMSummary            `json:"summary"`
}
