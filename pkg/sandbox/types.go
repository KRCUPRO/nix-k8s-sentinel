package sandbox

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Security bounds and memory safety invariants.
const (
	MaxManifestBytes           = 10 * 1024 * 1024 // 10MB maximum manifest size
	MaxTelemetryBytes          = 5 * 1024 * 1024  // 5MB maximum telemetry size
	MaxDetonations             = 1000             // Maximum detonation records per batch
	MaxHoneypotInteractions    = 5000             // Maximum honeypot interactions per audit
	MaxAllowedScanLines        = 20000            // Maximum lines processed in streaming parser
	DefaultDetonationTimeoutMs = 30000            // 30 seconds default detonation SLA timeout
	MaxVCPUsAllowed            = 32               // Sanity bound for MicroVM vCPUs
	MaxMemoryMiBAllowed        = 65536            // 64GB sanity bound for MicroVM RAM
)

// DetonationStatus represents the lifecycle state of a sandboxed payload detonation.
type DetonationStatus string

const (
	StatusPending     DetonationStatus = "PENDING"
	StatusRunning     DetonationStatus = "RUNNING"
	StatusClean       DetonationStatus = "CLEAN"
	StatusSuspicious  DetonationStatus = "SUSPICIOUS"
	StatusQuarantined DetonationStatus = "QUARANTINED"
	StatusTimedOut    DetonationStatus = "TIMED_OUT"
	StatusError       DetonationStatus = "ERROR"
)

// HypervisorType defines the backend microVM hypervisor.
type HypervisorType string

const (
	HypervisorFirecracker HypervisorType = "firecracker"
	HypervisorCloudHyper  HypervisorType = "cloud-hypervisor"
	HypervisorQEMU        HypervisorType = "qemu"
)

// MicroVMConfig defines the declarative hardware and execution parameters of an ephemeral microVM sandbox.
type MicroVMConfig struct {
	VMID             string            `json:"vmId"`
	Hypervisor       HypervisorType    `json:"hypervisor"`
	VCPUs            int               `json:"vcpus"`
	MemoryMiB        int               `json:"memoryMib"`
	KernelPath       string            `json:"kernelPath"`
	RootFSPath       string            `json:"rootfsPath"`
	JailerEnabled    bool              `json:"jailerEnabled"`
	JailerUID        int               `json:"jailerUid"`
	JailerGID        int               `json:"jailerGid"`
	KVMDevice        string            `json:"kvmDevice"`
	NetworkInterface string            `json:"networkInterface"`
	GuestMAC         string            `json:"guestMac"`
	EgressIsolated   bool              `json:"egressIsolated"`
	ReadOnlyRootFS   bool              `json:"readOnlyRootfs"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	SourceFile       string            `json:"sourceFile,omitempty"`
	LineNumber       int               `json:"lineNumber,omitempty"`
}

// DetonationPayload represents a suspicious container image, binary, or script artifact scheduled for detonation.
type DetonationPayload struct {
	PayloadID      string   `json:"payloadId"`
	TargetType     string   `json:"targetType"` // e.g., "container_image", "binary", "tarball", "script"
	DigestSHA256   string   `json:"digestSha256"`
	SourceRegistry string   `json:"sourceRegistry,omitempty"`
	CommandLine    string   `json:"commandLine,omitempty"`
	TimeoutMs      int      `json:"timeoutMs"`
	Tags           []string `json:"tags,omitempty"`
}

// HoneypotInteraction represents intercepted attacker interaction with sandbox decoy services.
type HoneypotInteraction struct {
	InteractionID string    `json:"interactionId"`
	SourceIP      string    `json:"sourceIp"`
	DestinationPort int     `json:"destPort"`
	Protocol      string    `json:"protocol"` // e.g., "KUBELET_API", "ETCD_PEER", "SSH", "HTTP_METADATA"
	ServiceLure   string    `json:"serviceLure"`
	PayloadSample string    `json:"payloadSample,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Severity      string    `json:"severity"`
}

// SyscallAnomaly records an unexpected or privileged system call invocation captured in kernel probes.
type SyscallAnomaly struct {
	SyscallName string `json:"syscallName"`
	Count       int    `json:"count"`
	Arguments   string `json:"arguments,omitempty"`
	Blocked     bool   `json:"blocked"`
	Reason      string `json:"reason"`
}

// DetonationTelemetry represents runtime kernel telemetry and sandbox telemetry captured during detonation.
type DetonationTelemetry struct {
	DetonationID       string                `json:"detonationId"`
	VMID               string                `json:"vmId"`
	PayloadID          string                `json:"payloadId"`
	Status             DetonationStatus      `json:"status"`
	DurationMs         int                   `json:"durationMs"`
	PeakMemoryMiB      int                   `json:"peakMemoryMib"`
	CPUUsagePct        float64               `json:"cpuUsagePct"`
	EgressAttempts     int                   `json:"egressAttempts"`
	EgressAllowed      bool                  `json:"egressAllowed"`
	SyscallAnomalies   []SyscallAnomaly      `json:"syscallAnomalies,omitempty"`
	HoneypotHits       []HoneypotInteraction `json:"honeypotHits,omitempty"`
	ZeroDayIndicators  []string              `json:"zeroDayIndicators,omitempty"`
	QuarantineEnforced bool                  `json:"quarantineEnforced"`
	Timestamp          time.Time             `json:"timestamp"`
}

// SandboxRule defines a canonical security rule for microVM sandbox and honeypot detonation audits.
type SandboxRule struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CVSSScore   float64 `json:"cvssScore"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	CVE         string `json:"cve,omitempty"`
}

// SandboxViolation records an identified security finding during sandbox audits.
type SandboxViolation struct {
	RuleID      string  `json:"ruleId"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvssScore"`
	Target      string  `json:"target"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
	MatchedCVE  string  `json:"matchedCve,omitempty"`
	RawContext  string  `json:"rawContext,omitempty"`
	LineNumber  int     `json:"lineNumber,omitempty"`
}

// SandboxSummary aggregates statistics for microVM configurations, detonation telemetry, and security score.
type SandboxSummary struct {
	TotalMicroVMsScanned int     `json:"totalMicroVMsScanned"`
	TotalDetonations     int     `json:"totalDetonations"`
	TotalHoneypotHits    int     `json:"totalHoneypotHits"`
	ViolationsCount      int     `json:"violationsCount"`
	QuarantinedCount     int     `json:"quarantinedCount"`
	CleanCount           int     `json:"cleanCount"`
	SandboxSecurityScore float64 `json:"sandboxSecurityScore"` // 0.0 to 100.0
	AuditStatus          string  `json:"auditStatus"`          // PASSED, WARNING, CRITICAL_RISK
}

// SandboxAuditReport compiles all microVM configurations, detonation events, violations, and summary metrics.
type SandboxAuditReport struct {
	MicroVMConfigs      []MicroVMConfig       `json:"microVMConfigs"`
	DetonationTelemetries []DetonationTelemetry `json:"detonationTelemetries"`
	Violations          []SandboxViolation    `json:"violations"`
	Summary             SandboxSummary        `json:"summary"`
	ThreatFeedReference *intel.Feed           `json:"threatFeedReference,omitempty"`
}
