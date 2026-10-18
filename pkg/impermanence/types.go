package impermanence

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Defensive memory safety bounds and streaming thresholds.
const (
	MaxManifestBytes      int64   = 10 * 1024 * 1024 // 10MB maximum configuration payload
	MaxTelemetryBytes     int64   = 5 * 1024 * 1024  // 5MB maximum runtime telemetry payload
	MaxAllowedScanLines   int     = 20000            // Maximum configuration lines to process
	MaxTelemetryEvents    int     = 5000             // Maximum telemetry events per audit cycle
	MaxHosts              int     = 512              // Maximum cluster hosts to evaluate
	MaxPersistentPaths    int     = 4096             // Maximum persistent paths
	CriticalTmpfsUsagePct float64 = 85.0             // Threshold for critical ephemeral storage usage
	WarningTmpfsUsagePct  float64 = 75.0             // Threshold for warning ephemeral storage usage
)

// PersistenceMode defines the root filesystem ephemerality strategy.
type PersistenceMode string

const (
	ModeTmpfsRoot     PersistenceMode = "TMPFS_ROOT"
	ModeZfsRollback   PersistenceMode = "ZFS_ROLLBACK"
	ModeBtrfsSnapshot PersistenceMode = "BTRFS_SNAPSHOT"
	ModeMutableDisk   PersistenceMode = "MUTABLE_DISK"
	ModeUnknown       PersistenceMode = "UNKNOWN"
)

// StorageMountType specifies how persistent items are attached.
type StorageMountType string

const (
	MountBind    StorageMountType = "BIND"
	MountSymlink StorageMountType = "SYMLINK"
)

// PersistentEntry models an individual directory or file declaration inside environment.persistence.
type PersistentEntry struct {
	Path       string           `json:"path"`
	MountType  StorageMountType `json:"mount_type"`
	Mode       string           `json:"mode,omitempty"`
	User       string           `json:"user,omitempty"`
	Group      string           `json:"group,omitempty"`
	HideMount  bool             `json:"hide_mount"`
	IsFile     bool             `json:"is_file"`
	FilePath   string           `json:"file_path,omitempty"`
	LineNumber int              `json:"line_number,omitempty"`
}

// SwapDeviceConfig describes host swap configuration.
type SwapDeviceConfig struct {
	Device           string `json:"device"`
	Label            string `json:"label,omitempty"`
	RandomEncryption bool   `json:"random_encryption"`
	DiscardPolicy    string `json:"discard_policy,omitempty"`
}

// ImpermanenceHostConfig models a NixOS host configuration with impermanence and root storage settings.
type ImpermanenceHostConfig struct {
	HostName            string             `json:"host_name"`
	PersistenceRoot     string             `json:"persistence_root"` // e.g. "/persist" or "/nix/persist"
	RootFsType          string             `json:"root_fs_type"`     // e.g. "tmpfs", "zfs", "btrfs", "ext4"
	Mode                PersistenceMode    `json:"mode"`
	StorageEncrypted    bool               `json:"storage_encrypted"`
	SwapDevices         []SwapDeviceConfig `json:"swap_devices"`
	SwapEncrypted       bool               `json:"swap_encrypted"`
	HasUnencryptedSwap  bool               `json:"has_unencrypted_swap"`
	WipeOnReboot        bool               `json:"wipe_on_reboot"`
	WipeHookCommand     string             `json:"wipe_hook_command,omitempty"`
	MachineIDPersisted  bool               `json:"machine_id_persisted"`
	KubeletPKIPersisted bool               `json:"kubelet_pki_persisted"`
	ContainerdPersisted bool               `json:"containerd_persisted"`
	ContainerdOnTmpfs   bool               `json:"containerd_on_tmpfs"`
	KernelMemoryWiping  bool               `json:"kernel_memory_wiping"` // page_poison=1, init_on_free=1, or init_on_alloc=1
	KernelParams        []string           `json:"kernel_params"`
	PersistentEntries   []PersistentEntry  `json:"persistent_entries"`
	FilePath            string             `json:"file_path,omitempty"`
	StartLine           int                `json:"start_line,omitempty"`
}

// ClusterMountReference models a Kubernetes volume or container mount from cluster manifests.
type ClusterMountReference struct {
	ResourceKind string `json:"resource_kind"` // Pod, DaemonSet, PersistentVolume, etc.
	ResourceName string `json:"resource_name"`
	Namespace    string `json:"namespace,omitempty"`
	HostPath     string `json:"host_path"`
	MountPath    string `json:"mount_path"`
	ReadOnly     bool   `json:"read_only"`
	FilePath     string `json:"file_path,omitempty"`
	LineNumber   int    `json:"line_number,omitempty"`
}

// EphemeralStorageTelemetry captures runtime ephemeral root metrics across cluster nodes.
type EphemeralStorageTelemetry struct {
	Timestamp            time.Time `json:"timestamp"`
	NodeName             string    `json:"node_name"`
	RootMount            string    `json:"root_mount"`
	TotalRAMBytes        int64     `json:"total_ram_bytes"`
	UsedRAMBytes         int64     `json:"used_ram_bytes"`
	RootTotalBytes       int64     `json:"root_total_bytes"`
	RootUsedBytes        int64     `json:"root_used_bytes"`
	RootUsagePercent     float64   `json:"root_usage_percent"`
	OrphanedInodes       int64     `json:"orphaned_inodes"`
	SwapUsedBytes        int64     `json:"swap_used_bytes"`
	SwapEncrypted        bool      `json:"swap_encrypted"`
	WipeOnRebootActive   bool      `json:"wipe_on_reboot_active"`
	ShutdownMemoryZeroed bool      `json:"shutdown_memory_zeroed"`
}

// ImpermanenceTelemetry encapsulates cluster-wide telemetry reports.
type ImpermanenceTelemetry struct {
	Timestamp time.Time                   `json:"timestamp"`
	ClusterID string                      `json:"cluster_id"`
	Nodes     []EphemeralStorageTelemetry `json:"nodes"`
}

// ImpermanenceRule represents an authoritative security rule in the catalog.
type ImpermanenceRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// ImpermanenceViolation represents an identified vulnerability finding.
type ImpermanenceViolation struct {
	RuleID      string         `json:"rule_id"`
	HostName    string         `json:"host_name"`
	TargetPath  string         `json:"target_path,omitempty"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
	FilePath    string         `json:"file_path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
}

// ImpermanenceSummary provides aggregated statistics.
type ImpermanenceSummary struct {
	TotalHostsScanned      int      `json:"total_hosts_scanned"`
	CompliantHosts         int      `json:"compliant_hosts"`
	EphemeralRootCount     int      `json:"ephemeral_root_count"`
	MutableRootCount       int      `json:"mutable_root_count"`
	UnencryptedSwapCount   int      `json:"unencrypted_swap_count"`
	WipeHookMissingCount   int      `json:"wipe_hook_missing_count"`
	UnpersistedSecretCount int      `json:"unpersisted_secret_count"`
	CriticalCount          int      `json:"critical_count"`
	HighCount              int      `json:"high_count"`
	MediumCount            int      `json:"medium_count"`
	LowCount               int      `json:"low_count"`
	ComplianceScore        float64  `json:"compliance_score"`
	HighRiskHostNames      []string `json:"high_risk_host_names,omitempty"`
}

// ImpermanenceAuditReport holds the complete evaluation results.
type ImpermanenceAuditReport struct {
	Hosts      []ImpermanenceHostConfig `json:"hosts"`
	Violations []ImpermanenceViolation  `json:"violations"`
	Summary    ImpermanenceSummary      `json:"summary"`
	Telemetry  *ImpermanenceTelemetry   `json:"telemetry,omitempty"`
}
