package replication

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB upper limit to prevent memory exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes limits telemetry payload sizes to 5MB.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines prevents unbounded manifest traversal.
	MaxAllowedScanLines = 20000
	// DefaultRPOTargetSeconds defines 15 minutes as baseline RPO SLA.
	DefaultRPOTargetSeconds = 900
	// DefaultMaxDeltaLagSeconds triggers severe lagging alerts at 30 minutes.
	DefaultMaxDeltaLagSeconds = 1800
)

// ReplicationMode represents CSI volume replication mirroring modes.
type ReplicationMode string

const (
	ReplicationModeSnapshot ReplicationMode = "snapshot"
	ReplicationModeJournal  ReplicationMode = "journal"
)

// ReplicationState represents the current state of a replicated volume.
type ReplicationState string

const (
	StatePrimary   ReplicationState = "Primary"
	StateSecondary ReplicationState = "Secondary"
	StateResyncing ReplicationState = "Resyncing"
	StateDegraded  ReplicationState = "Degraded"
	StateError     ReplicationState = "Error"
	StateUnknown   ReplicationState = "Unknown"
)

// DeletionPolicy defines CSI snapshot reclamation rules.
type DeletionPolicy string

const (
	DeletionPolicyRetain DeletionPolicy = "Retain"
	DeletionPolicyDelete DeletionPolicy = "Delete"
)

// DRClusterRole defines role in a multi-region disaster recovery topology.
type DRClusterRole string

const (
	RoleActivePrimary    DRClusterRole = "ActivePrimary"
	RoleStandbySecondary DRClusterRole = "StandbySecondary"
	RoleArbiter          DRClusterRole = "Arbiter"
)

// VolumeSnapshotClassConfig captures declarative VolumeSnapshotClass definitions.
type VolumeSnapshotClassConfig struct {
	Name           string            `json:"name"`
	Driver         string            `json:"driver"`
	DeletionPolicy DeletionPolicy    `json:"deletion_policy"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	File           string            `json:"file,omitempty"`
	Line           int               `json:"line,omitempty"`
}

// SnapshotSchedulePolicy captures automated CephFS/RBD snapshot schedules.
type SnapshotSchedulePolicy struct {
	Name            string `json:"name"`
	FilesystemName  string `json:"filesystem_name,omitempty"`
	SubVolumeGroup  string `json:"subvolume_group,omitempty"`
	Schedule        string `json:"schedule"` // e.g. "1h", "24h", "0 0 * * *"
	RetentionCount  int    `json:"retention_count"`
	PruneOldEnabled bool   `json:"prune_old_enabled"`
	File            string `json:"file,omitempty"`
	Line            int    `json:"line,omitempty"`
}

// VolumeReplicationClassConfig captures declarative VolumeReplicationClass CRDs.
type VolumeReplicationClassConfig struct {
	Name               string            `json:"name"`
	Provisioner        string            `json:"provisioner"`
	MirroringMode      ReplicationMode   `json:"mirroring_mode"`
	SchedulingInterval string            `json:"scheduling_interval"` // e.g. "15m", "1h"
	EncryptedTransport bool              `json:"encrypted_transport"`
	Parameters         map[string]string `json:"parameters,omitempty"`
	File               string            `json:"file,omitempty"`
	Line               int               `json:"line,omitempty"`
}

// VolumeReplicationConfig captures declarative VolumeReplication CRDs binding PVCs.
type VolumeReplicationConfig struct {
	Name                     string           `json:"name"`
	Namespace                string           `json:"namespace"`
	VolumeReplicationClass   string           `json:"volume_replication_class"`
	PVCName                  string           `json:"pvc_name"`
	ReplicationState         ReplicationState `json:"replication_state"`
	PeerClusterID            string           `json:"peer_cluster_id,omitempty"`
	AutoResyncEnabled        bool             `json:"auto_resync_enabled"`
	File                     string           `json:"file,omitempty"`
	Line                     int              `json:"line,omitempty"`
}

// CephMirrorDaemonConfig captures CephFS/RBD mirror daemon definitions.
type CephMirrorDaemonConfig struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"` // CephFilesystemMirror or CephRBDMirror
	Replicas     int    `json:"replicas"`
	AntiAffinity bool   `json:"anti_affinity"`
	File         string `json:"file,omitempty"`
	Line         int    `json:"line,omitempty"`
}

// CephArbiterConfig models 3rd-zone arbiter configuration for stretched clusters.
type CephArbiterConfig struct {
	ClusterName    string `json:"cluster_name"`
	ArbiterZone    string `json:"arbiter_zone"`
	ArbiterEnabled bool   `json:"arbiter_enabled"`
	FailureDomain  string `json:"failure_domain"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`
}

// VolumeReplicationStatus models live telemetry for an individual replicated volume.
type VolumeReplicationStatus struct {
	VolumeName            string           `json:"volume_name"`
	Namespace             string           `json:"namespace"`
	LocalClusterID        string           `json:"local_cluster_id"`
	LocalRegion           string           `json:"local_region"`
	PeerClusterID         string           `json:"peer_cluster_id"`
	PeerRegion            string           `json:"peer_region"`
	State                 ReplicationState `json:"state"`
	PeerState             ReplicationState `json:"peer_state,omitempty"`
	ReplicationLagSeconds int              `json:"replication_lag_seconds"`
	LastCompletionTime    time.Time        `json:"last_completion_time"`
	DeltaBacklogBytes     int64            `json:"delta_backlog_bytes"`
	InSync                bool             `json:"in_sync"`
	SplitBrainRisk        bool             `json:"split_brain_risk"`
	Message               string           `json:"message,omitempty"`
}

// CrossRegionDRTelemetry models aggregate telemetry from cross-region clusters.
type CrossRegionDRTelemetry struct {
	PrimaryClusterID string                    `json:"primary_cluster_id"`
	PrimaryRegion    string                    `json:"primary_region"`
	PeerClusterID    string                    `json:"peer_cluster_id"`
	PeerRegion       string                    `json:"peer_region"`
	TotalVolumes     int                       `json:"total_volumes"`
	InSyncCount      int                       `json:"in_sync_count"`
	LaggingCount     int                       `json:"lagging_count"`
	SplitBrainCount  int                       `json:"split_brain_count"`
	DegradedCount    int                       `json:"degraded_count"`
	Volumes          []VolumeReplicationStatus `json:"volumes,omitempty"`
	ArbiterAlive     bool                      `json:"arbiter_alive"`
	GeneratedAt      time.Time                 `json:"generated_at"`
}

// ReplicationRule encapsulates metadata for a CephFS snapshot & volume replication DR rule.
type ReplicationRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// ReplicationViolation models a single discovered violation.
type ReplicationViolation struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	ResourceKind string         `json:"resource_kind"`
	ResourceName string         `json:"resource_name"`
	Namespace    string         `json:"namespace,omitempty"`
	Severity     intel.Severity `json:"severity"`
	CVSSScore    float64        `json:"cvss_score"`
	Description  string         `json:"description"`
	Remediation  string         `json:"remediation"`
	MatchedCVE   string         `json:"matched_cve,omitempty"`
	File         string         `json:"file,omitempty"`
	Line         int            `json:"line,omitempty"`
}

// ReplicationSummary provides deterministic compliance scoring and category metrics.
type ReplicationSummary struct {
	Score                 float64 `json:"score"`
	Status                string  `json:"status"` // COMPLIANT, WARNING, NON_COMPLIANT
	TotalManifests        int     `json:"total_manifests"`
	TotalSnapshotClasses  int     `json:"total_snapshot_classes"`
	TotalSchedules        int     `json:"total_schedules"`
	TotalReplications     int     `json:"total_replications"`
	TotalViolations       int     `json:"total_violations"`
	CriticalCount         int     `json:"critical_count"`
	HighCount             int     `json:"high_count"`
	MediumCount           int     `json:"medium_count"`
	LowCount              int     `json:"low_count"`
	SplitBrainDetected    bool    `json:"split_brain_detected"`
	MaxDeltaLagSeconds    int     `json:"max_delta_lag_seconds"`
}

// ReplicationAuditReport combines all findings from manifests and telemetry.
type ReplicationAuditReport struct {
	TotalFiles int                    `json:"total_files"`
	Violations []ReplicationViolation `json:"violations"`
	Summary    *ReplicationSummary    `json:"summary,omitempty"`
	Telemetry  *CrossRegionDRTelemetry `json:"telemetry,omitempty"`
}
