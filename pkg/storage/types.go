package storage

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB upper limit to prevent memory exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxDocumentsPerStream prevents algorithmic complexity attacks via document flooding.
	MaxDocumentsPerStream = 1000
	// MaxTelemetryBytes limits telemetry payload sizes to 5MB.
	MaxTelemetryBytes = 5 * 1024 * 1024
)

// CephHealthStatus reflects overall Ceph cluster health enum.
type CephHealthStatus string

const (
	HealthOK   CephHealthStatus = "HEALTH_OK"
	HealthWarn CephHealthStatus = "HEALTH_WARN"
	HealthErr  CephHealthStatus = "HEALTH_ERR"
)

// RuleCategory groups storage cluster audit rules.
type RuleCategory string

const (
	CategoryDeclarativeCRD RuleCategory = "DECLARATIVE_CRD"
	CategoryRuntimeAnomaly RuleCategory = "RUNTIME_ANOMALY"
	CategoryVolumePosture  RuleCategory = "VOLUME_POSTURE"
)

// StorageViolation represents a verified integrity, security, or anomaly violation in a storage cluster.
type StorageViolation struct {
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
	FilePath     string         `json:"file_path,omitempty"`
	StartLine    int            `json:"start_line,omitempty"`
}

// StorageRule defines metadata and baseline metrics for a storage integrity rule.
type StorageRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Category    RuleCategory   `json:"category"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// OSDSummary aggregates cluster OSD states and latency metrics.
type OSDSummary struct {
	Total           int     `json:"total"`
	Up              int     `json:"up"`
	In              int     `json:"in"`
	Down            int     `json:"down"`
	Out             int     `json:"out"`
	FlappingCount   int     `json:"flapping_count"`
	AvgHeartbeatMs  float64 `json:"avg_heartbeat_ms"`
	MaxHeartbeatMs  float64 `json:"max_heartbeat_ms"`
}

// PGSummary aggregates placement group states.
type PGSummary struct {
	Total        int `json:"total"`
	ActiveClean  int `json:"active_clean"`
	Peering      int `json:"peering"`
	Degraded     int `json:"degraded"`
	Undersized   int `json:"undersized"`
	Incomplete   int `json:"incomplete"`
	Stale        int `json:"stale"`
	Inconsistent int `json:"inconsistent"`
	BackfillWait int `json:"backfill_wait"`
}

// PoolUsage tracks storage capacity and utilization thresholds for a Ceph pool.
type PoolUsage struct {
	Name        string  `json:"name"`
	ID          int     `json:"id"`
	UsedBytes   int64   `json:"used_bytes"`
	TotalBytes  int64   `json:"total_bytes"`
	PercentUsed float64 `json:"percent_used"`
	NearFull    bool    `json:"near_full"`
	Full        bool    `json:"full"`
}

// BlueStoreAlert models low-level BlueStore engine anomaly events.
type BlueStoreAlert struct {
	OSDID            int    `json:"osd_id"`
	Device           string `json:"device"`
	Engine           string `json:"engine"`
	ChecksumErrors   int    `json:"checksum_errors"`
	SlowOpsCount     int    `json:"slow_ops_count"`
	AsyncFlushErrors int    `json:"async_flush_errors"`
	KernelVersion    string `json:"kernel_version,omitempty"`
	Message          string `json:"message"`
}

// PeeringAlert models placement group peering failures or latency spikes.
type PeeringAlert struct {
	PGID            string   `json:"pg_id"`
	PrimaryOSD      int      `json:"primary_osd"`
	PeerOSDs        []int    `json:"peer_osds"`
	State           string   `json:"state"`
	DurationSeconds int      `json:"duration_seconds"`
	Message         string   `json:"message"`
}

// CephHealthReport models structured runtime telemetry from Ceph daemons.
type CephHealthReport struct {
	ClusterFSID     string           `json:"cluster_fsid,omitempty"`
	Status          CephHealthStatus `json:"status"`
	Summary         []string         `json:"summary,omitempty"`
	MonQuorum       []string         `json:"mon_quorum,omitempty"`
	OSDStats        OSDSummary       `json:"osd_stats"`
	PGStats         PGSummary        `json:"pg_stats"`
	Pools           []PoolUsage      `json:"pools,omitempty"`
	BlueStoreAlerts []BlueStoreAlert `json:"bluestore_alerts,omitempty"`
	PeeringAlerts   []PeeringAlert   `json:"peering_alerts,omitempty"`
}

// StorageAuditReport consolidates findings across declarative manifests and runtime telemetry.
type StorageAuditReport struct {
	TotalFiles     int                `json:"total_files"`
	TotalResources int                `json:"total_resources"`
	Violations     []StorageViolation `json:"violations"`
	HealthReport   *CephHealthReport  `json:"health_report,omitempty"`
}
