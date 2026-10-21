package clustermesh

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes defines the 10MB memory safety ceiling for Cilium and Kubernetes manifests.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes defines the 5MB memory safety ceiling for runtime ClusterMesh telemetry payloads.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines defines the line count ceiling for manifest scans.
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents defines the ceiling for runtime telemetry events.
	MaxTelemetryEvents = 5000
	// MaxClusterMeshSyncLatencyMs is the threshold above which etcd sync latency is considered degraded.
	MaxClusterMeshSyncLatencyMs = 5000.0
	// MaxGlobalServiceEndpoints is the maximum recommended endpoint count for a single global service.
	MaxGlobalServiceEndpoints = 1024
	// MaxAllowedClusterID defines the upper bound for Cilium Cluster IDs (1..255).
	MaxAllowedClusterID = 255
)

// TunnelEncryptionMode represents the encryption protocol for cross-cluster overlay packets.
type TunnelEncryptionMode string

const (
	// EncryptionNone represents unencrypted cross-cluster tunnel traffic.
	EncryptionNone TunnelEncryptionMode = "none"
	// EncryptionWireGuard represents kernel WireGuard encrypted tunnels.
	EncryptionWireGuard TunnelEncryptionMode = "wireguard"
	// EncryptionIPsec represents IPsec ESP encrypted tunnels.
	EncryptionIPsec TunnelEncryptionMode = "ipsec"
)

// MeshSyncState represents the synchronization health between ClusterMesh nodes.
type MeshSyncState string

const (
	// SyncStateHealthy indicates active and up-to-date etcd synchronization.
	SyncStateHealthy MeshSyncState = "HEALTHY"
	// SyncStateDegraded indicates elevated latency or transient sync retries.
	SyncStateDegraded MeshSyncState = "DEGRADED"
	// SyncStatePartitioned indicates a split-brain or network partition condition.
	SyncStatePartitioned MeshSyncState = "PARTITIONED"
	// SyncStateDisconnected indicates a complete loss of remote cluster peering.
	SyncStateDisconnected MeshSyncState = "DISCONNECTED"
)

// ClusterMeshConfig represents Cilium ClusterMesh control plane and daemon configurations.
type ClusterMeshConfig struct {
	ClusterName      string               `json:"cluster_name"`
	ClusterID        int                  `json:"cluster_id"`
	EtcdTLS          bool                 `json:"etcd_tls"`
	EtcdClientCert   string               `json:"etcd_client_cert,omitempty"`
	EtcdCACert       string               `json:"etcd_ca_cert,omitempty"`
	TunnelEncryption TunnelEncryptionMode `json:"tunnel_encryption"`
	TunnelProtocol   string               `json:"tunnel_protocol,omitempty"` // vxlan, geneve
	SharedKVStore    bool                 `json:"shared_kvstore"`
	ApiserverEnabled bool                 `json:"apiserver_enabled"`
	LineNumber       int                  `json:"line_number"`
	FilePath         string               `json:"file_path"`
}

// GlobalServiceConfig represents Kubernetes services exported or shared across clusters.
type GlobalServiceConfig struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	ClusterName   string `json:"cluster_name,omitempty"`
	ClusterID     int    `json:"cluster_id,omitempty"`
	IsGlobal      bool   `json:"is_global"`
	IsShared      bool   `json:"is_shared"`
	ServiceExport bool   `json:"service_export"`
	BackendCount  int    `json:"backend_count,omitempty"`
	LineNumber    int    `json:"line_number"`
	FilePath      string `json:"file_path"`
}

// MeshNetworkPolicyConfig represents Cilium cross-cluster network security policies.
type MeshNetworkPolicyConfig struct {
	Name            string   `json:"name"`
	Namespace       string   `json:"namespace"`
	ClusterSelector string   `json:"cluster_selector,omitempty"` // "*", "cluster-east", etc.
	AllowedClusters []string `json:"allowed_clusters,omitempty"`
	IsClusterwide   bool     `json:"is_clusterwide"`
	LineNumber      int      `json:"line_number"`
	FilePath        string   `json:"file_path"`
}

// ClusterMeshTelemetryReport represents runtime telemetry captured from Cilium agents.
type ClusterMeshTelemetryReport struct {
	LocalClusterName     string        `json:"local_cluster_name"`
	LocalClusterID       int           `json:"local_cluster_id"`
	SyncState            MeshSyncState `json:"sync_state"`
	SyncLatencyMs        float64       `json:"sync_latency_ms"`
	ConnectedClusters    []string      `json:"connected_clusters"`
	DisconnectedClusters []string      `json:"disconnected_clusters"`
	TotalGlobalServices  int           `json:"total_global_services"`
	TotalMeshEndpoints   int           `json:"total_mesh_endpoints"`
	EtcdSyncErrors       int           `json:"etcd_sync_errors"`
	Timestamp            time.Time     `json:"timestamp"`
}

// MeshRule represents a canonical security rule in the ClusterMesh radar catalog.
type MeshRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// MeshViolation represents a detected security finding or compliance gap.
type MeshViolation struct {
	RuleID      string         `json:"rule_id"`
	Name        string         `json:"name"`
	Severity    intel.Severity `json:"severity"`
	Resource    string         `json:"resource"`
	Cluster     string         `json:"cluster,omitempty"`
	Message     string         `json:"message"`
	LineNumber  int            `json:"line_number"`
	FilePath    string         `json:"file_path"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
	CVSSScore   float64        `json:"cvss_score"`
}

// MeshSummary aggregates findings and compliance posture for the ClusterMesh audit.
type MeshSummary struct {
	TotalAudited    int     `json:"total_audited"`
	TotalViolations int     `json:"total_violations"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
	ComplianceScore float64 `json:"compliance_score"`
	MeshHealthy     bool    `json:"mesh_healthy"`
}

// MeshAuditReport represents the consolidated audit report across all ClusterMesh assets.
type MeshAuditReport struct {
	Summary     MeshSummary                 `json:"summary"`
	Violations  []MeshViolation             `json:"violations"`
	Configs     []ClusterMeshConfig         `json:"configs"`
	Services    []GlobalServiceConfig       `json:"services"`
	Policies    []MeshNetworkPolicyConfig   `json:"policies"`
	Telemetry   *ClusterMeshTelemetryReport `json:"telemetry,omitempty"`
	GeneratedAt time.Time                   `json:"generated_at"`
}
