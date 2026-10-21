package clustermesh

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// CanonicalMeshRules defines the authoritative catalog of 12 Cilium ClusterMesh and Global Service Discovery rules.
var CanonicalMeshRules = []MeshRule{
	{
		ID:          "MESH-RADAR-001",
		Name:        "UnencryptedCrossClusterTunnel",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Description: "Cross-cluster ClusterMesh interconnect uses unencrypted VXLAN or Geneve encapsulation over public or cross-cloud WAN without WireGuard or IPsec encryption.",
		Remediation: "Enable transparent encryption in Cilium with encryption.type=wireguard or encryption.type=ipsec and configure node-to-node encryption across clusters.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-002",
		Name:        "ClusterIDCollisionOrReservedZero",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Description: "ClusterMesh cluster-id is set to 0 (reserved/invalid) or collides with an existing remote cluster in the mesh federation, causing BPF endpoint map corruption and route hijacking.",
		Remediation: "Assign a unique non-zero cluster-id (between 1 and 255) to each cluster participating in the ClusterMesh federation.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-003",
		Name:        "InsecureClusterMeshEtcdTLS",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.2,
		Description: "ClusterMesh apiserver or remote etcd kvstore connection has TLS disabled, missing client mTLS certificates, or allows plaintext communication.",
		Remediation: "Enforce mutual TLS (mTLS) with client certificate authentication and validated CA certificate bundles on clustermesh-apiserver etcd channels.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-004",
		Name:        "ServiceExportNamespaceCollision",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.8,
		Description: "Kubernetes ServiceExport or Cilium global service exported in a multi-tenant namespace collides with a remote cluster's service name without mutual cryptographic verification.",
		Remediation: "Enforce tenant-isolated namespaces and mandate cryptographic domain authorization before reconciling remote ServiceExports.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-005",
		Name:        "UnrestrictedGlobalServiceExposure",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.6,
		Description: "Sensitive internal workload (e.g. database, secret vault, control plane) declared with io.cilium/global-service: 'true' without cross-cluster ingress network policy restrictions.",
		Remediation: "Remove global-service annotation from sensitive internal services or attach restrictive CiliumClusterwideNetworkPolicy ingress rules.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-006",
		Name:        "MissingCrossClusterNetworkPolicy",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.3,
		Description: "Workload participating in global service mesh lacks CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy restricting cross-cluster cluster-id and namespace endpoints.",
		Remediation: "Deploy CiliumNetworkPolicy specifying explicit fromEndpoints with cluster selectors to enforce least-privilege inter-cluster ingress.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-007",
		Name:        "WildcardRemoteClusterSelector",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Description: "Cilium network policy utilizes unrestricted wildcard cluster selectors (fromEndpoints.cluster: '*' or toEndpoints.cluster: '*'), eliminating multi-cluster tenant boundaries.",
		Remediation: "Replace wildcard cluster selectors with explicit allowed cluster names and namespace-scoped identity selectors.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-008",
		Name:        "ClusterMeshSyncHeartbeatTimeout",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Description: "Runtime ClusterMesh etcd kvstore synchronization latency exceeds 5000ms or heartbeat indicates partitioned / degraded remote cluster state.",
		Remediation: "Tune etcd heartbeat timers, inspect WAN overlay latency, and deploy automated health probing for clustermesh-apiserver replicas.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-009",
		Name:        "CrossClusterServiceEndpointSaturation",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.7,
		Description: "Global service endpoint count exceeds BPF service table allocation threshold (> 1024 backends), risking kernel BPF load balancer map drops.",
		Remediation: "Increase bpf-lb-map-max in Cilium config or segment global services into regional subsets using topology-aware routing.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-010",
		Name:        "UnverifiedRemoteClusterCACertificate",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Description: "ClusterMesh remote cluster configuration specifies an empty, self-signed, or unverified CA certificate bundle.",
		Remediation: "Provision enterprise PKI or cert-manager automated CA certificates for ClusterMesh secrets and eliminate unverified certificates.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-011",
		Name:        "NonSharedServiceRoutingLeak",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Description: "Cilium service marked with io.cilium/shared-service: 'false' but configured as global-service or referenced in multi-cluster routing tables.",
		Remediation: "Align shared-service and global-service annotations to prevent unintended multi-cluster routing exposure.",
		MatchedCVE:  "CVE-2026-11483",
	},
	{
		ID:          "MESH-RADAR-012",
		Name:        "ClusterMeshDaemonDisconnected",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.7,
		Description: "Runtime Cilium agent clustermesh status reports one or more remote clusters in DISCONNECTED or PARTITIONED state.",
		Remediation: "Investigate firewall rules on port 2379/4240, check control plane connectivity, and restart stale clustermesh-apiserver pods.",
		MatchedCVE:  "CVE-2026-11483",
	},
}

// FindRuleByID retrieves a canonical rule by its ID.
func FindRuleByID(id string) *MeshRule {
	for i := range CanonicalMeshRules {
		if CanonicalMeshRules[i].ID == id {
			return &CanonicalMeshRules[i]
		}
	}
	return nil
}
