package storage

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	RuleRookHostNetwork          = "ROOK-CEPH-001"
	RuleRookInTransitCrypto      = "ROOK-CEPH-002"
	RuleRookAtRestEncryption     = "ROOK-CEPH-003"
	RuleRookReplicationSize      = "ROOK-CEPH-004"
	RuleRookMonQuorum            = "ROOK-CEPH-005"
	RuleRookDashboardInsecure    = "ROOK-CEPH-006"
	RuleRookDaemonPrivileged     = "ROOK-CEPH-007"
	RuleRookPVCMultiAttach       = "ROOK-CEPH-008"
	RuleRookStorageClassReclaim  = "ROOK-CEPH-009"
	RuleRookBlueStoreAsyncDesync = "ROOK-CEPH-010"
	RuleCephOSDPeeringStall      = "ROOK-CEPH-011"
	RuleCephPGDegraded           = "ROOK-CEPH-012"
	RuleCephCapacityNearFull     = "ROOK-CEPH-013"
	RuleCephBlueStoreCorruption  = "ROOK-CEPH-014"
)

// StorageRuleRegistry contains all canonical storage cluster integrity rules.
var StorageRuleRegistry = map[string]StorageRule{
	RuleRookHostNetwork: {
		ID:          RuleRookHostNetwork,
		Title:       "Rook Ceph Insecure Host Network Public Exposure",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Description: "CephCluster enables hostNetwork without isolated public/cluster network CIDRs, exposing MON (6789/3300) and OSD (6800-7300) daemons directly to node host network interfaces.",
		Remediation: "Configure dedicated cluster/public network interfaces or enable network isolation to restrict Ceph daemon ports.",
	},
	RuleRookInTransitCrypto: {
		ID:          RuleRookInTransitCrypto,
		Title:       "Rook Ceph Unencrypted In-Transit Network Transport",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.2,
		Description: "Ceph cluster wire encryption is disabled. Storage data blocks and management RPCs are transmitted in cleartext over the cluster network.",
		Remediation: "Enable network encryption in CephCluster spec via 'network.connections.encryption: true' or 'ms_mode: secure' (msgr2 protocol).",
	},
	RuleRookAtRestEncryption: {
		ID:          RuleRookAtRestEncryption,
		Title:       "Rook Ceph OSD Storage Encryption at Rest Disabled",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Description: "CephCluster storage configuration leaves physical NVMe/SSD disks unencrypted without dm-crypt or KMS key envelope protection.",
		Remediation: "Set 'storage.storageDeviceSets[].encrypted: true' or enable dm-crypt with KMS integration in CephCluster storage spec.",
	},
	RuleRookReplicationSize: {
		ID:          RuleRookReplicationSize,
		Title:       "Rook Ceph Inadequate Pool Replication & Failure Domain Risk",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Description: "CephBlockPool or CephFilesystem specifies replication size < 3 or sets failureDomain to 'osd' instead of 'host' or 'rack', risking data loss on single-node failure.",
		Remediation: "Set 'replicated.size: 3', 'replicated.requireSafeReplicaSize: true', and ensure 'failureDomain: host'.",
	},
	RuleRookMonQuorum: {
		ID:          RuleRookMonQuorum,
		Title:       "Rook Ceph Fragile Monitor Quorum & Missing Anti-Affinity",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.5,
		Description: "Ceph MON daemon count is less than 3, even-numbered (split-brain tie risk), or lacks pod anti-affinity across node failure domains.",
		Remediation: "Configure odd MON count (min 3 or 5) and enforce requiredDuringSchedulingIgnoredDuringExecution anti-affinity across nodes.",
	},
	RuleRookDashboardInsecure: {
		ID:          RuleRookDashboardInsecure,
		Title:       "Rook Ceph Dashboard Insecure Cleartext or Unauthenticated Ingress",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.1,
		Description: "Ceph Dashboard is enabled with SSL disabled ('dashboard.ssl: false') or exposed via unauthenticated public ingress without mTLS/SSO.",
		Remediation: "Enable 'dashboard.ssl: true' and enforce OIDC/SSO authentication on all management access paths.",
	},
	RuleRookDaemonPrivileged: {
		ID:          RuleRookDaemonPrivileged,
		Title:       "Rook Ceph Unconfined Privileged Daemon Security Context",
		Category:    CategoryDeclarativeCRD,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.4,
		Description: "Ceph daemon containers (MGR, MON, OSD) run with 'privileged: true' or 'allowPrivilegeEscalation: true' without restrictive seccomp confinement.",
		Remediation: "Drop all unnecessary Linux capabilities, set 'allowPrivilegeEscalation: false', and enforce runtime/default seccomp profiles.",
	},
	RuleRookPVCMultiAttach: {
		ID:          RuleRookPVCMultiAttach,
		Title:       "Rook Ceph RBD Block Volume Unsafe Multi-Attach (RWX)",
		Category:    CategoryVolumePosture,
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Description: "PersistentVolumeClaim references Ceph RBD block storage with ReadWriteMany (RWX) access mode without cluster-aware locking, risking silent filesystem corruption.",
		Remediation: "Use ReadWriteOnce (RWO) for Ceph RBD block volumes, or migrate to CephFS (rook-ceph.cephfs.csi.ceph.com) for shared multi-writer workloads.",
	},
	RuleRookStorageClassReclaim: {
		ID:          RuleRookStorageClassReclaim,
		Title:       "Rook Ceph StorageClass Reclaim Policy Immediate Deletion",
		Category:    CategoryVolumePosture,
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Description: "StorageClass specifies 'reclaimPolicy: Delete' without VolumeSnapshotClass or soft-delete protection, risking accidental loss of persistent state upon PVC deletion.",
		Remediation: "Set 'reclaimPolicy: Retain' on production database storage classes and establish automated CSI volume snapshot policies.",
	},
	RuleRookBlueStoreAsyncDesync: {
		ID:          RuleRookBlueStoreAsyncDesync,
		Title:       "Ceph OSD BlueStore Async Direct I/O Metadata Desync",
		Category:    CategoryRuntimeAnomaly,
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.5,
		MatchedCVE:  "CVE-2026-15509",
		Description: "Host running Linux kernel 6.12+ with Ceph BlueStore triggers transient OSD peering heartbeat timeouts during direct I/O async flushes on NVMe namespaces.",
		Remediation: "Tune bluestore_default_buffered_write and ensure Linux kernel is pinned to verified stable 6.12.18-hardened or newer.",
	},
	RuleCephOSDPeeringStall: {
		ID:          RuleCephOSDPeeringStall,
		Title:       "Ceph OSD Peering Storm & Heartbeat Ping Latency Spike",
		Category:    CategoryRuntimeAnomaly,
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Description: "One or more Ceph OSD daemons are down/out or experiencing peering stalls exceeding 30 seconds with heartbeat ping latency spikes > 1000ms.",
		Remediation: "Inspect node network interfaces, check MTU consistency, verify disk I/O health, and prevent OSD thrashing.",
	},
	RuleCephPGDegraded: {
		ID:          RuleCephPGDegraded,
		Title:       "Ceph Placement Group Degraded or Undersized Quorum Loss",
		Category:    CategoryRuntimeAnomaly,
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Description: "Placement groups are in degraded, undersized, stale, or incomplete states, reducing fault tolerance and placing data replicas at risk.",
		Remediation: "Allow backfill reconciliation to complete, restore downed OSDs, or adjust PG distribution weights.",
	},
	RuleCephCapacityNearFull: {
		ID:          RuleCephCapacityNearFull,
		Title:       "Ceph Storage Capacity Watermark Nearfull / Backfillfull Exceeded",
		Category:    CategoryRuntimeAnomaly,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.6,
		Description: "Storage pool or cluster-wide raw capacity has exceeded nearfull (>=80%) or backfillfull (>=85%) watermarks, threatening cluster read-only freeze.",
		Remediation: "Add OSD storage capacity, reweight OSDs, or purge stale snapshots to prevent write lockouts at 90% full ratio.",
	},
	RuleCephBlueStoreCorruption: {
		ID:          RuleCephBlueStoreCorruption,
		Title:       "Ceph BlueStore Checksum Error & RocksDB Write Stall",
		Category:    CategoryRuntimeAnomaly,
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Description: "BlueStore engine reports hardware or block CRC32c/XXH64 checksum mismatches or RocksDB WAL write stalls, indicating persistent media degradation.",
		Remediation: "Evict affected OSD, replace degraded NVMe/SSD drive, and trigger deep-scrub verification on all impacted placement groups.",
	},
}

// GetStorageRule retrieves a rule definition by its ID.
func GetStorageRule(id string) (StorageRule, bool) {
	rule, ok := StorageRuleRegistry[id]
	return rule, ok
}
