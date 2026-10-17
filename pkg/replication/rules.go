package replication

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	RuleSnapshotClassDeletionPolicy  = "CEPH-DR-001"
	RuleSnapshotScheduleMissing      = "CEPH-DR-002"
	RuleSnapshotRetentionInadequate  = "CEPH-DR-003"
	RuleReplicationTransportInsecure = "CEPH-DR-004"
	RuleReplicationIntervalExcessive = "CEPH-DR-005"
	RuleVolumeReplicationStateMissing= "CEPH-DR-006"
	RuleMirrorDaemonNoAntiAffinity   = "CEPH-DR-007"
	RuleArbiterMonitorMissing        = "CEPH-DR-008"
	RuleReplicationDeltaLagExceeded  = "CEPH-DR-009"
	RuleReplicationSplitBrain        = "CEPH-DR-010"
	RuleReplicationDegradedError     = "CEPH-DR-011"
	RuleDRFailoverNotReady           = "CEPH-DR-012"
)

// ReplicationRuleRegistry contains the authoritative canonical catalog of CephFS snapshot & volume replication DR rules.
var ReplicationRuleRegistry = map[string]ReplicationRule{
	RuleSnapshotClassDeletionPolicy: {
		ID:          RuleSnapshotClassDeletionPolicy,
		Title:       "VolumeSnapshotClass DeletionPolicy Set to Delete Instead of Retain",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.4,
		Description: "VolumeSnapshotClass specifies deletionPolicy 'Delete'. If a VolumeSnapshot CR is accidentally deleted or purged by an automated cleanup script, the underlying storage snapshot on CephFS/RBD is instantly destroyed, eliminating disaster recovery recovery points.",
		Remediation: "Configure 'deletionPolicy: Retain' on production VolumeSnapshotClasses and manage snapshot lifecycle via declarative retention policies.",
	},
	RuleSnapshotScheduleMissing: {
		ID:          RuleSnapshotScheduleMissing,
		Title:       "CephFS / RBD Volume Lacks Automated Snapshot Schedule or Interval > 24h",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Description: "Persistent volumes hosting production workloads lack automated snapshot schedule policies or configure snapshot intervals exceeding 24 hours, directly violating Disaster Recovery RPO service level agreements.",
		Remediation: "Declare CephFilesystemSubVolumeGroup snapshot schedule policies (e.g., interval: 1h or 4h) with automated snapshot schedules.",
	},
	RuleSnapshotRetentionInadequate: {
		ID:          RuleSnapshotRetentionInadequate,
		Title:       "CephFS Snapshot Retention Count Inadequate (< 3) or Pruning Disabled",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.5,
		Description: "Snapshot schedule policy defines retention count < 3 or disables automated pruning, risking either premature point-in-time recovery loss or uncontrolled Ceph metadata server (MDS) storage bloat.",
		Remediation: "Enforce retention count >= 7 daily and 4 weekly snapshots with active pruning enabled in subvolume group configurations.",
	},
	RuleReplicationTransportInsecure: {
		ID:          RuleReplicationTransportInsecure,
		Title:       "VolumeReplicationClass Unencrypted WAN Transport Across Regions",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Description: "VolumeReplicationClass mirrors CephFS / RBD delta chunks across geographically separated data centers over cleartext WAN links without TLS or msgr2 cryptographic encryption.",
		Remediation: "Enable wire encryption on cross-region mirroring transport via msgr2 'ms_mode: secure' or encapsulate replication traffic within WireGuard/IPsec tunnels.",
	},
	RuleReplicationIntervalExcessive: {
		ID:          RuleReplicationIntervalExcessive,
		Title:       "VolumeReplication SchedulingInterval Exceeds Cluster RPO SLA (> 60m)",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.2,
		Description: "VolumeReplicationClass specifies a replication interval greater than 60 minutes, risking excessive data delta loss during unexpected cross-region failover events.",
		Remediation: "Configure schedulingInterval to 15m or lower to guarantee standard disaster recovery RPO targets.",
	},
	RuleVolumeReplicationStateMissing: {
		ID:          RuleVolumeReplicationStateMissing,
		Title:       "VolumeReplication Missing Explicit ReplicationState (Primary / Secondary)",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.1,
		Description: "VolumeReplication CRD omits spec.replicationState or references an undefined VolumeReplicationClass, leaving volume replication unmanaged by CSI replication controllers.",
		Remediation: "Explicitly declare 'spec.replicationState: Primary' on active site workloads and 'Secondary' on standby disaster recovery sites.",
	},
	RuleMirrorDaemonNoAntiAffinity: {
		ID:          RuleMirrorDaemonNoAntiAffinity,
		Title:       "Ceph Mirror Daemon Single Replica or Missing Failure Domain Anti-Affinity",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.0,
		Description: "CephFilesystemMirror or CephRBDMirror runs with a single daemon replica (replicas < 2) or lacks pod anti-affinity across node failure domains, introducing single point of failure in DR replication.",
		Remediation: "Deploy at least 2 mirror daemon replicas with requiredDuringSchedulingIgnoredDuringExecution anti-affinity across distinct failure domains.",
	},
	RuleArbiterMonitorMissing: {
		ID:          RuleArbiterMonitorMissing,
		Title:       "Stretched Cluster Deployment Missing 3rd-Zone Arbiter / Tie-Breaker Monitor",
		Severity:    intel.SeverityCritical,
		CVSSScore:   8.9,
		Description: "Stretched multi-region Ceph cluster lacks a designated arbiter monitor in a 3rd independent failure zone, creating severe split-brain tie risks during cross-region network partitions.",
		Remediation: "Configure an Arbiter monitor in an independent 3rd cloud or edge failure zone to arbitrate MON quorum without hosting storage data.",
	},
	RuleReplicationDeltaLagExceeded: {
		ID:          RuleReplicationDeltaLagExceeded,
		Title:       "Volume Replication Delta Lag Exceeds RPO SLA (> 900s / 15m)",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.3,
		Description: "Runtime telemetry indicates delta replication lag has exceeded the 900-second (15-minute) RPO threshold, indicating network congestion, high write volumes, or mirror daemon stalls.",
		Remediation: "Inspect mirror daemon logs, check WAN bandwidth utilization, and tune rbd-mirror / cephfs-mirror concurrent sync worker threads.",
	},
	RuleReplicationSplitBrain: {
		ID:          RuleReplicationSplitBrain,
		Title:       "Cross-Region Volume Replication Split-Brain Dual-Primary Condition",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.6,
		MatchedCVE:  "CVE-2026-10140",
		Description: "Both primary and disaster recovery clusters assert 'replicationState: Primary' for the same volume, causing simultaneous diverging writes and catastrophic data divergence.",
		Remediation: "Immediately fence off the partitioned cluster, demote the secondary site to 'Secondary', and execute volume resynchronization from verified primary snapshot.",
	},
	RuleReplicationDegradedError: {
		ID:          RuleReplicationDegradedError,
		Title:       "Volume Replication in Degraded, Error, or Continuous Resyncing Loop",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Description: "VolumeReplication telemetry reports Error or persistent Degraded status, indicating snapshot transfer failure, corrupted journal stream, or broken peer authentication.",
		Remediation: "Verify peer token exchange secrets, inspect Ceph health reports, and re-trigger baseline volume synchronization if journal entries are truncated.",
	},
	RuleDRFailoverNotReady: {
		ID:          RuleDRFailoverNotReady,
		Title:       "Disaster Recovery Secondary Site Lacks Promotion-Ready Clean Snapshot",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.7,
		Description: "Standby disaster recovery cluster lacks recent clean, crash-consistent volume snapshots, preventing rapid failover promotion and extending recovery time objective (RTO).",
		Remediation: "Ensure initial baseline volume snapshot synchronization is completed and verified before directing production traffic to primary volume.",
	},
}

// GetReplicationRule retrieves a rule by its ID.
func GetReplicationRule(id string) (ReplicationRule, bool) {
	rule, ok := ReplicationRuleRegistry[id]
	return rule, ok
}
