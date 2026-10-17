package replication

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	reDurationMinutes = regexp.MustCompile(`^(\d+)\s*(m|min|h|hr|d)?$`)
)

// AuditManifests evaluates declarative manifests against canonical DR rules.
func AuditManifests(manifests *ParsedDRManifests, feed *intel.Feed) []ReplicationViolation {
	var violations []ReplicationViolation
	if manifests == nil {
		return violations
	}

	// 1. Audit VolumeSnapshotClasses
	for _, sc := range manifests.SnapshotClasses {
		if sc.DeletionPolicy != DeletionPolicyRetain {
			v := newViolation(RuleSnapshotClassDeletionPolicy, "VolumeSnapshotClass", sc.Name, "", sc.File, sc.Line, feed)
			violations = append(violations, v)
		}
	}

	// 2. Audit Snapshot Schedules
	if len(manifests.SnapshotSchedules) == 0 && len(manifests.VolumeReplications) > 0 {
		// Replicated volumes exist but no automated snapshot schedules declared
		v := newViolation(RuleSnapshotScheduleMissing, "ClusterSnapshotPolicy", "default", "", "", 1, feed)
		v.Description = "Production workloads configure volume replication but lack automated CephFS/RBD snapshot schedule policies."
		violations = append(violations, v)
	}

	for _, s := range manifests.SnapshotSchedules {
		mins := parseIntervalToMinutes(s.Schedule)
		if mins > 24*60 || (mins == 0 && s.Schedule == "") {
			v := newViolation(RuleSnapshotScheduleMissing, "CephFilesystemSubVolumeGroup", s.Name, "", s.File, s.Line, feed)
			violations = append(violations, v)
		}

		if s.RetentionCount > 0 && s.RetentionCount < 3 {
			v := newViolation(RuleSnapshotRetentionInadequate, "CephFilesystemSubVolumeGroup", s.Name, "", s.File, s.Line, feed)
			v.Description = fmt.Sprintf("Snapshot policy '%s' specifies retention count %d (< 3 required for disaster recovery point-in-time recovery).", s.Name, s.RetentionCount)
			violations = append(violations, v)
		} else if !s.PruneOldEnabled && s.RetentionCount == 0 {
			v := newViolation(RuleSnapshotRetentionInadequate, "CephFilesystemSubVolumeGroup", s.Name, "", s.File, s.Line, feed)
			v.Description = fmt.Sprintf("Snapshot policy '%s' disables automated pruning without fixed retention limit.", s.Name)
			violations = append(violations, v)
		}
	}

	// 3. Audit VolumeReplicationClasses
	for _, rc := range manifests.ReplicationClasses {
		if !rc.EncryptedTransport {
			v := newViolation(RuleReplicationTransportInsecure, "VolumeReplicationClass", rc.Name, "", rc.File, rc.Line, feed)
			violations = append(violations, v)
		}

		mins := parseIntervalToMinutes(rc.SchedulingInterval)
		if mins > 60 {
			v := newViolation(RuleReplicationIntervalExcessive, "VolumeReplicationClass", rc.Name, "", rc.File, rc.Line, feed)
			v.Description = fmt.Sprintf("VolumeReplicationClass '%s' specifies replication interval %s (> 60m), risking RPO target violations.", rc.Name, rc.SchedulingInterval)
			violations = append(violations, v)
		}
	}

	// 4. Audit VolumeReplications
	for _, vr := range manifests.VolumeReplications {
		if vr.ReplicationState != StatePrimary && vr.ReplicationState != StateSecondary {
			v := newViolation(RuleVolumeReplicationStateMissing, "VolumeReplication", vr.Name, vr.Namespace, vr.File, vr.Line, feed)
			violations = append(violations, v)
		}
	}

	// 5. Audit Ceph Mirror Daemons
	for _, md := range manifests.MirrorDaemons {
		if md.Replicas < 2 || !md.AntiAffinity {
			v := newViolation(RuleMirrorDaemonNoAntiAffinity, md.Kind, md.Name, "", md.File, md.Line, feed)
			if md.Replicas < 2 {
				v.Description = fmt.Sprintf("%s '%s' runs with %d replica (< 2 required for high availability DR mirroring).", md.Kind, md.Name, md.Replicas)
			}
			violations = append(violations, v)
		}
	}

	// 6. Audit Arbiter Configurations
	for _, ac := range manifests.ArbiterConfigs {
		if !ac.ArbiterEnabled {
			v := newViolation(RuleArbiterMonitorMissing, "CephCluster", ac.ClusterName, "", ac.File, ac.Line, feed)
			violations = append(violations, v)
		}
	}

	return violations
}

// AuditTelemetry evaluates live cross-region disaster recovery telemetry against operational SLAs.
func AuditTelemetry(telemetry *CrossRegionDRTelemetry, feed *intel.Feed) []ReplicationViolation {
	var violations []ReplicationViolation
	if telemetry == nil {
		return violations
	}

	if !telemetry.ArbiterAlive && telemetry.PrimaryClusterID != "" && telemetry.PeerClusterID != "" {
		v := newViolation(RuleArbiterMonitorMissing, "CrossRegionQuorum", telemetry.PrimaryClusterID, "", "", 1, feed)
		v.Description = "Cross-region telemetry indicates 3rd-zone Arbiter tie-breaker monitor is offline or unreachable."
		violations = append(violations, v)
	}

	for _, vol := range telemetry.Volumes {
		// Delta lag check
		if vol.ReplicationLagSeconds > DefaultRPOTargetSeconds {
			v := newViolation(RuleReplicationDeltaLagExceeded, "VolumeReplicationStatus", vol.VolumeName, vol.Namespace, "", 1, feed)
			v.Description = fmt.Sprintf("Volume '%s/%s' replication delta lag (%ds) exceeds RPO target (%ds).",
				vol.Namespace, vol.VolumeName, vol.ReplicationLagSeconds, DefaultRPOTargetSeconds)
			violations = append(violations, v)
		}

		// Split brain check
		if (vol.State == StatePrimary && vol.PeerState == StatePrimary) || vol.SplitBrainRisk {
			v := newViolation(RuleReplicationSplitBrain, "VolumeReplicationStatus", vol.VolumeName, vol.Namespace, "", 1, feed)
			v.Description = fmt.Sprintf("CRITICAL SPLIT-BRAIN: Volume '%s/%s' is marked Primary on both '%s' and '%s' clusters.",
				vol.Namespace, vol.VolumeName, vol.LocalClusterID, vol.PeerClusterID)
			violations = append(violations, v)
		}

		// Degraded or error check
		if vol.State == StateError || vol.State == StateDegraded {
			v := newViolation(RuleReplicationDegradedError, "VolumeReplicationStatus", vol.VolumeName, vol.Namespace, "", 1, feed)
			v.Description = fmt.Sprintf("Volume '%s/%s' replication is in %s state: %s",
				vol.Namespace, vol.VolumeName, vol.State, vol.Message)
			violations = append(violations, v)
		}

		// Secondary DR failover readiness check
		if vol.State == StateSecondary && (!vol.InSync || vol.ReplicationLagSeconds > DefaultMaxDeltaLagSeconds) {
			v := newViolation(RuleDRFailoverNotReady, "VolumeReplicationStatus", vol.VolumeName, vol.Namespace, "", 1, feed)
			v.Description = fmt.Sprintf("Standby DR volume '%s/%s' is not promotion-ready (InSync=%v, Lag=%ds).",
				vol.Namespace, vol.VolumeName, vol.InSync, vol.ReplicationLagSeconds)
			violations = append(violations, v)
		}
	}

	return violations
}

// ComputeSummary calculates compliance score, severity counts, and operational status.
func ComputeSummary(manifests *ParsedDRManifests, telemetry *CrossRegionDRTelemetry, violations []ReplicationViolation) *ReplicationSummary {
	sum := &ReplicationSummary{
		Score: 100.0,
	}

	if manifests != nil {
		sum.TotalSnapshotClasses = len(manifests.SnapshotClasses)
		sum.TotalSchedules = len(manifests.SnapshotSchedules)
		sum.TotalReplications = len(manifests.VolumeReplications)
		sum.TotalManifests = sum.TotalSnapshotClasses + sum.TotalSchedules + sum.TotalReplications + len(manifests.MirrorDaemons) + len(manifests.ArbiterConfigs)
	}

	sum.TotalViolations = len(violations)
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			sum.CriticalCount++
			sum.Score -= 25.0
			if v.RuleID == RuleReplicationSplitBrain {
				sum.SplitBrainDetected = true
			}
		case intel.SeverityHigh:
			sum.HighCount++
			sum.Score -= 15.0
		case intel.SeverityMedium:
			sum.MediumCount++
			sum.Score -= 8.0
		case intel.SeverityLow:
			sum.LowCount++
			sum.Score -= 3.0
		}
	}

	if telemetry != nil {
		for _, vol := range telemetry.Volumes {
			if vol.ReplicationLagSeconds > sum.MaxDeltaLagSeconds {
				sum.MaxDeltaLagSeconds = vol.ReplicationLagSeconds
			}
			if vol.SplitBrainRisk {
				sum.SplitBrainDetected = true
			}
		}
	}

	sum.Score = math.Max(0.0, math.Min(100.0, sum.Score))

	switch {
	case sum.Score >= 90.0 && sum.CriticalCount == 0:
		sum.Status = "COMPLIANT"
	case sum.Score >= 70.0 && sum.CriticalCount == 0:
		sum.Status = "WARNING"
	default:
		sum.Status = "NON_COMPLIANT"
	}

	return sum
}

func newViolation(ruleID, kind, name, ns, file string, line int, feed *intel.Feed) ReplicationViolation {
	rule, exists := GetReplicationRule(ruleID)
	cve := ""
	if exists {
		cve = rule.MatchedCVE
	}
	if cve == "" && feed != nil {
		for _, item := range feed.Items {
			if item.Component == "cephfs-dr" || item.Component == "ceph" {
				cve = item.ID
				break
			}
		}
	}

	title := ruleID
	desc := "Disaster recovery posture deviation detected."
	rem := "Remediate storage manifest according to DR specification."
	sev := intel.SeverityMedium
	cvss := 5.0

	if exists {
		title = rule.Title
		desc = rule.Description
		rem = rule.Remediation
		sev = rule.Severity
		cvss = rule.CVSSScore
	}

	return ReplicationViolation{
		RuleID:       ruleID,
		Title:        title,
		ResourceKind: kind,
		ResourceName: name,
		Namespace:    ns,
		Severity:     sev,
		CVSSScore:    cvss,
		Description:  desc,
		Remediation:  rem,
		MatchedCVE:   cve,
		File:         file,
		Line:         line,
	}
}

func parseIntervalToMinutes(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	m := reDurationMinutes.FindStringSubmatch(s)
	if len(m) < 2 {
		return 0
	}
	val, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	unit := "m"
	if len(m) >= 3 && m[2] != "" {
		unit = m[2]
	}
	switch unit {
	case "h", "hr":
		return val * 60
	case "d":
		return val * 60 * 24
	default:
		return val
	}
}
