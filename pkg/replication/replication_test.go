package replication

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestReplicationRulesCatalog(t *testing.T) {
	expectedRules := []string{
		RuleSnapshotClassDeletionPolicy,
		RuleSnapshotScheduleMissing,
		RuleSnapshotRetentionInadequate,
		RuleReplicationTransportInsecure,
		RuleReplicationIntervalExcessive,
		RuleVolumeReplicationStateMissing,
		RuleMirrorDaemonNoAntiAffinity,
		RuleArbiterMonitorMissing,
		RuleReplicationDeltaLagExceeded,
		RuleReplicationSplitBrain,
		RuleReplicationDegradedError,
		RuleDRFailoverNotReady,
	}

	if len(ReplicationRuleRegistry) != len(expectedRules) {
		t.Fatalf("expected %d canonical rules, got %d", len(expectedRules), len(ReplicationRuleRegistry))
	}

	for _, ruleID := range expectedRules {
		rule, ok := GetReplicationRule(ruleID)
		if !ok {
			t.Errorf("rule %s not found in registry", ruleID)
		}
		if rule.ID != ruleID {
			t.Errorf("expected ID %s, got %s", ruleID, rule.ID)
		}
		if rule.Title == "" || rule.Description == "" || rule.Remediation == "" {
			t.Errorf("rule %s has empty fields", ruleID)
		}
		if rule.CVSSScore <= 0.0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", ruleID, rule.CVSSScore)
		}
	}
}

func TestParseCompliantManifest(t *testing.T) {
	manifestYAML := `
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: cephfs-snapshot-class
driver: rook-ceph.cephfs.csi.ceph.com
deletionPolicy: Retain
parameters:
  clusterID: rook-ceph
---
apiVersion: ceph.rook.io/v1
kind: CephFilesystemSubVolumeGroup
metadata:
  name: csi
spec:
  filesystemName: my-cephfs
  snapshotSchedule:
    schedule: "1h"
    retention: 14
    pruneOld: true
---
apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplicationClass
metadata:
  name: cephfs-rep-class
spec:
  provisioner: rook-ceph.cephfs.csi.ceph.com
  parameters:
    mirroringMode: snapshot
    schedulingInterval: "15m"
    encrypted: "true"
---
apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplication
metadata:
  name: prod-db-vr
  namespace: prod
spec:
  volumeReplicationClassName: cephfs-rep-class
  replicationState: Primary
  claimName: prod-db-pvc
---
apiVersion: ceph.rook.io/v1
kind: CephFilesystemMirror
metadata:
  name: my-fs-mirror
spec:
  replicas: 2
  placement:
    podAntiAffinity: true
---
apiVersion: ceph.rook.io/v1
kind: CephCluster
metadata:
  name: rook-ceph
spec:
  arbiter:
    enabled: true
    arbiterZone: "zone-c"
    failureDomain: zone
`

	manifests, err := ParseManifestBytes([]byte(manifestYAML), "test-compliant.yaml")
	if err != nil {
		t.Fatalf("failed to parse compliant manifests: %v", err)
	}

	if len(manifests.SnapshotClasses) != 1 {
		t.Errorf("expected 1 snapshot class, got %d", len(manifests.SnapshotClasses))
	}
	if len(manifests.SnapshotSchedules) != 1 {
		t.Errorf("expected 1 snapshot schedule, got %d", len(manifests.SnapshotSchedules))
	}
	if len(manifests.ReplicationClasses) != 1 {
		t.Errorf("expected 1 replication class, got %d", len(manifests.ReplicationClasses))
	}
	if len(manifests.VolumeReplications) != 1 {
		t.Errorf("expected 1 volume replication, got %d", len(manifests.VolumeReplications))
	}
	if len(manifests.MirrorDaemons) != 1 {
		t.Errorf("expected 1 mirror daemon, got %d", len(manifests.MirrorDaemons))
	}
	if len(manifests.ArbiterConfigs) != 1 {
		t.Errorf("expected 1 arbiter config, got %d", len(manifests.ArbiterConfigs))
	}

	violations := AuditManifests(manifests, nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for compliant manifest, got %d: %+v", len(violations), violations)
	}

	summary := ComputeSummary(manifests, nil, violations)
	if summary.Status != "COMPLIANT" || summary.Score < 95.0 {
		t.Errorf("expected COMPLIANT status with high score, got %s (%.1f)", summary.Status, summary.Score)
	}
}

func TestParseVulnerableManifest(t *testing.T) {
	manifestYAML := `
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: vulnerable-snapshot-class
driver: rook-ceph.cephfs.csi.ceph.com
deletionPolicy: Delete
---
apiVersion: ceph.rook.io/v1
kind: CephFilesystemSubVolumeGroup
metadata:
  name: insecure-schedule
spec:
  filesystemName: my-cephfs
  snapshotSchedule:
    schedule: "48h"
    retention: 1
    pruneOld: false
---
apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplicationClass
metadata:
  name: unencrypted-rep-class
spec:
  provisioner: rook-ceph.cephfs.csi.ceph.com
  parameters:
    mirroringMode: snapshot
    schedulingInterval: "120m"
    encrypted: "false"
---
apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplication
metadata:
  name: unmanaged-vr
  namespace: prod
spec:
  volumeReplicationClassName: unencrypted-rep-class
  claimName: prod-db-pvc
---
apiVersion: ceph.rook.io/v1
kind: CephFilesystemMirror
metadata:
  name: single-replica-mirror
spec:
  replicas: 1
---
apiVersion: ceph.rook.io/v1
kind: CephCluster
metadata:
  name: rook-ceph
spec:
  arbiter:
    enabled: false
`

	manifests, err := ParseManifestBytes([]byte(manifestYAML), "test-vulnerable.yaml")
	if err != nil {
		t.Fatalf("failed to parse vulnerable manifests: %v", err)
	}

	violations := AuditManifests(manifests, nil)
	if len(violations) == 0 {
		t.Fatalf("expected multiple violations for vulnerable manifest, got 0")
	}

	violationMap := make(map[string]bool)
	for _, v := range violations {
		violationMap[v.RuleID] = true
	}

	expectedRules := []string{
		RuleSnapshotClassDeletionPolicy,
		RuleSnapshotScheduleMissing,
		RuleSnapshotRetentionInadequate,
		RuleReplicationTransportInsecure,
		RuleReplicationIntervalExcessive,
		RuleVolumeReplicationStateMissing,
		RuleMirrorDaemonNoAntiAffinity,
		RuleArbiterMonitorMissing,
	}

	for _, rule := range expectedRules {
		if !violationMap[rule] {
			t.Errorf("expected violation %s not triggered", rule)
		}
	}

	summary := ComputeSummary(manifests, nil, violations)
	if summary.Status != "NON_COMPLIANT" {
		t.Errorf("expected NON_COMPLIANT status, got %s", summary.Status)
	}
}

func TestTelemetryAuditing(t *testing.T) {
	now := time.Now().UTC()
	telemetry := &CrossRegionDRTelemetry{
		PrimaryClusterID: "us-east-cluster",
		PrimaryRegion:    "us-east-1",
		PeerClusterID:    "us-west-cluster",
		PeerRegion:       "us-west-2",
		TotalVolumes:     3,
		ArbiterAlive:     false, // Triggers ArbiterMonitorMissing
		GeneratedAt:      now,
		Volumes: []VolumeReplicationStatus{
			{
				VolumeName:            "vol-lagging",
				Namespace:             "prod",
				LocalClusterID:        "us-east-cluster",
				PeerClusterID:         "us-west-cluster",
				State:                 StatePrimary,
				PeerState:             StateSecondary,
				ReplicationLagSeconds: 1500, // > 900s RPO
				InSync:                false,
			},
			{
				VolumeName:            "vol-split-brain",
				Namespace:             "prod",
				LocalClusterID:        "us-east-cluster",
				PeerClusterID:         "us-west-cluster",
				State:                 StatePrimary,
				PeerState:             StatePrimary, // Split-brain!
				SplitBrainRisk:        true,
			},
			{
				VolumeName:            "vol-degraded",
				Namespace:             "prod",
				LocalClusterID:        "us-east-cluster",
				PeerClusterID:         "us-west-cluster",
				State:                 StateDegraded,
				Message:               "journal write timeout",
			},
			{
				VolumeName:            "vol-standby-unready",
				Namespace:             "prod",
				LocalClusterID:        "us-west-cluster",
				PeerClusterID:         "us-east-cluster",
				State:                 StateSecondary,
				InSync:                false,
				ReplicationLagSeconds: 2400, // Not promotion ready
			},
		},
	}

	violations := AuditTelemetry(telemetry, nil)
	if len(violations) == 0 {
		t.Fatalf("expected telemetry violations, got 0")
	}

	violationMap := make(map[string]bool)
	for _, v := range violations {
		violationMap[v.RuleID] = true
	}

	expectedRules := []string{
		RuleArbiterMonitorMissing,
		RuleReplicationDeltaLagExceeded,
		RuleReplicationSplitBrain,
		RuleReplicationDegradedError,
		RuleDRFailoverNotReady,
	}

	for _, rule := range expectedRules {
		if !violationMap[rule] {
			t.Errorf("expected telemetry violation %s not triggered", rule)
		}
	}

	summary := ComputeSummary(nil, telemetry, violations)
	if !summary.SplitBrainDetected {
		t.Errorf("expected split brain flag to be true")
	}
	if summary.MaxDeltaLagSeconds < 1500 {
		t.Errorf("expected MaxDeltaLagSeconds >= 1500, got %d", summary.MaxDeltaLagSeconds)
	}
}

func TestSynthesizers(t *testing.T) {
	tempDir := t.TempDir()

	sc := SynthesizeHardenedVolumeSnapshotClass("custom-sc", "cluster-1", "rook-ceph.cephfs.csi.ceph.com")
	if !strings.Contains(sc, "deletionPolicy: Retain") || !strings.Contains(sc, "custom-sc") {
		t.Errorf("SynthesizeHardenedVolumeSnapshotClass output malformed: %s", sc)
	}

	sched := SynthesizeCephFSSnapshotSchedule("csi", "prod-fs", 2, 30)
	if !strings.Contains(sched, `schedule: "2h"`) || !strings.Contains(sched, "retention: 30") {
		t.Errorf("SynthesizeCephFSSnapshotSchedule output malformed: %s", sched)
	}

	vrc := SynthesizeVolumeReplicationClass("custom-vrc", "rook-ceph.cephfs.csi.ceph.com", "10m")
	if !strings.Contains(vrc, `schedulingInterval: "10m"`) || !strings.Contains(vrc, "encrypted: \"true\"") {
		t.Errorf("SynthesizeVolumeReplicationClass output malformed: %s", vrc)
	}

	prim, sec := SynthesizeVolumeReplicationPair("test-pvc", "test-ns", "custom-vrc", "peer-cluster")
	if !strings.Contains(prim, "replicationState: Primary") || !strings.Contains(sec, "replicationState: Secondary") {
		t.Errorf("SynthesizeVolumeReplicationPair output malformed: prim=%s, sec=%s", prim, sec)
	}

	arb := SynthesizeArbiterCephCluster("rook-cluster", "zone-us-central")
	if !strings.Contains(arb, "enabled: true") || !strings.Contains(arb, "zone-us-central") {
		t.Errorf("SynthesizeArbiterCephCluster output malformed: %s", arb)
	}

	if err := WriteSyntheticPoliciesToDir(tempDir); err != nil {
		t.Fatalf("WriteSyntheticPoliciesToDir failed: %v", err)
	}

	files := []string{
		"volumesnapshotclass-retained.yaml",
		"cephfs-snapshot-schedule.yaml",
		"volumereplicationclass-dr.yaml",
		"volumereplication-primary.yaml",
		"volumereplication-secondary.yaml",
	}
	for _, f := range files {
		p := filepath.Join(tempDir, f)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected synthesized file %s not found: %v", f, err)
		}
	}
}

func TestMemoryBoundsAndScanner(t *testing.T) {
	tempDir := t.TempDir()
	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-10140",
				Component: "cephfs-dr",
				Severity:  intel.SeverityCritical,
				CVSSScore: 9.6,
			},
		},
	}

	scanner := NewReplicationScanner(feed)

	// Test oversized manifest protection
	oversizedData := make([]byte, MaxManifestBytes+1024)
	_, err := ParseManifestBytes(oversizedData, "oversized.yaml")
	if err == nil {
		t.Fatalf("expected error on oversized manifest, got nil")
	}

	// Test valid directory scan
	samplePath := filepath.Join(tempDir, "sample-dr.yaml")
	sampleContent := SynthesizeHardenedVolumeSnapshotClass("test-sc", "cluster-1", "")
	if err := os.WriteFile(samplePath, []byte(sampleContent), 0644); err != nil {
		t.Fatalf("failed to write sample file: %v", err)
	}

	rep, err := scanner.ScanDirectory(tempDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}
	if rep.TotalFiles != 1 {
		t.Errorf("expected 1 file scanned, got %d", rep.TotalFiles)
	}
}
