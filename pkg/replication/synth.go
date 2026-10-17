package replication

import (
	"fmt"
	"os"
	"path/filepath"
)

// SynthesizeHardenedVolumeSnapshotClass generates declarative VolumeSnapshotClass with Retain policy.
func SynthesizeHardenedVolumeSnapshotClass(name, clusterID, driver string) string {
	if name == "" {
		name = "cephfs-snapshot-retained"
	}
	if clusterID == "" {
		clusterID = "rook-ceph"
	}
	if driver == "" {
		driver = "rook-ceph.cephfs.csi.ceph.com"
	}

	return fmt.Sprintf(`apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: %s
  labels:
    app.kubernetes.io/managed-by: nix-k8s-sentinel
    sentinel.dr.io/policy: hardened-retain
driver: %s
deletionPolicy: Retain
parameters:
  clusterID: %s
  csi.storage.k8s.io/snapshotter-secret-name: rook-csi-cephfs-provisioner
  csi.storage.k8s.io/snapshotter-secret-namespace: %s
`, name, driver, clusterID, clusterID)
}

// SynthesizeCephFSSnapshotSchedule generates CephFilesystemSubVolumeGroup with automated schedule.
func SynthesizeCephFSSnapshotSchedule(name, fsName string, intervalHours, retentionDays int) string {
	if name == "" {
		name = "csi"
	}
	if fsName == "" {
		fsName = "my-cephfs"
	}
	if intervalHours <= 0 {
		intervalHours = 1
	}
	if retentionDays <= 0 {
		retentionDays = 14
	}

	return fmt.Sprintf(`apiVersion: ceph.rook.io/v1
kind: CephFilesystemSubVolumeGroup
metadata:
  name: %s
  namespace: rook-ceph
  labels:
    app.kubernetes.io/managed-by: nix-k8s-sentinel
spec:
  filesystemName: %s
  snapshotSchedule:
    schedule: "%dh"
    retention: %d
    pruneOld: true
`, name, fsName, intervalHours, retentionDays)
}

// SynthesizeVolumeReplicationClass generates declarative VolumeReplicationClass with encrypted transport.
func SynthesizeVolumeReplicationClass(name, provisioner, interval string) string {
	if name == "" {
		name = "cephfs-dr-replication-class"
	}
	if provisioner == "" {
		provisioner = "rook-ceph.cephfs.csi.ceph.com"
	}
	if interval == "" {
		interval = "15m"
	}

	return fmt.Sprintf(`apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplicationClass
metadata:
  name: %s
  labels:
    app.kubernetes.io/managed-by: nix-k8s-sentinel
spec:
  provisioner: %s
  parameters:
    mirroringMode: snapshot
    schedulingInterval: "%s"
    replication.storage.openshift.io/replication-secret-name: rook-ceph-replication-secret
    replication.storage.openshift.io/replication-secret-namespace: rook-ceph
    ms_mode: secure
    encrypted: "true"
`, name, provisioner, interval)
}

// SynthesizeVolumeReplicationPair generates paired Primary and Secondary VolumeReplication manifests.
func SynthesizeVolumeReplicationPair(pvcName, ns, repClassName, peerClusterID string) (primaryYAML, secondaryYAML string) {
	if pvcName == "" {
		pvcName = "prod-data-pvc"
	}
	if ns == "" {
		ns = "default"
	}
	if repClassName == "" {
		repClassName = "cephfs-dr-replication-class"
	}
	if peerClusterID == "" {
		peerClusterID = "dr-peer-cluster"
	}

	primaryYAML = fmt.Sprintf(`apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplication
metadata:
  name: %s-vr
  namespace: %s
  labels:
    sentinel.dr.io/role: primary
spec:
  volumeReplicationClassName: %s
  replicationState: Primary
  dataSource:
    name: %s
    kind: PersistentVolumeClaim
  autoResync: true
`, pvcName, ns, repClassName, pvcName)

	secondaryYAML = fmt.Sprintf(`apiVersion: replication.storage.openshift.io/v1alpha1
kind: VolumeReplication
metadata:
  name: %s-vr
  namespace: %s
  labels:
    sentinel.dr.io/role: secondary
spec:
  volumeReplicationClassName: %s
  replicationState: Secondary
  dataSource:
    name: %s
    kind: PersistentVolumeClaim
  autoResync: true
`, pvcName, ns, repClassName, pvcName)

	return primaryYAML, secondaryYAML
}

// SynthesizeArbiterCephCluster generates CephCluster snippet with 3rd-zone arbiter configuration.
func SynthesizeArbiterCephCluster(clusterName, arbiterZone string) string {
	if clusterName == "" {
		clusterName = "rook-ceph"
	}
	if arbiterZone == "" {
		arbiterZone = "zone-c-arbiter"
	}

	return fmt.Sprintf(`spec:
  mon:
    count: 3
    allowMultiplePerNode: false
  arbiter:
    enabled: true
    arbiterZone: "%s"
    failureDomain: zone
`, arbiterZone)
}

// WriteSyntheticPoliciesToDir exports canonical hardened templates into the output directory.
func WriteSyntheticPoliciesToDir(outDir string) error {
	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory for synthetic DR policies: %w", err)
	}

	sc := SynthesizeHardenedVolumeSnapshotClass("cephfs-snapshot-retained", "rook-ceph", "rook-ceph.cephfs.csi.ceph.com")
	if err := os.WriteFile(filepath.Join(cleanDir, "volumesnapshotclass-retained.yaml"), []byte(sc), 0o644); err != nil {
		return err
	}

	sched := SynthesizeCephFSSnapshotSchedule("csi", "my-cephfs", 1, 14)
	if err := os.WriteFile(filepath.Join(cleanDir, "cephfs-snapshot-schedule.yaml"), []byte(sched), 0o644); err != nil {
		return err
	}

	vrc := SynthesizeVolumeReplicationClass("cephfs-dr-replication-class", "rook-ceph.cephfs.csi.ceph.com", "15m")
	if err := os.WriteFile(filepath.Join(cleanDir, "volumereplicationclass-dr.yaml"), []byte(vrc), 0o644); err != nil {
		return err
	}

	prim, sec := SynthesizeVolumeReplicationPair("prod-data-pvc", "production", "cephfs-dr-replication-class", "dr-cluster-west")
	if err := os.WriteFile(filepath.Join(cleanDir, "volumereplication-primary.yaml"), []byte(prim), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cleanDir, "volumereplication-secondary.yaml"), []byte(sec), 0o644); err != nil {
		return err
	}

	return nil
}
