package storage

import (
	"os"
	"strings"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func sampleFeed() *intel.Feed {
	return &intel.Feed{
		Version: "1.0.0",
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-15509",
				Title:       "Ceph OSD BlueStore Metadata Desync on Kernel 6.12",
				Component:   "ceph",
				Target:      "nixos",
				Severity:    intel.SeverityMedium,
				CVSSScore:   5.5,
				Description: "Direct I/O async flushes on NVMe namespaces may trigger transient OSD peering heartbeats timeouts.",
				Mitigation:  "Tune bluestore_default_buffered_write and use stable kernel 6.12.18-hardened.",
			},
		},
	}
}

func TestStorageScanner_VulnerableCluster(t *testing.T) {
	fixturePath := "../../fixtures/rook-ceph-cluster.yaml"
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		fixturePath = "fixtures/rook-ceph-cluster.yaml"
	}

	scanner := NewStorageScanner(sampleFeed())
	violations, err := scanner.ScanFile(fixturePath)
	if err != nil {
		t.Fatalf("expected successful scan of %s, got error: %v", fixturePath, err)
	}

	if len(violations) == 0 {
		t.Fatalf("expected multiple storage violations, got 0")
	}

	ruleHits := make(map[string]int)
	for _, v := range violations {
		ruleHits[v.RuleID]++
	}

	expectedRules := []string{
		RuleRookHostNetwork,
		RuleRookInTransitCrypto,
		RuleRookAtRestEncryption,
		RuleRookReplicationSize,
		RuleRookMonQuorum,
		RuleRookDashboardInsecure,
		RuleRookPVCMultiAttach,
		RuleRookStorageClassReclaim,
	}

	for _, ruleID := range expectedRules {
		if ruleHits[ruleID] == 0 {
			t.Errorf("expected violation for rule %s, but got 0 hits (total hits: %v)", ruleID, ruleHits)
		}
	}
}

func TestStorageScanner_HardenedCluster(t *testing.T) {
	hardenedYAML := `apiVersion: ceph.rook.io/v1
kind: CephCluster
metadata:
  name: rook-ceph-secure
  namespace: rook-ceph
spec:
  cephVersion:
    image: quay.io/ceph/ceph:v18.2.4
  dataDirHostPath: /var/lib/rook
  mon:
    count: 3
    allowMultiplePerNode: false
  network:
    connections:
      encryption: true
  dashboard:
    enabled: true
    ssl: true
  storage:
    useAllNodes: false
    storageDeviceSets:
      - name: encrypted-nvme-osds
        count: 3
        encrypted: true
---
apiVersion: ceph.rook.io/v1
kind: CephBlockPool
metadata:
  name: safe-pool
  namespace: rook-ceph
spec:
  failureDomain: host
  replicated:
    size: 3
    requireSafeReplicaSize: true
`
	scanner := NewStorageScanner(sampleFeed())
	violations, err := scanner.ScanManifest(hardenedYAML, "hardened.yaml")
	if err != nil {
		t.Fatalf("scan manifest failed: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("expected 0 violations for hardened cluster, got %d: %+v", len(violations), violations)
	}
}

func TestStorageScanner_BoundsChecking(t *testing.T) {
	scanner := NewStorageScanner(nil)

	// Exceed MaxManifestBytes
	hugeContent := strings.Repeat("a", MaxManifestBytes+10)
	_, err := scanner.ScanManifest(hugeContent, "huge.yaml")
	if err == nil {
		t.Errorf("expected error when manifest exceeds MaxManifestBytes, got nil")
	}

	// Exceed MaxDocumentsPerStream
	var docStream strings.Builder
	for i := 0; i < MaxDocumentsPerStream+5; i++ {
		docStream.WriteString("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n")
	}
	_, err = scanner.ScanManifest(docStream.String(), "stream.yaml")
	if err == nil {
		t.Errorf("expected error when document count exceeds safety ceiling, got nil")
	}
}

func TestCephAnomalyDetector_HealthyBaseline(t *testing.T) {
	detector := NewCephAnomalyDetector(sampleFeed())

	healthy := &CephHealthReport{
		ClusterFSID: "c1-healthy-cluster",
		Status:      HealthOK,
		Summary:     []string{"Cluster is fully healthy"},
		MonQuorum:   []string{"mon.a", "mon.b", "mon.c"},
		OSDStats: OSDSummary{
			Total:          6,
			Up:             6,
			In:             6,
			Down:           0,
			Out:            0,
			FlappingCount:  0,
			AvgHeartbeatMs: 15.0,
			MaxHeartbeatMs: 45.0,
		},
		PGStats: PGSummary{
			Total:       256,
			ActiveClean: 256,
		},
		Pools: []PoolUsage{
			{
				Name:        "datapool",
				ID:          1,
				UsedBytes:   20000000000,
				TotalBytes:  100000000000,
				PercentUsed: 20.0,
				NearFull:    false,
				Full:        false,
			},
		},
	}

	violations, err := detector.AnalyzeHealth(healthy)
	if err != nil {
		t.Fatalf("unexpected error analyzing healthy report: %v", err)
	}

	if len(violations) != 0 {
		t.Errorf("expected 0 violations for healthy cluster, got %d: %+v", len(violations), violations)
	}
}

func TestCephAnomalyDetector_TelemetryFixture(t *testing.T) {
	fixturePath := "../../fixtures/ceph-health-telemetry.json"
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		fixturePath = "fixtures/ceph-health-telemetry.json"
	}

	feed := sampleFeed()
	detector := NewCephAnomalyDetector(feed)

	report, violations, err := detector.AnalyzeHealthFile(fixturePath)
	if err != nil {
		t.Fatalf("expected successful telemetry analysis, got error: %v", err)
	}

	if report.Status != HealthWarn {
		t.Errorf("expected status HEALTH_WARN, got %s", report.Status)
	}

	if len(violations) == 0 {
		t.Fatalf("expected anomaly violations, got 0")
	}

	ruleHits := make(map[string]int)
	var foundCVE bool
	for _, v := range violations {
		ruleHits[v.RuleID]++
		if v.MatchedCVE == "CVE-2026-15509" {
			foundCVE = true
			if v.Severity != intel.SeverityMedium {
				t.Errorf("expected severity MEDIUM for CVE-2026-15509, got %s", v.Severity)
			}
			if v.CVSSScore != 5.5 {
				t.Errorf("expected CVSS 5.5 for CVE-2026-15509, got %.1f", v.CVSSScore)
			}
		}
	}

	if ruleHits[RuleCephOSDPeeringStall] == 0 {
		t.Errorf("expected violation for RuleCephOSDPeeringStall, got 0")
	}
	if ruleHits[RuleCephPGDegraded] == 0 {
		t.Errorf("expected violation for RuleCephPGDegraded, got 0")
	}
	if ruleHits[RuleCephCapacityNearFull] == 0 {
		t.Errorf("expected violation for RuleCephCapacityNearFull, got 0")
	}
	if ruleHits[RuleCephBlueStoreCorruption] == 0 {
		t.Errorf("expected violation for RuleCephBlueStoreCorruption, got 0")
	}
	if !foundCVE {
		t.Errorf("expected violation mapped to CVE-2026-15509, not found")
	}
}

func TestVolumeAuditor_SafeRWXCephFS(t *testing.T) {
	cephFSManifest := `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: shared-docs-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteMany
  storageClassName: rook-cephfs-shared
`
	scanner := NewStorageScanner(nil)
	violations, err := scanner.ScanManifest(cephFSManifest, "cephfs.yaml")
	if err != nil {
		t.Fatalf("scan manifest failed: %v", err)
	}

	for _, v := range violations {
		if v.RuleID == RuleRookPVCMultiAttach {
			t.Errorf("CephFS shared volume should not trigger ROOK-CEPH-008 multi-attach violation: %+v", v)
		}
	}
}

func TestStorageScanner_DirectoryWalk(t *testing.T) {
	dirPath := "../../fixtures"
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		dirPath = "fixtures"
	}

	scanner := NewStorageScanner(sampleFeed())
	report, err := scanner.ScanDirectory(dirPath)
	if err != nil {
		t.Fatalf("ScanDirectory failed on %s: %v", dirPath, err)
	}

	if report.TotalFiles == 0 {
		t.Errorf("expected scanned files > 0, got %d", report.TotalFiles)
	}
	if len(report.Violations) == 0 {
		t.Errorf("expected storage violations discovered, got 0")
	}
}
