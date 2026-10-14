package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// CephAnomalyDetector evaluates runtime health telemetry for Ceph storage clusters.
type CephAnomalyDetector struct {
	feed *intel.Feed
}

// NewCephAnomalyDetector instantiates a detector with optional threat feed correlation.
func NewCephAnomalyDetector(feed *intel.Feed) *CephAnomalyDetector {
	return &CephAnomalyDetector{feed: feed}
}

// ParseHealthJSON parses raw telemetry JSON bytes into a CephHealthReport with bounds safety.
func (d *CephAnomalyDetector) ParseHealthJSON(data []byte) (*CephHealthReport, error) {
	if len(data) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload exceeds maximum allowable size of %d bytes", MaxTelemetryBytes)
	}

	var report CephHealthReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to decode Ceph health telemetry JSON: %w", err)
	}

	return &report, nil
}

// AnalyzeHealthFile loads telemetry from disk and executes anomaly detection.
func (d *CephAnomalyDetector) AnalyzeHealthFile(filePath string) (*CephHealthReport, []StorageViolation, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat telemetry file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, nil, fmt.Errorf("telemetry file %s exceeds %d bytes", cleanPath, MaxTelemetryBytes)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read telemetry file %s: %w", cleanPath, err)
	}

	report, err := d.ParseHealthJSON(data)
	if err != nil {
		return nil, nil, err
	}

	violations, err := d.AnalyzeHealth(report)
	if err != nil {
		return report, nil, err
	}

	for i := range violations {
		if violations[i].FilePath == "" {
			violations[i].FilePath = cleanPath
		}
	}

	return report, violations, nil
}

// AnalyzeHealth inspects a CephHealthReport and yields detected anomalies as StorageViolations.
func (d *CephAnomalyDetector) AnalyzeHealth(report *CephHealthReport) ([]StorageViolation, error) {
	if report == nil {
		return nil, fmt.Errorf("telemetry report cannot be nil")
	}

	var violations []StorageViolation

	// 1. OSD Peering Stalls & Latency Spikes (ROOK-CEPH-011)
	if report.OSDStats.Down > 0 || report.OSDStats.Out > 0 || report.OSDStats.FlappingCount > 0 || report.OSDStats.MaxHeartbeatMs > 1000.0 {
		rule, _ := GetStorageRule(RuleCephOSDPeeringStall)
		desc := fmt.Sprintf("Ceph cluster reports %d OSDs down, %d out, and %d flapping daemons. Peak heartbeat ping latency is %.1fms (threshold: 1000ms).",
			report.OSDStats.Down, report.OSDStats.Out, report.OSDStats.FlappingCount, report.OSDStats.MaxHeartbeatMs)

		violations = append(violations, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: "CephCluster",
			ResourceName: report.ClusterFSID,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  desc,
			Remediation:  rule.Remediation,
		})
	}

	for _, alert := range report.PeeringAlerts {
		if alert.DurationSeconds > 30 || strings.Contains(strings.ToLower(alert.State), "peering") {
			rule, _ := GetStorageRule(RuleCephOSDPeeringStall)
			violations = append(violations, StorageViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				ResourceKind: "PlacementGroup",
				ResourceName: alert.PGID,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Description:  fmt.Sprintf("PG %s stuck in peering state '%s' for %ds (Primary OSD: %d, Peers: %v): %s", alert.PGID, alert.State, alert.DurationSeconds, alert.PrimaryOSD, alert.PeerOSDs, alert.Message),
				Remediation:  rule.Remediation,
			})
		}
	}

	// 2. Placement Group Degraded or Undersized Quorum (ROOK-CEPH-012)
	pgs := report.PGStats
	if pgs.Degraded > 0 || pgs.Undersized > 0 || pgs.Incomplete > 0 || pgs.Stale > 0 || pgs.Inconsistent > 0 {
		rule, _ := GetStorageRule(RuleCephPGDegraded)
		desc := fmt.Sprintf("Cluster has abnormal placement groups: degraded=%d, undersized=%d, incomplete=%d, stale=%d, inconsistent=%d (Total: %d, Active+Clean: %d).",
			pgs.Degraded, pgs.Undersized, pgs.Incomplete, pgs.Stale, pgs.Inconsistent, pgs.Total, pgs.ActiveClean)

		violations = append(violations, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: "CephCluster",
			ResourceName: report.ClusterFSID,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  desc,
			Remediation:  rule.Remediation,
		})
	}

	// 3. Storage Capacity Watermarks (ROOK-CEPH-013)
	for _, pool := range report.Pools {
		if pool.PercentUsed >= 80.0 || pool.NearFull || pool.Full {
			rule, _ := GetStorageRule(RuleCephCapacityNearFull)
			sev := rule.Severity
			score := rule.CVSSScore
			if pool.PercentUsed >= 90.0 || pool.Full {
				sev = intel.SeverityCritical
				score = 9.0
			}

			violations = append(violations, StorageViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				ResourceKind: "CephBlockPool",
				ResourceName: pool.Name,
				Severity:     sev,
				CVSSScore:    score,
				Description:  fmt.Sprintf("Pool '%s' capacity reached %.1f%% (%d of %d bytes). Exceeds nearfull safety watermark, risking cluster-wide read-only freeze at 90%%.", pool.Name, pool.PercentUsed, pool.UsedBytes, pool.TotalBytes),
				Remediation:  rule.Remediation,
			})
		}
	}

	// 4. BlueStore Checksum Corruptions & Hardware I/O Faults (ROOK-CEPH-014)
	// 5. BlueStore Kernel 6.12 Async Direct I/O Desync (ROOK-CEPH-010, CVE-2026-15509)
	for _, alert := range report.BlueStoreAlerts {
		// Hardware Checksum Mismatch
		if alert.ChecksumErrors > 0 {
			rule, _ := GetStorageRule(RuleCephBlueStoreCorruption)
			violations = append(violations, StorageViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				ResourceKind: "OSD",
				ResourceName: fmt.Sprintf("osd.%d", alert.OSDID),
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Description:  fmt.Sprintf("BlueStore engine on OSD.%d (%s) reported %d hardware checksum corruption errors: %s", alert.OSDID, alert.Device, alert.ChecksumErrors, alert.Message),
				Remediation:  rule.Remediation,
			})
		}

		// Linux 6.12 Async Direct I/O Desync (CVE-2026-15509)
		isKernel612 := strings.Contains(alert.KernelVersion, "6.12")
		if alert.AsyncFlushErrors > 0 || (isKernel612 && alert.SlowOpsCount > 5) {
			rule, _ := GetStorageRule(RuleRookBlueStoreAsyncDesync)
			cveScore := rule.CVSSScore
			mitigation := rule.Remediation

			if d.feed != nil {
				for _, item := range d.feed.Items {
					if item.ID == "CVE-2026-15509" {
						cveScore = item.CVSSScore
						mitigation = item.Mitigation
						break
					}
				}
			}

			violations = append(violations, StorageViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				ResourceKind: "OSD",
				ResourceName: fmt.Sprintf("osd.%d", alert.OSDID),
				Severity:     rule.Severity,
				CVSSScore:    cveScore,
				MatchedCVE:   "CVE-2026-15509",
				Description:  fmt.Sprintf("OSD.%d running on kernel %s detected %d async direct I/O flush errors on NVMe device %s: %s", alert.OSDID, alert.KernelVersion, alert.AsyncFlushErrors, alert.Device, alert.Message),
				Remediation:  mitigation,
			})
		}
	}

	return violations, nil
}
