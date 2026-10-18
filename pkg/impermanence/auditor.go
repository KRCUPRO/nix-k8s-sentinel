package impermanence

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Auditor evaluates NixOS impermanence host configurations, cluster mounts, and runtime telemetry.
type Auditor struct{}

// NewAuditor creates a new instance of Auditor.
func NewAuditor() *Auditor {
	return &Auditor{}
}

// AuditHost evaluates a parsed NixOS host configuration against canonical impermanence rules.
func (a *Auditor) AuditHost(host *ImpermanenceHostConfig) []ImpermanenceViolation {
	var violations []ImpermanenceViolation

	// IMP-ROOT-001: Mutable root filesystem check
	if host.Mode == ModeMutableDisk || host.RootFsType == "ext4" || host.RootFsType == "xfs" {
		if rule := GetRule("IMP-ROOT-001"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "/",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Host '%s' mounts root on persistent mutable storage (%s) without tmpfs or snapshot rollback.", host.HostName, host.RootFsType),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-002: Missing wipe hook on ZFS / Btrfs root
	if (host.RootFsType == "zfs" || host.RootFsType == "btrfs") && !host.WipeOnReboot {
		if rule := GetRule("IMP-ROOT-002"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "/",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Host '%s' uses %s root without boot.initrd.postDeviceCommands blank snapshot rollback hook.", host.HostName, host.RootFsType),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-003: Unencrypted swap partition
	if host.HasUnencryptedSwap {
		if rule := GetRule("IMP-ROOT-003"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "swapDevices",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Host '%s' enables unencrypted swap devices, risking transient secret memory leakage to disk (CVE-2026-61842).", host.HostName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-004: Critical Kubelet PKI unpersisted
	if (host.Mode == ModeTmpfsRoot || host.WipeOnReboot) && !host.KubeletPKIPersisted {
		if rule := GetRule("IMP-ROOT-004"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "/var/lib/kubelet",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Host '%s' has ephemeral root but omits /var/lib/kubelet from environment.persistence.", host.HostName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-005: Unencrypted persistence storage volume
	if host.PersistenceRoot != "" && !host.StorageEncrypted {
		if rule := GetRule("IMP-ROOT-005"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  host.PersistenceRoot,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Persistence root '%s' on host '%s' resides on unencrypted storage partition without LUKS2/dm-crypt.", host.PersistenceRoot, host.HostName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-006: Overly permissive permissions in persistence
	for _, entry := range host.PersistentEntries {
		if a.isPermissiveMode(entry) {
			if rule := GetRule("IMP-ROOT-006"); rule != nil {
				violations = append(violations, ImpermanenceViolation{
					RuleID:      rule.ID,
					HostName:    host.HostName,
					TargetPath:  entry.Path,
					Severity:    rule.Severity,
					CVSSScore:   rule.CVSSScore,
					Title:       rule.Title,
					Description: fmt.Sprintf("Persisted path '%s' on host '%s' specifies overly permissive mode '%s'.", entry.Path, host.HostName, entry.Mode),
					Remediation: rule.Remediation,
					MatchedCVE:  rule.MatchedCVE,
					FilePath:    entry.FilePath,
					StartLine:   entry.LineNumber,
				})
			}
		}
	}

	// IMP-ROOT-007: Containerd on tmpfs root
	if host.ContainerdOnTmpfs {
		if rule := GetRule("IMP-ROOT-007"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "/var/lib/containerd",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Container runtime storage root (/var/lib/containerd) on host '%s' resides on memory-backed tmpfs root.", host.HostName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-008: Missing machine-id persistence
	if (host.Mode == ModeTmpfsRoot || host.WipeOnReboot) && !host.MachineIDPersisted {
		if rule := GetRule("IMP-ROOT-008"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "/etc/machine-id",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Host '%s' has ephemeral root but does not persist /etc/machine-id, risking cluster node identity desynchronization.", host.HostName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	// IMP-ROOT-012: Missing kernel memory wiping parameters
	if !host.KernelMemoryWiping {
		if rule := GetRule("IMP-ROOT-012"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    host.HostName,
				TargetPath:  "boot.kernelParams",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Host '%s' kernel parameters omit transient memory scrubbing flags (init_on_free=1, page_poison=1).", host.HostName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				FilePath:    host.FilePath,
				StartLine:   host.StartLine,
			})
		}
	}

	return violations
}

// AuditClusterMountCollisions cross-checks Kubernetes cluster volume mounts against ephemeral root paths.
func (a *Auditor) AuditClusterMountCollisions(host *ImpermanenceHostConfig, mounts []ClusterMountReference) []ImpermanenceViolation {
	var violations []ImpermanenceViolation

	if host.Mode != ModeTmpfsRoot && !host.WipeOnReboot {
		return violations
	}

	for _, mount := range mounts {
		if mount.HostPath == "" {
			continue
		}
		cleanPath := filepath.ToSlash(filepath.Clean(mount.HostPath))

		// If mount points to ephemeral path outside /persist or /nix
		if !strings.HasPrefix(cleanPath, "/persist") &&
			!strings.HasPrefix(cleanPath, "/nix/persist") &&
			!strings.HasPrefix(cleanPath, "/proc") &&
			!strings.HasPrefix(cleanPath, "/sys") &&
			!strings.HasPrefix(cleanPath, "/dev") {

			// Check if cleanPath is explicitly persisted
			isPersisted := false
			for _, entry := range host.PersistentEntries {
				ep := filepath.ToSlash(filepath.Clean(entry.Path))
				if cleanPath == ep || strings.HasPrefix(cleanPath, ep+"/") {
					isPersisted = true
					break
				}
			}

			if !isPersisted {
				if rule := GetRule("IMP-ROOT-010"); rule != nil {
					violations = append(violations, ImpermanenceViolation{
						RuleID:      rule.ID,
						HostName:    host.HostName,
						TargetPath:  mount.HostPath,
						Severity:    rule.Severity,
						CVSSScore:   rule.CVSSScore,
						Title:       rule.Title,
						Description: fmt.Sprintf("%s '%s' specifies hostPath '%s' on ephemeral root outside persistence storage.", mount.ResourceKind, mount.ResourceName, mount.HostPath),
						Remediation: rule.Remediation,
						MatchedCVE:  rule.MatchedCVE,
						FilePath:    mount.FilePath,
						StartLine:   mount.LineNumber,
					})
				}
			}
		}
	}

	return violations
}

// AuditTelemetry evaluates live node ephemeral storage telemetry.
func (a *Auditor) AuditTelemetry(host *ImpermanenceHostConfig, telemetry *EphemeralStorageTelemetry) []ImpermanenceViolation {
	var violations []ImpermanenceViolation
	if telemetry == nil {
		return violations
	}

	// IMP-ROOT-011: Root tmpfs memory usage or dirty inode saturation
	if telemetry.RootUsagePercent >= CriticalTmpfsUsagePct || telemetry.OrphanedInodes > 1000 {
		if rule := GetRule("IMP-ROOT-011"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    telemetry.NodeName,
				TargetPath:  telemetry.RootMount,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Node '%s' ephemeral root usage is %.1f%% (exceeds %.1f%%) with %d orphaned inodes.", telemetry.NodeName, telemetry.RootUsagePercent, CriticalTmpfsUsagePct, telemetry.OrphanedInodes),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
			})
		}
	}

	// IMP-ROOT-003: Active unencrypted swap in telemetry
	if telemetry.SwapUsedBytes > 0 && !telemetry.SwapEncrypted {
		if rule := GetRule("IMP-ROOT-003"); rule != nil {
			violations = append(violations, ImpermanenceViolation{
				RuleID:      rule.ID,
				HostName:    telemetry.NodeName,
				TargetPath:  "swap",
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Node '%s' has %d bytes of active unencrypted swap in use.", telemetry.NodeName, telemetry.SwapUsedBytes),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
			})
		}
	}

	return violations
}

func (a *Auditor) isPermissiveMode(entry PersistentEntry) bool {
	if entry.Mode == "" {
		return false
	}
	clean := strings.TrimSpace(entry.Mode)
	isKeyOrSecret := strings.Contains(entry.Path, "key") ||
		strings.Contains(entry.Path, "secret") ||
		strings.Contains(entry.Path, "token") ||
		strings.Contains(entry.Path, "pki") ||
		strings.Contains(entry.Path, "shadow")

	if isKeyOrSecret {
		// Keys and secrets must be 0600 or 0400 for files, 0700 for dirs
		if entry.IsFile && clean != "0600" && clean != "0400" && clean != "0440" {
			return true
		}
		if !entry.IsFile && clean != "0700" && clean != "0750" {
			return true
		}
	}

	// General loose modes
	if clean == "0777" || clean == "0666" || clean == "0775" {
		return true
	}

	return false
}

// ComputeSummary aggregates findings and calculates the deterministic compliance score.
func ComputeSummary(hosts []ImpermanenceHostConfig, violations []ImpermanenceViolation) ImpermanenceSummary {
	summary := ImpermanenceSummary{
		TotalHostsScanned: len(hosts),
		HighRiskHostNames: make([]string, 0),
	}

	hostViolationMap := make(map[string]int)

	for _, h := range hosts {
		if h.Mode == ModeTmpfsRoot || h.Mode == ModeZfsRollback || h.Mode == ModeBtrfsSnapshot {
			summary.EphemeralRootCount++
		} else {
			summary.MutableRootCount++
		}
		if h.HasUnencryptedSwap {
			summary.UnencryptedSwapCount++
		}
		if !h.WipeOnReboot && (h.RootFsType == "zfs" || h.RootFsType == "btrfs") {
			summary.WipeHookMissingCount++
		}
		if (h.Mode == ModeTmpfsRoot || h.WipeOnReboot) && !h.KubeletPKIPersisted {
			summary.UnpersistedSecretCount++
		}
	}

	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
		case intel.SeverityHigh:
			summary.HighCount++
		case intel.SeverityMedium:
			summary.MediumCount++
		case intel.SeverityLow:
			summary.LowCount++
		}
		hostViolationMap[v.HostName]++
	}

	for host, count := range hostViolationMap {
		if count >= 2 {
			summary.HighRiskHostNames = append(summary.HighRiskHostNames, host)
		}
	}

	summary.CompliantHosts = summary.TotalHostsScanned - len(hostViolationMap)
	if summary.CompliantHosts < 0 {
		summary.CompliantHosts = 0
	}

	// Deterministic compliance score (0.0% to 100.0%)
	deduction := float64(summary.CriticalCount)*25.0 +
		float64(summary.HighCount)*12.0 +
		float64(summary.MediumCount)*5.0 +
		float64(summary.LowCount)*2.0

	score := 100.0 - deduction
	if score < 0.0 {
		score = 0.0
	}
	summary.ComplianceScore = math.Round(score*10.0) / 10.0

	return summary
}
