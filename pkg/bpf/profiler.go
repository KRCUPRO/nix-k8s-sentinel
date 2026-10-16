package bpf

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditRuntimeTelemetry parses and evaluates kernel runtime telemetry for syscall and socket anomalies.
func AuditRuntimeTelemetry(filePath string, feed *intel.Feed) ([]BPFViolation, int, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat telemetry file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, 0, fmt.Errorf("telemetry file %s exceeds %d byte limit (%d bytes)", cleanPath, MaxTelemetryBytes, info.Size())
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read telemetry file %s: %w", cleanPath, err)
	}

	var telem BPFRuntimeTelemetry
	if err := json.Unmarshal(data, &telem); err != nil {
		return nil, 0, fmt.Errorf("failed to deserialize BPF runtime telemetry: %w", err)
	}

	var violations []BPFViolation
	totalEvents := len(telem.SocketEvents) + len(telem.SyscallEvents)

	// 1. Audit active LSM hooks
	hasSocketCreateHook := false
	for _, hook := range telem.ActiveLSMHooks {
		if strings.Contains(strings.ToLower(hook), "socket_create") || strings.Contains(strings.ToLower(hook), "bpf") {
			hasSocketCreateHook = true
			break
		}
	}
	if len(telem.ActiveLSMHooks) == 0 || !hasSocketCreateHook {
		r, _ := LookupBPFRule("BPF-SEC-005")
		violations = append(violations, BPFViolation{
			RuleID:      r.RuleID,
			Title:       r.Title,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			ResourceURI: cleanPath,
			StartLine:   1,
			Description: fmt.Sprintf("Node %s is missing active eBPF LSM socket_create or bpf hooks", telem.NodeName),
			Remediation: r.Remediation,
		})
	}

	// 2. Audit Socket Telemetry
	for _, sock := range telem.SocketEvents {
		isRaw := strings.EqualFold(sock.Type, "SOCK_RAW") || strings.EqualFold(sock.Domain, "AF_PACKET")
		isBurst := sock.CreationRate > MaxSocketRateThreshold || sock.AnomalyFlag

		if isRaw {
			r, _ := LookupBPFRule("BPF-SEC-003")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    1,
				WorkloadName: sock.ProcessName,
				Namespace:    sock.Namespace,
				Description:  fmt.Sprintf("Process %s (PID %d) opened %s/%s socket without verified LSM drop filter", sock.ProcessName, sock.PID, sock.Domain, sock.Type),
				Remediation:  r.Remediation,
			})
		}

		if isBurst {
			r, _ := LookupBPFRule("BPF-SEC-004")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    1,
				WorkloadName: sock.ProcessName,
				Namespace:    sock.Namespace,
				Description:  fmt.Sprintf("Process %s (PID %d) exhibits abnormal socket creation rate: %.1f sockets/sec (threshold: %.1f)", sock.ProcessName, sock.PID, sock.CreationRate, MaxSocketRateThreshold),
				Remediation:  r.Remediation,
			})
		}

		// Check CVE-2026-90412 correlation (raw socket creation storm in unconfined environment)
		if isRaw && isBurst {
			r, _ := LookupBPFRule("BPF-SEC-007")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    1,
				WorkloadName: sock.ProcessName,
				Namespace:    sock.Namespace,
				Description:  fmt.Sprintf("Correlated attack signature with CVE-2026-90412: Process %s burst socket allocation (%.1f/s) in raw socket domain", sock.ProcessName, sock.CreationRate),
				Remediation:  r.Remediation,
				MatchedCVE:   r.MatchedCVE,
			})
		}
	}

	// 3. Audit Syscall Telemetry
	for _, sys := range telem.SyscallEvents {
		lowerName := strings.ToLower(sys.SyscallName)

		if sys.BlockedByLSM {
			r, _ := LookupBPFRule("BPF-SEC-012")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    1,
				WorkloadName: sys.ProcessName,
				Namespace:    sys.Namespace,
				Description:  fmt.Sprintf("Kernel LSM blocked unauthorized syscall '%s' from process %s (PID %d)", sys.SyscallName, sys.ProcessName, sys.PID),
				Remediation:  r.Remediation,
			})
		}

		switch lowerName {
		case "ptrace", "process_vm_writev", "kexec_load", "reboot", "pivot_root":
			r, _ := LookupBPFRule("BPF-SEC-002")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    1,
				WorkloadName: sys.ProcessName,
				Namespace:    sys.Namespace,
				Description:  fmt.Sprintf("Process %s (PID %d) invoked high-privilege syscall '%s' (%d calls)", sys.ProcessName, sys.PID, sys.SyscallName, sys.CallCount),
				Remediation:  r.Remediation,
			})
		case "init_module", "finit_module", "delete_module":
			r, _ := LookupBPFRule("BPF-SEC-010")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    1,
				WorkloadName: sys.ProcessName,
				Namespace:    sys.Namespace,
				Description:  fmt.Sprintf("Process %s (PID %d) attempted kernel module modification via '%s'", sys.ProcessName, sys.PID, sys.SyscallName),
				Remediation:  r.Remediation,
			})
		case "bpf":
			if sys.IsPrivileged {
				r, _ := LookupBPFRule("BPF-SEC-008")
				violations = append(violations, BPFViolation{
					RuleID:       r.RuleID,
					Title:        r.Title,
					Severity:     r.Severity,
					CVSSScore:    r.CVSSScore,
					ResourceURI:  cleanPath,
					StartLine:    1,
					WorkloadName: sys.ProcessName,
					Namespace:    sys.Namespace,
					Description:  fmt.Sprintf("Process %s invoked bpf() syscall (%d calls); monitor for verifier race or JIT exploitation", sys.ProcessName, sys.CallCount),
					Remediation:  r.Remediation,
				})
			}
		}
	}

	return violations, totalEvents, nil
}

// ComputeBPFSummary calculates aggregate compliance scores and severity distributions.
func ComputeBPFSummary(scannedProfiles int, telemetryEvents int, violations []BPFViolation) BPFSummary {
	var crit, high, med, low int
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	score := 100.0 - float64(crit*20+high*10+med*5+low*2)
	if score < 0.0 {
		score = 0.0
	}
	score = math.Round(score*10.0) / 10.0

	status := "PASS"
	if score < 70.0 || crit > 0 {
		status = "FAIL"
	} else if score < 90.0 || high > 0 {
		status = "WARN"
	}

	return BPFSummary{
		TotalProfilesScanned: scannedProfiles,
		TotalTelemetryEvents: telemetryEvents,
		ViolationsCount:      len(violations),
		CriticalCount:        crit,
		HighCount:            high,
		MediumCount:          med,
		LowCount:             low,
		ComplianceScore:      score,
		AuditStatus:          status,
	}
}
