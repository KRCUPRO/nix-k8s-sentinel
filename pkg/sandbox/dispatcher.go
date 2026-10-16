package sandbox

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditMicroVMConfig audits declarative microVM specifications against canonical security rules.
func AuditMicroVMConfig(cfg MicroVMConfig, feed *intel.Feed) []SandboxViolation {
	var violations []SandboxViolation

	// 1. Jailer daemon and chroot isolation check (SANDBOX-DET-003)
	if !cfg.JailerEnabled {
		rule, _ := GetRuleByID("SANDBOX-DET-003")
		violations = append(violations, SandboxViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Target:      fmt.Sprintf("microvm/%s", cfg.VMID),
			Title:       rule.Title,
			Description: fmt.Sprintf("MicroVM '%s' is declared without Firecracker jailer daemon or chroot confinement.", cfg.VMID),
			Remediation: rule.Remediation,
			RawContext:  fmt.Sprintf("hypervisor: %s, jailer: false", cfg.Hypervisor),
			LineNumber:  cfg.LineNumber,
		})
	}

	// 2. Unrestricted egress network isolation check (SANDBOX-DET-002)
	if !cfg.EgressIsolated {
		rule, _ := GetRuleByID("SANDBOX-DET-002")
		v := SandboxViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Target:      fmt.Sprintf("microvm/%s/network", cfg.VMID),
			Title:       rule.Title,
			Description: fmt.Sprintf("MicroVM '%s' network interface has unrestricted egress enabled.", cfg.VMID),
			Remediation: rule.Remediation,
			RawContext:  fmt.Sprintf("networkInterface: %s, egressIsolated: false", cfg.NetworkInterface),
			LineNumber:  cfg.LineNumber,
		}
		if threat := CorrelateThreatWithRule(rule, feed); threat != nil {
			v.MatchedCVE = threat.ID
		}
		violations = append(violations, v)
	}

	// 3. Read-only root filesystem check (SANDBOX-DET-012)
	if !cfg.ReadOnlyRootFS {
		rule, _ := GetRuleByID("SANDBOX-DET-012")
		violations = append(violations, SandboxViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Target:      fmt.Sprintf("microvm/%s/rootfs", cfg.VMID),
			Title:       rule.Title,
			Description: fmt.Sprintf("MicroVM '%s' root filesystem is mounted read-write, risking guest binary tampering.", cfg.VMID),
			Remediation: rule.Remediation,
			RawContext:  fmt.Sprintf("rootfsPath: %s, readOnly: false", cfg.RootFSPath),
			LineNumber:  cfg.LineNumber,
		})
	}

	// 4. Hardware acceleration device verification (SANDBOX-DET-011)
	if cfg.KVMDevice == "" || cfg.KVMDevice == "none" {
		rule, _ := GetRuleByID("SANDBOX-DET-011")
		violations = append(violations, SandboxViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Target:      fmt.Sprintf("microvm/%s/kvm", cfg.VMID),
			Title:       rule.Title,
			Description: fmt.Sprintf("MicroVM '%s' declarative configuration is missing hardware virtualization (/dev/kvm).", cfg.VMID),
			Remediation: rule.Remediation,
			RawContext:  fmt.Sprintf("kvmDevice: '%s'", cfg.KVMDevice),
			LineNumber:  cfg.LineNumber,
		})
	}

	// 5. Missing payload digest metadata in detonation job (SANDBOX-DET-001)
	if digest, ok := cfg.Metadata["payloadDigest"]; !ok || digest == "" {
		if strings.HasPrefix(cfg.VMID, "k8s-sandbox") {
			rule, _ := GetRuleByID("SANDBOX-DET-001")
			violations = append(violations, SandboxViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Target:      fmt.Sprintf("detonation-job/%s", cfg.VMID),
				Title:       rule.Title,
				Description: fmt.Sprintf("Detonation job '%s' has no verified cryptographic payload digest scheduled for pre-flight testing.", cfg.VMID),
				Remediation: rule.Remediation,
				RawContext:  "payloadDigest: <missing>",
				LineNumber:  cfg.LineNumber,
			})
		}
	}

	return violations
}

// AuditDetonationTelemetry audits runtime detonation telemetry and intercepted honeypot events.
func AuditDetonationTelemetry(t DetonationTelemetry, feed *intel.Feed) []SandboxViolation {
	var violations []SandboxViolation

	// 1. Egress attempt detection in telemetry (SANDBOX-DET-002)
	if t.EgressAllowed || t.EgressAttempts > 0 {
		rule, _ := GetRuleByID("SANDBOX-DET-002")
		v := SandboxViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Target:      fmt.Sprintf("detonation/%s/egress", t.DetonationID),
			Title:       rule.Title,
			Description: fmt.Sprintf("Detonation '%s' triggered %d unauthorized egress network attempts during payload execution.", t.DetonationID, t.EgressAttempts),
			Remediation: rule.Remediation,
			RawContext:  fmt.Sprintf("egressAttempts: %d, egressAllowed: %v", t.EgressAttempts, t.EgressAllowed),
		}
		if threat := CorrelateThreatWithRule(rule, feed); threat != nil {
			v.MatchedCVE = threat.ID
		}
		violations = append(violations, v)
	}

	// 2. Honeypot lure hits analysis
	for _, hit := range t.HoneypotHits {
		proto := strings.ToUpper(hit.Protocol)
		lure := strings.ToLower(hit.ServiceLure)

		if hit.DestinationPort == 10250 || proto == "KUBELET_API" || strings.Contains(lure, "kubelet") {
			rule, _ := GetRuleByID("SANDBOX-DET-004")
			violations = append(violations, SandboxViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Target:      fmt.Sprintf("honeypot/%s", hit.InteractionID),
				Title:       rule.Title,
				Description: fmt.Sprintf("Detonation payload probed honeypot Kubelet decoy (port %d) from source %s.", hit.DestinationPort, hit.SourceIP),
				Remediation: rule.Remediation,
				RawContext:  fmt.Sprintf("protocol: %s, lure: %s, sample: %s", hit.Protocol, hit.ServiceLure, hit.PayloadSample),
			})
		}

		if hit.DestinationPort == 2379 || hit.DestinationPort == 2380 || proto == "ETCD_PEER" || strings.Contains(lure, "etcd") {
			rule, _ := GetRuleByID("SANDBOX-DET-005")
			violations = append(violations, SandboxViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Target:      fmt.Sprintf("honeypot/%s", hit.InteractionID),
				Title:       rule.Title,
				Description: fmt.Sprintf("Detonation payload probed honeypot etcd peering decoy (port %d) from source %s.", hit.DestinationPort, hit.SourceIP),
				Remediation: rule.Remediation,
				RawContext:  fmt.Sprintf("protocol: %s, lure: %s, sample: %s", hit.Protocol, hit.ServiceLure, hit.PayloadSample),
			})
		}

		if strings.Contains(lure, "credential") || strings.Contains(lure, "token") || strings.Contains(lure, "secret") {
			rule, _ := GetRuleByID("SANDBOX-DET-010")
			violations = append(violations, SandboxViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Target:      fmt.Sprintf("honeypot/%s", hit.InteractionID),
				Title:       rule.Title,
				Description: fmt.Sprintf("Detonation payload accessed honeypot credential decoy '%s'.", hit.ServiceLure),
				Remediation: rule.Remediation,
				RawContext:  fmt.Sprintf("sample: %s", hit.PayloadSample),
			})
		}
	}

	// 3. Syscall anomaly analysis
	for _, anomaly := range t.SyscallAnomalies {
		sc := strings.ToLower(anomaly.SyscallName)

		// Reverse shell / socket beaconing (SANDBOX-DET-006)
		if strings.Contains(sc, "connect") || strings.Contains(sc, "socket") || strings.Contains(sc, "execve") {
			if strings.Contains(anomaly.Arguments, "sh") || strings.Contains(anomaly.Arguments, "bash") || strings.Contains(anomaly.Arguments, "nc") {
				rule, _ := GetRuleByID("SANDBOX-DET-006")
				violations = append(violations, SandboxViolation{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					CVSSScore:   rule.CVSSScore,
					Target:      fmt.Sprintf("detonation/%s/syscall/%s", t.DetonationID, sc),
					Title:       rule.Title,
					Description: fmt.Sprintf("Payload spawned reverse shell socket inside microVM: syscall %s (%s).", sc, anomaly.Arguments),
					Remediation: rule.Remediation,
					RawContext:  fmt.Sprintf("syscall: %s, args: %s, count: %d", sc, anomaly.Arguments, anomaly.Count),
				})
			}
		}

		// Privilege escalation sequences (SANDBOX-DET-007)
		if sc == "setuid" || sc == "setgid" || sc == "ptrace" || sc == "bpf" || sc == "process_vm_writev" {
			rule, _ := GetRuleByID("SANDBOX-DET-007")
			violations = append(violations, SandboxViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Target:      fmt.Sprintf("detonation/%s/privilege/%s", t.DetonationID, sc),
				Title:       rule.Title,
				Description: fmt.Sprintf("Privilege escalation syscall invocation detected in microVM: %s.", sc),
				Remediation: rule.Remediation,
				RawContext:  fmt.Sprintf("syscall: %s, args: %s, reason: %s", sc, anomaly.Arguments, anomaly.Reason),
			})
		}

		// Virtio MMIO / hypervisor escape anomaly (SANDBOX-DET-008)
		if strings.Contains(sc, "mmio") || strings.Contains(sc, "virtio") || strings.Contains(anomaly.Reason, "escape") {
			rule, _ := GetRuleByID("SANDBOX-DET-008")
			violations = append(violations, SandboxViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Target:      fmt.Sprintf("detonation/%s/hypervisor", t.DetonationID),
				Title:       rule.Title,
				Description: fmt.Sprintf("Hypervisor device escape anomaly detected on virtio MMIO interface: %s.", anomaly.Reason),
				Remediation: rule.Remediation,
				RawContext:  fmt.Sprintf("syscall: %s, args: %s", sc, anomaly.Arguments),
			})
		}
	}

	// 4. Detonation timeout / anti-analysis stalling (SANDBOX-DET-009)
	if t.Status == StatusTimedOut || t.DurationMs >= DefaultDetonationTimeoutMs {
		rule, _ := GetRuleByID("SANDBOX-DET-009")
		violations = append(violations, SandboxViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Target:      fmt.Sprintf("detonation/%s/duration", t.DetonationID),
			Title:       rule.Title,
			Description: fmt.Sprintf("Detonation payload exceeded execution SLA (%d ms >= %d ms limit), indicating anti-analysis evasion.", t.DurationMs, DefaultDetonationTimeoutMs),
			Remediation: rule.Remediation,
			RawContext:  fmt.Sprintf("durationMs: %d, status: %s", t.DurationMs, t.Status),
		})
	}

	return violations
}

// ComputeSandboxScore computes the overall sandbox security compliance score (0.0 - 100.0) and status.
func ComputeSandboxScore(totalVMs int, totalDetonations int, violations []SandboxViolation, quarantined int) (float64, string) {
	if totalVMs == 0 && totalDetonations == 0 {
		return 100.0, "PASSED"
	}

	score := 100.0
	for _, v := range violations {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			score -= 15.0
		case "HIGH":
			score -= 8.0
		case "MEDIUM":
			score -= 3.0
		case "LOW":
			score -= 1.0
		}
	}

	if score < 0.0 {
		score = 0.0
	}
	score = math.Round(score*10.0) / 10.0

	status := "PASSED"
	if score < 60.0 || quarantined > 0 {
		status = "CRITICAL_RISK"
	} else if score < 85.0 || len(violations) > 0 {
		status = "WARNING"
	}

	return score, status
}
