package lsm

import (
	"fmt"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditNixOSLSM evaluates declarative host configurations against canonical LSM rules.
func AuditNixOSLSM(cfg *NixOSLSMConfig, file string, feed *intel.Feed) []LSMViolation {
	var violations []LSMViolation
	if cfg == nil {
		return violations
	}

	src := file
	if src == "" {
		src = cfg.SourceFile
	}
	if src == "" {
		src = "configuration.nix"
	}

	// Rule LSM-MAC-001: bpf in LSM parameters
	if !cfg.BPFLSMEnabled {
		rule, _ := LookupLSMRule("LSM-MAC-001")
		cve := rule.MatchedCVE
		cvss := rule.CVSSScore
		if feed != nil {
			for _, item := range feed.Items {
				if item.ID == cve {
					cvss = item.CVSSScore
					break
				}
			}
		}
		violations = append(violations, LSMViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Resource:    "kernel.boot.params",
			File:        src,
			Line:        1,
			Message:     fmt.Sprintf("eBPF LSM is not declared in boot.kernelParams or security.lsm. Active LSM order: %v", cfg.LSMOrder),
			Remediation: rule.Remediation,
			MatchedCVE:  cve,
			CVSSScore:   cvss,
		})
	}

	// Rule LSM-MAC-006: Unprivileged BPF disablement
	if !cfg.UnprivilegedBPFDisabled {
		rule, _ := LookupLSMRule("LSM-MAC-006")
		violations = append(violations, LSMViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Resource:    "sysctl.kernel.unprivileged_bpf_disabled",
			File:        src,
			Line:        1,
			Message:     "kernel.unprivileged_bpf_disabled is not set to 1, permitting unprivileged user namespaces to invoke sys_bpf()",
			Remediation: rule.Remediation,
			MatchedCVE:  rule.MatchedCVE,
			CVSSScore:   rule.CVSSScore,
		})
	}

	// Rule LSM-MAC-002: Missing bprm_check_security hook service
	hasBprmHook := false
	for _, u := range cfg.SystemdUnits {
		if strings.Contains(strings.ToLower(u), "bprm") || strings.Contains(strings.ToLower(u), "lsm-mac") {
			hasBprmHook = true
			break
		}
	}
	if !hasBprmHook && !cfg.BPFLSMEnabled {
		rule, _ := LookupLSMRule("LSM-MAC-002")
		violations = append(violations, LSMViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Resource:    "lsm.hooks.bprm_check_security",
			File:        src,
			Line:        1,
			Message:     "No systemd eBPF LSM service declared to attach bprm_check_security hook against writable directories",
			Remediation: rule.Remediation,
			MatchedCVE:  rule.MatchedCVE,
			CVSSScore:   rule.CVSSScore,
		})
	}

	// Rule LSM-MAC-003: Missing file_open mandatory access control
	hasFileHook := false
	for _, u := range cfg.SystemdUnits {
		if strings.Contains(strings.ToLower(u), "file-open") || strings.Contains(strings.ToLower(u), "lsm-mac") {
			hasFileHook = true
			break
		}
	}
	if !hasFileHook && !cfg.BPFLSMEnabled {
		rule, _ := LookupLSMRule("LSM-MAC-003")
		violations = append(violations, LSMViolation{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Resource:    "lsm.hooks.file_open",
			File:        src,
			Line:        1,
			Message:     "No eBPF LSM mandatory access control program declared to protect /proc/kcore and sensitive host files",
			Remediation: rule.Remediation,
			MatchedCVE:  rule.MatchedCVE,
			CVSSScore:   rule.CVSSScore,
		})
	}

	return violations
}

// AuditMACProfiles evaluates Kubernetes workload security contexts and ContainerMACProfiles.
func AuditMACProfiles(profiles []ContainerMACProfile, file string, feed *intel.Feed) []LSMViolation {
	var violations []LSMViolation

	for _, p := range profiles {
		src := file
		if src == "" {
			src = p.SourceFile
		}
		if src == "" {
			src = "k8s-workload.yaml"
		}
		line := p.LineNumber
		if line <= 0 {
			line = 1
		}
		resName := fmt.Sprintf("%s/%s", p.Namespace, p.WorkloadName)

		// Rule LSM-MAC-008: Privileged container without LSM MAC confinement
		if p.Privileged && !p.MACEnforced {
			rule, _ := LookupLSMRule("LSM-MAC-008")
			violations = append(violations, LSMViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Resource:    resName,
				File:        src,
				Line:        line,
				Message:     fmt.Sprintf("Privileged container '%s' declared without mandatory eBPF LSM MAC confinement profile", resName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}

		// Rule LSM-MAC-009: Host namespace sharing
		if (p.HostPID || p.HostIPC) && !p.MACEnforced {
			rule, _ := LookupLSMRule("LSM-MAC-009")
			violations = append(violations, LSMViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Resource:    resName,
				File:        src,
				Line:        line,
				Message:     fmt.Sprintf("Workload '%s' enables hostPID/hostIPC without eBPF LSM mandatory access control overrides", resName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}

		// Rule LSM-MAC-010: Elevated capabilities without eBPF LSM filter
		for _, capName := range p.Capabilities {
			norm := strings.ToUpper(capName)
			if norm == "SYS_ADMIN" || norm == "CAP_SYS_ADMIN" || norm == "BPF" || norm == "CAP_BPF" || norm == "SYS_PTRACE" || norm == "CAP_SYS_PTRACE" {
				if !p.MACEnforced {
					rule, _ := LookupLSMRule("LSM-MAC-010")
					violations = append(violations, LSMViolation{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Resource:    resName,
						File:        src,
						Line:        line,
						Message:     fmt.Sprintf("Workload '%s' grants elevated capability %s without granular eBPF LSM syscall filter", resName, capName),
						Remediation: rule.Remediation,
						MatchedCVE:  rule.MatchedCVE,
						CVSSScore:   rule.CVSSScore,
					})
					break
				}
			}
		}

		// Rule LSM-MAC-004: Raw socket capability without socket_create hook
		for _, capName := range p.Capabilities {
			norm := strings.ToUpper(capName)
			if norm == "NET_RAW" || norm == "CAP_NET_RAW" {
				hasSockHook := false
				for _, h := range p.BlockedHooks {
					if h == HookSocketCreate {
						hasSockHook = true
						break
					}
				}
				if !hasSockHook && !p.MACEnforced {
					rule, _ := LookupLSMRule("LSM-MAC-004")
					violations = append(violations, LSMViolation{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Resource:    resName,
						File:        src,
						Line:        line,
						Message:     fmt.Sprintf("Workload '%s' grants %s without eBPF LSM socket_create hook filtering raw sockets", resName, capName),
						Remediation: rule.Remediation,
						MatchedCVE:  rule.MatchedCVE,
						CVSSScore:   rule.CVSSScore,
					})
					break
				}
			}
		}

		// Rule LSM-MAC-005: Unconfined workload lacking task_fix_setuid hook
		if !p.MACEnforced && len(p.BlockedHooks) == 0 {
			rule, _ := LookupLSMRule("LSM-MAC-005")
			violations = append(violations, LSMViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Resource:    resName,
				File:        src,
				Line:        line,
				Message:     fmt.Sprintf("Workload '%s' lacks eBPF LSM task_fix_setuid hook guarding against container privilege escalation", resName),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}
	}

	return violations
}

// AuditTelemetry reconciles runtime eBPF LSM denial telemetry against security rules.
func AuditTelemetry(events []LSMTelemetryEvent, file string, feed *intel.Feed) []LSMViolation {
	var violations []LSMViolation

	src := file
	if src == "" {
		src = "lsm-telemetry.json"
	}

	for idx, e := range events {
		res := fmt.Sprintf("%s/%s", e.Node, e.ContainerID)
		if e.Comm != "" {
			res = fmt.Sprintf("%s (%s)", res, e.Comm)
		}

		// Rule LSM-MAC-011: Blocked binary execution in writable directory
		if e.Hook == HookBprmCheckSecurity && e.Blocked {
			rule, _ := LookupLSMRule("LSM-MAC-011")
			violations = append(violations, LSMViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Resource:    res,
				File:        src,
				Line:        idx + 1,
				Message:     fmt.Sprintf("eBPF LSM bprm_check_security blocked unauthorized binary execution in '%s' (comm: %s, syscall: %s)", e.TargetPath, e.Comm, e.Syscall),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}

		// Rule LSM-MAC-012: Blocked privilege escalation, raw socket, or BPF program load
		if (e.Hook == HookTaskFixSetuid || e.Hook == HookSocketCreate || e.Hook == HookSecurityBPF) && e.Blocked {
			rule, _ := LookupLSMRule("LSM-MAC-012")
			violations = append(violations, LSMViolation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Resource:    res,
				File:        src,
				Line:        idx + 1,
				Message:     fmt.Sprintf("Kernel MAC policy blocked unconfined operation on hook '%s' (syscall: %s, target: %s)", e.Hook, e.Syscall, e.TargetPath),
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}
	}

	return violations
}
