package lsm

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// CanonicalLSMRules returns the authoritative catalog of 12 eBPF LSM and Kernel MAC security rules.
func CanonicalLSMRules() []LSMRule {
	return []LSMRule{
		{
			ID:          "LSM-MAC-001",
			Name:        "eBPF Linux Security Module (LSM) Disabled in Kernel Parameters",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.8,
			MatchedCVE:  "CVE-2026-99103",
			Description: "The NixOS kernel boot parameters omit 'bpf' from the 'lsm=' list, leaving eBPF LSM security hooks inactive and exposing container hosts to unconfined kernel syscall escapes.",
			Remediation: "Add 'bpf' to boot.kernelParams (e.g. boot.kernelParams = [ \"lsm=lockdown,yama,bpf,apparmor\" ];) and declare security.lsm = [ \"lockdown\" \"yama\" \"bpf\" \"apparmor\" ];.",
		},
		{
			ID:          "LSM-MAC-002",
			Name:        "Missing bprm_check_security Execution Guard on Writable Directories",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.6,
			MatchedCVE:  "CVE-2026-99103",
			Description: "The container host lacks an attached eBPF LSM 'bprm_check_security' hook, permitting untrusted workloads to execute arbitrary scripts and ELF binaries directly from world-writable paths (/tmp, /dev/shm).",
			Remediation: "Synthesize and attach an eBPF LSM bprm_check_security hook returning -EPERM for executable binaries located in /tmp or /dev/shm within container cgroups.",
		},
		{
			ID:          "LSM-MAC-003",
			Name:        "Missing file_open Mandatory Access Control on Sensitive Host Structures",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.4,
			MatchedCVE:  "CVE-2026-99103",
			Description: "No eBPF LSM 'file_open' or 'file_permission' hook protects host sensitive kernel paths (/proc/kcore, /sys/kernel/debug, /etc/shadow) from container mount or read access.",
			Remediation: "Attach an eBPF LSM file_open hook rejecting container cgroup access to /proc/kcore, /proc/sysrq-trigger, /sys/kernel/debug, and /etc/shadow.",
		},
		{
			ID:          "LSM-MAC-004",
			Name:        "Permissive socket_create Hook Permitting Raw Sockets in Containers",
			Severity:    intel.SeverityHigh,
			CVSSScore:   7.9,
			MatchedCVE:  "CVE-2026-20914",
			Description: "Container workloads lack an eBPF LSM 'socket_create' filter, allowing unprivileged processes with CAP_NET_RAW or packet sockets (AF_PACKET) to craft spoofed link-layer frames.",
			Remediation: "Enforce an eBPF LSM socket_create hook rejecting AF_PACKET and SOCK_RAW socket families within non-root container namespaces.",
		},
		{
			ID:          "LSM-MAC-005",
			Name:        "Missing task_fix_setuid Guard Against Container Privilege Escalation",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.2,
			MatchedCVE:  "CVE-2026-99103",
			Description: "The host does not enforce an eBPF LSM 'task_fix_setuid' or 'cred_prepare' hook to intercept unauthorized setuid transitions inside container user namespaces.",
			Remediation: "Attach an eBPF LSM task_fix_setuid program blocking setuid transition to UID 0 unless explicitly permitted by workload MAC profile.",
		},
		{
			ID:          "LSM-MAC-006",
			Name:        "Unrestricted security_bpf Hook Allowing Container BPF Program Loading",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.4,
			MatchedCVE:  "CVE-2026-90412",
			Description: "Containers without an eBPF LSM 'bpf' hook can invoke sys_bpf() to load arbitrary BPF programs, probe host kernel pointers, or trigger verifier bugs.",
			Remediation: "Attach an eBPF LSM security_bpf hook returning -EPERM for BPF_PROG_LOAD and BPF_MAP_CREATE originating from container cgroups.",
		},
		{
			ID:          "LSM-MAC-007",
			Name:        "Missing ptrace_access_check Hook Permitting Cross-Process Tracing",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.5,
			MatchedCVE:  "CVE-2026-99103",
			Description: "The container runtime does not attach an eBPF LSM 'ptrace_access_check' hook, risking inter-container process inspection or shellcode injection.",
			Remediation: "Configure eBPF LSM ptrace_access_check hook denying PTRACE_MODE_ATTACH across distinct container cgroup boundaries.",
		},
		{
			ID:          "LSM-MAC-008",
			Name:        "Privileged Container Workload Operating Without LSM Cgroup Confinement",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.6,
			MatchedCVE:  "CVE-2026-99103",
			Description: "A container manifest requests 'securityContext.privileged: true' without declaring a corresponding eBPF LSM mandatory access control profile or cgroup restriction.",
			Remediation: "Revoke privileged mode or attach a strict eBPF LSM MAC profile restricting dangerous kernel hooks (bpf, capable, file_open).",
		},
		{
			ID:          "LSM-MAC-009",
			Name:        "Host Namespace Sharing Enabled Without Kernel MAC Hook Override",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.8,
			MatchedCVE:  "CVE-2026-90412",
			Description: "A container workload declares 'hostPID: true' or 'hostIPC: true' without an eBPF LSM policy restricting access to host kernel tasks.",
			Remediation: "Disable hostPID/hostIPC sharing or enforce mandatory access control restricting ptrace and signal delivery to host processes.",
		},
		{
			ID:          "LSM-MAC-010",
			Name:        "Elevated Administrative Capabilities Granted Without eBPF LSM Syscall Filter",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.1,
			MatchedCVE:  "CVE-2026-99103",
			Description: "A container adds CAP_SYS_ADMIN, CAP_BPF, or CAP_SYS_PTRACE without an active eBPF LSM capable hook bounding kernel capability invocations.",
			Remediation: "Drop broad capabilities from securityContext.capabilities.add or bind an eBPF LSM capable hook restricting specific cap operations.",
		},
		{
			ID:          "LSM-MAC-011",
			Name:        "Runtime eBPF LSM Telemetry Recorded Blocked Execution in Writable Directory",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.7,
			MatchedCVE:  "CVE-2026-99103",
			Description: "Runtime kernel telemetry recorded an unauthorized binary execution attempt intercepted and denied by the eBPF LSM 'bprm_check_security' hook.",
			Remediation: "Investigate container process tree, isolate anomalous pod, and verify immutable read-only rootfs enforcement.",
		},
		{
			ID:          "LSM-MAC-012",
			Name:        "Runtime eBPF LSM Telemetry Recorded Blocked Kernel Privilege Escalation or Raw Socket",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.5,
			MatchedCVE:  "CVE-2026-99103",
			Description: "Runtime kernel telemetry recorded an unconfined container syscall (raw socket, setuid transition, or BPF program load) intercepted and denied by kernel MAC policy.",
			Remediation: "Quarantine workload namespace, verify admission controller enforcement, and rotate container service account tokens.",
		},
	}
}

// LookupLSMRule retrieves a canonical LSM rule definition by its unique identifier.
func LookupLSMRule(ruleID string) (LSMRule, bool) {
	for _, r := range CanonicalLSMRules() {
		if r.ID == ruleID {
			return r, true
		}
	}
	return LSMRule{}, false
}
