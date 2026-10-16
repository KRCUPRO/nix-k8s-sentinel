package bpf

import (
	"fmt"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// CanonicalBPFRules contains the authoritative 12 security rules for kernel runtime threat profiling and syscall filtering.
var CanonicalBPFRules = []BPFRule{
	{
		RuleID:      "BPF-SEC-001",
		Title:       "Unconfined Seccomp Profile in Workload Manifest",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Description: "Workload container explicitly configures 'seccompProfile.type: Unconfined' or omits baseline seccomp profiles, exposing all 450+ host syscalls.",
		Remediation: "Set 'securityContext.seccompProfile.type: RuntimeDefault' or provide a hardened 'Localhost' custom profile rejecting unnecessary kernel interfaces.",
	},
	{
		RuleID:      "BPF-SEC-002",
		Title:       "Unrestricted High-Privilege Syscall Permitted in Profile",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.3,
		Description: "Seccomp profile allows hazardous administrative syscalls ('ptrace', 'process_vm_writev', 'kexec_load', 'reboot', 'pivot_root') risking host takeover.",
		Remediation: "Explicitly remove or blacklist high-privilege syscalls from the seccomp allowlist and mandate SCMP_ACT_ERRNO default action.",
	},
	{
		RuleID:      "BPF-SEC-003",
		Title:       "Raw or Packet Socket Creation Permitted Without LSM Filter",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Description: "Container possesses CAP_NET_RAW or opens SOCK_RAW / AF_PACKET sockets without eBPF LSM mediation, enabling network spoofing and ARP poisoning.",
		Remediation: "Drop CAP_NET_RAW from securityContext capabilities and enforce eBPF LSM socket_create hook to block unprivileged raw socket creation.",
	},
	{
		RuleID:      "BPF-SEC-004",
		Title:       "Abnormal Socket Creation Rate Burst Detected in Runtime Telemetry",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.1,
		Description: "Process socket creation frequency exceeds the safe operational threshold (> 250 sockets/sec), indicating potential port scanning, C2 beaconing, or DoS flood.",
		Remediation: "Throttle network socket allocation, isolate the offending container cgroup, and apply an emergency eBPF socket rate-limiting filter.",
	},
	{
		RuleID:      "BPF-SEC-005",
		Title:       "Missing eBPF LSM Mandatory Access Control in NixOS Host Configuration",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Description: "NixOS host configuration does not include 'bpf' in 'security.lsm', preventing the kernel from attaching eBPF security hooks to kernel objects.",
		Remediation: "Add '\"bpf\"' to 'security.lsm = [ \"lockdown\" \"yama\" \"bpf\" \"apparmor\" ];' in your NixOS configuration.",
	},
	{
		RuleID:      "BPF-SEC-006",
		Title:       "Host Namespace Sharing Bypassing Container Boundary",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.6,
		Description: "Pod specification configures 'hostPID: true' or 'hostIPC: true', allowing containerized processes to inspect and signal host processes.",
		Remediation: "Remove hostPID and hostIPC settings from workload definitions to enforce Linux kernel PID and IPC namespace isolation.",
	},
	{
		RuleID:      "BPF-SEC-007",
		Title:       "Kernel BPF Subsystem Syscall Race & Unconfined Socket Flood Attack",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.8,
		Description: "Runtime telemetry and manifest analysis correlate with CVE-2026-90412, where unconfined containers leverage eBPF verifier races during socket flood storms.",
		Remediation: "Set 'boot.kernel.sysctl.\"kernel.unprivileged_bpf_disabled\" = 1;', attach LSM socket_create filters, and upgrade host Linux kernel to 6.12.18-hardened.",
		MatchedCVE:  "CVE-2026-90412",
	},
	{
		RuleID:      "BPF-SEC-008",
		Title:       "Unrestricted Unprivileged BPF Subsystem Access in Host Parameters",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Description: "Host kernel allows unprivileged users to invoke the bpf() syscall (kernel.unprivileged_bpf_disabled != 1), exposing JIT spray and Spectre vulnerabilities.",
		Remediation: "Enforce 'boot.kernel.sysctl.\"kernel.unprivileged_bpf_disabled\" = 1;' (or 2) in declarative NixOS host configuration.",
	},
	{
		RuleID:      "BPF-SEC-009",
		Title:       "Insecure Default Action in Seccomp Filter Profile",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Description: "Seccomp profile specifies SCMP_ACT_ALLOW as its default action, inverting the principle of least privilege and allowing unlisted future syscalls.",
		Remediation: "Change defaultAction to SCMP_ACT_ERRNO or SCMP_ACT_KILL_PROCESS, and explicitly enumerate only required syscalls in the allowlist.",
	},
	{
		RuleID:      "BPF-SEC-010",
		Title:       "Dangerous Kernel Module Loading Syscalls Enabled in Profile",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.7,
		Description: "Workload seccomp profile permits 'init_module', 'finit_module', or 'delete_module' syscalls, enabling unauthorized kernel rootkit injection.",
		Remediation: "Drop CAP_SYS_MODULE, filter out kernel module syscalls in seccomp, and set 'security.protectKernelModules = true;' in NixOS.",
	},
	{
		RuleID:      "BPF-SEC-011",
		Title:       "NixOS Systemd Unit Missing SystemCallFilter or Native Architecture",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.4,
		Description: "NixOS host service systemd unit definition omits 'SystemCallFilter' sandboxing or lacks 'SystemCallArchitectures = \"native\"' protection.",
		Remediation: "Configure 'systemd.services.<name>.serviceConfig.SystemCallFilter = [ \"@system-service\" \"~@privileged\" ];' and restrict architectures to native.",
	},
	{
		RuleID:      "BPF-SEC-012",
		Title:       "Runtime Container Boundary Escape Attempt or Blocked LSM Security Denial",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.6,
		Description: "Telemetry reveals repeated blocked LSM denials or abnormal container escape syscall sequences (e.g., pivot_root, open_by_handle_at) from non-root workloads.",
		Remediation: "Quarantine workload pod immediately, generate forensic memory snapshot, and enforce immutable eBPF LSM confinement policy.",
	},
}

// LookupBPFRule retrieves a canonical rule definition by its identifier.
func LookupBPFRule(ruleID string) (BPFRule, error) {
	for _, r := range CanonicalBPFRules {
		if r.RuleID == ruleID {
			return r, nil
		}
	}
	return BPFRule{}, fmt.Errorf("bpf rule %s not found in canonical catalog", ruleID)
}
