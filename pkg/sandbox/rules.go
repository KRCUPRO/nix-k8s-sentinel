package sandbox

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// CanonicalRuleCatalog defines the authoritative 12 microVM sandbox and honeypot security rules.
var CanonicalRuleCatalog = []SandboxRule{
	{
		ID:          "SANDBOX-DET-001",
		Title:       "Missing Ephemeral MicroVM Pre-flight Detonation",
		Severity:    "HIGH",
		CVSSScore:   8.5,
		Description: "Untrusted container image, binary, or OCI artifact is scheduled for cluster deployment without pre-flight detonation in an isolated microVM sandbox.",
		Remediation: "Enforce dynamic Firecracker microVM pre-flight execution in CI/CD and admission controllers prior to cluster scheduling.",
	},
	{
		ID:          "SANDBOX-DET-002",
		Title:       "Unrestricted MicroVM Network Egress Detected",
		Severity:    "CRITICAL",
		CVSSScore:   9.2,
		Description: "Ephemeral microVM sandbox network interface has unrestricted egress enabled, allowing detonation payloads to initiate external command-and-control (C2) or data exfiltration.",
		Remediation: "Enforce strict TAP device firewall isolation with default-drop egress rules and redirect traffic to internal honeypot sinkholes.",
		CVE:         "CVE-2026-97105",
	},
	{
		ID:          "SANDBOX-DET-003",
		Title:       "MicroVM Jailer Daemon and Chroot Isolation Disabled",
		Severity:    "HIGH",
		CVSSScore:   8.8,
		Description: "Firecracker hypervisor instance is executed without jailer daemon confinement, exposing host root filesystem and system namespaces.",
		Remediation: "Enable Firecracker jailer with unprivileged UID/GID mappings, chroot sandboxing, and strict cgroup v2 resource limits.",
	},
	{
		ID:          "SANDBOX-DET-004",
		Title:       "Honeypot Kubelet Decoy Interaction Intercepted",
		Severity:    "HIGH",
		CVSSScore:   8.1,
		Description: "Detonation payload attempted unauthorized port scan or unauthenticated API query against the honeypot Kubelet lure listener (port 10250).",
		Remediation: "Quarantine source container image immediately and inspect build pipeline for credential harvesting backdoors.",
	},
	{
		ID:          "SANDBOX-DET-005",
		Title:       "Honeypot etcd Decoy Peering Probe Intercepted",
		Severity:    "CRITICAL",
		CVSSScore:   9.0,
		Description: "Detonation payload probed unauthenticated honeypot etcd client/peer port (2379/2380) attempting cluster key retrieval.",
		Remediation: "Quarantine workload artifact, rotate active cluster tokens, and alert SecOps incident response team.",
	},
	{
		ID:          "SANDBOX-DET-006",
		Title:       "Suspicious Reverse Shell or C2 Beaconing Spun in Sandbox",
		Severity:    "CRITICAL",
		CVSSScore:   9.5,
		Description: "Runtime kernel telemetry inside the microVM captured interactive shell spawn (`/bin/sh`, `/bin/bash`, `nc -e`) bound to external socket.",
		Remediation: "Mark artifact as malicious, isolate container registry digest, and block source developer credential.",
	},
	{
		ID:          "SANDBOX-DET-007",
		Title:       "Privilege Escalation Exploit Vector Executed in Sandbox",
		Severity:    "CRITICAL",
		CVSSScore:   9.6,
		Description: "Payload executed kernel privilege escalation syscall sequences (e.g. `setuid(0)`, `ptrace`, `bpf_prog_load`, `process_vm_writev`).",
		Remediation: "Revoke deployment authorization, capture memory snapshot for forensic analysis, and patch host kernel.",
	},
	{
		ID:          "SANDBOX-DET-008",
		Title:       "Hypervisor Escape Attempt via Virtio Device Anomaly",
		Severity:    "CRITICAL",
		CVSSScore:   9.8,
		Description: "MicroVM guest kernel attempted out-of-bounds MMIO read/write or invalid ring buffer manipulation on virtio-net/virtio-block devices.",
		Remediation: "Terminate VM process immediately, update Firecracker binary to latest secure release, and lock down host KVM permissions.",
	},
	{
		ID:          "SANDBOX-DET-009",
		Title:       "Sandbox Execution Timeout Anti-Analysis Evasion",
		Severity:    "MEDIUM",
		CVSSScore:   6.8,
		Description: "Detonation execution exceeded SLA timeout (> 30s) without entering workload main loop, indicating anti-sandbox sleep stalling or evasion.",
		Remediation: "Increase detonation observation window with accelerated hypervisor clock skew or reject artifact build.",
	},
	{
		ID:          "SANDBOX-DET-010",
		Title:       "Honeypot Credential Decoy Harvesting Detected",
		Severity:    "HIGH",
		CVSSScore:   7.8,
		Description: "Payload accessed synthetic canary files (e.g., fake `/var/run/secrets/kubernetes.io/serviceaccount/token` or AWS credentials) deployed in sandbox.",
		Remediation: "Mark payload as malicious harvester, verify canary token hash, and block downstream admission.",
	},
	{
		ID:          "SANDBOX-DET-011",
		Title:       "Unhardened NixOS MicroVM Host Configuration",
		Severity:    "HIGH",
		CVSSScore:   7.5,
		Description: "Declarative NixOS microVM module is missing hardware acceleration (`/dev/kvm`), lacks read-only rootfs, or runs as root.",
		Remediation: "Configure `microvm.vms.<name>.hypervisor = \"firecracker\";` with unprivileged user, read-only rootfs, and restricted TAP interfaces.",
	},
	{
		ID:          "SANDBOX-DET-012",
		Title:       "Immutable RootFS or Nix Store Path Tampering in Sandbox",
		Severity:    "HIGH",
		CVSSScore:   8.3,
		Description: "Payload attempted write operations against read-only root filesystem or immutable `/nix/store` mount inside microVM guest.",
		Remediation: "Ensure guest OS mounts rootfs with strict `ro` flags and reject payloads attempting remount or binary overwrites.",
	},
}

// GetRuleByID retrieves a canonical sandbox rule by its identifier.
func GetRuleByID(id string) (SandboxRule, bool) {
	for _, rule := range CanonicalRuleCatalog {
		if rule.ID == id {
			return rule, true
		}
	}
	return SandboxRule{}, false
}

// CorrelateThreatWithRule finds matching threat feed items for a given rule.
func CorrelateThreatWithRule(rule SandboxRule, feed *intel.Feed) *intel.ThreatItem {
	if feed == nil {
		return nil
	}
	for _, item := range feed.Items {
		if rule.CVE != "" && item.ID == rule.CVE {
			return &item
		}
	}
	return nil
}
