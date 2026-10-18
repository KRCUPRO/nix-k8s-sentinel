package impermanence

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// Canonical NixOS Immutable Root & Impermanence Storage Ephemerality rules catalog (IMP-ROOT-001 through IMP-ROOT-012).
var rulesCatalog = map[string]ImpermanenceRule{
	"IMP-ROOT-001": {
		ID:          "IMP-ROOT-001",
		Title:       "Mutable Persistent Root Filesystem Detected Without Ephemeral tmpfs or Snapshot Rollback",
		Description: "The NixOS host root filesystem (/) is mounted on persistent mutable disk without tmpfs backing or automated snapshot rollback, permitting persistent malware, compromised binaries, and configuration drift to survive host reboots.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   8.8,
		Remediation: "Configure root filesystem on tmpfs (fsType = 'tmpfs') or implement boot-time ZFS/Btrfs blank snapshot rollback in boot.initrd.postDeviceCommands.",
	},
	"IMP-ROOT-002": {
		ID:          "IMP-ROOT-002",
		Title:       "Missing Boot-Time Snapshot Rollback or Wipe-on-Reboot Sanitization Hook",
		Description: "Root filesystem is declared on ZFS or Btrfs without an automated blank snapshot rollback hook in initrd, failing to sanitize ephemeral state across cluster node restarts.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Remediation: "Add boot.initrd.postDeviceCommands or systemd-initrd unit executing 'zfs rollback -r rpool/root@blank' or Btrfs subvolume reset prior to root mount.",
	},
	"IMP-ROOT-003": {
		ID:          "IMP-ROOT-003",
		Title:       "Unencrypted Swap Partition Enabled Risking Transient Secret Leakage to Disk",
		Description: "Host swap partition or swap file is active without random cryptographic encryption (randomEncryption = true), allowing decrypted RAM secrets, ephemeral TLS session keys, and tmpfs payloads to be flushed to plaintext disk storage.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Remediation: "Enable random swap encryption via swapDevices.*.randomEncryption = true or disable unencrypted host swap entirely.",
		MatchedCVE:  "CVE-2026-61842",
	},
	"IMP-ROOT-004": {
		ID:          "IMP-ROOT-004",
		Title:       "Critical Kubernetes Credentials or Host PKI Outside Persistence Declarations",
		Description: "Essential node cryptographic material (e.g. /etc/ssh/ssh_host_*_key, /var/lib/kubelet/pki) is not included in environment.persistence, risking identity loss and cluster node authentication failure upon reboot.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.4,
		Remediation: "Add /etc/ssh host keys and /var/lib/kubelet PKI directories to environment.persistence with restricted ownership and permissions.",
	},
	"IMP-ROOT-005": {
		ID:          "IMP-ROOT-005",
		Title:       "Persistence Root Partition Resides on Unencrypted Storage Volume",
		Description: "The persistence root directory (/persist or /nix/persist) is mounted on an unencrypted storage device without LUKS2 or dm-crypt envelope encryption, leaving stored persistent credentials vulnerable to cold-boot physical extraction.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Remediation: "Ensure the persistent storage volume backing environment.persistence is configured on top of LUKS2 encrypted partitions (boot.initrd.luks).",
	},
	"IMP-ROOT-006": {
		ID:          "IMP-ROOT-006",
		Title:       "Overly Permissive File or Directory Permissions in Persistence Storage",
		Description: "Persisted sensitive credentials or configuration directories declare permissive Unix modes (> 0600 for files, > 0700 for credential directories), exposing secrets to unprivileged local processes.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.8,
		Remediation: "Enforce strict mode declarations (mode = '0600' for sensitive files, mode = '0700' for private keys and PKI directories) in environment.persistence.",
	},
	"IMP-ROOT-007": {
		ID:          "IMP-ROOT-007",
		Title:       "Container Runtime Storage Root Configured on Memory-Backed tmpfs Root",
		Description: "Containerd or Docker state directory (/var/lib/containerd or /var/lib/docker) is mounted on memory-backed tmpfs root instead of dedicated persistent disk, risking RAM exhaustion and kernel OOM panic during heavy container image pulls.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Remediation: "Bind-mount /var/lib/containerd to dedicated persistent storage via environment.persistence or dedicated storage mount.",
	},
	"IMP-ROOT-008": {
		ID:          "IMP-ROOT-008",
		Title:       "Missing /etc/machine-id Persistence Causing Node Identity Desynchronization",
		Description: "System machine-id (/etc/machine-id) is omitted from environment.persistence.files, resulting in regeneration of a random machine-id on every node reboot and destabilizing etcd, Kubelet, and DHCP leases.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.2,
		Remediation: "Add /etc/machine-id to environment.persistence.<root>.files to guarantee deterministic node identity across stateless reboots.",
	},
	"IMP-ROOT-009": {
		ID:          "IMP-ROOT-009",
		Title:       "Impermanence Bind Mounts Configured Without hideMounts Isolation",
		Description: "The environment.persistence module is configured without hideMounts = true, exposing real underlying persistent storage mount targets in /proc/mounts and increasing local reconnaissance surface.",
		Severity:    intel.SeverityLow,
		CVSSScore:   4.5,
		Remediation: "Set environment.persistence.<root>.hideMounts = true to isolate persistent bind mount references from local namespace inspection.",
	},
	"IMP-ROOT-010": {
		ID:          "IMP-ROOT-010",
		Title:       "Cluster CSI or hostPath Volume Mount Collision with Ephemeral Root Paths",
		Description: "Kubernetes workload manifest specifies hostPath volume referencing an ephemeral root path outside /persist, causing persistent workload state loss or silent data corruption when worker node restarts.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.7,
		Remediation: "Update cluster hostPath specifications to point to dedicated persistent volumes or paths explicitly declared under /persist.",
	},
	"IMP-ROOT-011": {
		ID:          "IMP-ROOT-011",
		Title:       "Ephemeral tmpfs Root Storage Utilization Exceeds Safe Threshold (> 80%)",
		Description: "Runtime telemetry indicates root tmpfs memory consumption exceeds 80% or accumulates orphaned dirty inodes, indicating temporary file accumulation without cleanup and imminent host kernel freeze.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Remediation: "Clean up unpersisted temporary files in /tmp and /var/tmp, tune tmpfs size limits, and audit running daemons for unlinked open file descriptor leaks.",
	},
	"IMP-ROOT-012": {
		ID:          "IMP-ROOT-012",
		Title:       "Missing Kernel Memory Scrubbing or Shutdown RAM Zeroization",
		Description: "Host kernel boot parameters omit transient memory scrubbing flags (init_on_alloc=1, init_on_free=1, page_poison=1), permitting residual cryptographic secrets to persist in cold RAM after node power cycling.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Remediation: "Append 'init_on_alloc=1', 'init_on_free=1', and 'page_poison=1' to boot.kernelParams to guarantee automatic kernel memory zeroization.",
	},
}

// GetRule returns the rule definition for the specified rule ID, or nil if not found.
func GetRule(id string) *ImpermanenceRule {
	if r, ok := rulesCatalog[id]; ok {
		return &r
	}
	return nil
}

// AllRules returns all canonical rules in the catalog.
func AllRules() []ImpermanenceRule {
	out := make([]ImpermanenceRule, 0, len(rulesCatalog))
	for _, r := range rulesCatalog {
		out = append(out, r)
	}
	return out
}
