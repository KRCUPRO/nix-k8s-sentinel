package lockdown

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var canonicalRules = []LockdownRule{
	{
		ID:          "LOCKDOWN-001",
		Name:        "Kernel Lockdown Mode Disabled",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Description: "Linux kernel lockdown is disabled (lockdown=none or parameter missing), permitting unrestricted ring 0 memory modification, raw I/O port writes, and BPF kernel alterations.",
		Remediation: "Append 'lockdown=confidentiality' to boot.kernelParams and set security.lockdown = \"confidentiality\" in NixOS configuration.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-002",
		Name:        "Kernel Lockdown Mode in Integrity Only",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Description: "Linux kernel lockdown is configured for integrity-only mode, permitting unprivileged physical memory reads, /proc/kcore dumps, and cryptographic secret extraction from kernel space.",
		Remediation: "Elevate lockdown parameter from 'lockdown=integrity' to 'lockdown=confidentiality' in boot.kernelParams.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-003",
		Name:        "Unsigned Kernel Module Loading Permitted",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Description: "Kernel module signature enforcement is inactive (module.sig_enforce=0 and kernel.modules_disabled=0), allowing arbitrary unsigned out-of-tree kernel modules to execute in ring 0.",
		Remediation: "Set boot.kernelParams = [ \"module.sig_enforce=1\" ] and configure boot.kernel.sysctl.\"kernel.modules_disabled\" = 1.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-004",
		Name:        "UEFI Secure Boot Disabled or in Insecure Setup Mode",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.3,
		Description: "UEFI Secure Boot is disabled in host firmware or operating in SetupMode, allowing unauthenticated bootloaders and malicious option ROMs to execute during pre-OS boot phase.",
		Remediation: "Enable UEFI Secure Boot in platform firmware, deploy custom PK/KEK platform keys, and transition firmware to DeployedMode.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-005",
		Name:        "Outdated UEFI DBX Forbidden Signature Database",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Description: "The UEFI Secure Boot DBX (Forbidden Signatures Database) has not been updated within the last 60 days, leaving the system vulnerable to known compromised bootloader binaries.",
		Remediation: "Synchronize the UEFI DBX database via fwupd or fwupdate with the latest UEFI Revocation List releases.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-006",
		Name:        "Active Bootloader / Shim Binary Hash Revoked in DBX",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.8,
		Description: "The active bootloader or shim EFI binary executable matches a forbidden SHA-256 authenticode digest registered in the UEFI DBX database (e.g. BootHole or shim RCE).",
		Remediation: "Replace revoked EFI bootloader binaries with newly signed, patched bootloaders and rebuild Unified Kernel Image (UKI).",
		MatchedCVE:  "CVE-2023-40547",
	},
	{
		ID:          "LOCKDOWN-007",
		Name:        "Insecure kexec Syscall Permitted Without Signature Enforcement",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.4,
		Description: "Fast kernel reboot via kexec_load/kexec_file_load is permitted without cryptographically enforcing PE/COFF image signatures on the target kernel image.",
		Remediation: "Enforce kernel signature checks on kexec images or ensure lockdown=integrity/confidentiality restricts unsigned kexec loading.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-008",
		Name:        "Unrestricted Physical Memory Access Permitted",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.9,
		Description: "Physical device memory access (/dev/mem, /dev/kmem) is not strictly confined (missing security.protectKernelImage or strict devmem sysctls), allowing ring 3 processes with raw I/O privileges to overwrite kernel memory.",
		Remediation: "Enable security.protectKernelImage = true and enforce CONFIG_STRICT_DEVMEM=y and CONFIG_IO_STRICT_DEVMEM=y.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-009",
		Name:        "Missing Lanzaboote / UKI Secure Boot Infrastructure",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.2,
		Description: "The NixOS host boots separate kernel and initrd binaries without Lanzaboote Unified Kernel Image (UKI) signing, exposing initrd to offline tampering.",
		Remediation: "Configure boot.lanzaboote.enable = true and enroll private secureboot keys in /etc/secureboot.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-010",
		Name:        "Runtime Unsigned Module Injection Attempts Detected",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.6,
		Description: "Kernel security auditing telemetry recorded unauthorized attempts to load unsigned or improperly signed kernel modules.",
		Remediation: "Investigate telemetry logs for compromised worker daemons attempting init_module/finit_module syscalls and ban rogue container images.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-011",
		Name:        "Live Kernel Lockdown State Mismatch",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Description: "Declarative configuration prescribes active kernel lockdown, but live runtime /sys/kernel/security/lockdown reports 'none', indicating bootloader parameter injection bypass.",
		Remediation: "Audit bootloader configuration integrity, ensure cmdline cannot be modified interactively, and reboot with verified UKI.",
		MatchedCVE:  "CVE-2026-92814",
	},
	{
		ID:          "LOCKDOWN-012",
		Name:        "Machine Owner Key Revocation List Desynchronization",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.8,
		Description: "The runtime MOK revocation list (MokListX) has fewer revocation entries than the authoritative platform DBX database, creating an inconsistent revocation posture.",
		Remediation: "Synchronize MokListX with platform DBX using mokutil --import-dbx and reboot into MOK manager.",
		MatchedCVE:  "CVE-2026-92814",
	},
}

// AllRules returns a clone of all 12 canonical lockdown and UEFI DBX rules.
func AllRules() []LockdownRule {
	rules := make([]LockdownRule, len(canonicalRules))
	copy(rules, canonicalRules)
	return rules
}

// GetRuleByID retrieves a canonical rule by its unique identifier.
func GetRuleByID(id string) *LockdownRule {
	for i := range canonicalRules {
		if canonicalRules[i].ID == id {
			return &canonicalRules[i]
		}
	}
	return nil
}
