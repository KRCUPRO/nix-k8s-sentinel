package attest

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// CanonicalAttestationRules provides the canonical catalog of Confidential Computing & Measured Boot security rules.
var CanonicalAttestationRules = map[string]AttestationRule{
	"ATTEST-BOOT-001": {
		ID:          "ATTEST-BOOT-001",
		Title:       "AMD SEV-SNP Memory Encryption Disabled or Unconfigured",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.2,
		Category:    "ConfidentialComputing",
		Technology:  string(PlatformAmdSEVSNP),
		Description: "The host or worker node fails to enforce AMD SEV-SNP hardware memory encryption. Hypervisor or adjacent tenant memory snooping is unprotected.",
		Remediation: "Ensure 'mem_encrypt=on kvm_amd.sev=1' is configured in NixOS boot.kernelParams and verify SEV-SNP firmware activation in BIOS.",
	},
	"ATTEST-BOOT-002": {
		ID:          "ATTEST-BOOT-002",
		Title:       "Intel TDX Trust Domain Execution Disabled in Kernel Flags",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.2,
		Category:    "ConfidentialComputing",
		Technology:  string(PlatformIntelTDX),
		Description: "The host or worker node does not enforce Intel Trust Domain Extensions (TDX). Guest hardware isolation and memory encryption are inactive.",
		Remediation: "Configure 'intel_iommu=on kvm_intel.tdx=1' in NixOS boot.kernelParams and enable Intel TDX module in host UEFI firmware.",
	},
	"ATTEST-BOOT-003": {
		ID:          "ATTEST-BOOT-003",
		Title:       "TPM 2.0 PCR 7 Secure Boot Measurement Mismatch or Policy Drift",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Category:    "MeasuredBoot",
		Technology:  string(PlatformBareMetal),
		Description: "TPM 2.0 PCR 7 (Secure Boot policy and certificate database) measurement deviates from the expected golden state, indicating untrusted signing keys or policy tampering.",
		Remediation: "Audit authorized Secure Boot keys (PK/KEK/db) in UEFI firmware and re-sign EFI binaries with the enterprise golden signing authority.",
	},
	"ATTEST-BOOT-004": {
		ID:          "ATTEST-BOOT-004",
		Title:       "TPM 2.0 PCR 11 Unified Kernel Image (UKI) / NixOS System Closure Digest Desync",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.7,
		Category:    "MeasuredBoot",
		Technology:  string(PlatformBareMetal),
		Description: "TPM 2.0 PCR 11 measurement does not match the signed NixOS UKI system closure hash. Possible unauthorized initrd or kernel binary substitution.",
		Remediation: "Regenerate signed NixOS Unified Kernel Images using Lanzaboote or systemd-stub and verify PCR 11 measurement against system closure signature.",
	},
	"ATTEST-BOOT-005": {
		ID:          "ATTEST-BOOT-005",
		Title:       "Confidential Computing Firmware Debug Mode Permitted in Remote Quote",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Category:    "EnclaveIntegrity",
		Technology:  string(PlatformGeneric),
		Description: "The attestation quote reveals that debug mode is enabled on the confidential VM/enclave. Host hypervisors can inspect guest registers and plaintext memory.",
		Remediation: "Deploy confidential VM instances with debug mode explicitly disabled in production launch templates and attestation policies.",
	},
	"ATTEST-BOOT-006": {
		ID:          "ATTEST-BOOT-006",
		Title:       "Insecure or Missing NixOS Store Path Cryptographic Signature in Measured Boot",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Category:    "SupplyChainSecurity",
		Technology:  string(PlatformGeneric),
		Description: "The measured boot artifact does not possess a verified cryptographic signature binding the Nix store closure to the hardware root of trust.",
		Remediation: "Configure Nix signing keys in nix.settings.trusted-public-keys and enforce cryptographic signature verification on all kernel store paths.",
	},
	"ATTEST-BOOT-007": {
		ID:          "ATTEST-BOOT-007",
		Title:       "Unhardened Bootloader (Missing Systemd-Boot Measured Boot Integration)",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.8,
		Category:    "BootloaderHardening",
		Technology:  string(PlatformBareMetal),
		Description: "The bootloader configuration lacks systemd-boot measured boot integration. Stage 1 bootloader phases are not measured into TPM PCR 4/5.",
		Remediation: "Set 'boot.loader.systemd-boot.enable = true;' and 'boot.initrd.systemd.enable = true;' in NixOS configuration.",
	},
	"ATTEST-BOOT-008": {
		ID:          "ATTEST-BOOT-008",
		Title:       "Expired or Revoked Remote Attestation Token / VCEK Certificate",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.1,
		Category:    "CredentialIntegrity",
		Technology:  string(PlatformGeneric),
		Description: "The remote attestation quote token or manufacturer endorsement certificate (VCEK/PCK) is expired or revoked. Attestation validity window has lapsed.",
		Remediation: "Refresh platform attestation tokens periodically via the node attestation daemon and ensure platform root certs are synchronized.",
	},
	"ATTEST-BOOT-009": {
		ID:          "ATTEST-BOOT-009",
		Title:       "Missing TPM2 Resource Manager (tpm2-abrmd / In-Kernel RM) in NixOS Config",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.5,
		Category:    "PlatformHardening",
		Technology:  string(PlatformBareMetal),
		Description: "NixOS security.tpm2 configuration is absent or disabled. Cluster applications cannot reliably access hardware cryptographic keys without contention.",
		Remediation: "Enable 'security.tpm2.enable = true;' and configure PKCS#11 support via 'security.tpm2.pkcs11.enable = true;' in NixOS configuration.",
	},
	"ATTEST-BOOT-010": {
		ID:          "ATTEST-BOOT-010",
		Title:       "TPM 2.0 PCR 8 Kernel Command Line Drift / Unsanitized Boot Parameters",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.6,
		Category:    "MeasuredBoot",
		Technology:  string(PlatformBareMetal),
		Description: "TPM 2.0 PCR 8 measurement indicates runtime kernel command-line tampering or unmeasured parameter injection at boot time.",
		Remediation: "Enforce immutable kernel command lines baked into signed Unified Kernel Images (UKI) and prevent interactive boot parameter editing.",
	},
	"ATTEST-BOOT-011": {
		ID:          "ATTEST-BOOT-011",
		Title:       "Unenforced TCB Version Policy on Confidential Computing Nodes",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.5,
		Category:    "TCBCompliance",
		Technology:  string(PlatformGeneric),
		Description: "The node attestation report reflects a Trusted Computing Base (TCB) microcode or firmware version below the minimum enterprise security baseline.",
		Remediation: "Apply latest processor microcode updates and motherboard UEFI firmware patches to meet minimum required TCB levels.",
	},
	"ATTEST-BOOT-012": {
		ID:          "ATTEST-BOOT-012",
		Title:       "Missing Measured Boot Stage for Initrd / Kernel Image in PCR 9",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Category:    "MeasuredBoot",
		Technology:  string(PlatformBareMetal),
		Description: "TPM 2.0 PCR 9 measurement for the Linux kernel and initial RAM disk is empty or unpopulated, leaving initrd rootfs modifications undetected.",
		Remediation: "Ensure systemd-stub or EFI boot stub measures the kernel image and initrd into PCR 9 before handing control to the kernel.",
	},
}

// GetAttestationRule retrieves a canonical rule by ID, returning a default rule if not found.
func GetAttestationRule(ruleID string) AttestationRule {
	if rule, exists := CanonicalAttestationRules[ruleID]; exists {
		return rule
	}
	return AttestationRule{
		ID:          ruleID,
		Title:       "Unknown Attestation Security Rule",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.0,
		Category:    "GeneralAttestation",
		Technology:  string(PlatformGeneric),
		Description: "An unclassified confidential computing or measured boot anomaly was detected.",
		Remediation: "Inspect node attestation quotes and NixOS measured boot configurations.",
	}
}
