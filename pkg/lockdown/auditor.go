package lockdown

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// KnownCompromisedBootloaderHashes defines authoritative SHA-256 digests of known-vulnerable bootloaders (e.g. BootHole CVE-2020-10713, Shim CVE-2023-40547).
var KnownCompromisedBootloaderHashes = []string{
	"c026859345ee3a652cc596fc7c4ab59f77e20b33c16262bf6a992e5954a1be2e", // CVE-2023-40547 vulnerable shim
	"2f8087913de8f08a8a25c1b69472e505ab384fe84f2b1d6d84f86d63bc36ad18", // CVE-2020-10713 BootHole grub2
	"f74b6f6c77bb1c2062fa9c336b9e4a36be5b8426f86b71bfbb1e96a4bc20d361", // CVE-2022-28737 grub PE parsing overflow
	"1bfae34898b965f956c3ee796646543b5df5b565814bfb287955c4643b9e0750", // CVE-2026-92814 revoked shim binary
}

// AuditLockdownConfig performs static declarative analysis on NixOS kernel lockdown and Secure Boot configurations.
func AuditLockdownConfig(cfg *LockdownSecurityConfig) []LockdownViolation {
	if cfg == nil {
		return nil
	}

	violations := make([]LockdownViolation, 0)

	// LOCKDOWN-001: Kernel Lockdown Mode Disabled
	hasLockdown := cfg.LockdownParam == LockdownModeConfidentiality ||
		cfg.LockdownParam == LockdownModeIntegrity ||
		cfg.SecurityLockdown == LockdownModeConfidentiality ||
		cfg.SecurityLockdown == LockdownModeIntegrity

	if !hasLockdown || cfg.LockdownParam == LockdownModeNone || cfg.SecurityLockdown == LockdownModeNone {
		line := cfg.LineNumbers["lockdownParam"]
		if line == 0 {
			line = cfg.LineNumbers["securityLockdown"]
		}
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-001")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	} else if (cfg.LockdownParam == LockdownModeIntegrity || cfg.SecurityLockdown == LockdownModeIntegrity) &&
		cfg.LockdownParam != LockdownModeConfidentiality && cfg.SecurityLockdown != LockdownModeConfidentiality {
		// LOCKDOWN-002: Kernel Lockdown Mode in Integrity Only
		line := cfg.LineNumbers["lockdownParam"]
		if line == 0 {
			line = cfg.LineNumbers["securityLockdown"]
		}
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-002")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-003: Unsigned Kernel Module Loading Permitted
	modulesPermitted := (cfg.ModulesDisabled == nil || !*cfg.ModulesDisabled) &&
		(cfg.ModuleSigEnforce == nil || !*cfg.ModuleSigEnforce)
	if modulesPermitted {
		line := cfg.LineNumbers["modulesDisabled"]
		if line == 0 {
			line = cfg.LineNumbers["moduleSigEnforce"]
		}
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-003")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-004: UEFI Secure Boot Disabled
	if cfg.SecureBootEnabled != nil && !*cfg.SecureBootEnabled {
		line := cfg.LineNumbers["secureboot"]
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-004")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-007: Insecure kexec Syscall Permitted Without Signature Enforcement
	if (cfg.KexecSignaturesEnforced == nil || !*cfg.KexecSignaturesEnforced) &&
		cfg.LockdownParam != LockdownModeConfidentiality && cfg.SecurityLockdown != LockdownModeConfidentiality {
		line := cfg.LineNumbers["kexec"]
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-007")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-008: Unrestricted Physical Memory Access Permitted
	if (cfg.ProtectKernelImage == nil || !*cfg.ProtectKernelImage) || (cfg.StrictDevMem != nil && !*cfg.StrictDevMem) {
		line := cfg.LineNumbers["protectKernelImage"]
		if line == 0 {
			line = cfg.LineNumbers["strictDevMem"]
		}
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-008")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-009: Missing Lanzaboote / UKI Secure Boot Infrastructure
	if cfg.LanzabooteEnabled == nil || !*cfg.LanzabooteEnabled {
		line := cfg.LineNumbers["lanzaboote"]
		if line == 0 {
			line = 1
		}
		r := GetRuleByID("LOCKDOWN-009")
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: r.Description,
			Remediation: r.Remediation,
			FilePath:    cfg.FilePath,
			StartLine:   line,
			EndLine:     line,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// Inspect declared bootloaders against known compromised DBX digests
	for _, bl := range cfg.Bootloaders {
		if bl.SHA256Hash != "" && isHashInList(bl.SHA256Hash, KnownCompromisedBootloaderHashes) {
			r := GetRuleByID("LOCKDOWN-006")
			violations = append(violations, LockdownViolation{
				RuleID:      r.ID,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				Title:       r.Name,
				Description: fmt.Sprintf("Declared bootloader binary (%s) has revoked SHA-256 digest %s.", bl.BinaryPath, bl.SHA256Hash),
				Remediation: r.Remediation,
				FilePath:    cfg.FilePath,
				StartLine:   bl.LineNumber,
				EndLine:     bl.LineNumber,
				MatchedCVE:  r.MatchedCVE,
			})
		}
	}

	return violations
}

// AuditLockdownTelemetry analyzes runtime kernel lockdown state and UEFI DBX revocation telemetry.
func AuditLockdownTelemetry(telemetry *LockdownTelemetryReport, cfg *LockdownSecurityConfig, additionalDBXHashes []string) []LockdownViolation {
	if telemetry == nil {
		return nil
	}

	violations := make([]LockdownViolation, 0)
	dbxLookup := make(map[string]bool)

	for _, h := range KnownCompromisedBootloaderHashes {
		dbxLookup[strings.ToLower(h)] = true
	}
	for _, h := range additionalDBXHashes {
		dbxLookup[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, entry := range telemetry.RevocationEntries {
		if entry.DigestHex != "" {
			dbxLookup[strings.ToLower(strings.TrimSpace(entry.DigestHex))] = true
		}
	}

	// LOCKDOWN-004: UEFI Secure Boot Disabled or in Setup Mode
	if telemetry.SecureBootStatus == SecureBootDisabled || telemetry.SetupModeActive {
		r := GetRuleByID("LOCKDOWN-004")
		desc := r.Description
		if telemetry.SetupModeActive {
			desc = fmt.Sprintf("UEFI firmware is operating in insecure SetupMode on host %s (SecureBoot=%s). Platform keys are not locked down.", telemetry.HostName, telemetry.SecureBootStatus)
		}
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: desc,
			Remediation: r.Remediation,
			FilePath:    "sysfs:/sys/firmware/efi/efivars/SecureBoot",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-005: Outdated UEFI DBX Forbidden Signature Database
	if telemetry.DBXAgeDays > 60 || telemetry.DBXTotalRevocations < 50 {
		r := GetRuleByID("LOCKDOWN-005")
		desc := fmt.Sprintf("Host %s UEFI DBX database (%s) is %d days old with only %d revocations (minimum expected >= 50).", telemetry.HostName, telemetry.DBXVersion, telemetry.DBXAgeDays, telemetry.DBXTotalRevocations)
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: desc,
			Remediation: r.Remediation,
			FilePath:    "sysfs:/sys/firmware/efi/efivars/dbx",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-006: Active Bootloader / Shim Binary Hash Revoked in DBX
	activeHash := strings.ToLower(strings.TrimSpace(telemetry.ActiveBootloaderSHA256))
	if telemetry.ActiveBootloaderRevoked || (activeHash != "" && dbxLookup[activeHash]) {
		r := GetRuleByID("LOCKDOWN-006")
		desc := fmt.Sprintf("Running bootloader %s on host %s has SHA-256 digest %s which is revoked in UEFI DBX.", telemetry.ActiveBootloaderPath, telemetry.HostName, activeHash)
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: desc,
			Remediation: r.Remediation,
			FilePath:    telemetry.ActiveBootloaderPath,
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-010: Runtime Unsigned Module Injection Attempts Detected
	if telemetry.UnsignedModuleLoadDenials > 0 {
		r := GetRuleByID("LOCKDOWN-010")
		desc := fmt.Sprintf("Host %s recorded %d unauthorized unsigned kernel module load denials in runtime telemetry.", telemetry.HostName, telemetry.UnsignedModuleLoadDenials)
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: desc,
			Remediation: r.Remediation,
			FilePath:    "sysfs:/sys/module/module_signing",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-011: Live Kernel Lockdown State Mismatch
	declarativeLockdownWanted := cfg != nil &&
		(cfg.LockdownParam == LockdownModeConfidentiality || cfg.SecurityLockdown == LockdownModeConfidentiality ||
			cfg.LockdownParam == LockdownModeIntegrity || cfg.SecurityLockdown == LockdownModeIntegrity)
	if declarativeLockdownWanted && telemetry.LiveLockdownMode == LockdownModeNone {
		r := GetRuleByID("LOCKDOWN-011")
		desc := fmt.Sprintf("Host %s declarative configuration specifies lockdown, but runtime /sys/kernel/security/lockdown reports 'none'.", telemetry.HostName)
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: desc,
			Remediation: r.Remediation,
			FilePath:    "sysfs:/sys/kernel/security/lockdown",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	// LOCKDOWN-012: Machine Owner Key (MOK) Revocation List Desynchronization
	if telemetry.DBXTotalRevocations > 50 && telemetry.MokListXRevocationsCount > 0 &&
		telemetry.MokListXRevocationsCount < (telemetry.DBXTotalRevocations/4) {
		r := GetRuleByID("LOCKDOWN-012")
		desc := fmt.Sprintf("Host %s has MokListX with only %d entries while platform DBX contains %d revocations, risking bypass via MOK.", telemetry.HostName, telemetry.MokListXRevocationsCount, telemetry.DBXTotalRevocations)
		violations = append(violations, LockdownViolation{
			RuleID:      r.ID,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Title:       r.Name,
			Description: desc,
			Remediation: r.Remediation,
			FilePath:    "sysfs:/sys/firmware/efi/efivars/MokListXRT",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  r.MatchedCVE,
		})
	}

	return violations
}

// ComputeComplianceScore calculates a deterministic 0.0% to 100.0% compliance score based on findings.
func ComputeComplianceScore(violations []LockdownViolation) float64 {
	score := 100.0
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			score -= 25.0
		case intel.SeverityHigh:
			score -= 15.0
		case intel.SeverityMedium:
			score -= 8.0
		case intel.SeverityLow:
			score -= 4.0
		default:
			score -= 5.0
		}
	}
	if score < 0.0 {
		score = 0.0
	}
	return math.Round(score*10) / 10
}

func isHashInList(hash string, list []string) bool {
	target := strings.ToLower(strings.TrimSpace(hash))
	for _, h := range list {
		if strings.ToLower(strings.TrimSpace(h)) == target {
			return true
		}
	}
	return false
}
