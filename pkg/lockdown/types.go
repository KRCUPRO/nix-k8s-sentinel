package lockdown

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes defines the 10MB memory safety ceiling for NixOS lockdown configuration files.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes defines the 5MB memory safety ceiling for runtime kernel & UEFI telemetry.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxAllowedScanLines defines the line count ceiling for configuration scans.
	MaxAllowedScanLines = 20000
	// MaxTelemetryEvents defines the ceiling for runtime telemetry events.
	MaxTelemetryEvents = 5000
)

// LockdownMode represents the operational confinement level of the Linux kernel.
type LockdownMode string

const (
	// LockdownModeNone indicates kernel lockdown is disabled, permitting ring 0 modifications.
	LockdownModeNone LockdownMode = "none"
	// LockdownModeIntegrity restricts kernel modifications (e.g. unsigned modules, kexec, msr writes).
	LockdownModeIntegrity LockdownMode = "integrity"
	// LockdownModeConfidentiality restricts both kernel modifications and unprivileged memory inspection.
	LockdownModeConfidentiality LockdownMode = "confidentiality"
)

// SecureBootState represents the UEFI firmware Secure Boot operational state.
type SecureBootState string

const (
	// SecureBootEnabled indicates Secure Boot is active and enforcing signature verification.
	SecureBootEnabled SecureBootState = "enabled"
	// SecureBootDisabled indicates Secure Boot is turned off in firmware settings.
	SecureBootDisabled SecureBootState = "disabled"
	// SecureBootSetupMode indicates platform keys are not enrolled, permitting unauthorized key injection.
	SecureBootSetupMode SecureBootState = "setup_mode"
	// SecureBootAuditMode indicates firmware logs signature violations without enforcing boot rejection.
	SecureBootAuditMode SecureBootState = "audit_mode"
	// SecureBootDeployedMode indicates firmware is fully provisioned and locked down.
	SecureBootDeployedMode SecureBootState = "deployed_mode"
)

// DBXRevocationEntry describes a forbidden authenticode digest in the UEFI DBX database.
type DBXRevocationEntry struct {
	SignatureOwner   string `json:"signature_owner"`
	HashType         string `json:"hash_type"`
	DigestHex        string `json:"digest_hex"`
	RevocationSource string `json:"revocation_source,omitempty"`
	MatchedCVE       string `json:"matched_cve,omitempty"`
}

// BootloaderDeclaration models a bootloader binary or Unified Kernel Image (UKI) configuration.
type BootloaderDeclaration struct {
	BinaryPath        string `json:"binary_path"`
	SHA256Hash        string `json:"sha256_hash"`
	IsRevokedInDBX    bool   `json:"is_revoked_in_dbx"`
	SignerCert        string `json:"signer_cert,omitempty"`
	LineNumber        int    `json:"line_number,omitempty"`
}

// LockdownSecurityConfig captures declarative Linux kernel lockdown and UEFI Secure Boot policies in NixOS.
type LockdownSecurityConfig struct {
	FilePath                string                  `json:"file_path"`
	HostName                string                  `json:"host_name,omitempty"`
	LockdownParam           LockdownMode            `json:"lockdown_param"`
	SecurityLockdown        LockdownMode            `json:"security_lockdown"`
	ProtectKernelImage      *bool                   `json:"protect_kernel_image"`
	ModulesDisabled         *bool                   `json:"modules_disabled"`
	ModuleSigEnforce        *bool                   `json:"module_sig_enforce"`
	SecureBootEnabled       *bool                   `json:"secure_boot_enabled"`
	LanzabooteEnabled       *bool                   `json:"lanzaboote_enabled"`
	StrictDevMem            *bool                   `json:"strict_dev_mem"`
	KexecSignaturesEnforced *bool                   `json:"kexec_signatures_enforced"`
	Bootloaders             []BootloaderDeclaration `json:"bootloaders"`
	LineNumbers             map[string]int          `json:"line_numbers,omitempty"`
}

// LockdownTelemetryEvent captures an individual kernel security event or denial.
type LockdownTelemetryEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"` // e.g., "UNSIGNED_MODULE_DENIED", "DEVMEM_ACCESS_BLOCKED", "LOCKDOWN_BREACH"
	Syscall   string    `json:"syscall,omitempty"`
	Process   string    `json:"process,omitempty"`
	Details   string    `json:"details"`
}

// LockdownTelemetryReport consolidates live kernel lockdown and UEFI Secure Boot state telemetry.
type LockdownTelemetryReport struct {
	HostName                    string                   `json:"host_name"`
	CollectedAt                 time.Time                `json:"collected_at"`
	LiveLockdownMode            LockdownMode             `json:"live_lockdown_mode"`
	ModuleSignatureEnforced     bool                     `json:"module_signature_enforced"`
	SecureBootStatus            SecureBootState          `json:"secure_boot_status"`
	SetupModeActive             bool                     `json:"setup_mode_active"`
	DBXVersion                  string                   `json:"dbx_version"`
	DBXReleaseDate              time.Time                `json:"dbx_release_date"`
	DBXTotalRevocations         int                      `json:"dbx_total_revocations"`
	DBXAgeDays                  int                      `json:"dbx_age_days"`
	ActiveBootloaderPath        string                   `json:"active_bootloader_path"`
	ActiveBootloaderSHA256      string                   `json:"active_bootloader_sha256"`
	ActiveBootloaderRevoked     bool                     `json:"active_bootloader_revoked"`
	MokListXRevocationsCount    int                      `json:"mok_list_x_revocations_count"`
	UnsignedModuleLoadDenials   int                      `json:"unsigned_module_load_denials"`
	DirectDevMemDenials         int                      `json:"direct_dev_mem_denials"`
	KexecDenials                int                      `json:"kexec_denials"`
	RevocationEntries           []DBXRevocationEntry     `json:"revocation_entries,omitempty"`
	Events                      []LockdownTelemetryEvent `json:"events"`
}

// LockdownRule defines a canonical security rule for kernel lockdown and UEFI DBX posture.
type LockdownRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// LockdownViolation models a detected non-compliance finding or runtime breach.
type LockdownViolation struct {
	RuleID      string         `json:"rule_id"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	FilePath    string         `json:"file_path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
	EndLine     int            `json:"end_line,omitempty"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// LockdownSummary provides aggregate counts and deterministic compliance metrics.
type LockdownSummary struct {
	TotalScanned    int     `json:"total_scanned"`
	CompliantCount  int     `json:"compliant_count"`
	ViolationCount  int     `json:"violation_count"`
	ComplianceScore float64 `json:"compliance_score"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
}

// LockdownAuditReport aggregates static configuration findings, runtime telemetry, and summary.
type LockdownAuditReport struct {
	HostName    string                   `json:"host_name"`
	ScannedAt   time.Time                `json:"scanned_at"`
	Config      *LockdownSecurityConfig  `json:"config,omitempty"`
	Telemetry   *LockdownTelemetryReport `json:"telemetry,omitempty"`
	Violations  []LockdownViolation      `json:"violations"`
	Summary     LockdownSummary          `json:"summary"`
}
