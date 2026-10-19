package lockdown

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	hexRegex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// ValidateSHA256Hash verifies that a hash string is a valid 64-character hexadecimal SHA-256 digest.
func ValidateSHA256Hash(hash string) bool {
	clean := strings.TrimSpace(hash)
	return hexRegex.MatchString(clean)
}

// ParseLiveLockdownSysfs extracts the active mode from a Linux /sys/kernel/security/lockdown read string.
// Kernel sysfs format: "[none] integrity confidentiality", "none [integrity] confidentiality", or "none integrity [confidentiality]".
func ParseLiveLockdownSysfs(raw string) LockdownMode {
	clean := strings.TrimSpace(raw)
	switch {
	case strings.Contains(clean, "[confidentiality]"):
		return LockdownModeConfidentiality
	case strings.Contains(clean, "[integrity]"):
		return LockdownModeIntegrity
	case strings.Contains(clean, "[none]"):
		return LockdownModeNone
	case strings.EqualFold(clean, "confidentiality"):
		return LockdownModeConfidentiality
	case strings.EqualFold(clean, "integrity"):
		return LockdownModeIntegrity
	default:
		return LockdownModeNone
	}
}

// ParseLockdownConfigFile reads and parses a NixOS configuration file from disk with defensive bounds.
func ParseLockdownConfigFile(filePath string) (*LockdownSecurityConfig, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat configuration file (%s): %w", cleanPath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("configuration file (%s) exceeds maximum size limit of %d bytes", cleanPath, MaxManifestBytes)
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file (%s): %w", cleanPath, err)
	}

	return ParseLockdownConfig(content, cleanPath)
}

// ParseLockdownConfig parses a NixOS module or configuration content for kernel lockdown and UEFI settings.
func ParseLockdownConfig(content []byte, filePath string) (*LockdownSecurityConfig, error) {
	if len(content) > MaxManifestBytes {
		return nil, fmt.Errorf("configuration payload exceeds %d bytes ceiling", MaxManifestBytes)
	}

	cfg := &LockdownSecurityConfig{
		FilePath:    filePath,
		HostName:    "localhost",
		Bootloaders: make([]BootloaderDeclaration, 0),
		LineNumbers: make(map[string]int),
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	inKernelParams := false

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)

		// Ignore empty lines and comment lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Track hostname if configured
		if strings.Contains(trimmed, "networking.hostName") {
			parts := strings.Split(trimmed, "=")
			if len(parts) >= 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), "\";")
				if val != "" {
					cfg.HostName = val
					cfg.LineNumbers["hostName"] = lineNum
				}
			}
		}

		// Detect boot.kernelParams list opening / contents
		if strings.Contains(trimmed, "boot.kernelParams") {
			cfg.LineNumbers["kernelParams"] = lineNum
			if strings.Contains(trimmed, "[") && !strings.Contains(trimmed, "]") {
				inKernelParams = true
			}
		}

		if inKernelParams || strings.Contains(trimmed, "boot.kernelParams") {
			if strings.Contains(trimmed, "lockdown=confidentiality") {
				cfg.LockdownParam = LockdownModeConfidentiality
				cfg.LineNumbers["lockdownParam"] = lineNum
			} else if strings.Contains(trimmed, "lockdown=integrity") && cfg.LockdownParam != LockdownModeConfidentiality {
				cfg.LockdownParam = LockdownModeIntegrity
				cfg.LineNumbers["lockdownParam"] = lineNum
			} else if strings.Contains(trimmed, "lockdown=none") {
				cfg.LockdownParam = LockdownModeNone
				cfg.LineNumbers["lockdownParam"] = lineNum
			}

			if strings.Contains(trimmed, "module.sig_enforce=1") {
				val := true
				cfg.ModuleSigEnforce = &val
				cfg.LineNumbers["moduleSigEnforce"] = lineNum
			} else if strings.Contains(trimmed, "module.sig_enforce=0") {
				val := false
				cfg.ModuleSigEnforce = &val
				cfg.LineNumbers["moduleSigEnforce"] = lineNum
			}

			if inKernelParams && strings.Contains(trimmed, "]") {
				inKernelParams = false
			}
		}

		// Detect security.lockdown
		if strings.Contains(trimmed, "security.lockdown") {
			cfg.LineNumbers["securityLockdown"] = lineNum
			if strings.Contains(trimmed, "confidentiality") {
				cfg.SecurityLockdown = LockdownModeConfidentiality
			} else if strings.Contains(trimmed, "integrity") {
				cfg.SecurityLockdown = LockdownModeIntegrity
			} else if strings.Contains(trimmed, "none") {
				cfg.SecurityLockdown = LockdownModeNone
			}
		}

		// Detect security.protectKernelImage
		if strings.Contains(trimmed, "security.protectKernelImage") {
			cfg.LineNumbers["protectKernelImage"] = lineNum
			if strings.Contains(trimmed, "true") {
				val := true
				cfg.ProtectKernelImage = &val
			} else if strings.Contains(trimmed, "false") {
				val := false
				cfg.ProtectKernelImage = &val
			}
		}

		// Detect kernel.modules_disabled
		if strings.Contains(trimmed, "kernel.modules_disabled") {
			cfg.LineNumbers["modulesDisabled"] = lineNum
			if strings.Contains(trimmed, "1") {
				val := true
				cfg.ModulesDisabled = &val
			} else if strings.Contains(trimmed, "0") {
				val := false
				cfg.ModulesDisabled = &val
			}
		}

		// Detect Lanzaboote Secure Boot framework (flat or nested)
		if strings.Contains(trimmed, "boot.lanzaboote") {
			cfg.LineNumbers["lanzaboote"] = lineNum
			if strings.Contains(trimmed, ".enable") {
				if strings.Contains(trimmed, "true") {
					val := true
					cfg.LanzabooteEnabled = &val
				} else if strings.Contains(trimmed, "false") {
					val := false
					cfg.LanzabooteEnabled = &val
				}
			}
		}

		if strings.Contains(trimmed, "enable = true") && cfg.LineNumbers["lanzaboote"] > 0 && cfg.LanzabooteEnabled == nil {
			val := true
			cfg.LanzabooteEnabled = &val
		} else if strings.Contains(trimmed, "enable = false") && cfg.LineNumbers["lanzaboote"] > 0 && cfg.LanzabooteEnabled == nil {
			val := false
			cfg.LanzabooteEnabled = &val
		}

		// Detect generic Secure Boot enabled
		if strings.Contains(trimmed, "boot.loader.secureboot.enable") || strings.Contains(trimmed, "security.secureBoot.enable") {
			cfg.LineNumbers["secureboot"] = lineNum
			if strings.Contains(trimmed, "true") {
				val := true
				cfg.SecureBootEnabled = &val
			} else if strings.Contains(trimmed, "false") {
				val := false
				cfg.SecureBootEnabled = &val
			}
		}

		// Detect strict devmem
		if strings.Contains(trimmed, "strict_devmem") || strings.Contains(trimmed, "CONFIG_STRICT_DEVMEM") {
			cfg.LineNumbers["strictDevMem"] = lineNum
			if strings.Contains(trimmed, "true") || strings.Contains(trimmed, "=y") {
				val := true
				cfg.StrictDevMem = &val
			} else if strings.Contains(trimmed, "false") || strings.Contains(trimmed, "=n") {
				val := false
				cfg.StrictDevMem = &val
			}
		}

		// Detect kexec signature verification
		if strings.Contains(trimmed, "security.kexec.requireSignature") || strings.Contains(trimmed, "kexec.load_limit") {
			cfg.LineNumbers["kexec"] = lineNum
			if strings.Contains(trimmed, "true") || strings.Contains(trimmed, "1") {
				val := true
				cfg.KexecSignaturesEnforced = &val
			}
		}

		// Parse declared bootloader EFI paths or hashes
		if strings.Contains(trimmed, "bootloader.efi") || strings.Contains(trimmed, "shimx64.efi") || strings.Contains(trimmed, "grubx64.efi") {
			decl := BootloaderDeclaration{
				BinaryPath: trimmed,
				LineNumber: lineNum,
			}
			parts := strings.Fields(trimmed)
			for _, p := range parts {
				cleanP := strings.Trim(p, "\";,[]")
				if ValidateSHA256Hash(cleanP) {
					decl.SHA256Hash = cleanP
				}
			}
			cfg.Bootloaders = append(cfg.Bootloaders, decl)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading configuration lines: %w", err)
	}

	return cfg, nil
}

// ParseLockdownTelemetryJSON parses runtime kernel lockdown and UEFI telemetry from JSON.
func ParseLockdownTelemetryJSON(data []byte) (*LockdownTelemetryReport, error) {
	if len(data) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload exceeds %d bytes ceiling", MaxTelemetryBytes)
	}

	var report LockdownTelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal lockdown telemetry JSON: %w", err)
	}

	// Defensive defaults and normalization
	if report.HostName == "" {
		report.HostName = "unknown-host"
	}
	if report.CollectedAt.IsZero() {
		report.CollectedAt = time.Now().UTC()
	}
	if report.DBXVersion == "" {
		report.DBXVersion = "UEFI-DBX-DEFAULT"
	}
	if !report.DBXReleaseDate.IsZero() && report.DBXAgeDays == 0 {
		age := time.Since(report.DBXReleaseDate).Hours() / 24.0
		if age > 0 {
			report.DBXAgeDays = int(age)
		}
	}

	// Parse sysfs string format if LiveLockdownMode was given as a raw sysfs line
	report.LiveLockdownMode = ParseLiveLockdownSysfs(string(report.LiveLockdownMode))

	if len(report.Events) > MaxTelemetryEvents {
		report.Events = report.Events[:MaxTelemetryEvents]
	}

	return &report, nil
}

// ParseLockdownTelemetryFile reads and parses a JSON telemetry report from disk.
func ParseLockdownTelemetryFile(filePath string) (*LockdownTelemetryReport, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat telemetry file (%s): %w", cleanPath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry file (%s) exceeds maximum size limit of %d bytes", cleanPath, MaxTelemetryBytes)
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file (%s): %w", cleanPath, err)
	}

	return ParseLockdownTelemetryJSON(content)
}

// ExtractHexValue parses integer values represented in hex strings or decimal strings.
func ExtractHexValue(raw string) int64 {
	clean := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		v, err := strconv.ParseInt(clean[2:], 16, 64)
		if err == nil {
			return v
		}
	}
	v, err := strconv.ParseInt(clean, 10, 64)
	if err == nil {
		return v
	}
	return 0
}
