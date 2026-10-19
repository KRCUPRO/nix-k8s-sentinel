package nixstore

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Regex for key-value extraction in Nix expressions and nix.conf
	reNixSettingLine = regexp.MustCompile(`^(?:nix\.settings\.)?([a-zA-Z0-9_\-]+)\s*=\s*(.+?);?$`)
	reNixGCLine      = regexp.MustCompile(`^(?:nix\.gc\.)?([a-zA-Z0-9_\-]+)\s*=\s*(.+?);?$`)
	reQuotedString   = regexp.MustCompile(`"([^"]+)"`)
	reWord           = regexp.MustCompile(`[^\s,;\[\]"']+`)
)

// ValidateEd25519PublicKey verifies whether a string conforms to the canonical Nix public key format: `<name>:<base64-key>`.
// The base64 portion must decode to exactly 32 bytes (256 bits).
func ValidateEd25519PublicKey(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	name := strings.TrimSpace(parts[0])
	keyBase64 := strings.TrimSpace(parts[1])
	if name == "" || keyBase64 == "" {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return name, keyBase64, false
	}
	if len(decoded) != 32 {
		return name, keyBase64, false
	}

	return name, keyBase64, true
}

// ParseNixStoreConfig parses raw bytes of a NixOS module or nix.conf file into a StoreSecurityConfig.
func ParseNixStoreConfig(data []byte, filename string) (*StoreSecurityConfig, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest payload exceeds safety limit (%d bytes > %d limit)", len(data), MaxManifestBytes)
	}

	cfg := &StoreSecurityConfig{
		FilePath:          filename,
		TrustedPublicKeys: make([]Ed25519KeyDeclaration, 0),
		Substituters:      make([]SubstituterDeclaration, 0),
		TrustedUsers:      make([]string, 0),
		AllowedUsers:      make([]string, 0),
		LineNumbers:       make(map[string]int),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	inListKey := ""
	var listItems []string

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			return nil, fmt.Errorf("configuration line count exceeds safety limit (%d lines)", MaxAllowedScanLines)
		}

		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle ongoing multi-line list accumulation
		if inListKey != "" {
			items := extractStringItems(line)
			listItems = append(listItems, items...)
			if strings.Contains(line, "]") {
				assignList(cfg, inListKey, listItems, lineNum)
				inListKey = ""
				listItems = nil
			}
			continue
		}

		// Check for host name attribute if available
		if strings.HasPrefix(line, "networking.hostName") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), "\";")
				cfg.HostName = val
			}
		}

		// 1. Check for nix.gc settings
		if strings.Contains(line, "nix.gc.automatic") || strings.HasPrefix(line, "gc.automatic") {
			if strings.Contains(line, "true") {
				t := true
				cfg.GCAutomatic = &t
				cfg.LineNumbers["gc_automatic"] = lineNum
			} else if strings.Contains(line, "false") {
				f := false
				cfg.GCAutomatic = &f
				cfg.LineNumbers["gc_automatic"] = lineNum
			}
			continue
		}

		// 2. Extract key-value directives
		key, val := extractKeyValue(line)
		if key == "" {
			continue
		}

		// Check if value opens a multi-line list: contains '[' but not ']'
		if strings.Contains(val, "[") && !strings.Contains(val, "]") {
			inListKey = key
			cfg.LineNumbers[normalizeKeyName(key)] = lineNum
			listItems = extractStringItems(val)
			continue
		}

		switch key {
		case "require-sigs", "requireSigs":
			b := parseBoolValue(val)
			cfg.RequireSigs = &b
			cfg.LineNumbers["require_sigs"] = lineNum

		case "sandbox":
			b := parseBoolValue(val)
			cfg.Sandbox = &b
			cfg.LineNumbers["sandbox"] = lineNum

		case "sandbox-fallback", "sandboxFallback":
			b := parseBoolValue(val)
			cfg.SandboxFallback = &b
			cfg.LineNumbers["sandbox_fallback"] = lineNum

		case "pure-eval", "pureEval":
			b := parseBoolValue(val)
			cfg.PureEval = &b
			cfg.LineNumbers["pure_eval"] = lineNum

		case "accept-flake-config", "acceptFlakeConfig":
			b := parseBoolValue(val)
			cfg.AcceptFlakeConfig = &b
			cfg.LineNumbers["accept_flake_config"] = lineNum

		case "build-users-group", "buildUsersGroup":
			cfg.BuildUsersGroup = extractFirstString(val)
			cfg.LineNumbers["build_users_group"] = lineNum

		case "nr-build-users", "buildUsersCount":
			if count, err := strconv.Atoi(extractFirstString(val)); err == nil {
				cfg.BuildUsersCount = count
			}

		case "netrc-file", "netrcFile":
			cfg.NetrcFile = extractFirstString(val)
			cfg.LineNumbers["netrc_file"] = lineNum

		case "trusted-public-keys", "trustedPublicKeys":
			cfg.LineNumbers["trusted_public_keys"] = lineNum
			assignList(cfg, key, extractStringItems(val), lineNum)

		case "substituters":
			cfg.LineNumbers["substituters"] = lineNum
			assignList(cfg, key, extractStringItems(val), lineNum)

		case "trusted-users", "trustedUsers":
			cfg.LineNumbers["trusted_users"] = lineNum
			assignList(cfg, key, extractStringItems(val), lineNum)

		case "allowed-users", "allowedUsers":
			cfg.LineNumbers["allowed_users"] = lineNum
			assignList(cfg, key, extractStringItems(val), lineNum)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading configuration stream: %w", err)
	}

	return cfg, nil
}

// ParseNixStoreConfigFile reads and parses a configuration file from disk.
func ParseNixStoreConfigFile(filePath string) (*StoreSecurityConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read store config file (%s): %w", filePath, err)
	}
	return ParseNixStoreConfig(data, filePath)
}

// ParseStoreTelemetryJSON deserializes a JSON runtime telemetry report.
func ParseStoreTelemetryJSON(data []byte) (*NixStoreTelemetryReport, error) {
	if len(data) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload exceeds safety limit (%d bytes > %d limit)", len(data), MaxTelemetryBytes)
	}

	var report NixStoreTelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal nix store telemetry json: %w", err)
	}

	// Calculate usage percentage if not pre-populated
	if report.StoreUsagePercent == 0 && report.StoreCapacityBytes > 0 {
		report.StoreUsagePercent = float64(report.StoreUsedBytes) / float64(report.StoreCapacityBytes) * 100.0
	}

	// Calculate signature rejection rate
	if report.SignatureVerificationsTotal > 0 {
		report.SignatureRejectionRate = float64(report.SignatureRejectionsCount) / float64(report.SignatureVerificationsTotal) * 100.0
	}

	// Enforce telemetry event ceiling
	if len(report.Events) > MaxTelemetryEvents {
		report.Events = report.Events[:MaxTelemetryEvents]
	}

	return &report, nil
}

// ParseStoreTelemetryFile reads and parses a telemetry report from disk.
func ParseStoreTelemetryFile(filePath string) (*NixStoreTelemetryReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file (%s): %w", filePath, err)
	}
	return ParseStoreTelemetryJSON(data)
}

// Helper: extract key and value from line
func extractKeyValue(line string) (string, string) {
	line = strings.TrimSpace(line)
	// Strip trailing semicolon if any
	line = strings.TrimSuffix(line, ";")

	if m := reNixSettingLine.FindStringSubmatch(line); len(m) == 3 {
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	}

	// Check standard nix.conf format: key = val
	idx := strings.Index(line, "=")
	if idx > 0 {
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		key = strings.TrimPrefix(key, "nix.settings.")
		return key, val
	}

	return "", ""
}

// Helper: parse boolean value
func parseBoolValue(val string) bool {
	val = strings.ToLower(strings.Trim(val, "\";' "))
	return val == "true" || val == "1" || val == "yes"
}

// Helper: extract string items from list or space-delimited string
func extractStringItems(val string) []string {
	val = strings.Trim(val, "[]();")
	// Try quoted string matches first
	matches := reQuotedString.FindAllStringSubmatch(val, -1)
	if len(matches) > 0 {
		res := make([]string, 0, len(matches))
		for _, m := range matches {
			if len(m) > 1 {
				res = append(res, strings.TrimSpace(m[1]))
			}
		}
		return res
	}

	// Fallback to word splitting
	words := reWord.FindAllString(val, -1)
	res := make([]string, 0, len(words))
	for _, w := range words {
		cleaned := strings.Trim(w, "\"'")
		if cleaned != "" {
			res = append(res, cleaned)
		}
	}
	return res
}

// Helper: extract first string value
func extractFirstString(val string) string {
	items := extractStringItems(val)
	if len(items) > 0 {
		return items[0]
	}
	return strings.Trim(val, "\"' ;")
}

// Helper: normalize key name for line numbers map
func normalizeKeyName(key string) string {
	switch key {
	case "requireSigs":
		return "require_sigs"
	case "trustedPublicKeys":
		return "trusted_public_keys"
	case "sandboxFallback":
		return "sandbox_fallback"
	case "pureEval":
		return "pure_eval"
	case "acceptFlakeConfig":
		return "accept_flake_config"
	case "buildUsersGroup":
		return "build_users_group"
	case "trustedUsers":
		return "trusted_users"
	case "allowedUsers":
		return "allowed_users"
	case "netrcFile":
		return "netrc_file"
	default:
		return strings.ReplaceAll(key, "-", "_")
	}
}

// Helper: assign parsed list items to the appropriate configuration field
func assignList(cfg *StoreSecurityConfig, key string, items []string, lineNum int) {
	switch key {
	case "trusted-public-keys", "trustedPublicKeys":
		for _, k := range items {
			name, pk, valid := ValidateEd25519PublicKey(k)
			cfg.TrustedPublicKeys = append(cfg.TrustedPublicKeys, Ed25519KeyDeclaration{
				KeyName:     name,
				PublicKey:   pk,
				RawString:   k,
				ValidFormat: valid,
				LineNumber:  lineNum,
			})
		}
	case "substituters":
		for _, u := range items {
			cfg.Substituters = append(cfg.Substituters, SubstituterDeclaration{
				URL:        u,
				IsHTTPS:    strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "s3://"),
				LineNumber: lineNum,
			})
		}
	case "trusted-users", "trustedUsers":
		cfg.TrustedUsers = append(cfg.TrustedUsers, items...)
	case "allowed-users", "allowedUsers":
		cfg.AllowedUsers = append(cfg.AllowedUsers, items...)
	}
}

