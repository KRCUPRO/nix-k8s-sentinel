package nixstore

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditStoreConfig audits a parsed StoreSecurityConfig against canonical rules.
func AuditStoreConfig(cfg *StoreSecurityConfig) []StoreViolation {
	if cfg == nil {
		return nil
	}

	violations := make([]StoreViolation, 0)
	target := cfg.FilePath
	if cfg.HostName != "" {
		target = fmt.Sprintf("%s (%s)", cfg.FilePath, cfg.HostName)
	}

	// 1. NIX-STORE-001: require-sigs enforcement (CVE-2026-81930)
	if cfg.RequireSigs == nil || !*cfg.RequireSigs {
		rule, _ := LookupRule("NIX-STORE-001")
		line := cfg.LineNumbers["require_sigs"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  rule.Description,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
			MatchedCVE:   "CVE-2026-81930",
		})
	}

	// 2. NIX-STORE-002: trusted-public-keys Ed25519 validation
	if len(cfg.TrustedPublicKeys) == 0 {
		rule, _ := LookupRule("NIX-STORE-002")
		line := cfg.LineNumbers["trusted_public_keys"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "trusted-public-keys is empty or unconfigured, preventing Ed25519 cryptographic signature verification of substitutes.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	} else {
		for _, key := range cfg.TrustedPublicKeys {
			if !key.ValidFormat {
				rule, _ := LookupRule("NIX-STORE-002")
				violations = append(violations, StoreViolation{
					RuleID:       rule.ID,
					Title:        rule.Name,
					Description:  fmt.Sprintf("Invalid Ed25519 public key format for '%s': key must be formatted as '<name>:<base64(32-bytes)>'.", key.RawString),
					Severity:     rule.Severity,
					CVSSScore:    rule.CVSSScore,
					ConfigTarget: target,
					FilePath:     cfg.FilePath,
					StartLine:    key.LineNumber,
					Remediation:  rule.Remediation,
				})
			}
		}
	}

	// 3. NIX-STORE-003: Plaintext HTTP substituters
	for _, sub := range cfg.Substituters {
		if !sub.IsHTTPS && strings.HasPrefix(sub.URL, "http://") {
			rule, _ := LookupRule("NIX-STORE-003")
			violations = append(violations, StoreViolation{
				RuleID:       rule.ID,
				Title:        rule.Name,
				Description:  fmt.Sprintf("Substituter '%s' uses insecure plaintext HTTP transport, exposing substitute archives to active network MITM tampering.", sub.URL),
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				ConfigTarget: target,
				FilePath:     cfg.FilePath,
				StartLine:    sub.LineNumber,
				Remediation:  rule.Remediation,
			})
		}
	}

	// 4. NIX-STORE-004: Overly permissive trusted-users
	for _, u := range cfg.TrustedUsers {
		uLower := strings.ToLower(u)
		if uLower == "*" || uLower == "@wheel" || uLower == "nobody" || uLower == "@users" {
			rule, _ := LookupRule("NIX-STORE-004")
			line := cfg.LineNumbers["trusted_users"]
			if line == 0 {
				line = 1
			}
			violations = append(violations, StoreViolation{
				RuleID:       rule.ID,
				Title:        rule.Name,
				Description:  fmt.Sprintf("trusted-users contains overly broad authority '%s', allowing non-privileged users to bypass signature checks and inject custom substituters.", u),
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				ConfigTarget: target,
				FilePath:     cfg.FilePath,
				StartLine:    line,
				Remediation:  rule.Remediation,
			})
			break
		}
	}

	// 5. NIX-STORE-005: Sandboxing and fallback
	if cfg.Sandbox == nil || !*cfg.Sandbox {
		rule, _ := LookupRule("NIX-STORE-005")
		line := cfg.LineNumbers["sandbox"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "Build sandboxing is disabled (sandbox = false or unset), allowing build scripts to access host network, filesystem, and processes.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	}
	if cfg.SandboxFallback != nil && *cfg.SandboxFallback {
		rule, _ := LookupRule("NIX-STORE-005")
		line := cfg.LineNumbers["sandbox_fallback"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "sandbox-fallback is enabled, permitting non-sandboxed build execution if namespace isolation fails.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	}

	// 6. NIX-STORE-006: Pure evaluation & flake config
	if cfg.PureEval != nil && !*cfg.PureEval {
		rule, _ := LookupRule("NIX-STORE-006")
		line := cfg.LineNumbers["pure_eval"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "pure-eval is disabled (pure-eval = false), permitting impure builds to read uncommitted state and host environment secrets.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	}
	if cfg.AcceptFlakeConfig != nil && *cfg.AcceptFlakeConfig {
		rule, _ := LookupRule("NIX-STORE-006")
		line := cfg.LineNumbers["accept_flake_config"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "accept-flake-config is enabled (accept-flake-config = true), allowing untrusted flakes to override daemon substitution and sandbox parameters.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	}

	// 7. NIX-STORE-007: Build users group isolation
	if cfg.BuildUsersGroup == "" {
		rule, _ := LookupRule("NIX-STORE-007")
		line := cfg.LineNumbers["build_users_group"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "build-users-group is not defined, running builds as the daemon user instead of an isolated unprivileged nixbld pool.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	} else if cfg.BuildUsersCount > 0 && cfg.BuildUsersCount < 10 {
		rule, _ := LookupRule("NIX-STORE-007")
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  fmt.Sprintf("Insufficient build user pool count (%d < 10), risking build concurrency starvation and UID collisions.", cfg.BuildUsersCount),
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    1,
			Remediation:  rule.Remediation,
		})
	}

	// 8. NIX-STORE-008: netrc-file credentials protection
	if cfg.NetrcFile != "" {
		if strings.HasPrefix(cfg.NetrcFile, "/nix/store") {
			rule, _ := LookupRule("NIX-STORE-008")
			line := cfg.LineNumbers["netrc_file"]
			if line == 0 {
				line = 1
			}
			violations = append(violations, StoreViolation{
				RuleID:       rule.ID,
				Title:        rule.Name,
				Description:  fmt.Sprintf("netrc-file points to world-readable path inside /nix/store ('%s'), leaking private cache authentication tokens to all local users.", cfg.NetrcFile),
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				ConfigTarget: target,
				FilePath:     cfg.FilePath,
				StartLine:    line,
				Remediation:  rule.Remediation,
			})
		}
	}

	// 9. NIX-STORE-012: GC configuration check
	if cfg.GCAutomatic != nil && !*cfg.GCAutomatic {
		rule, _ := LookupRule("NIX-STORE-012")
		line := cfg.LineNumbers["gc_automatic"]
		if line == 0 {
			line = 1
		}
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  "Automated garbage collection is explicitly disabled (nix.gc.automatic = false), risking store disk volume exhaustion.",
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     cfg.FilePath,
			StartLine:    line,
			Remediation:  rule.Remediation,
		})
	}

	return violations
}

// AuditStoreTelemetry correlates runtime substitute telemetry against anomaly thresholds.
func AuditStoreTelemetry(tel *NixStoreTelemetryReport) []StoreViolation {
	if tel == nil {
		return nil
	}

	violations := make([]StoreViolation, 0)
	target := fmt.Sprintf("telemetry://%s", tel.HostName)

	// 1. NIX-STORE-009: High signature rejection rate
	if tel.SignatureVerificationsTotal > 0 && tel.SignatureRejectionRate > 5.0 {
		rule, _ := LookupRule("NIX-STORE-009")
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  fmt.Sprintf("High substitute signature rejection rate (%.1f%% rejected: %d / %d), indicating active cache poisoning attempts or key desync.", tel.SignatureRejectionRate, tel.SignatureRejectionsCount, tel.SignatureVerificationsTotal),
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     target,
			StartLine:    1,
			Remediation:  rule.Remediation,
		})
	}

	// 2. NIX-STORE-010: NAR checksum failures
	if tel.NARChecksumFailuresCount > 0 {
		rule, _ := LookupRule("NIX-STORE-010")
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  fmt.Sprintf("Detected %d NAR archive SHA-256 checksum mismatches during substitute extraction, indicating payload corruption or cache tampering.", tel.NARChecksumFailuresCount),
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     target,
			StartLine:    1,
			Remediation:  rule.Remediation,
			MatchedCVE:   "CVE-2026-81930",
		})
	}

	// 3. NIX-STORE-011: Excessive download latency
	if tel.DownloadP95LatencyMs > 15000.0 {
		rule, _ := LookupRule("NIX-STORE-011")
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  fmt.Sprintf("Substitute download P95 latency is excessively high (%.1f ms > 15000 ms), causing build timeouts and worker queue starvation.", tel.DownloadP95LatencyMs),
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     target,
			StartLine:    1,
			Remediation:  rule.Remediation,
		})
	}

	// 4. NIX-STORE-012: Store disk usage threshold
	if tel.StoreUsagePercent > 85.0 {
		rule, _ := LookupRule("NIX-STORE-012")
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  fmt.Sprintf("Nix store disk utilization is critically high (%.1f%% > 85.0%% ceiling, used %d of %d bytes).", tel.StoreUsagePercent, tel.StoreUsedBytes, tel.StoreCapacityBytes),
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     target,
			StartLine:    1,
			Remediation:  rule.Remediation,
		})
	}

	// 5. NIX-STORE-004: Unauthorized elevation attempts
	if tel.UnauthorizedElevationAttempts > 0 {
		rule, _ := LookupRule("NIX-STORE-004")
		violations = append(violations, StoreViolation{
			RuleID:       rule.ID,
			Title:        rule.Name,
			Description:  fmt.Sprintf("Detected %d unauthorized trusted-users privilege elevation attempts by non-whitelisted users.", tel.UnauthorizedElevationAttempts),
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			ConfigTarget: target,
			FilePath:     target,
			StartLine:    1,
			Remediation:  rule.Remediation,
		})
	}

	return violations
}

// ComputeStoreCompliance calculates overall compliance metrics and score.
func ComputeStoreCompliance(violations []StoreViolation, configsCount int, tel *NixStoreTelemetryReport) StoreSummary {
	summary := StoreSummary{
		TotalConfigs:       configsCount,
		TotalViolations:    len(violations),
		SandboxingEnforced: true,
		SignaturesEnforced: true,
	}

	scoreDeductions := 0.0

	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
			scoreDeductions += 15.0
		case intel.SeverityHigh:
			summary.HighCount++
			scoreDeductions += 8.0
		case intel.SeverityMedium:
			summary.MediumCount++
			scoreDeductions += 4.0
		default:
			summary.LowCount++
			scoreDeductions += 2.0
		}

		if v.RuleID == "NIX-STORE-001" || v.RuleID == "NIX-STORE-002" || v.RuleID == "NIX-STORE-009" || v.RuleID == "NIX-STORE-010" {
			summary.SignaturesEnforced = false
		}
		if v.RuleID == "NIX-STORE-005" {
			summary.SandboxingEnforced = false
		}
	}

	finalScore := 100.0 - scoreDeductions
	if finalScore < 0.0 {
		finalScore = 0.0
	}
	summary.ComplianceScore = math.Round(finalScore*10.0) / 10.0

	return summary
}
