package hsm

import (
	"fmt"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditEncryptionConfig performs static security analysis on a Kubernetes KMSEncryptionConfig.
func AuditEncryptionConfig(cfg *KMSEncryptionConfig, feed *intel.Feed) []HSMViolation {
	violations := make([]HSMViolation, 0)
	if cfg == nil {
		return violations
	}

	srcFile := cfg.FilePath
	if srcFile == "" {
		srcFile = "k8s-encryption-config.yaml"
	}

	// HSM-ENC-001: Insecure etcd encryption at rest (identity provider first or no KMS)
	if cfg.PrimaryProviderType == "identity" || len(cfg.KMSProviders) == 0 {
		rule, _ := GetRule("HSM-ENC-001")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   rule.Description,
			Remediation:   rule.Remediation,
			ResourceURI:   srcFile,
			LineNumber:    1,
			ActualValue:   fmt.Sprintf("primary_provider=%s", cfg.PrimaryProviderType),
			ExpectedValue: "primary_provider=kms (v2)",
		})
	}

	// HSM-ENC-002: Deprecated KMS v1 plugin specification
	if !cfg.IsKMSv2 {
		rule, _ := GetRule("HSM-ENC-002")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   rule.Description,
			Remediation:   rule.Remediation,
			ResourceURI:   srcFile,
			LineNumber:    1,
			ActualValue:   fmt.Sprintf("apiVersion=%s", cfg.ApiVersion),
			ExpectedValue: "apiVersion=apiserver.config.k8s.io/v1 (KMS v2)",
		})
	}

	for _, p := range cfg.KMSProviders {
		if p.ApiVersion == KMSVersionV1 {
			rule, _ := GetRule("HSM-ENC-002")
			violations = append(violations, HSMViolation{
				RuleID:        rule.ID,
				Title:         rule.Title,
				Severity:      rule.Severity,
				CVSSScore:     rule.DefaultCVSS,
				Description:   fmt.Sprintf("KMS provider '%s' uses deprecated API version 'v1'.", p.Name),
				Remediation:   rule.Remediation,
				ResourceURI:   srcFile,
				ProviderName:  p.Name,
				ActualValue:   "apiVersion=v1",
				ExpectedValue: "apiVersion=v2",
			})
		}

		// HSM-ENC-008: Insecure KMS network transport (non-unix domain socket)
		if p.Endpoint != "" && !p.IsUnixSocket {
			rule, _ := GetRule("HSM-ENC-008")
			violations = append(violations, HSMViolation{
				RuleID:        rule.ID,
				Title:         rule.Title,
				Severity:      rule.Severity,
				CVSSScore:     rule.DefaultCVSS,
				Description:   fmt.Sprintf("KMS provider '%s' specifies network transport endpoint '%s'.", p.Name, p.Endpoint),
				Remediation:   rule.Remediation,
				ResourceURI:   srcFile,
				ProviderName:  p.Name,
				ActualValue:   p.Endpoint,
				ExpectedValue: "unix:///var/run/kmsplugin/socket.sock",
			})
		}
	}

	// HSM-ENC-009: Missing fallback KMS provider or single point of failure
	if len(cfg.KMSProviders) == 1 && !cfg.HasIdentityFallback && !cfg.HasKMSFallback {
		rule, _ := GetRule("HSM-ENC-009")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   "EncryptionConfiguration has only a single KMS provider without fallback failover.",
			Remediation:   rule.Remediation,
			ResourceURI:   srcFile,
			LineNumber:    1,
			ActualValue:   "kms_count=1, fallback=none",
			ExpectedValue: "secondary KMS provider or identity fallback declared",
		})
	}

	return violations
}

// AuditPKCS11 checks PKCS#11 configuration declarations for credential leaks and cipher strength.
func AuditPKCS11(decl *PKCS11Declaration, feed *intel.Feed) []HSMViolation {
	violations := make([]HSMViolation, 0)
	if decl == nil {
		return violations
	}

	srcFile := decl.SourceFile
	if srcFile == "" {
		srcFile = "pkcs11-config"
	}

	// HSM-ENC-003: Plaintext PKCS#11 PIN or password exposed in manifest
	if decl.HasPlaintextPIN {
		rule, _ := GetRule("HSM-ENC-003")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   rule.Description,
			Remediation:   rule.Remediation,
			ResourceURI:   srcFile,
			LineNumber:    decl.LineNumber,
			ProviderName:  decl.TokenLabel,
			ActualValue:   "pin-value=[EXPOSED_IN_MANIFEST]",
			ExpectedValue: "pin-source file with 0400 permissions or kernel keyring",
		})

		// Also flags HSM-ENC-012 for missing PIN masking/zeroization
		rule12, _ := GetRule("HSM-ENC-012")
		violations = append(violations, HSMViolation{
			RuleID:        rule12.ID,
			Title:         rule12.Title,
			Severity:      rule12.Severity,
			CVSSScore:     rule12.DefaultCVSS,
			Description:   rule12.Description,
			Remediation:   rule12.Remediation,
			ResourceURI:   srcFile,
			LineNumber:    decl.LineNumber,
			ProviderName:  decl.TokenLabel,
			ActualValue:   "plaintext pin in memory context",
			ExpectedValue: "zeroized secure memory envelope",
		})
	}

	// HSM-ENC-004: Insecure or deprecated cipher suite
	if decl.CipherSuite == Cipher3DES || decl.CipherSuite == CipherAESCBC128 || decl.CipherSuite == CipherRSA1024 {
		rule, _ := GetRule("HSM-ENC-004")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   fmt.Sprintf("PKCS#11 token '%s' utilizes weak cipher suite '%s'.", decl.TokenLabel, decl.CipherSuite),
			Remediation:   rule.Remediation,
			ResourceURI:   srcFile,
			LineNumber:    decl.LineNumber,
			ProviderName:  decl.TokenLabel,
			ActualValue:   string(decl.CipherSuite),
			ExpectedValue: "AES-GCM-256 or ChaCha20-Poly1305",
		})
	}

	return violations
}

// AuditTelemetry checks live KMS plugin telemetry for health, rotation age, and session leakage.
func AuditTelemetry(t *HSMRuntimeTelemetry, feed *intel.Feed) []HSMViolation {
	violations := make([]HSMViolation, 0)
	if t == nil {
		return violations
	}

	resURI := fmt.Sprintf("telemetry://%s/%s", t.ClusterID, t.NodeName)

	// HSM-ENC-005: KMS v2 plugin gRPC health check failure
	if t.PluginStatus == PluginStatusOffline || t.PluginStatus == PluginStatusDegraded {
		rule, _ := GetRule("HSM-ENC-005")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   fmt.Sprintf("KMS plugin '%s' on node '%s' reports status %s.", t.ProviderType, t.NodeName, t.PluginStatus),
			Remediation:   rule.Remediation,
			ResourceURI:   resURI,
			ProviderName:  string(t.ProviderType),
			ActualValue:   string(t.PluginStatus),
			ExpectedValue: string(PluginStatusHealthy),
		})
	}

	// HSM-ENC-007: Nitro Enclave session leakage or unsealed attestation
	if !t.NitroEnclaveOK {
		rule, _ := GetRule("HSM-ENC-007")
		cve := rule.AssociatedCVE
		if feed != nil {
			for _, item := range feed.Items {
				if item.ID == "CVE-2026-83190" {
					cve = item.ID
					break
				}
			}
		}
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   fmt.Sprintf("Nitro Enclave session handle on node '%s' is unsealed or leaking credentials.", t.NodeName),
			Remediation:   rule.Remediation,
			ResourceURI:   resURI,
			ProviderName:  string(t.ProviderType),
			MatchedCVE:    cve,
			ActualValue:   "nitro_enclave_ok=false",
			ExpectedValue: "nitro_enclave_ok=true (cryptographically sealed)",
		})
	}

	// HSM-ENC-006: Key Encryption Key rotation window
	for _, k := range t.ActiveKeys {
		if k.AgeDays > MaxRotationAgeDays {
			rule, _ := GetRule("HSM-ENC-006")
			sev := rule.Severity
			cvss := rule.DefaultCVSS
			if k.AgeDays > CriticalRotationAgeDays {
				sev = intel.SeverityCritical
				cvss = 9.1
			}
			violations = append(violations, HSMViolation{
				RuleID:        rule.ID,
				Title:         rule.Title,
				Severity:      sev,
				CVSSScore:     cvss,
				Description:   fmt.Sprintf("Key Encryption Key '%s' (%s) age is %.1f days (threshold: %.0f days).", k.KeyID, k.KeyLabel, k.AgeDays, MaxRotationAgeDays),
				Remediation:   rule.Remediation,
				ResourceURI:   resURI,
				ProviderName:  k.ProviderType,
				ActualValue:   fmt.Sprintf("%.1f days", k.AgeDays),
				ExpectedValue: "<= 90.0 days",
			})
		}
	}

	// HSM-ENC-010: Excessive KMS encryption latency or zero cache hit ratio
	if t.AverageLatencyMs > MaxKMSLatencyMs {
		rule, _ := GetRule("HSM-ENC-010")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   fmt.Sprintf("KMS plugin average latency is %.2f ms (threshold: %.0f ms).", t.AverageLatencyMs, MaxKMSLatencyMs),
			Remediation:   rule.Remediation,
			ResourceURI:   resURI,
			ProviderName:  string(t.ProviderType),
			ActualValue:   fmt.Sprintf("%.2f ms", t.AverageLatencyMs),
			ExpectedValue: "<= 100.0 ms",
		})
	}

	return violations
}

// AuditNixOSHost evaluates host system configurations for required HSM service daemons.
func AuditNixOSHost(p11List []PKCS11Declaration, nitroList []NitroEnclaveDeclaration, p11Enabled bool, nitroEnabled bool, filePath string) []HSMViolation {
	violations := make([]HSMViolation, 0)
	if !p11Enabled && !nitroEnabled && (len(p11List) > 0 || len(nitroList) > 0 || strings.Contains(filePath, "hsm")) {
		rule, _ := GetRule("HSM-ENC-011")
		violations = append(violations, HSMViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSSScore:     rule.DefaultCVSS,
			Description:   "NixOS configuration does not enable 'services.p11-kit' or 'hardware.nitro-enclaves'.",
			Remediation:   rule.Remediation,
			ResourceURI:   filePath,
			LineNumber:    1,
			ActualValue:   "p11_kit=false, nitro_enclaves=false",
			ExpectedValue: "services.p11-kit.enable = true or hardware.nitro-enclaves.enable = true",
		})
	}
	return violations
}
