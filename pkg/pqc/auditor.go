package pqc

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditControlPlaneConfig evaluates Kubernetes control plane components against PQC & CNSA 2.0 standards.
func AuditControlPlaneConfig(cfg *K8sControlPlaneTLSConfig, feed *intel.Feed) []PQCViolation {
	var violations []PQCViolation
	if cfg == nil {
		return violations
	}

	resName := fmt.Sprintf("%s/tls-config", cfg.Component)

	// 1. Audit TLS Protocol Minimum Version (PQC-TLS-001)
	minVer := strings.TrimSpace(cfg.TLSMinVersion)
	if minVer == "" || minVer == "VersionTLS10" || minVer == "VersionTLS11" || minVer == "VersionTLS12" || minVer == "1.0" || minVer == "1.1" || minVer == "1.2" {
		rule, _ := LookupRule("PQC-TLS-001")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   cfg.Component,
			Target:      "kubernetes",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: fmt.Sprintf("Component '%s' configures insecure TLS minimum version '%s' (expected 'VersionTLS13')", cfg.Component, minVer),
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 2. Audit Hybrid Post-Quantum Key Encapsulation (PQC-TLS-002)
	hasHybridGroup := false
	for _, g := range cfg.KeyExchangeGroups {
		gl := strings.ToLower(g)
		if strings.Contains(gl, "mlkem") || strings.Contains(gl, "kyber") || strings.Contains(gl, "ml-kem") {
			hasHybridGroup = true
			break
		}
	}
	if !hasHybridGroup {
		rule, _ := LookupRule("PQC-TLS-002")
		cve := rule.MatchedCVE
		if feed != nil {
			for _, item := range feed.Items {
				if item.Component == "pqc-tls" || strings.Contains(strings.ToLower(item.Title), "post-quantum") {
					cve = item.ID
					break
				}
			}
		}
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   cfg.Component,
			Target:      "kubernetes",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: fmt.Sprintf("Component '%s' lacks hybrid post-quantum key encapsulation groups (ML-KEM/Kyber), exposing control plane channels to retroactive Harvest-Now-Decrypt-Later decryption", cfg.Component),
			Remediation: rule.Remediation,
			MatchedCVE:  cve,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 3. Audit Cipher Suites for Weak / Deprecated Algorithms (PQC-TLS-003)
	hasWeakCipher := false
	has128BitOnly := len(cfg.TLSCipherSuites) > 0
	hasSHA1 := false

	for _, c := range cfg.TLSCipherSuites {
		cl := strings.ToUpper(c)
		if strings.Contains(cl, "CBC") || strings.Contains(cl, "3DES") || strings.Contains(cl, "RC4") || strings.HasPrefix(cl, "TLS_RSA_") {
			hasWeakCipher = true
		}
		if strings.Contains(cl, "256") || strings.Contains(cl, "CHACHA20") {
			has128BitOnly = false
		}
		if strings.Contains(cl, "SHA") && !strings.Contains(cl, "SHA256") && !strings.Contains(cl, "SHA384") && !strings.Contains(cl, "SHA512") {
			hasSHA1 = true
		}
	}

	if hasWeakCipher {
		rule, _ := LookupRule("PQC-TLS-003")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   cfg.Component,
			Target:      "kubernetes",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: fmt.Sprintf("Component '%s' declares weak or deprecated classical cipher suites (CBC/3DES/static RSA)", cfg.Component),
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 4. Audit CNSA 2.0 Symmetric Key Length (PQC-TLS-004)
	if has128BitOnly {
		rule, _ := LookupRule("PQC-TLS-004")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   cfg.Component,
			Target:      "kubernetes",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: fmt.Sprintf("Component '%s' restricts cipher suites to 128-bit symmetric keys, failing CNSA 2.0 256-bit requirement", cfg.Component),
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 5. Audit CNSA 2.0 Hash Digest (PQC-TLS-005)
	if hasSHA1 {
		rule, _ := LookupRule("PQC-TLS-005")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   cfg.Component,
			Target:      "kubernetes",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: fmt.Sprintf("Component '%s' configures insecure SHA-1 or legacy hash digest algorithms", cfg.Component),
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 6. etcd Specific Peer Transport Audit (PQC-TLS-009)
	if cfg.Component == "etcd" {
		peerVer := strings.TrimSpace(cfg.PeerTLSMinVersion)
		if peerVer == "" || peerVer == "VersionTLS12" || peerVer == "1.2" {
			rule, _ := LookupRule("PQC-TLS-009")
			violations = append(violations, PQCViolation{
				RuleID:      rule.RuleID,
				Title:       rule.Title,
				Component:   cfg.Component,
				Target:      "kubernetes",
				Resource:    resName,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Description: "Distributed etcd peer transport lacks quantum-safe mutual TLS 1.3 policy",
				Remediation: rule.Remediation,
				Location:    cfg.FilePath,
				LineNumber:  cfg.StartLine,
			})
		}
	}

	// 7. Kubelet Downgrade Vulnerability Audit (PQC-TLS-010)
	if cfg.Component == "kubelet" && (len(cfg.TLSCipherSuites) == 0 || minVer != "VersionTLS13") {
		rule, _ := LookupRule("PQC-TLS-010")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   cfg.Component,
			Target:      "kubernetes",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: "Kubelet allows negotiable TLS cipher fallback and non-PQC downgrade",
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 8. Expired or Draft PQC Parameter Audit (PQC-TLS-011)
	for _, g := range cfg.KeyExchangeGroups {
		gl := strings.ToLower(g)
		if strings.Contains(gl, "draft") || strings.Contains(gl, "kyber-v1") || strings.Contains(gl, "kyber-v2") {
			rule, _ := LookupRule("PQC-TLS-011")
			violations = append(violations, PQCViolation{
				RuleID:      rule.RuleID,
				Title:       rule.Title,
				Component:   cfg.Component,
				Target:      "kubernetes",
				Resource:    resName,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Description: fmt.Sprintf("Key exchange group '%s' references deprecated pre-standard draft specification", g),
				Remediation: rule.Remediation,
				Location:    cfg.FilePath,
				LineNumber:  cfg.StartLine,
			})
		}
	}

	return violations
}

// AuditNixOSCrypto evaluates NixOS OpenSSL and GnuTLS configuration modules.
func AuditNixOSCrypto(cfg *NixOSCryptoConfig, feed *intel.Feed) []PQCViolation {
	var violations []PQCViolation
	if cfg == nil {
		return violations
	}

	resName := "nixos/crypto-policy"

	// 1. Audit OpenSSL Provider for OQS / PQC (PQC-TLS-007)
	hasOQSProvider := false
	for _, p := range cfg.OpenSSLProviders {
		pl := strings.ToLower(p)
		if pl == "oqsprovider" || pl == "mlkem" || pl == "oqs" {
			hasOQSProvider = true
			break
		}
	}
	if !hasOQSProvider {
		rule, _ := LookupRule("PQC-TLS-007")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   "openssl",
			Target:      "nixos",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: "NixOS OpenSSL configuration does not activate 'oqsprovider' or native post-quantum provider in providers list",
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 2. Audit OpenSSL Default Groups for Hybrid PQC (PQC-TLS-002)
	hasHybridGroup := false
	for _, g := range cfg.OpenSSLDefaultGroups {
		gl := strings.ToLower(g)
		if strings.Contains(gl, "mlkem") || strings.Contains(gl, "kyber") || strings.Contains(gl, "ml-kem") {
			hasHybridGroup = true
			break
		}
	}
	if !hasHybridGroup {
		rule, _ := LookupRule("PQC-TLS-002")
		cve := rule.MatchedCVE
		if feed != nil {
			for _, item := range feed.Items {
				if item.Component == "pqc-tls" || strings.Contains(strings.ToLower(item.Title), "post-quantum") {
					cve = item.ID
					break
				}
			}
		}
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   "openssl",
			Target:      "nixos",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: "NixOS OpenSSL default groups lack hybrid post-quantum key exchange (e.g. X25519MLKEM768)",
			Remediation: rule.Remediation,
			MatchedCVE:  cve,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	// 3. Audit GnuTLS Priority String (PQC-TLS-008)
	if cfg.GnuTLSPriorityString != "" {
		hasGnuTLSPQC := false
		for _, g := range cfg.GnuTLSGroups {
			gl := strings.ToLower(g)
			if strings.Contains(gl, "kyber") || strings.Contains(gl, "mlkem") {
				hasGnuTLSPQC = true
				break
			}
		}
		if !hasGnuTLSPQC || !strings.Contains(cfg.GnuTLSPriorityString, "TLS1.3") {
			rule, _ := LookupRule("PQC-TLS-008")
			violations = append(violations, PQCViolation{
				RuleID:      rule.RuleID,
				Title:       rule.Title,
				Component:   "gnutls",
				Target:      "nixos",
				Resource:    resName,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Description: fmt.Sprintf("GnuTLS priority string '%s' does not enforce TLS 1.3 or quantum-safe groups", cfg.GnuTLSPriorityString),
				Remediation: rule.Remediation,
				Location:    cfg.FilePath,
				LineNumber:  cfg.StartLine,
			})
		}
	}

	// 4. Audit OpenSSL Minimum Protocol (PQC-TLS-001)
	if cfg.OpenSSLMinProtocol != "" && cfg.OpenSSLMinProtocol != "TLSv1.3" {
		rule, _ := LookupRule("PQC-TLS-001")
		violations = append(violations, PQCViolation{
			RuleID:      rule.RuleID,
			Title:       rule.Title,
			Component:   "openssl",
			Target:      "nixos",
			Resource:    resName,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Description: fmt.Sprintf("OpenSSL MinProtocol set to '%s' (expected 'TLSv1.3')", cfg.OpenSSLMinProtocol),
			Remediation: rule.Remediation,
			Location:    cfg.FilePath,
			LineNumber:  cfg.StartLine,
		})
	}

	return violations
}

// AuditTelemetry inspects active TLS handshakes for quantum resistance and protocol security.
func AuditTelemetry(telemetry *PQCRuntimeTelemetry, feed *intel.Feed) ([]PQCViolation, float64, float64) {
	var violations []PQCViolation
	if telemetry == nil || len(telemetry.Handshakes) == 0 {
		return violations, 0.0, 0.0
	}

	hybridCount := 0
	tls13Count := 0
	total := len(telemetry.Handshakes)

	for i, h := range telemetry.Handshakes {
		loc := fmt.Sprintf("runtime/handshake[%d]", i)

		// 1. Check protocol version
		if h.ProtocolVersion == string(TLSVersion13) {
			tls13Count++
		} else {
			rule, _ := LookupRule("PQC-TLS-001")
			violations = append(violations, PQCViolation{
				RuleID:      rule.RuleID,
				Title:       rule.Title,
				Component:   h.Component,
				Target:      "kubernetes",
				Resource:    h.Endpoint,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Description: fmt.Sprintf("Active handshake at %s negotiated legacy protocol '%s'", h.Endpoint, h.ProtocolVersion),
				Remediation: rule.Remediation,
				Location:    loc,
				LineNumber:  i + 1,
			})
		}

		// 2. Check Key Encapsulation (Hybrid PQC)
		isHybrid := h.IsHybridPQC
		groupLower := strings.ToLower(h.KeyExchangeGroup)
		if strings.Contains(groupLower, "mlkem") || strings.Contains(groupLower, "kyber") {
			isHybrid = true
		}

		if isHybrid {
			hybridCount++
		} else {
			rule, _ := LookupRule("PQC-TLS-002")
			cve := rule.MatchedCVE
			if feed != nil {
				for _, item := range feed.Items {
					if item.Component == "pqc-tls" || strings.Contains(strings.ToLower(item.Title), "post-quantum") {
						cve = item.ID
						break
					}
				}
			}
			violations = append(violations, PQCViolation{
				RuleID:      rule.RuleID,
				Title:       rule.Title,
				Component:   h.Component,
				Target:      "kubernetes",
				Resource:    h.Endpoint,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Description: fmt.Sprintf("Handshake at %s negotiated classical key exchange '%s' without quantum-safe hybrid encapsulation", h.Endpoint, h.KeyExchangeGroup),
				Remediation: rule.Remediation,
				MatchedCVE:  cve,
				Location:    loc,
				LineNumber:  i + 1,
			})
		}

		// 3. Check Signature Algorithm for Classical-Only Certificate (PQC-TLS-006)
		sigLower := strings.ToLower(h.SignatureAlgorithm)
		if strings.Contains(sigLower, "rsa") || strings.Contains(sigLower, "sha256") || strings.Contains(sigLower, "secp256r1") {
			if !strings.Contains(sigLower, "mldsa") && !strings.Contains(sigLower, "dilithium") {
				rule, _ := LookupRule("PQC-TLS-006")
				violations = append(violations, PQCViolation{
					RuleID:      rule.RuleID,
					Title:       rule.Title,
					Component:   h.Component,
					Target:      "kubernetes",
					Resource:    h.Endpoint,
					Severity:    rule.Severity,
					CVSSScore:   rule.CVSSScore,
					Description: fmt.Sprintf("Handshake at %s uses classical-only certificate signature '%s'", h.Endpoint, h.SignatureAlgorithm),
					Remediation: rule.Remediation,
					Location:    loc,
					LineNumber:  i + 1,
				})
			}
		}
	}

	hybridPct := math.Round((float64(hybridCount)/float64(total))*1000) / 10
	tls13Pct := math.Round((float64(tls13Count)/float64(total))*1000) / 10

	return violations, hybridPct, tls13Pct
}

// EvaluateCNSACompliance computes the CNSA 2.0 readiness level based on cipher suites and key exchange groups.
func EvaluateCNSACompliance(ciphers []string, groups []string, tlsMinVersion string) CNSAComplianceLevel {
	if tlsMinVersion != string(TLSVersion13) && tlsMinVersion != "VersionTLS13" {
		return CNSANonCompliant
	}

	hasAES256 := false
	hasWeak := false
	for _, c := range ciphers {
		cu := strings.ToUpper(c)
		if strings.Contains(cu, "AES_256_GCM") || strings.Contains(cu, "CHACHA20") {
			hasAES256 = true
		}
		if strings.Contains(cu, "CBC") || strings.Contains(cu, "3DES") || strings.Contains(cu, "RC4") {
			hasWeak = true
		}
	}

	if hasWeak || !hasAES256 {
		return CNSANonCompliant
	}

	hasHybrid1024 := false
	hasHybrid768 := false
	for _, g := range groups {
		gl := strings.ToLower(g)
		if strings.Contains(gl, "mlkem1024") || strings.Contains(gl, "ml-kem-1024") {
			hasHybrid1024 = true
		}
		if strings.Contains(gl, "mlkem768") || strings.Contains(gl, "kyber768") {
			hasHybrid768 = true
		}
	}

	if hasHybrid1024 {
		return CNSACompliant2033
	}
	if hasHybrid768 {
		return CNSACompliant2030
	}

	return CNSATransitional
}
