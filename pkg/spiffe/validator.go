package spiffe

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ParseSPIFFEID parses and validates a raw SPIFFE ID according to the SPIFFE specification.
// Format: spiffe://<trust-domain>/<path>
func ParseSPIFFEID(raw string) (trustDomain string, path string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty SPIFFE ID")
	}

	if !strings.HasPrefix(raw, "spiffe://") {
		return "", "", fmt.Errorf("invalid scheme: must start with 'spiffe://'")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("malformed SPIFFE URI: %w", err)
	}

	if u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("invalid URI scheme: %s", u.Scheme)
	}

	trustDomain = strings.ToLower(u.Host)
	if trustDomain == "" {
		return "", "", fmt.Errorf("missing trust domain in SPIFFE ID: %s", raw)
	}

	path = u.Path
	if path == "" || path == "/" {
		return "", "", fmt.Errorf("missing path component in SPIFFE ID: %s", raw)
	}

	return trustDomain, path, nil
}

// AuditSVID inspects an X.509 SVID record against zero-trust cryptographic invariants.
func AuditSVID(record SVIDRecord, primaryTrustDomain string, federatedDomains []string, now time.Time) []SPIFFEViolation {
	var violations []SPIFFEViolation

	td, _, err := ParseSPIFFEID(record.SPIFFEID)
	if err != nil {
		violations = append(violations, SPIFFEViolation{
			RuleID:       "SPIFFE-SVID-001",
			Title:        "Untrusted Foreign Trust Domain in SPIFFE ID",
			Severity:     CanonicalRules[0].DefaultSeverity,
			CVSSScore:    CanonicalRules[0].BaseCVSS,
			Category:     CategoryTrustDomain,
			ResourceKind: "X509SVID",
			ResourceName: record.WorkloadID,
			Namespace:    record.Namespace,
			Message:      fmt.Sprintf("Invalid SPIFFE ID formatting '%s': %v", record.SPIFFEID, err),
			Remediation:  CanonicalRules[0].Remediation,
			SPIFFEID:     record.SPIFFEID,
			Workload:     record.WorkloadID,
		})
	} else if primaryTrustDomain != "" && td != strings.ToLower(primaryTrustDomain) {
		isFederated := false
		for _, fd := range federatedDomains {
			if td == strings.ToLower(fd) {
				isFederated = true
				break
			}
		}
		if !isFederated {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-001",
				Title:        "Untrusted Foreign Trust Domain in SPIFFE ID",
				Severity:     CanonicalRules[0].DefaultSeverity,
				CVSSScore:    CanonicalRules[0].BaseCVSS,
				Category:     CategoryTrustDomain,
				ResourceKind: "X509SVID",
				ResourceName: record.WorkloadID,
				Namespace:    record.Namespace,
				Message:      fmt.Sprintf("Workload '%s' presents SVID for unauthorized foreign trust domain '%s' (Primary: '%s')", record.WorkloadID, td, primaryTrustDomain),
				Remediation:  CanonicalRules[0].Remediation,
				SPIFFEID:     record.SPIFFEID,
				TrustDomain:  td,
				Workload:     record.WorkloadID,
			})
		}
	}

	// 2. Lifespan check (Max 24 hours)
	if !record.IssuedAt.IsZero() && !record.ExpiresAt.IsZero() {
		lifespan := record.ExpiresAt.Sub(record.IssuedAt).Hours()
		if lifespan > MaxSVIDLifespanHours {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-002",
				Title:        "Excessive SVID Certificate Lifespan (> 24 Hours)",
				Severity:     CanonicalRules[1].DefaultSeverity,
				CVSSScore:    CanonicalRules[1].BaseCVSS,
				Category:     CategorySVIDValidity,
				ResourceKind: "X509SVID",
				ResourceName: record.WorkloadID,
				Namespace:    record.Namespace,
				Message:      fmt.Sprintf("SVID for workload '%s' has a lifespan of %.1f hours, exceeding the 24.0h ephemeral threshold", record.WorkloadID, lifespan),
				Remediation:  CanonicalRules[1].Remediation,
				SPIFFEID:     record.SPIFFEID,
				Workload:     record.WorkloadID,
			})
		}
	}

	// 3. Expiration & Renewal Window (< 15 Minutes Remaining or Expired)
	if !record.ExpiresAt.IsZero() {
		remaining := record.ExpiresAt.Sub(now).Hours()
		if remaining <= 0 {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-003",
				Title:        "SVID Approaching Expiration Without Renewal Window (< 15 Minutes Remaining)",
				Severity:     CanonicalRules[2].DefaultSeverity,
				CVSSScore:    CanonicalRules[2].BaseCVSS,
				Category:     CategorySVIDValidity,
				ResourceKind: "X509SVID",
				ResourceName: record.WorkloadID,
				Namespace:    record.Namespace,
				Message:      fmt.Sprintf("SVID for workload '%s' has expired (%s ago) without active renewal", record.WorkloadID, now.Sub(record.ExpiresAt).Round(time.Minute)),
				Remediation:  CanonicalRules[2].Remediation,
				SPIFFEID:     record.SPIFFEID,
				Workload:     record.WorkloadID,
			})
		} else if remaining < MinSVIDRenewalRemainingHours {
			mins := int(remaining * 60)
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-003",
				Title:        "SVID Approaching Expiration Without Renewal Window (< 15 Minutes Remaining)",
				Severity:     CanonicalRules[2].DefaultSeverity,
				CVSSScore:    CanonicalRules[2].BaseCVSS,
				Category:     CategorySVIDValidity,
				ResourceKind: "X509SVID",
				ResourceName: record.WorkloadID,
				Namespace:    record.Namespace,
				Message:      fmt.Sprintf("SVID for workload '%s' expires in %d minutes (below 15m safety renewal buffer)", record.WorkloadID, mins),
				Remediation:  CanonicalRules[2].Remediation,
				SPIFFEID:     record.SPIFFEID,
				Workload:     record.WorkloadID,
			})
		}
	}

	// 4. Cryptographic Key Strength (Reject RSA < 2048 or weak ciphers)
	kt := strings.ToUpper(record.KeyType)
	if strings.Contains(kt, "RSA") && record.KeyBits > 0 && record.KeyBits < 2048 {
		violations = append(violations, SPIFFEViolation{
			RuleID:       "SPIFFE-SVID-009",
			Title:        "Weak Cryptographic Key Algorithm in X.509 SVID",
			Severity:     CanonicalRules[8].DefaultSeverity,
			CVSSScore:    CanonicalRules[8].BaseCVSS,
			Category:     CategoryCryptographicKey,
			ResourceKind: "X509SVID",
			ResourceName: record.WorkloadID,
			Namespace:    record.Namespace,
			Message:      fmt.Sprintf("SVID for workload '%s' uses insecure RSA key length (%d bits < 2048)", record.WorkloadID, record.KeyBits),
			Remediation:  CanonicalRules[8].Remediation,
			SPIFFEID:     record.SPIFFEID,
			Workload:     record.WorkloadID,
		})
	} else if strings.Contains(kt, "SHA1") || strings.Contains(kt, "MD5") {
		violations = append(violations, SPIFFEViolation{
			RuleID:       "SPIFFE-SVID-009",
			Title:        "Weak Cryptographic Key Algorithm in X.509 SVID",
			Severity:     CanonicalRules[8].DefaultSeverity,
			CVSSScore:    CanonicalRules[8].BaseCVSS,
			Category:     CategoryCryptographicKey,
			ResourceKind: "X509SVID",
			ResourceName: record.WorkloadID,
			Namespace:    record.Namespace,
			Message:      fmt.Sprintf("SVID for workload '%s' uses deprecated digest algorithm '%s'", record.WorkloadID, record.KeyType),
			Remediation:  CanonicalRules[8].Remediation,
			SPIFFEID:     record.SPIFFEID,
			Workload:     record.WorkloadID,
		})
	}

	return violations
}

// AuditRegistrationEntry audits declarative SPIRE registration entries for attestation selector hygiene.
func AuditRegistrationEntry(entry WorkloadIdentity, primaryTrustDomain string, federatedDomains []string) []SPIFFEViolation {
	var violations []SPIFFEViolation

	// 1. Check for permissive wildcard selectors
	if len(entry.Selectors) == 0 {
		violations = append(violations, SPIFFEViolation{
			RuleID:       "SPIFFE-SVID-004",
			Title:        "Permissive Wildcard Attestation Selector in SPIRE Registration Entry",
			Severity:     CanonicalRules[3].DefaultSeverity,
			CVSSScore:    CanonicalRules[3].BaseCVSS,
			Category:     CategoryAttestation,
			ResourceKind: "SpireRegistrationEntry",
			ResourceName: entry.Name,
			Namespace:    entry.Namespace,
			Message:      fmt.Sprintf("Registration entry '%s' declares zero attestation selectors, permitting any node process to claim identity '%s'", entry.Name, entry.SPIFFEID),
			Remediation:  CanonicalRules[3].Remediation,
			SPIFFEID:     entry.SPIFFEID,
			Workload:     entry.Name,
		})
	} else {
		for k, v := range entry.Selectors {
			if v == "*" || v == ".*" {
				violations = append(violations, SPIFFEViolation{
					RuleID:       "SPIFFE-SVID-004",
					Title:        "Permissive Wildcard Attestation Selector in SPIRE Registration Entry",
					Severity:     CanonicalRules[3].DefaultSeverity,
					CVSSScore:    CanonicalRules[3].BaseCVSS,
					Category:     CategoryAttestation,
					ResourceKind: "SpireRegistrationEntry",
					ResourceName: entry.Name,
					Namespace:    entry.Namespace,
					Message:      fmt.Sprintf("Registration entry '%s' specifies wildcard attestation selector '%s: %s'", entry.Name, k, v),
					Remediation:  CanonicalRules[3].Remediation,
					SPIFFEID:     entry.SPIFFEID,
					Workload:     entry.Name,
				})
			}
		}
	}

	// 2. Cross-domain trust validation
	if entry.TrustDomain != "" && primaryTrustDomain != "" && strings.ToLower(entry.TrustDomain) != strings.ToLower(primaryTrustDomain) {
		isFederated := false
		for _, fd := range federatedDomains {
			if strings.ToLower(entry.TrustDomain) == strings.ToLower(fd) {
				isFederated = true
				break
			}
		}
		if !isFederated {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-008",
				Title:        "Unfederated Cross-Cluster Workload Identity Reference",
				Severity:     CanonicalRules[7].DefaultSeverity,
				CVSSScore:    CanonicalRules[7].BaseCVSS,
				Category:     CategoryTrustDomain,
				ResourceKind: "SpireRegistrationEntry",
				ResourceName: entry.Name,
				Namespace:    entry.Namespace,
				Message:      fmt.Sprintf("Registration entry '%s' references unmanaged external trust domain '%s'", entry.Name, entry.TrustDomain),
				Remediation:  CanonicalRules[7].Remediation,
				SPIFFEID:     entry.SPIFFEID,
				TrustDomain:  entry.TrustDomain,
				Workload:     entry.Name,
			})
		}
	}

	return violations
}
