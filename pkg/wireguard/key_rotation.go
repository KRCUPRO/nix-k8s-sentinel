package wireguard

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// KeyRotationEngine performs cryptographic validation, lifecycle auditing, and key redaction.
type KeyRotationEngine struct{}

// NewKeyRotationEngine instantiates a key rotation audit engine.
func NewKeyRotationEngine() *KeyRotationEngine {
	return &KeyRotationEngine{}
}

// ValidateKeyFormat checks if a given key string is a valid 32-byte Base64-encoded Curve25519 or PSK key.
func (e *KeyRotationEngine) ValidateKeyFormat(keyStr string) (bool, error) {
	trimmed := strings.TrimSpace(keyStr)
	if len(trimmed) != 44 {
		return false, fmt.Errorf("key string length must be exactly 44 base64 characters, got %d", len(trimmed))
	}

	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return false, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	if len(decoded) != 32 {
		return false, fmt.Errorf("decoded raw key length must be exactly 32 bytes, got %d", len(decoded))
	}

	// Guard against degenerate all-zero or all-ones key bytes
	allZeros := true
	allOnes := true
	for _, b := range decoded {
		if b != 0x00 {
			allZeros = false
		}
		if b != 0xFF {
			allOnes = false
		}
	}

	if allZeros || allOnes {
		return false, fmt.Errorf("cryptographically weak or degenerate key pattern detected")
	}

	return true, nil
}

// MaskKey redacts the middle characters of a WireGuard public or private key to prevent secret leakage in logs.
func (e *KeyRotationEngine) MaskKey(keyStr string) string {
	trimmed := strings.TrimSpace(keyStr)
	if len(trimmed) < 10 {
		return "[REDACTED-KEY]"
	}
	return fmt.Sprintf("%s...%s", trimmed[:4], trimmed[len(trimmed)-4:])
}

// AuditKeyAge evaluates key age against the 60-day warning and 90-day hard expiration thresholds.
func (e *KeyRotationEngine) AuditKeyAge(createdAt time.Time, now time.Time) (KeyRotationStatus, int) {
	if createdAt.IsZero() {
		return KeyStatusActive, 0
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	duration := now.Sub(createdAt)
	days := int(duration.Hours() / 24)
	if days < 0 {
		days = 0
	}

	if days >= DefaultKeyRotationDays {
		return KeyStatusExpired, days
	}
	if days >= WarningKeyRotationDays {
		return KeyStatusNeedsRotation, days
	}

	return KeyStatusActive, days
}

// InspectPeerKeys audits key validity and rotation posture for a runtime peer.
func (e *KeyRotationEngine) InspectPeerKeys(ifaceName string, peer RuntimePeerTelemetry, now time.Time) []WireGuardViolation {
	var violations []WireGuardViolation

	// 1. Validate Public Key Format
	if valid, err := e.ValidateKeyFormat(peer.PublicKey); !valid {
		rule := WireGuardRuleRegistry[RuleWGInvalidKeyFormat]
		violations = append(violations, WireGuardViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			InterfaceName: ifaceName,
			PeerPublicKey: e.MaskKey(peer.PublicKey),
			Endpoint:      peer.Endpoint,
			Severity:      rule.Severity,
			CVSSScore:     rule.CVSSScore,
			Description:   fmt.Sprintf("Peer on interface %s has invalid cryptographic public key: %v", ifaceName, err),
			Remediation:   rule.Remediation,
		})
	}

	// 2. Audit Key Age & Expiration
	if !peer.KeyCreatedAt.IsZero() {
		status, days := e.AuditKeyAge(peer.KeyCreatedAt, now)
		if status == KeyStatusExpired {
			rule := WireGuardRuleRegistry[RuleWGKeyExpired]
			violations = append(violations, WireGuardViolation{
				RuleID:        rule.ID,
				Title:         rule.Title,
				InterfaceName: ifaceName,
				PeerPublicKey: e.MaskKey(peer.PublicKey),
				Endpoint:      peer.Endpoint,
				Severity:      rule.Severity,
				CVSSScore:     rule.CVSSScore,
				Description:   fmt.Sprintf("Peer %s key age is %d days (created: %s), exceeding 90-day maximum lifetime.", e.MaskKey(peer.PublicKey), days, peer.KeyCreatedAt.Format("2006-01-02")),
				Remediation:   rule.Remediation,
			})
		} else if status == KeyStatusNeedsRotation {
			rule := WireGuardRuleRegistry[RuleWGKeyRotationWarning]
			violations = append(violations, WireGuardViolation{
				RuleID:        rule.ID,
				Title:         rule.Title,
				InterfaceName: ifaceName,
				PeerPublicKey: e.MaskKey(peer.PublicKey),
				Endpoint:      peer.Endpoint,
				Severity:      rule.Severity,
				CVSSScore:     rule.CVSSScore,
				Description:   fmt.Sprintf("Peer %s key age is %d days (created: %s), approaching 90-day rotation deadline.", e.MaskKey(peer.PublicKey), days, peer.KeyCreatedAt.Format("2006-01-02")),
				Remediation:   rule.Remediation,
			})
		}
	}

	// 3. Check for Missing PSK in Runtime Peer
	if !peer.PresharedKeyPresent {
		rule := WireGuardRuleRegistry[RuleWGMpyMissingPSK]
		violations = append(violations, WireGuardViolation{
			RuleID:        rule.ID,
			Title:         rule.Title,
			InterfaceName: ifaceName,
			PeerPublicKey: e.MaskKey(peer.PublicKey),
			Endpoint:      peer.Endpoint,
			Severity:      rule.Severity,
			CVSSScore:     rule.CVSSScore,
			Description:   fmt.Sprintf("Peer %s does not have an active symmetric pre-shared key (PSK) configured.", e.MaskKey(peer.PublicKey)),
			Remediation:   rule.Remediation,
		})
	}

	return violations
}

// SummarizeKeyRotation compiles high-level key rotation metrics across all audited peers.
func (e *KeyRotationEngine) SummarizeKeyRotation(peers []RuntimePeerTelemetry, now time.Time) KeyRotationSummary {
	summary := KeyRotationSummary{
		TotalKeys: len(peers),
	}

	for _, peer := range peers {
		if peer.KeyCreatedAt.IsZero() {
			summary.ActiveKeys++
			continue
		}

		status, days := e.AuditKeyAge(peer.KeyCreatedAt, now)
		if days > summary.OldestKeyAgeDays {
			summary.OldestKeyAgeDays = days
		}

		switch status {
		case KeyStatusExpired:
			summary.ExpiredKeys++
		case KeyStatusNeedsRotation:
			summary.NeedsRotationKeys++
		case KeyStatusActive:
			summary.ActiveKeys++
		}
	}

	return summary
}
