package wireguard

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Reconciler audits runtime WireGuard telemetry against declarative NixOS configuration states.
type Reconciler struct {
	feed      *intel.Feed
	keyEngine *KeyRotationEngine
}

// NewReconciler constructs a mesh reconciler.
func NewReconciler(feed *intel.Feed) *Reconciler {
	return &Reconciler{
		feed:      feed,
		keyEngine: NewKeyRotationEngine(),
	}
}

// ParseTelemetryFile loads WireGuard runtime telemetry from a JSON export.
func (r *Reconciler) ParseTelemetryFile(filePath string) ([]RuntimeInterfaceTelemetry, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat telemetry file %s: %w", filePath, err)
	}

	if fi.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry file exceeds size limit (%d bytes)", MaxTelemetryBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file %s: %w", filePath, err)
	}

	var telemetry []RuntimeInterfaceTelemetry
	if err := json.Unmarshal(data, &telemetry); err != nil {
		// Attempt single interface object parsing as fallback
		var single RuntimeInterfaceTelemetry
		if errSingle := json.Unmarshal(data, &single); errSingle == nil && single.InterfaceName != "" {
			telemetry = append(telemetry, single)
		} else {
			return nil, fmt.Errorf("failed to unmarshal WireGuard telemetry: %w", err)
		}
	}

	return telemetry, nil
}

// Reconcile performs cross-domain reconciliation between declarative interfaces and live runtime telemetry.
func (r *Reconciler) Reconcile(declared []InterfaceDeclaration, runtime []RuntimeInterfaceTelemetry, now time.Time) *ReconciliationReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	report := &ReconciliationReport{
		InterfaceCount: len(runtime),
		Violations:     make([]WireGuardViolation, 0),
	}

	// Index declarative peers by interface:map[PublicKey]PeerDeclaration
	declMap := make(map[string]map[string]PeerDeclaration)
	for _, di := range declared {
		if _, exists := declMap[di.Name]; !exists {
			declMap[di.Name] = make(map[string]PeerDeclaration)
		}
		for _, p := range di.Peers {
			declMap[di.Name][p.PublicKey] = p
			report.DeclarativePeersCount++
		}
	}

	var allRuntimePeers []RuntimePeerTelemetry

	// 1. Audit each runtime interface
	for _, ri := range runtime {
		declPeers, hasDeclIface := declMap[ri.InterfaceName]
		seenDeclKeys := make(map[string]bool)

		for _, rp := range ri.Peers {
			report.RuntimePeersCount++
			allRuntimePeers = append(allRuntimePeers, rp)

			maskedKey := r.keyEngine.MaskKey(rp.PublicKey)

			// 1.1 Key validity & rotation checks
			keyViols := r.keyEngine.InspectPeerKeys(ri.InterfaceName, rp, now)
			report.Violations = append(report.Violations, keyViols...)

			// 1.2 Handshake Posture (Stale / Abandoned Peer)
			if !rp.LatestHandshake.IsZero() {
				handshakeAge := now.Sub(rp.LatestHandshake)
				if handshakeAge > StaleHandshakeDuration {
					report.StaleHandshakeCount++
					rule := WireGuardRuleRegistry[RuleWGStaleHandshake]
					hours := int(handshakeAge.Hours())
					report.Violations = append(report.Violations, WireGuardViolation{
						RuleID:        rule.ID,
						Title:         rule.Title,
						InterfaceName: ri.InterfaceName,
						PeerPublicKey: maskedKey,
						Endpoint:      rp.Endpoint,
						Severity:      rule.Severity,
						CVSSScore:     rule.CVSSScore,
						Description:   fmt.Sprintf("Peer %s on interface '%s' last completed handshake %d hours ago (stale > 24h).", maskedKey, ri.InterfaceName, hours),
						Remediation:   rule.Remediation,
					})
				}
			}

			// 1.3 Threat Radar Cross-Correlation
			if r.feed != nil && len(r.feed.Items) > 0 {
				r.correlateThreatRadar(ri.InterfaceName, rp, &report.Violations)
			}

			// 1.4 Unmanaged Ephemeral Peer Check
			if hasDeclIface {
				if _, ok := declPeers[rp.PublicKey]; !ok {
					report.UnmanagedPeersCount++
					rule := WireGuardRuleRegistry[RuleWGPeerPostureUnknown]
					if rule.ID == "" {
						rule = WireGuardRule{
							ID:          "WG-MESH-013",
							Title:       "Unmanaged Runtime WireGuard Peer Detected (Configuration Drift)",
							Severity:    intel.SeverityHigh,
							CVSSScore:   7.6,
							Remediation: "Audit node authorized keys or add missing peer to declarative NixOS manifest.",
						}
					}
					report.Violations = append(report.Violations, WireGuardViolation{
						RuleID:        rule.ID,
						Title:         rule.Title,
						InterfaceName: ri.InterfaceName,
						PeerPublicKey: maskedKey,
						Endpoint:      rp.Endpoint,
						Severity:      rule.Severity,
						CVSSScore:     rule.CVSSScore,
						Description:   fmt.Sprintf("Runtime peer %s (endpoint: %s) is active on interface '%s' but not declared in NixOS configuration.", maskedKey, rp.Endpoint, ri.InterfaceName),
						Remediation:   rule.Remediation,
					})
				} else {
					seenDeclKeys[rp.PublicKey] = true
				}
			}
		}

		// 1.5 Missing Declarative Peers Check
		if hasDeclIface {
			for declKey, dp := range declPeers {
				if !seenDeclKeys[declKey] {
					report.MissingPeersCount++
					rule := WireGuardRule{
						ID:          "WG-MESH-014",
						Title:       "Declarative WireGuard Peer Absent in Runtime Mesh",
						Severity:    intel.SeverityMedium,
						CVSSScore:   5.4,
						Remediation: "Verify peer host connectivity, wireguard service status, and physical routing path.",
					}
					report.Violations = append(report.Violations, WireGuardViolation{
						RuleID:        rule.ID,
						Title:         rule.Title,
						InterfaceName: ri.InterfaceName,
						PeerPublicKey: r.keyEngine.MaskKey(dp.PublicKey),
						Endpoint:      dp.Endpoint,
						Severity:      rule.Severity,
						CVSSScore:     rule.CVSSScore,
						Description:   fmt.Sprintf("Peer %s declared for interface '%s' is not registered or communicating in active runtime mesh.", r.keyEngine.MaskKey(dp.PublicKey), ri.InterfaceName),
						Remediation:   rule.Remediation,
					})
				}
			}
		}
	}

	report.KeyRotation = r.keyEngine.SummarizeKeyRotation(allRuntimePeers, now)
	return report
}

// correlateThreatRadar cross-checks peer endpoints and IPs with the threat intelligence feed.
func (r *Reconciler) correlateThreatRadar(ifaceName string, peer RuntimePeerTelemetry, violations *[]WireGuardViolation) {
	maskedKey := r.keyEngine.MaskKey(peer.PublicKey)

	for _, item := range r.feed.Items {
		isTargetMatch := item.Target == "nixos" || item.Target == "kubernetes"
		if !isTargetMatch {
			continue
		}

		// Match against threat component or description indicators
		isWireGuardRelated := strings.Contains(strings.ToLower(item.Component), "wireguard") ||
			strings.Contains(strings.ToLower(item.Title), "wireguard") ||
			strings.Contains(strings.ToLower(item.Description), "wireguard")

		if isWireGuardRelated {
			// Check if peer endpoint matches threat indicators
			if peer.Endpoint != "" && (strings.Contains(item.Description, peer.Endpoint) || strings.Contains(item.Title, peer.Endpoint)) {
				rule := WireGuardRuleRegistry[RuleWGThreatRadarMatch]
				*violations = append(*violations, WireGuardViolation{
					RuleID:        rule.ID,
					Title:         rule.Title,
					InterfaceName: ifaceName,
					PeerPublicKey: maskedKey,
					Endpoint:      peer.Endpoint,
					Severity:      rule.Severity,
					CVSSScore:     rule.CVSSScore,
					Description:   fmt.Sprintf("Peer endpoint '%s' matches threat advisory %s (%s).", peer.Endpoint, item.ID, item.Title),
					Remediation:   rule.Remediation,
					MatchedCVE:    item.ID,
				})
			}
		}
	}
}

// Constant fallback for unmanaged peer rule
var RuleWGPeerPostureUnknown = "WG-MESH-013"
