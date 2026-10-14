package wireguard

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	RuleWGPlaintextPrivateKey   = "WG-MESH-001"
	RuleWGMpyMissingPSK         = "WG-MESH-002"
	RuleWGPlaintextPSK          = "WG-MESH-003"
	RuleWGPermissiveAllowedIPs  = "WG-MESH-004"
	RuleWGAllowedIPsOverlap     = "WG-MESH-005"
	RuleWGKeyExpired            = "WG-MESH-006"
	RuleWGKeyRotationWarning    = "WG-MESH-007"
	RuleWGStaleHandshake        = "WG-MESH-008"
	RuleWGPublicPortExposed     = "WG-MESH-009"
	RuleWGInvalidKeyFormat      = "WG-MESH-010"
	RuleWGSuboptimalMTU         = "WG-MESH-011"
	RuleWGThreatRadarMatch      = "WG-MESH-012"
)

// WireGuardRuleRegistry contains all canonical WireGuard mesh security rules.
var WireGuardRuleRegistry = map[string]WireGuardRule{
	RuleWGPlaintextPrivateKey: {
		ID:          RuleWGPlaintextPrivateKey,
		Title:       "Plaintext WireGuard Private Key Exposed in Nix Configuration",
		Category:    CategoryDeclarativeNix,
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.2,
		Description: "A WireGuard private key is embedded directly as a plaintext string in NixOS configuration files. Because /nix/store is world-readable by all unprivileged local users, private keys are immediately compromised.",
		Remediation: "Migrate private keys to encrypted secret management paths via 'privateKeyFile' using sops-nix, agenix, or runtime credentials stored in /run/keys/.",
		MatchedCVE:  "CVE-2026-31048",
	},
	RuleWGMpyMissingPSK: {
		ID:          RuleWGMpyMissingPSK,
		Title:       "Missing WireGuard Pre-Shared Key (PSK) for Post-Quantum Defense",
		Category:    CategoryDeclarativeNix,
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Description: "A WireGuard peer does not define a Pre-Shared Key (PSK). While Curve25519 provides robust classical security, an additional symmetric PSK provides vital defense-in-depth against future harvest-now-decrypt-later quantum attacks.",
		Remediation: "Generate a 256-bit symmetric pre-shared key ('wg genpsk') and configure 'presharedKeyFile' for all inter-node mesh peers.",
	},
	RuleWGPlaintextPSK: {
		ID:          RuleWGPlaintextPSK,
		Title:       "Hardcoded Plaintext Pre-Shared Key in Nix Configuration",
		Category:    CategoryDeclarativeNix,
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.4,
		Description: "A symmetric pre-shared key (presharedKey) is declared as a raw literal in NixOS files, exposing the symmetric secret to world-readable store paths.",
		Remediation: "Use 'presharedKeyFile' referencing an encrypted secret mounted at runtime with 0400 file permissions.",
	},
	RuleWGPermissiveAllowedIPs: {
		ID:          RuleWGPermissiveAllowedIPs,
		Title:       "Overly Permissive AllowedIPs (0.0.0.0/0) Without Default-Deny Firewall",
		Category:    CategoryNetworkCollision,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Description: "WireGuard peer specifies '0.0.0.0/0' or '::/0' in allowedIPs within a cluster mesh interface, routing all node outbound traffic through this peer and risking split-tunnel interception.",
		Remediation: "Restrict 'allowedIPs' strictly to the internal mesh subnet CIDR (e.g. 10.100.0.0/16) and isolate internet default gateways.",
	},
	RuleWGAllowedIPsOverlap: {
		ID:          RuleWGAllowedIPsOverlap,
		Title:       "Peer AllowedIPs Subnet Routing Collision & Traffic Hijacking Risk",
		Category:    CategoryNetworkCollision,
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Description: "Multiple WireGuard peers on the same interface declare overlapping or duplicate AllowedIPs subnets. WireGuard's Cryptokey Routing table will nondeterministically route packets to the latest cryptokey, causing packet loss or traffic interception.",
		Remediation: "Ensure every peer in the mesh interface has a strictly unique, non-overlapping host IP or dedicated subnet in allowedIPs.",
		MatchedCVE:  "CVE-2026-31048",
	},
	RuleWGKeyExpired: {
		ID:          RuleWGKeyExpired,
		Title:       "WireGuard Cryptographic Identity Key Exceeded 90-Day Lifetime",
		Category:    CategoryKeyRotation,
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.1,
		Description: "A WireGuard peer or interface identity key has exceeded the standard 90-day cryptographic lifecycle without rotation, violating zero-trust and compliance baselines.",
		Remediation: "Execute automated key rotation: generate new Curve25519 keypair, distribute public key to mesh peers, and revoke previous credentials.",
	},
	RuleWGKeyRotationWarning: {
		ID:          RuleWGKeyRotationWarning,
		Title:       "WireGuard Cryptographic Key Approaching Expiration (> 60 Days)",
		Category:    CategoryKeyRotation,
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.0,
		Description: "A WireGuard identity key is older than 60 days. Proactive key rotation should be scheduled before the 90-day hard expiration threshold is reached.",
		Remediation: "Schedule an automated rotation window to stage new ephemeral keys across cluster nodes.",
	},
	RuleWGStaleHandshake: {
		ID:          RuleWGStaleHandshake,
		Title:       "Stale / Abandoned WireGuard Peer Handshake Posture (> 24 Hours)",
		Category:    CategoryPeerPosture,
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.3,
		Description: "A configured WireGuard peer has not performed a cryptographic handshake in over 24 hours. Abandoned peers leave dormant routing slots and represent potential orphaned nodes.",
		Remediation: "Inspect peer node reachability, verify firewall UDP pass-through, or prune decommissioned peers from declarative NixOS manifests.",
	},
	RuleWGPublicPortExposed: {
		ID:          RuleWGPublicPortExposed,
		Title:       "WireGuard Listening Port Exposed on Public Interface Without Rate-Limiting",
		Category:    CategoryPeerPosture,
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.5,
		Description: "WireGuard UDP port (e.g. 51820) is declared without explicit host firewall filtering or iptables hashlimit DDoS protections on public network interfaces.",
		Remediation: "Bind WireGuard listeners to designated management interfaces or enforce kernel rate-limiting rules on incoming UDP packets.",
	},
	RuleWGInvalidKeyFormat: {
		ID:          RuleWGInvalidKeyFormat,
		Title:       "Invalid or Weak WireGuard Cryptographic Key Encoding",
		Category:    CategoryKeyRotation,
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Description: "A WireGuard public key or pre-shared key does not adhere to 32-byte Base64 encoding specifications (44 characters) or represents a weak all-zero key.",
		Remediation: "Regenerate keys using standard Curve25519 tooling ('wg genkey') ensuring valid Base64 serialization.",
	},
	RuleWGSuboptimalMTU: {
		ID:          RuleWGSuboptimalMTU,
		Title:       "Sub-optimal WireGuard MTU (> 1420) Triggering Overlay Fragmentation",
		Category:    CategoryDeclarativeNix,
		Severity:    intel.SeverityLow,
		CVSSScore:   4.2,
		Description: "The declared WireGuard interface MTU exceeds 1420 bytes on standard 1500-byte MTU physical networks, causing packet fragmentation or PMTUD blackholing for cluster overlay traffic.",
		Remediation: "Set interface MTU to 1420 (or 1360 for IPv6 / nested overlay encapsulation) to prevent fragmentation overhead.",
	},
	RuleWGThreatRadarMatch: {
		ID:          RuleWGThreatRadarMatch,
		Title:       "WireGuard Peer Endpoint / CIDR Threat Radar Correlation Match",
		Category:    CategoryThreatRadar,
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.8,
		Description: "A WireGuard peer endpoint IP address, hostname, or allowedIPs subnet correlates directly with an active threat advisory or compromised indicator in the threat intelligence feed.",
		Remediation: "Immediately quarantine the peer, revoke its public key, inspect node logs for intrusion, and update cluster firewalls.",
	},
}
