package wireguard

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB upper limit to prevent memory exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes limits telemetry payload sizes to 5MB.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// DefaultKeyRotationDays establishes the 90-day cryptographic key lifetime.
	DefaultKeyRotationDays = 90
	// WarningKeyRotationDays flags keys approaching expiration at 60 days.
	WarningKeyRotationDays = 60
	// StaleHandshakeDuration marks peers without handshakes for 24 hours as dormant.
	StaleHandshakeDuration = 24 * time.Hour
	// OptimalWireGuardMTU defines standard overlay MTU over Ethernet (1500 - 80).
	OptimalWireGuardMTU = 1420
)

// RuleCategory categorizes WireGuard mesh network security rules.
type RuleCategory string

const (
	CategoryDeclarativeNix   RuleCategory = "DECLARATIVE_NIX"
	CategoryKeyRotation      RuleCategory = "KEY_ROTATION"
	CategoryPeerPosture      RuleCategory = "PEER_POSTURE"
	CategoryThreatRadar      RuleCategory = "THREAT_RADAR"
	CategoryNetworkCollision RuleCategory = "NETWORK_COLLISION"
)

// KeyRotationStatus represents the administrative lifecycle status of a WireGuard key.
type KeyRotationStatus string

const (
	KeyStatusActive        KeyRotationStatus = "ACTIVE"
	KeyStatusNeedsRotation KeyRotationStatus = "NEEDS_ROTATION"
	KeyStatusExpired       KeyRotationStatus = "EXPIRED"
	KeyStatusInvalid       KeyRotationStatus = "INVALID"
)

// WireGuardViolation models a detected cryptographic, configuration, or posture anomaly.
type WireGuardViolation struct {
	RuleID        string         `json:"rule_id"`
	Title         string         `json:"title"`
	InterfaceName string         `json:"interface_name"`
	PeerPublicKey string         `json:"peer_public_key,omitempty"`
	Endpoint      string         `json:"endpoint,omitempty"`
	Severity      intel.Severity `json:"severity"`
	CVSSScore     float64        `json:"cvss_score"`
	Description   string         `json:"description"`
	Remediation   string         `json:"remediation"`
	MatchedCVE    string         `json:"matched_cve,omitempty"`
	FilePath      string         `json:"file_path,omitempty"`
	StartLine     int            `json:"start_line,omitempty"`
}

// WireGuardRule defines metadata and baseline metrics for a WireGuard security rule.
type WireGuardRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Category    RuleCategory   `json:"category"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// PeerDeclaration models a peer block in declarative NixOS networking.
type PeerDeclaration struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	PresharedKeyFile    string   `json:"preshared_key_file,omitempty"`
	AllowedIPs         []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
	StartLine           int      `json:"start_line,omitempty"`
}

// InterfaceDeclaration models a declarative NixOS WireGuard interface.
type InterfaceDeclaration struct {
	Name           string            `json:"name"`
	IPs            []string          `json:"ips"`
	ListenPort     int               `json:"listen_port"`
	PrivateKey     string            `json:"private_key,omitempty"`
	PrivateKeyFile string            `json:"private_key_file,omitempty"`
	MTU            int               `json:"mtu,omitempty"`
	Peers          []PeerDeclaration `json:"peers"`
	FilePath       string            `json:"file_path,omitempty"`
	StartLine      int               `json:"start_line,omitempty"`
}

// RuntimePeerTelemetry models live WireGuard peer telemetry from wg show.
type RuntimePeerTelemetry struct {
	PublicKey           string    `json:"public_key"`
	PresharedKeyPresent bool      `json:"preshared_key_present"`
	Endpoint            string    `json:"endpoint"`
	AllowedIPs         []string  `json:"allowed_ips"`
	LatestHandshake     time.Time `json:"latest_handshake"`
	TransferRxBytes     uint64    `json:"transfer_rx_bytes"`
	TransferTxBytes     uint64    `json:"transfer_tx_bytes"`
	PersistentKeepalive int       `json:"persistent_keepalive"`
	KeyCreatedAt        time.Time `json:"key_created_at"`
}

// RuntimeInterfaceTelemetry models live interface stats.
type RuntimeInterfaceTelemetry struct {
	InterfaceName string                 `json:"interface_name"`
	PublicKey     string                 `json:"public_key"`
	ListenPort    int                    `json:"listen_port"`
	Peers         []RuntimePeerTelemetry `json:"peers"`
	KeyCreatedAt  time.Time              `json:"key_created_at"`
}

// KeyRotationSummary aggregates cryptographic key ages across the mesh.
type KeyRotationSummary struct {
	TotalKeys        int `json:"total_keys"`
	ActiveKeys       int `json:"active_keys"`
	NeedsRotationKeys int `json:"needs_rotation_keys"`
	ExpiredKeys      int `json:"expired_keys"`
	OldestKeyAgeDays int `json:"oldest_key_age_days"`
}

// ReconciliationReport captures drift between declarative NixOS declarations and runtime mesh.
type ReconciliationReport struct {
	InterfaceCount        int                 `json:"interface_count"`
	DeclarativePeersCount int                 `json:"declarative_peers_count"`
	RuntimePeersCount     int                 `json:"runtime_peers_count"`
	UnmanagedPeersCount   int                 `json:"unmanaged_peers_count"`
	MissingPeersCount     int                 `json:"missing_peers_count"`
	StaleHandshakeCount   int                 `json:"stale_handshake_count"`
	KeyRotation           KeyRotationSummary  `json:"key_rotation"`
	Violations            []WireGuardViolation `json:"violations"`
}
