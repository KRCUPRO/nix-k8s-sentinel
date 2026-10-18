package wgenclave

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// Memory bounds and streaming limits for defensive memory safety.
const (
	MaxManifestBytes     int64         = 10 * 1024 * 1024 // 10MB maximum manifest payload
	MaxTelemetryBytes    int64         = 5 * 1024 * 1024  // 5MB maximum runtime telemetry payload
	MaxAllowedScanLines  int           = 20000            // Maximum configuration lines to process
	MaxTelemetryEvents   int           = 5000             // Maximum telemetry events per audit cycle
	MaxAttestationAge    time.Duration = 3600 * time.Second // 1 hour max attestation report freshness
	DefaultMinTCBSVN     uint32        = 4                // Default minimum hardware TCB security version number
)

// EnclavePlatform identifies the underlying confidential computing hardware root-of-trust.
type EnclavePlatform string

const (
	PlatformSEVSNP EnclavePlatform = "AMD_SEV_SNP"
	PlatformTDX    EnclavePlatform = "INTEL_TDX"
	PlatformNitro  EnclavePlatform = "AWS_NITRO"
	PlatformTPM    EnclavePlatform = "GENERIC_TPM"
)

// TunnelState represents the operational posture of a WireGuard peer connection.
type TunnelState string

const (
	TunnelEstablished TunnelState = "ESTABLISHED"
	TunnelRejected    TunnelState = "REJECTED"
	TunnelPending     TunnelState = "PENDING_ATTESTATION"
	TunnelRevoked     TunnelState = "REVOKED"
)

// EnclavePeerConfig encapsulates declarative WireGuard peer attestation requirements.
type EnclavePeerConfig struct {
	InterfaceName          string             `json:"interface_name"`
	PeerName               string             `json:"peer_name"`
	PublicKey              string             `json:"public_key"`
	Endpoint               string             `json:"endpoint"`
	AllowedIPs             []string           `json:"allowed_ips"`
	Platform               EnclavePlatform    `json:"platform"`
	MinTCBSVN              uint32             `json:"min_tcb_svn"`
	RequiredPCRs           map[int]string     `json:"required_pcrs"`
	RequiredRTMRs          map[int]string     `json:"required_rtmrs"`
	GoldenImageDigest      string             `json:"golden_image_digest"`
	SessionKeyBinding      bool               `json:"session_key_binding"`
	AllowDebug             bool               `json:"allow_debug"`
	MaxAttestationAgeSec   int                `json:"max_attestation_age_sec"`
	RequireHardwareRoot    bool               `json:"require_hardware_root"`
	FilePath               string             `json:"file_path,omitempty"`
	StartLine              int                `json:"start_line,omitempty"`
}

// AttestationReport represents a cryptographic quote or report issued by a secure enclave.
type AttestationReport struct {
	ReportID            string             `json:"report_id"`
	Platform            EnclavePlatform    `json:"platform"`
	NodeID              string             `json:"node_id"`
	PeerPublicKey       string             `json:"peer_public_key"`
	ReportDataHash      string             `json:"report_data_hash"`
	TCBSVN              uint32             `json:"tcb_svn"`
	DebugAllowed        bool               `json:"debug_allowed"`
	MeasuredPCRs        map[int]string     `json:"measured_pcrs"`
	MeasuredRTMRs       map[int]string     `json:"measured_rtmrs"`
	VCEKCertChainValid  bool               `json:"vcek_cert_chain_valid"`
	TDXQuoteValid       bool               `json:"tdx_quote_valid"`
	Timestamp           time.Time          `json:"timestamp"`
	RawQuoteLength      int                `json:"raw_quote_length"`
}

// PeerTunnelStatus captures runtime WireGuard tunnel state and active session key hashes.
type PeerTunnelStatus struct {
	InterfaceName        string             `json:"interface_name"`
	PeerPublicKey        string             `json:"peer_public_key"`
	PeerName             string             `json:"peer_name"`
	TunnelState          TunnelState        `json:"tunnel_state"`
	ActiveSessionKeyHash string             `json:"active_session_key_hash"`
	BoundReportID        string             `json:"bound_report_id"`
	AttestationValid     bool               `json:"attestation_valid"`
	RejectionReason      string             `json:"rejection_reason,omitempty"`
	LastAttestation      time.Time          `json:"last_attestation"`
}

// EnclaveTelemetry represents runtime telemetry collected from confidential nodes and WireGuard interfaces.
type EnclaveTelemetry struct {
	Timestamp            time.Time          `json:"timestamp"`
	ClusterID            string             `json:"cluster_id"`
	NodeID               string             `json:"node_id"`
	Reports              []AttestationReport `json:"reports"`
	Peers                []PeerTunnelStatus  `json:"peers"`
}

// WGEnclaveRule represents an authoritative security rule in the WireGuard enclave peer catalog.
type WGEnclaveRule struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// WGEnclaveViolation represents a specific non-compliance finding identified during an audit.
type WGEnclaveViolation struct {
	RuleID        string          `json:"rule_id"`
	PeerName      string          `json:"peer_name"`
	InterfaceName string          `json:"interface_name"`
	Platform      EnclavePlatform `json:"platform"`
	Severity      intel.Severity  `json:"severity"`
	CVSSScore     float64         `json:"cvss_score"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	Remediation   string          `json:"remediation"`
	MatchedCVE    string          `json:"matched_cve,omitempty"`
	FilePath      string          `json:"file_path,omitempty"`
	StartLine     int             `json:"start_line,omitempty"`
}

// WGEnclaveSummary provides aggregate statistics on WireGuard enclave peer security posture.
type WGEnclaveSummary struct {
	TotalPeersScanned      int      `json:"total_peers_scanned"`
	CompliantPeers         int      `json:"compliant_peers"`
	RejectedPeers          int      `json:"rejected_peers"`
	PendingPeers           int      `json:"pending_peers"`
	CriticalCount          int      `json:"critical_count"`
	HighCount              int      `json:"high_count"`
	MediumCount            int      `json:"medium_count"`
	LowCount               int      `json:"low_count"`
	SEVSNPVerified         bool     `json:"sev_snp_verified"`
	TDXVerified            bool     `json:"tdx_verified"`
	PCRDeviationsDetected  int      `json:"pcr_deviations_detected"`
	ComplianceScore        float64  `json:"compliance_score"`
	RejectedPeerIDs        []string `json:"rejected_peer_ids,omitempty"`
}

// WGEnclaveAuditReport holds the complete results of a WireGuard enclave attestation audit.
type WGEnclaveAuditReport struct {
	Configurations []EnclavePeerConfig  `json:"configurations"`
	Reports        []AttestationReport  `json:"reports"`
	Peers          []PeerTunnelStatus   `json:"peers"`
	Violations     []WGEnclaveViolation `json:"violations"`
	Summary        WGEnclaveSummary     `json:"summary"`
}
