package pqc

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a strict 10MB memory safety ceiling on scanned files.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxTelemetryBytes sets a strict 5MB ceiling on runtime TLS handshake telemetry.
	MaxTelemetryBytes = 5 * 1024 * 1024
	// MaxEndpoints caps the maximum number of network endpoints tracked per audit run.
	MaxEndpoints = 1024
	// MaxCipherSuites caps the maximum number of evaluated cipher suites per configuration.
	MaxCipherSuites = 128
	// MaxAllowedScanLines sets a strict scanner boundary against unbounded or cyclical manifests.
	MaxAllowedScanLines = 20000
)

// PQCAlgorithmType designates post-quantum and hybrid key encapsulation or signature algorithms.
type PQCAlgorithmType string

const (
	PQCAlgoMLKEM768                 PQCAlgorithmType = "ML-KEM-768"
	PQCAlgoMLKEM1024                PQCAlgorithmType = "ML-KEM-1024"
	PQCAlgoMLDSA65                  PQCAlgorithmType = "ML-DSA-65"
	PQCAlgoMLDSA87                  PQCAlgorithmType = "ML-DSA-87"
	PQCAlgoHybridX25519MLKEM768     PQCAlgorithmType = "X25519MLKEM768"
	PQCAlgoHybridSecP384r1MLKEM1024 PQCAlgorithmType = "SecP384r1MLKEM1024"
	PQCAlgoClassicalECDH            PQCAlgorithmType = "Classical-ECDH"
	PQCAlgoClassicalRSA             PQCAlgorithmType = "Classical-RSA"
)

// CNSAComplianceLevel defines conformity with the NSA Commercial National Security Algorithm Suite 2.0.
type CNSAComplianceLevel string

const (
	CNSANonCompliant    CNSAComplianceLevel = "CNSA-NonCompliant"
	CNSATransitional    CNSAComplianceLevel = "CNSA-Transitional"
	CNSACompliant2030   CNSAComplianceLevel = "CNSA-Compliant-2030"
	CNSACompliant2033   CNSAComplianceLevel = "CNSA-Compliant-2033"
)

// TLSProtocolVersion models supported or detected TLS protocol versions.
type TLSProtocolVersion string

const (
	TLSVersion10 TLSProtocolVersion = "TLSv1.0"
	TLSVersion11 TLSProtocolVersion = "TLSv1.1"
	TLSVersion12 TLSProtocolVersion = "TLSv1.2"
	TLSVersion13 TLSProtocolVersion = "TLSv1.3"
)

// K8sControlPlaneTLSConfig encapsulates parsed TLS parameters for Kubernetes control plane components.
type K8sControlPlaneTLSConfig struct {
	Component           string            `json:"component"`
	FilePath            string            `json:"file_path"`
	StartLine           int               `json:"start_line"`
	TLSMinVersion       string            `json:"tls_min_version"`
	TLSCipherSuites     []string          `json:"tls_cipher_suites"`
	KeyExchangeGroups   []string          `json:"key_exchange_groups"`
	PeerTLSMinVersion   string            `json:"peer_tls_min_version,omitempty"`
	PeerTLSCipherSuites []string          `json:"peer_tls_cipher_suites,omitempty"`
	ClientCAFile        string            `json:"client_ca_file,omitempty"`
	TLSCertFile         string            `json:"tls_cert_file,omitempty"`
	TLSPrivateKeyFile   string            `json:"tls_private_key_file,omitempty"`
	RawArgs             map[string]string `json:"raw_args,omitempty"`
}

// NixOSCryptoConfig encapsulates parsed cryptographic policies for NixOS OpenSSL and GnuTLS configurations.
type NixOSCryptoConfig struct {
	FilePath             string   `json:"file_path"`
	StartLine            int      `json:"start_line"`
	OpenSSLProviders     []string `json:"openssl_providers"`
	OpenSSLDefaultGroups []string `json:"openssl_default_groups"`
	OpenSSLCipherSuites  []string `json:"openssl_cipher_suites"`
	OpenSSLMinProtocol   string   `json:"openssl_min_protocol"`
	GnuTLSPriorityString string   `json:"gnutls_priority_string"`
	GnuTLSGroups         []string `json:"gnutls_groups"`
	SecurityPKIEnabled   bool     `json:"security_pki_enabled"`
}

// PQCHandshakeTelemetry models individual runtime TLS connection telemetry with negotiated cryptographic parameters.
type PQCHandshakeTelemetry struct {
	Endpoint           string    `json:"endpoint"`
	Component          string    `json:"component"`
	ProtocolVersion    string    `json:"protocol_version"`
	CipherSuite        string    `json:"cipher_suite"`
	KeyExchangeGroup   string    `json:"key_exchange_group"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IsHybridPQC        bool      `json:"is_hybrid_pqc"`
	PeerCertSubject    string    `json:"peer_cert_subject,omitempty"`
	PeerCertIssuer     string    `json:"peer_cert_issuer,omitempty"`
	HandshakeLatencyMs float64   `json:"handshake_latency_ms"`
	Timestamp          time.Time `json:"timestamp"`
}

// PQCRuntimeTelemetry models cluster-wide runtime TLS connection telemetry.
type PQCRuntimeTelemetry struct {
	ClusterID   string                  `json:"cluster_id"`
	CapturedAt  time.Time               `json:"captured_at"`
	Handshakes  []PQCHandshakeTelemetry `json:"handshakes"`
}

// PQCRule models a declarative security rule in the PQC & CNSA 2.0 catalog.
type PQCRule struct {
	RuleID         string         `json:"rule_id"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Severity       intel.Severity `json:"severity"`
	CVSSScore      float64        `json:"cvss_score"`
	Remediation    string         `json:"remediation"`
	MatchedCVE     string         `json:"matched_cve,omitempty"`
	CNSATargetYear int            `json:"cnsa_target_year,omitempty"`
}

// PQCViolation represents an identified violation against PQC rules in manifests or runtime handshakes.
type PQCViolation struct {
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Component   string         `json:"component"`
	Target      string         `json:"target"`
	Resource    string         `json:"resource"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
	Location    string         `json:"location"`
	LineNumber  int            `json:"line_number"`
}

// PQCSummary provides aggregated metrics and compliance scoring for a PQC audit run.
type PQCSummary struct {
	TotalEndpointsScanned int     `json:"total_endpoints_scanned"`
	TotalConfigsScanned   int     `json:"total_configs_scanned"`
	TotalTelemetryEvents  int     `json:"total_telemetry_events"`
	ViolationsCount       int     `json:"violations_count"`
	CriticalCount         int     `json:"critical_count"`
	HighCount             int     `json:"high_count"`
	MediumCount           int     `json:"medium_count"`
	LowCount              int     `json:"low_count"`
	HybridKEMPercentage   float64 `json:"hybrid_kem_percentage"`
	TLS13Percentage       float64 `json:"tls13_percentage"`
	CNSAComplianceScore   float64 `json:"cnsa_compliance_score"`
	AuditStatus           string  `json:"audit_status"`
}

// PQCAuditReport packages all findings and summary metrics for the PQC audit domain.
type PQCAuditReport struct {
	ReportID   string         `json:"report_id"`
	ScannedAt  time.Time      `json:"scanned_at"`
	Summary    PQCSummary     `json:"summary"`
	Violations []PQCViolation `json:"violations"`
}
