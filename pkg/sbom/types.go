package sbom

import (
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxSBOMBytes defines the strict 15MB size ceiling for SBOM document ingestion.
	MaxSBOMBytes = 15 * 1024 * 1024

	// MaxAttestationBytes defines the strict 10MB size ceiling for In-Toto / SLSA provenance.
	MaxAttestationBytes = 10 * 1024 * 1024

	// MaxPackageCount defines the defensive bounds ceiling for parsed packages per document.
	MaxPackageCount = 10000

	// MaxDeltaItems defines the maximum differential records permitted in a single delta audit.
	MaxDeltaItems = 5000

	// MaxSpecVersionLen defines the maximum character length for specification version identifiers.
	MaxSpecVersionLen = 64
)

// SBOMFormat enumerates supported Software Bill of Materials standard formats.
type SBOMFormat string

const (
	FormatSPDXv3      SBOMFormat = "SPDX-v3.0"
	FormatSPDXv2      SBOMFormat = "SPDX-v2.3"
	FormatCycloneDXv16 SBOMFormat = "CycloneDX-v1.6"
	FormatCycloneDXv15 SBOMFormat = "CycloneDX-v1.5"
	FormatNixClosure  SBOMFormat = "Nix-Store-Closure"
	FormatUnknown     SBOMFormat = "Unknown"
)

// SLSALevel represents the Supply chain Levels for Software Artifacts maturity level.
type SLSALevel string

const (
	SLSALevel0 SLSALevel = "SLSA_LEVEL_0"
	SLSALevel1 SLSALevel = "SLSA_LEVEL_1"
	SLSALevel2 SLSALevel = "SLSA_LEVEL_2"
	SLSALevel3 SLSALevel = "SLSA_LEVEL_3"
)

// SBOMDeltaStatus classifies comparison states between declared SBOM and cluster runtime state.
type SBOMDeltaStatus string

const (
	DeltaMatch            SBOMDeltaStatus = "MATCH"
	DeltaVersionDrift      SBOMDeltaStatus = "VERSION_DRIFT"
	DeltaUndeclaredRuntime SBOMDeltaStatus = "UNDECLARED_RUNTIME"
	DeltaMissingInRuntime  SBOMDeltaStatus = "MISSING_IN_RUNTIME"
	DeltaHashMismatch      SBOMDeltaStatus = "HASH_MISMATCH"
)

// PackageComponent represents an individual software dependency or component.
type PackageComponent struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	PURL         string            `json:"purl,omitempty"`
	StorePath    string            `json:"store_path,omitempty"`
	Checksum     string            `json:"checksum,omitempty"`
	ChecksumType string            `json:"checksum_type,omitempty"`
	License      string            `json:"license,omitempty"`
	Supplier     string            `json:"supplier,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// SBOMDocument represents a parsed and normalized SBOM document.
type SBOMDocument struct {
	Format        SBOMFormat         `json:"format"`
	SpecVersion   string             `json:"spec_version"`
	DocumentName  string             `json:"document_name"`
	RootComponent string             `json:"root_component"`
	CreationTime  time.Time          `json:"creation_time"`
	Components    []PackageComponent `json:"components"`
	Metadata      map[string]string  `json:"metadata,omitempty"`
}

// InTotoSubject describes an artifact attested within an In-Toto statement.
type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// InTotoMaterial represents an input source or artifact consumed during build.
type InTotoMaterial struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// InTotoAttestation represents a validated In-Toto Statement and SLSA Provenance envelope.
type InTotoAttestation struct {
	Type               string            `json:"_type"`
	PredicateType      string            `json:"predicateType"`
	Subject            []InTotoSubject   `json:"subject"`
	BuilderID          string            `json:"builder_id"`
	BuildType          string            `json:"build_type"`
	Materials          []InTotoMaterial  `json:"materials"`
	Hermetic           bool              `json:"hermetic"`
	Reproducible       bool              `json:"reproducible"`
	VerifiedSignature  bool              `json:"verified_signature"`
	EvaluatedSLSALevel SLSALevel         `json:"evaluated_slsa_level"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// RuntimePackageState represents the observed state of an active package in the runtime cluster.
type RuntimePackageState struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	StorePath   string `json:"store_path,omitempty"`
	Node        string `json:"node,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

// SBOMDeltaItem details a specific package divergence between declarative and runtime states.
type SBOMDeltaItem struct {
	PackageName      string          `json:"package_name"`
	DeclaredVersion  string          `json:"declared_version,omitempty"`
	RuntimeVersion   string          `json:"runtime_version,omitempty"`
	DeclaredHash     string          `json:"declared_hash,omitempty"`
	RuntimeHash      string          `json:"runtime_hash,omitempty"`
	Status           SBOMDeltaStatus `json:"status"`
	Severity         intel.Severity  `json:"severity"`
	Message          string          `json:"message"`
	SecurityImpact   string          `json:"security_impact"`
}

// SBOMRule defines a canonical security rule for supply chain and SBOM audits.
type SBOMRule struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Severity      intel.Severity `json:"severity"`
	DefaultCVSS   float64        `json:"default_cvss"`
	Description   string         `json:"description"`
	Remediation   string         `json:"remediation"`
	AssociatedCVE string         `json:"associated_cve,omitempty"`
}

// SBOMViolation captures an audited supply chain violation.
type SBOMViolation struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Severity    intel.Severity `json:"severity"`
	CVSSScore   float64        `json:"cvss_score"`
	ResourceURI string         `json:"resource_uri"`
	PackageName string         `json:"package_name"`
	LineNumber  int            `json:"line_number,omitempty"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	MatchedCVE  string         `json:"matched_cve,omitempty"`
}

// SBOMSummary consolidates supply chain and SBOM compliance metrics.
type SBOMSummary struct {
	TotalPackages        int       `json:"total_packages"`
	TotalDocuments       int       `json:"total_documents"`
	TotalViolations      int       `json:"total_violations"`
	CriticalCount        int       `json:"critical_count"`
	HighCount            int       `json:"high_count"`
	MediumCount          int       `json:"medium_count"`
	LowCount             int       `json:"low_count"`
	AttestationVerified  bool      `json:"attestation_verified"`
	EvaluatedSLSALevel   SLSALevel `json:"evaluated_slsa_level"`
	DriftingPackages     int       `json:"drifting_packages"`
	UndeclaredPackages   int       `json:"undeclared_packages"`
	ComplianceScore      float64   `json:"compliance_score"`
}

// SBOMAuditReport encapsulates the holistic results of an SBOM and supply chain audit.
type SBOMAuditReport struct {
	TotalFiles   int                 `json:"total_files"`
	Documents    []SBOMDocument      `json:"documents"`
	Attestations []InTotoAttestation `json:"attestations"`
	DeltaItems   []SBOMDeltaItem     `json:"delta_items"`
	Violations   []SBOMViolation     `json:"violations"`
	Summary      SBOMSummary         `json:"summary"`
}
