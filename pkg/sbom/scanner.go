package sbom

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// SBOMScanner orchestrates declarative SBOM ingestion, attestation verification, and runtime delta audits.
type SBOMScanner struct {
	feed *intel.Feed
}

// NewSBOMScanner constructs a new supply chain and SBOM scanner instance.
func NewSBOMScanner(feed *intel.Feed) *SBOMScanner {
	return &SBOMScanner{
		feed: feed,
	}
}

// ScanFile audits a single SBOM file or attestation envelope on disk.
func (s *SBOMScanner) ScanFile(filePath string) (*SBOMAuditReport, error) {
	doc, err := ParseSBOMFile(filePath)
	if err != nil {
		// Attempt to parse as In-Toto attestation if SBOM parsing fails
		attest, attestVios, attestErr := ParseInTotoAttestationFile(filePath)
		if attestErr == nil && attest != nil {
			rep := &SBOMAuditReport{
				TotalFiles:   1,
				Attestations: []InTotoAttestation{*attest},
				Violations:   attestVios,
			}
			rep.Summary = s.computeSummary(0, 0, rep.Violations, attest.EvaluatedSLSALevel, true, 0, 0)
			return rep, nil
		}
		return nil, fmt.Errorf("failed to audit file %s: %w", filePath, err)
	}

	report := &SBOMAuditReport{
		TotalFiles: 1,
		Documents:  []SBOMDocument{*doc},
	}

	report.Violations = s.AuditDocument(doc, filePath)
	report.Summary = s.computeSummary(len(doc.Components), 1, report.Violations, SLSALevel0, false, 0, 0)
	return report, nil
}

// ScanDirectory walks a directory tree and audits all identified SBOM and attestation manifests.
func (s *SBOMScanner) ScanDirectory(dirPath string) (*SBOMAuditReport, error) {
	cleanDir := filepath.Clean(dirPath)
	rep := &SBOMAuditReport{}

	err := filepath.Walk(cleanDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		lower := strings.ToLower(info.Name())
		isSBOM := strings.HasSuffix(lower, ".json") && (strings.Contains(lower, "sbom") ||
			strings.Contains(lower, "spdx") ||
			strings.Contains(lower, "cyclonedx") ||
			strings.Contains(lower, "bom"))
		isAttestation := strings.HasSuffix(lower, ".json") && (strings.Contains(lower, "attestation") ||
			strings.Contains(lower, "provenance") ||
			strings.Contains(lower, "intoto"))

		if !isSBOM && !isAttestation {
			return nil
		}

		rep.TotalFiles++

		if isAttestation {
			attest, vios, aErr := ParseInTotoAttestationFile(path)
			if aErr == nil && attest != nil {
				rep.Attestations = append(rep.Attestations, *attest)
				rep.Violations = append(rep.Violations, vios...)
			}
			return nil
		}

		doc, dErr := ParseSBOMFile(path)
		if dErr == nil && doc != nil {
			rep.Documents = append(rep.Documents, *doc)
			rep.Violations = append(rep.Violations, s.AuditDocument(doc, path)...)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking SBOM directory: %w", err)
	}

	totalPkgs := 0
	for _, d := range rep.Documents {
		totalPkgs += len(d.Components)
	}

	slsaMax := SLSALevel0
	attestVerified := false
	for _, a := range rep.Attestations {
		if a.EvaluatedSLSALevel > slsaMax {
			slsaMax = a.EvaluatedSLSALevel
		}
		if a.VerifiedSignature {
			attestVerified = true
		}
	}

	rep.Summary = s.computeSummary(totalPkgs, len(rep.Documents), rep.Violations, slsaMax, attestVerified, 0, 0)
	return rep, nil
}

// AuditDocument evaluates an SBOM document against canonical supply chain security rules and threat feeds.
func (s *SBOMScanner) AuditDocument(doc *SBOMDocument, filename string) []SBOMViolation {
	var violations []SBOMViolation
	if doc == nil {
		return violations
	}

	// 1. Audit Spec Version (SBOM-CHAIN-010)
	if doc.Format == FormatCycloneDXv15 || strings.HasPrefix(doc.SpecVersion, "1.4") || strings.HasPrefix(doc.SpecVersion, "2.2") {
		rule, _ := GetRule("SBOM-CHAIN-010")
		violations = append(violations, SBOMViolation{
			ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, filename),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.DefaultCVSS,
			ResourceURI: filename,
			Description: fmt.Sprintf("Document uses older specification version %s (%s). Recommend upgrading to SPDX v3.0 or CycloneDX v1.6.", doc.SpecVersion, doc.Format),
			Remediation: rule.Remediation,
		})
	}

	// 2. Audit Components
	for _, comp := range doc.Components {
		// Check for unknown or restrictive licenses (SBOM-CHAIN-011)
		licUpper := strings.ToUpper(comp.License)
		if licUpper == "UNLICENSED" || licUpper == "UNKNOWN" || comp.License == "" {
			rule, _ := GetRule("SBOM-CHAIN-011")
			violations = append(violations, SBOMViolation{
				ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, comp.Name),
				RuleID:      rule.ID,
				Title:       rule.Title,
				Severity:    rule.Severity,
				CVSSScore:   rule.DefaultCVSS,
				ResourceURI: filename,
				PackageName: comp.Name,
				Description: fmt.Sprintf("Component '%s' has missing or unrecognized license declaration: '%s'.", comp.Name, comp.License),
				Remediation: rule.Remediation,
			})
		}

		// Check Nix store path integrity (SBOM-CHAIN-012)
		if strings.HasPrefix(comp.StorePath, "/nix/store/") && (comp.Checksum == "" || comp.Checksum == "unknown") {
			rule, _ := GetRule("SBOM-CHAIN-012")
			violations = append(violations, SBOMViolation{
				ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, comp.Name),
				RuleID:      rule.ID,
				Title:       rule.Title,
				Severity:    rule.Severity,
				CVSSScore:   rule.DefaultCVSS,
				ResourceURI: filename,
				PackageName: comp.Name,
				Description: fmt.Sprintf("Nix store path component '%s' is missing a cryptographic output/narHash checksum.", comp.Name),
				Remediation: rule.Remediation,
			})
		}

		// Correlate with active threat intelligence feed (SBOM-CHAIN-007)
		if s.feed != nil {
			normPkg := strings.ToLower(comp.Name)
			for _, item := range s.feed.Items {
				if s.isComponentVulnerable(normPkg, comp.Version, item) {
					rule, _ := GetRule("SBOM-CHAIN-007")
					violations = append(violations, SBOMViolation{
						ID:          fmt.Sprintf("VIO-%s-%s-%s", rule.ID, comp.Name, item.ID),
						RuleID:      rule.ID,
						Title:       fmt.Sprintf("%s (%s)", rule.Title, item.ID),
						Severity:    item.Severity,
						CVSSScore:   item.CVSSScore,
						ResourceURI: filename,
						PackageName: comp.Name,
						Description: fmt.Sprintf("Component '%s' (v%s) is vulnerable to %s: %s", comp.Name, comp.Version, item.ID, item.Description),
						Remediation: item.Mitigation,
						MatchedCVE:  item.ID,
					})
				}
			}
		}
	}

	return violations
}

// ReconcileRuntimeState performs differential audit between declarative SBOM and cluster runtime state.
func (s *SBOMScanner) ReconcileRuntimeState(sbomFilePath, runtimeFilePath string) (*SBOMAuditReport, error) {
	doc, err := ParseSBOMFile(sbomFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read declarative SBOM: %w", err)
	}

	runtimePkgs, err := ParseRuntimeStateFile(runtimeFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read runtime state telemetry: %w", err)
	}

	deltaItems, deltaVios := GenerateSBOMDelta(doc, runtimePkgs)
	docVios := s.AuditDocument(doc, sbomFilePath)

	allVios := append(docVios, deltaVios...)

	drifting := 0
	undeclared := 0
	for _, d := range deltaItems {
		if d.Status == DeltaVersionDrift || d.Status == DeltaHashMismatch {
			drifting++
		}
		if d.Status == DeltaUndeclaredRuntime {
			undeclared++
		}
	}

	rep := &SBOMAuditReport{
		TotalFiles: 2,
		Documents:  []SBOMDocument{*doc},
		DeltaItems: deltaItems,
		Violations: allVios,
	}

	rep.Summary = s.computeSummary(len(doc.Components), 1, allVios, SLSALevel0, false, drifting, undeclared)
	return rep, nil
}

func (s *SBOMScanner) isComponentVulnerable(pkgName, version string, item intel.ThreatItem) bool {
	itemTitle := strings.ToLower(item.Title)
	itemDesc := strings.ToLower(item.Description)
	itemTarget := strings.ToLower(item.Target)

	// Check if package name is directly mentioned in threat advisory
	if strings.Contains(itemTitle, pkgName) || strings.Contains(itemDesc, pkgName) || strings.Contains(itemTarget, pkgName) {
		return true
	}

	return false
}

func (s *SBOMScanner) computeSummary(totalPkgs, totalDocs int, vios []SBOMViolation, slsa SLSALevel, attestVerified bool, drifting, undeclared int) SBOMSummary {
	crit := 0
	high := 0
	med := 0
	low := 0

	for _, v := range vios {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	// Calculate deterministic compliance score (0.0 to 100.0)
	score := 100.0
	score -= float64(crit) * 15.0
	score -= float64(high) * 7.5
	score -= float64(med) * 3.0
	score -= float64(low) * 1.0

	if score < 0.0 {
		score = 0.0
	}
	score = math.Round(score*10) / 10

	return SBOMSummary{
		TotalPackages:       totalPkgs,
		TotalDocuments:      totalDocs,
		TotalViolations:     len(vios),
		CriticalCount:       crit,
		HighCount:           high,
		MediumCount:         med,
		LowCount:            low,
		AttestationVerified: attestVerified,
		EvaluatedSLSALevel:  slsa,
		DriftingPackages:    drifting,
		UndeclaredPackages:  undeclared,
		ComplianceScore:     score,
	}
}
