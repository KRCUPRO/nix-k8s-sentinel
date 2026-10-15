package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// ParseRuntimeStateFile reads observed cluster runtime packages from a JSON telemetry file.
func ParseRuntimeStateFile(filePath string) ([]RuntimePackageState, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat runtime state file: %w", err)
	}
	if info.Size() > MaxSBOMBytes {
		return nil, fmt.Errorf("runtime state file exceeds size ceiling (%d bytes)", info.Size())
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read runtime state file: %w", err)
	}

	var wrapper struct {
		Packages []RuntimePackageState `json:"packages"`
	}

	// Try struct wrapper first
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Packages) > 0 {
		return wrapper.Packages, nil
	}

	// Try direct array
	var list []RuntimePackageState
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("failed to parse runtime package state array: %w", err)
	}

	return list, nil
}

// GenerateSBOMDelta reconciles declared SBOM components against runtime cluster packages.
func GenerateSBOMDelta(doc *SBOMDocument, runtimePackages []RuntimePackageState) ([]SBOMDeltaItem, []SBOMViolation) {
	var deltaItems []SBOMDeltaItem
	var violations []SBOMViolation

	declaredMap := make(map[string]PackageComponent)
	if doc != nil {
		for _, comp := range doc.Components {
			normName := normalizePkgName(comp.Name)
			declaredMap[normName] = comp
		}
	}

	observedNames := make(map[string]bool)

	// 1. Audit active runtime packages against declarative baseline
	for _, rp := range runtimePackages {
		if len(deltaItems) >= MaxDeltaItems {
			break
		}
		normName := normalizePkgName(rp.PackageName)
		observedNames[normName] = true

		decl, declared := declaredMap[normName]
		if !declared {
			// Shadow binary / undeclared runtime package
			rule, _ := GetRule("SBOM-CHAIN-008")
			msg := fmt.Sprintf("Package '%s' (v%s) is running in the cluster but was never declared in the authoritative SBOM.", rp.PackageName, rp.Version)
			deltaItems = append(deltaItems, SBOMDeltaItem{
				PackageName:    rp.PackageName,
				RuntimeVersion: rp.Version,
				RuntimeHash:    rp.SHA256,
				Status:         DeltaUndeclaredRuntime,
				Severity:       rule.Severity,
				Message:        msg,
				SecurityImpact: "Potential supply chain backdoor, container escape, or unmanaged shadow dependency.",
			})

			violations = append(violations, SBOMViolation{
				ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, rp.PackageName),
				RuleID:      rule.ID,
				Title:       rule.Title,
				Severity:    rule.Severity,
				CVSSScore:   rule.DefaultCVSS,
				ResourceURI: rp.StorePath,
				PackageName: rp.PackageName,
				Description: msg,
				Remediation: rule.Remediation,
			})
			continue
		}

		// Check for cryptographic checksum mismatch (tampered binary)
		if decl.Checksum != "" && rp.SHA256 != "" {
			cleanDecl := strings.ToLower(strings.TrimPrefix(decl.Checksum, "sha256:"))
			cleanRun := strings.ToLower(strings.TrimPrefix(rp.SHA256, "sha256:"))
			if cleanDecl != cleanRun {
				rule, _ := GetRule("SBOM-CHAIN-004")
				msg := fmt.Sprintf("Cryptographic hash mismatch for package '%s'! Declared: %s, Runtime: %s", rp.PackageName, cleanDecl, cleanRun)
				deltaItems = append(deltaItems, SBOMDeltaItem{
					PackageName:     rp.PackageName,
					DeclaredVersion: decl.Version,
					RuntimeVersion:  rp.Version,
					DeclaredHash:    cleanDecl,
					RuntimeHash:     cleanRun,
					Status:          DeltaHashMismatch,
					Severity:        rule.Severity,
					Message:         msg,
					SecurityImpact:  "High risk of binary modification or poisoned dependency substitution in runtime.",
				})

				violations = append(violations, SBOMViolation{
					ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, rp.PackageName),
					RuleID:      rule.ID,
					Title:       rule.Title,
					Severity:    rule.Severity,
					CVSSScore:   rule.DefaultCVSS,
					ResourceURI: rp.StorePath,
					PackageName: rp.PackageName,
					Description: msg,
					Remediation: rule.Remediation,
					MatchedCVE:  rule.AssociatedCVE,
				})
				continue
			}
		}

		// Check for version drift
		if decl.Version != "" && rp.Version != "" && decl.Version != rp.Version {
			rule, _ := GetRule("SBOM-CHAIN-009")
			msg := fmt.Sprintf("Package version drift for '%s': Declared %s != Runtime %s", rp.PackageName, decl.Version, rp.Version)
			deltaItems = append(deltaItems, SBOMDeltaItem{
				PackageName:     rp.PackageName,
				DeclaredVersion: decl.Version,
				RuntimeVersion:  rp.Version,
				DeclaredHash:    decl.Checksum,
				RuntimeHash:     rp.SHA256,
				Status:          DeltaVersionDrift,
				Severity:        rule.Severity,
				Message:         msg,
				SecurityImpact:  "Runtime environment has diverged from declarative GitOps state; could harbor untested CVEs.",
			})

			violations = append(violations, SBOMViolation{
				ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, rp.PackageName),
				RuleID:      rule.ID,
				Title:       rule.Title,
				Severity:    rule.Severity,
				CVSSScore:   rule.DefaultCVSS,
				ResourceURI: rp.StorePath,
				PackageName: rp.PackageName,
				Description: msg,
				Remediation: rule.Remediation,
			})
			continue
		}

		// Clean match
		deltaItems = append(deltaItems, SBOMDeltaItem{
			PackageName:     rp.PackageName,
			DeclaredVersion: decl.Version,
			RuntimeVersion:  rp.Version,
			DeclaredHash:    decl.Checksum,
			RuntimeHash:     rp.SHA256,
			Status:          DeltaMatch,
			Severity:        intel.SeverityLow,
			Message:         fmt.Sprintf("Package '%s' (v%s) verified against declarative SBOM.", rp.PackageName, rp.Version),
			SecurityImpact:  "None; runtime state adheres to declarative supply chain specification.",
		})
	}

	// 2. Identify declared packages absent from runtime
	if doc != nil {
		for _, comp := range doc.Components {
			if len(deltaItems) >= MaxDeltaItems {
				break
			}
			normName := normalizePkgName(comp.Name)
			if !observedNames[normName] {
				deltaItems = append(deltaItems, SBOMDeltaItem{
					PackageName:     comp.Name,
					DeclaredVersion: comp.Version,
					DeclaredHash:    comp.Checksum,
					Status:          DeltaMissingInRuntime,
					Severity:        intel.SeverityLow,
					Message:         fmt.Sprintf("Package '%s' declared in SBOM but not observed active in runtime cluster.", comp.Name),
					SecurityImpact:  "Informational; component may be unused, optional, or dormant in cluster pods.",
				})
			}
		}
	}

	return deltaItems, violations
}

func normalizePkgName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	lower = strings.TrimPrefix(lower, "pkg:")
	if strings.HasPrefix(lower, "/nix/store/") {
		parts := strings.Split(lower, "-")
		if len(parts) > 1 {
			lower = strings.Join(parts[1:], "-")
		}
	}
	return lower
}
