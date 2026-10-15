package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseInTotoAttestationFile reads and validates an In-Toto Statement & SLSA Provenance file from disk.
func ParseInTotoAttestationFile(filePath string) (*InTotoAttestation, []SBOMViolation, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat attestation file: %w", err)
	}
	if info.Size() > MaxAttestationBytes {
		return nil, nil, fmt.Errorf("attestation file exceeds size ceiling (%d > %d bytes)", info.Size(), MaxAttestationBytes)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read attestation file: %w", err)
	}

	return VerifyAttestationPayload(data, filepath.Base(cleanPath))
}

// VerifyAttestationPayload parses an In-Toto attestation and evaluates SLSA Level 3 compliance rules.
func VerifyAttestationPayload(data []byte, filename string) (*InTotoAttestation, []SBOMViolation, error) {
	if len(data) > MaxAttestationBytes {
		return nil, nil, fmt.Errorf("attestation payload exceeds size limit (%d > %d bytes)", len(data), MaxAttestationBytes)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("malformed JSON in attestation: %w", err)
	}

	var violations []SBOMViolation

	// 1. Verify In-Toto Statement Envelope
	stmtType, _ := raw["_type"].(string)
	if stmtType == "" {
		// check if wrapped in DSSE envelope (payload / signatures)
		if payload, ok := raw["payload"].(string); ok && payload != "" {
			stmtType = "application/vnd.in-toto+json"
		}
	}

	if stmtType == "" || (!strings.Contains(stmtType, "in-toto.io/Statement") && !strings.Contains(stmtType, "in-toto")) {
		rule, _ := GetRule("SBOM-CHAIN-002")
		violations = append(violations, SBOMViolation{
			ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, filename),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.DefaultCVSS,
			ResourceURI: filename,
			Description: "Document lacks a valid In-Toto Statement envelope (_type: https://in-toto.io/Statement/v0.1 or v1).",
			Remediation: rule.Remediation,
		})
	}

	predicateType, _ := raw["predicateType"].(string)
	var subjects []InTotoSubject
	if rawSubjects, ok := raw["subject"].([]any); ok {
		for _, s := range rawSubjects {
			if sMap, ok := s.(map[string]any); ok {
				name, _ := sMap["name"].(string)
				digestMap := make(map[string]string)
				if digests, ok := sMap["digest"].(map[string]any); ok {
					for k, v := range digests {
						if vStr, ok := v.(string); ok {
							digestMap[strings.ToLower(k)] = vStr
						}
					}
				}
				subjects = append(subjects, InTotoSubject{
					Name:   name,
					Digest: digestMap,
				})
			}
		}
	}

	// 2. Extract Predicate details
	predicate, _ := raw["predicate"].(map[string]any)
	builderID := ""
	buildType := ""
	hermetic := false
	reproducible := false
	verifiedSignature := false

	if predicate != nil {
		if b, ok := predicate["builder"].(map[string]any); ok {
			builderID, _ = b["id"].(string)
		} else if bID, ok := predicate["builderId"].(string); ok {
			builderID = bID
		}

		buildType, _ = predicate["buildType"].(string)

		// Check buildDefinition or runDetails for hermeticity
		if bd, ok := predicate["buildDefinition"].(map[string]any); ok {
			if systemParams, ok := bd["systemParameters"].(map[string]any); ok {
				if h, ok := systemParams["hermetic"].(bool); ok {
					hermetic = h
				}
				if r, ok := systemParams["reproducible"].(bool); ok {
					reproducible = r
				}
			}
		}
		if runDetails, ok := predicate["runDetails"].(map[string]any); ok {
			if meta, ok := runDetails["metadata"].(map[string]any); ok {
				if h, ok := meta["hermetic"].(bool); ok {
					hermetic = h
				}
				if r, ok := meta["reproducible"].(bool); ok {
					reproducible = r
				}
			}
		}
	}

	// Check signatures
	if sigs, ok := raw["signatures"].([]any); ok && len(sigs) > 0 {
		verifiedSignature = true
	} else if sig, ok := raw["signature"].(string); ok && sig != "" {
		verifiedSignature = true
	}

	// 3. Inspect materials / dependencies for unpinned references
	var materials []InTotoMaterial
	hasUnpinnedMaterials := false
	var rawMaterials []any
	if predicate != nil {
		if mats, ok := predicate["materials"].([]any); ok {
			rawMaterials = mats
		} else if deps, ok := predicate["resolvedDependencies"].([]any); ok {
			rawMaterials = deps
		}
	}

	for _, m := range rawMaterials {
		if mMap, ok := m.(map[string]any); ok {
			uri, _ := mMap["uri"].(string)
			digestMap := make(map[string]string)
			if digests, ok := mMap["digest"].(map[string]any); ok {
				for k, v := range digests {
					if vStr, ok := v.(string); ok {
						digestMap[strings.ToLower(k)] = vStr
					}
				}
			}

			// Audit for unpinned references (SBOM-CHAIN-005)
			if len(digestMap) == 0 {
				if strings.Contains(uri, "latest") || strings.Contains(uri, "refs/heads/main") || strings.Contains(uri, "refs/heads/master") {
					hasUnpinnedMaterials = true
				}
			}

			materials = append(materials, InTotoMaterial{
				URI:    uri,
				Digest: digestMap,
			})
		}
	}

	if hasUnpinnedMaterials {
		rule, _ := GetRule("SBOM-CHAIN-005")
		violations = append(violations, SBOMViolation{
			ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, filename),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.DefaultCVSS,
			ResourceURI: filename,
			Description: "Attestation materials contain mutable branch references or unpinned upstream URLs without cryptographic hashes.",
			Remediation: rule.Remediation,
		})
	}

	// 4. Check Hermeticity (SBOM-CHAIN-006)
	if !hermetic {
		rule, _ := GetRule("SBOM-CHAIN-006")
		violations = append(violations, SBOMViolation{
			ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, filename),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.DefaultCVSS,
			ResourceURI: filename,
			Description: "Attestation does not verify a hermetic build environment; ambient network access or external state could alter build output.",
			Remediation: rule.Remediation,
		})
	}

	// 5. Evaluate SLSA Level
	evaluatedLevel := SLSALevel0
	if builderID != "" && len(subjects) > 0 {
		evaluatedLevel = SLSALevel1
		if verifiedSignature && len(materials) > 0 {
			evaluatedLevel = SLSALevel2
			if hermetic && !hasUnpinnedMaterials {
				evaluatedLevel = SLSALevel3
			}
		}
	}

	if evaluatedLevel != SLSALevel3 {
		rule, _ := GetRule("SBOM-CHAIN-003")
		violations = append(violations, SBOMViolation{
			ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, filename),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.DefaultCVSS,
			ResourceURI: filename,
			Description: fmt.Sprintf("Evaluated SLSA provenance level is %s (below mandatory SLSA Level 3 requirement).", evaluatedLevel),
			Remediation: rule.Remediation,
		})
	}

	attestation := &InTotoAttestation{
		Type:               stmtType,
		PredicateType:      predicateType,
		Subject:            subjects,
		BuilderID:          builderID,
		BuildType:          buildType,
		Materials:          materials,
		Hermetic:           hermetic,
		Reproducible:       reproducible,
		VerifiedSignature:  verifiedSignature,
		EvaluatedSLSALevel: evaluatedLevel,
		Metadata: map[string]string{
			"filename": filename,
		},
	}

	return attestation, violations, nil
}

// VerifySubjectDigest verifies that a target artifact's cryptographic hash matches the attested In-Toto subject.
func VerifySubjectDigest(attestation *InTotoAttestation, targetName, expectedSHA256 string) *SBOMViolation {
	if attestation == nil || len(attestation.Subject) == 0 {
		rule, _ := GetRule("SBOM-CHAIN-004")
		return &SBOMViolation{
			ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, targetName),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.DefaultCVSS,
			ResourceURI: targetName,
			PackageName: targetName,
			Description: "No cryptographic subject found in In-Toto attestation to verify artifact integrity.",
			Remediation: rule.Remediation,
			MatchedCVE:  rule.AssociatedCVE,
		}
	}

	cleanExpected := strings.ToLower(strings.TrimPrefix(expectedSHA256, "sha256:"))

	for _, s := range attestation.Subject {
		if s.Name == targetName || targetName == "" || len(attestation.Subject) == 1 {
			if sDigest, ok := s.Digest["sha256"]; ok {
				cleanAttested := strings.ToLower(strings.TrimPrefix(sDigest, "sha256:"))
				if cleanAttested != cleanExpected {
					rule, _ := GetRule("SBOM-CHAIN-004")
					return &SBOMViolation{
						ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, targetName),
						RuleID:      rule.ID,
						Title:       rule.Title,
						Severity:    rule.Severity,
						CVSSScore:   rule.DefaultCVSS,
						ResourceURI: targetName,
						PackageName: targetName,
						Description: fmt.Sprintf("Artifact digest mismatch! Attested: %s, Actual: %s (potential binary tampering)", cleanAttested, cleanExpected),
						Remediation: rule.Remediation,
						MatchedCVE:  rule.AssociatedCVE,
					}
				}
				return nil
			}
		}
	}

	rule, _ := GetRule("SBOM-CHAIN-004")
	return &SBOMViolation{
		ID:          fmt.Sprintf("VIO-%s-%s", rule.ID, targetName),
		RuleID:      rule.ID,
		Title:       rule.Title,
		Severity:    rule.Severity,
		CVSSScore:   rule.DefaultCVSS,
		ResourceURI: targetName,
		PackageName: targetName,
		Description: fmt.Sprintf("Artifact %s not attested in In-Toto subject manifest.", targetName),
		Remediation: rule.Remediation,
		MatchedCVE:  rule.AssociatedCVE,
	}
}
