package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ParseSBOMFile loads and parses an SBOM document from disk with memory safety limits.
func ParseSBOMFile(filePath string) (*SBOMDocument, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat SBOM file: %w", err)
	}
	if info.Size() > MaxSBOMBytes {
		return nil, fmt.Errorf("SBOM file exceeds size limit (%d > %d bytes)", info.Size(), MaxSBOMBytes)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM file: %w", err)
	}

	return ParseSBOM(data, filepath.Base(cleanPath))
}

// ParseSBOM parses raw JSON or manifest data into a normalized SBOMDocument.
func ParseSBOM(data []byte, filename string) (*SBOMDocument, error) {
	if len(data) > MaxSBOMBytes {
		return nil, fmt.Errorf("SBOM data exceeds size ceiling (%d > %d bytes)", len(data), MaxSBOMBytes)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("malformed JSON in SBOM document: %w", err)
	}

	// 1. Detect CycloneDX format
	if bomFormat, ok := raw["bomFormat"].(string); ok && strings.EqualFold(bomFormat, "CycloneDX") {
		return parseCycloneDX(raw, filename)
	}

	// 2. Detect SPDX format
	if spdxVer, ok := raw["spdxVersion"].(string); ok {
		return parseSPDX(raw, spdxVer, filename)
	}

	// 3. Detect Nix store closure format
	if _, ok := raw["storePaths"]; ok {
		return parseNixClosure(raw, filename)
	}
	if _, ok := raw["closure"]; ok {
		return parseNixClosure(raw, filename)
	}

	return nil, fmt.Errorf("unrecognized SBOM format in document %s", filename)
}

func parseCycloneDX(raw map[string]any, filename string) (*SBOMDocument, error) {
	specVer := "1.6"
	if sv, ok := raw["specVersion"].(string); ok && sv != "" {
		specVer = sv
	}

	docFormat := FormatCycloneDXv16
	if strings.HasPrefix(specVer, "1.5") {
		docFormat = FormatCycloneDXv15
	}

	docName := filename
	rootComp := ""
	if meta, ok := raw["metadata"].(map[string]any); ok {
		if comp, ok := meta["component"].(map[string]any); ok {
			if name, ok := comp["name"].(string); ok {
				rootComp = name
				docName = name
			}
		}
	}

	var components []PackageComponent
	if comps, ok := raw["components"].([]any); ok {
		for _, item := range comps {
			if len(components) >= MaxPackageCount {
				break
			}
			compMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := compMap["name"].(string)
			version, _ := compMap["version"].(string)
			purl, _ := compMap["purl"].(string)

			checksum := ""
			checksumType := ""
			if hashes, ok := compMap["hashes"].([]any); ok {
				for _, h := range hashes {
					if hMap, ok := h.(map[string]any); ok {
						alg, _ := hMap["alg"].(string)
						content, _ := hMap["content"].(string)
						if strings.EqualFold(alg, "SHA-256") || strings.EqualFold(alg, "SHA256") {
							checksum = content
							checksumType = "sha256"
							break
						} else if checksum == "" {
							checksum = content
							checksumType = strings.ToLower(alg)
						}
					}
				}
			}

			license := ""
			if licenses, ok := compMap["licenses"].([]any); ok && len(licenses) > 0 {
				if lMap, ok := licenses[0].(map[string]any); ok {
					if lic, ok := lMap["license"].(map[string]any); ok {
						if id, ok := lic["id"].(string); ok {
							license = id
						} else if name, ok := lic["name"].(string); ok {
							license = name
						}
					}
				}
			}

			supplier := ""
			if sup, ok := compMap["supplier"].(map[string]any); ok {
				supplier, _ = sup["name"].(string)
			}

			storePath := ""
			props := make(map[string]string)
			if propList, ok := compMap["properties"].([]any); ok {
				for _, p := range propList {
					if pMap, ok := p.(map[string]any); ok {
						k, _ := pMap["name"].(string)
						v, _ := pMap["value"].(string)
						if k != "" {
							props[k] = v
							if k == "nix:storePath" || k == "storePath" {
								storePath = v
							}
						}
					}
				}
			}

			components = append(components, PackageComponent{
				Name:         name,
				Version:      version,
				PURL:         purl,
				StorePath:    storePath,
				Checksum:     checksum,
				ChecksumType: checksumType,
				License:      license,
				Supplier:     supplier,
				Properties:   props,
			})
		}
	}

	return &SBOMDocument{
		Format:        docFormat,
		SpecVersion:   specVer,
		DocumentName:  docName,
		RootComponent: rootComp,
		CreationTime:  time.Now().UTC(),
		Components:    components,
		Metadata: map[string]string{
			"standard": "CycloneDX",
			"filename": filename,
		},
	}, nil
}

func parseSPDX(raw map[string]any, spdxVer string, filename string) (*SBOMDocument, error) {
	docFormat := FormatSPDXv2
	if strings.Contains(spdxVer, "3.0") {
		docFormat = FormatSPDXv3
	}

	docName, _ := raw["name"].(string)
	if docName == "" {
		docName = filename
	}

	var components []PackageComponent

	// SPDX packages array
	packages, _ := raw["packages"].([]any)
	if packages == nil {
		// SPDX 3.0 elements
		packages, _ = raw["elements"].([]any)
	}

	for _, item := range packages {
		if len(components) >= MaxPackageCount {
			break
		}
		pkgMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := pkgMap["name"].(string)
		if name == "" {
			name, _ = pkgMap["spdxId"].(string)
		}

		version, _ := pkgMap["versionInfo"].(string)
		if version == "" {
			version, _ = pkgMap["packageVersion"].(string)
		}

		supplier, _ := pkgMap["supplier"].(string)
		license, _ := pkgMap["licenseConcluded"].(string)
		if license == "" || license == "NOASSERTION" {
			license, _ = pkgMap["licenseDeclared"].(string)
		}

		purl := ""
		if refs, ok := pkgMap["externalRefs"].([]any); ok {
			for _, r := range refs {
				if rMap, ok := r.(map[string]any); ok {
					refType, _ := rMap["referenceType"].(string)
					if strings.EqualFold(refType, "purl") {
						purl, _ = rMap["referenceLocator"].(string)
					}
				}
			}
		}

		checksum := ""
		checksumType := ""
		if checksums, ok := pkgMap["checksums"].([]any); ok {
			for _, c := range checksums {
				if cMap, ok := c.(map[string]any); ok {
					alg, _ := cMap["algorithm"].(string)
					val, _ := cMap["checksumValue"].(string)
					if strings.EqualFold(alg, "SHA256") {
						checksum = val
						checksumType = "sha256"
						break
					} else if checksum == "" {
						checksum = val
						checksumType = strings.ToLower(alg)
					}
				}
			}
		}

		storePath := ""
		if strings.HasPrefix(name, "/nix/store/") {
			storePath = name
			parts := strings.Split(name, "-")
			if len(parts) > 1 {
				name = strings.Join(parts[1:], "-")
			}
		}

		components = append(components, PackageComponent{
			Name:         name,
			Version:      version,
			PURL:         purl,
			StorePath:    storePath,
			Checksum:     checksum,
			ChecksumType: checksumType,
			License:      license,
			Supplier:     supplier,
			Properties:   map[string]string{},
		})
	}

	return &SBOMDocument{
		Format:        docFormat,
		SpecVersion:   spdxVer,
		DocumentName:  docName,
		RootComponent: docName,
		CreationTime:  time.Now().UTC(),
		Components:    components,
		Metadata: map[string]string{
			"standard": "SPDX",
			"filename": filename,
		},
	}, nil
}

func parseNixClosure(raw map[string]any, filename string) (*SBOMDocument, error) {
	var components []PackageComponent

	// Either array of store paths or dictionary of store path details
	if storePaths, ok := raw["storePaths"].([]any); ok {
		for _, sp := range storePaths {
			if len(components) >= MaxPackageCount {
				break
			}
			pathStr, ok := sp.(string)
			if !ok {
				continue
			}
			pkgName, pkgVer := extractNixNameAndVersion(pathStr)
			components = append(components, PackageComponent{
				Name:      pkgName,
				Version:   pkgVer,
				StorePath: pathStr,
			})
		}
	} else if closureMap, ok := raw["closure"].(map[string]any); ok {
		for pathStr, val := range closureMap {
			if len(components) >= MaxPackageCount {
				break
			}
			pkgName, pkgVer := extractNixNameAndVersion(pathStr)
			checksum := ""
			if valMap, ok := val.(map[string]any); ok {
				if nh, ok := valMap["narHash"].(string); ok {
					checksum = nh
				}
			}
			components = append(components, PackageComponent{
				Name:         pkgName,
				Version:      pkgVer,
				StorePath:    pathStr,
				Checksum:     checksum,
				ChecksumType: "narHash",
			})
		}
	}

	return &SBOMDocument{
		Format:        FormatNixClosure,
		SpecVersion:   "2.0",
		DocumentName:  filename,
		RootComponent: filename,
		CreationTime:  time.Now().UTC(),
		Components:    components,
		Metadata: map[string]string{
			"standard": "NixOS-Closure",
			"filename": filename,
		},
	}, nil
}

func extractNixNameAndVersion(storePath string) (string, string) {
	base := filepath.Base(storePath)
	// /nix/store/<hash>-<name>-<version>
	parts := strings.SplitN(base, "-", 2)
	if len(parts) < 2 {
		return base, "1.0.0"
	}
	remainder := parts[1]
	lastDash := strings.LastIndex(remainder, "-")
	if lastDash == -1 {
		return remainder, "latest"
	}

	name := remainder[:lastDash]
	ver := remainder[lastDash+1:]
	// check if ver starts with a digit
	if len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9' {
		return name, ver
	}
	return remainder, "latest"
}
