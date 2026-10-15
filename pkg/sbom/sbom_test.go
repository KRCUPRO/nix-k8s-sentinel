package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalRules(t *testing.T) {
	rules := AllRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 canonical SBOM rules, got %d", len(rules))
	}

	for _, r := range rules {
		if r.ID == "" || r.Title == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s has empty required fields", r.ID)
		}
		if r.DefaultCVSS < 0.0 || r.DefaultCVSS > 10.0 {
			t.Errorf("rule %s has out of bounds CVSS: %f", r.ID, r.DefaultCVSS)
		}
		retrieved, found := GetRule(r.ID)
		if !found || retrieved.ID != r.ID {
			t.Errorf("failed to retrieve rule %s via GetRule", r.ID)
		}
	}
}

func TestParseCycloneDX(t *testing.T) {
	cdxPayload := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {
				"name": "nix-k8s-sentinel-core",
				"version": "0.15.0"
			}
		},
		"components": [
			{
				"name": "containerd",
				"version": "1.7.12",
				"purl": "pkg:generic/containerd@1.7.12",
				"hashes": [
					{"alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
				],
				"licenses": [
					{"license": {"id": "Apache-2.0"}}
				],
				"properties": [
					{"name": "nix:storePath", "value": "/nix/store/x1y2z3-containerd-1.7.12"}
				]
			},
			{
				"name": "libseccomp",
				"version": "2.5.4",
				"purl": "pkg:generic/libseccomp@2.5.4",
				"hashes": [
					{"alg": "SHA-256", "content": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"}
				],
				"licenses": [
					{"license": {"id": "LGPL-2.1-only"}}
				]
			}
		]
	}`

	doc, err := ParseSBOM([]byte(cdxPayload), "test-cyclonedx.json")
	if err != nil {
		t.Fatalf("unexpected error parsing CycloneDX: %v", err)
	}

	if doc.Format != FormatCycloneDXv16 {
		t.Errorf("expected format %s, got %s", FormatCycloneDXv16, doc.Format)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(doc.Components))
	}

	c1 := doc.Components[0]
	if c1.Name != "containerd" || c1.Version != "1.7.12" || c1.License != "Apache-2.0" {
		t.Errorf("component 1 mismatch: %+v", c1)
	}
	if c1.StorePath != "/nix/store/x1y2z3-containerd-1.7.12" {
		t.Errorf("expected storePath, got: %s", c1.StorePath)
	}
}

func TestParseSPDX(t *testing.T) {
	spdxPayload := `{
		"spdxVersion": "SPDX-3.0.0",
		"name": "nixos-system-image",
		"packages": [
			{
				"name": "linux-kernel",
				"versionInfo": "6.12.8",
				"supplier": "Organization: NixOS",
				"licenseConcluded": "GPL-2.0-only",
				"checksums": [
					{"algorithm": "SHA256", "checksumValue": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}
				],
				"externalRefs": [
					{"referenceType": "purl", "referenceLocator": "pkg:generic/linux@6.12.8"}
				]
			}
		]
	}`

	doc, err := ParseSBOM([]byte(spdxPayload), "test-spdx.json")
	if err != nil {
		t.Fatalf("unexpected error parsing SPDX: %v", err)
	}

	if doc.Format != FormatSPDXv3 {
		t.Errorf("expected format %s, got %s", FormatSPDXv3, doc.Format)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Components))
	}

	pkg := doc.Components[0]
	if pkg.Name != "linux-kernel" || pkg.Version != "6.12.8" || pkg.License != "GPL-2.0-only" {
		t.Errorf("package mismatch: %+v", pkg)
	}
}

func TestParseNixClosure(t *testing.T) {
	nixPayload := `{
		"closure": {
			"/nix/store/abc123def456-glibc-2.39": {
				"narHash": "sha256-11223344",
				"closureSize": 35000000
			},
			"/nix/store/def456ghi789-openssl-3.0.13": {
				"narHash": "sha256-55667788",
				"closureSize": 12000000
			}
		}
	}`

	doc, err := ParseSBOM([]byte(nixPayload), "test-closure.json")
	if err != nil {
		t.Fatalf("unexpected error parsing Nix closure: %v", err)
	}

	if doc.Format != FormatNixClosure {
		t.Errorf("expected format %s, got %s", FormatNixClosure, doc.Format)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(doc.Components))
	}
}

func TestInTotoAttestationSLSALevel3(t *testing.T) {
	attestPayload := `{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [
			{
				"name": "nix-k8s-sentinel-bin",
				"digest": {
					"sha256": "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"
				}
			}
		],
		"predicate": {
			"builder": {
				"id": "https://github.com/KRCUPRO/nix-k8s-sentinel/.github/workflows/release.yml@refs/tags/v0.15.0"
			},
			"buildType": "https://slsa.dev/container-based-build/v1",
			"buildDefinition": {
				"systemParameters": {
					"hermetic": true,
					"reproducible": true
				}
			},
			"materials": [
				{
					"uri": "git+https://github.com/KRCUPRO/nix-k8s-sentinel",
					"digest": {
						"sha1": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b"
					}
				}
			]
		},
		"signatures": [
			{"keyid": "cosign-root", "sig": "MEYCIQCc8y21"}
		]
	}`

	attest, vios, err := VerifyAttestationPayload([]byte(attestPayload), "attestation.json")
	if err != nil {
		t.Fatalf("unexpected error verifying attestation: %v", err)
	}

	if attest.EvaluatedSLSALevel != SLSALevel3 {
		t.Errorf("expected SLSA Level 3, got %s (violations: %d)", attest.EvaluatedSLSALevel, len(vios))
	}
	if len(vios) != 0 {
		t.Errorf("expected 0 violations for clean SLSA Level 3 attestation, got %d: %+v", len(vios), vios)
	}

	// Verify matching subject digest
	v := VerifySubjectDigest(attest, "nix-k8s-sentinel-bin", "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b")
	if v != nil {
		t.Errorf("expected nil violation for matching digest, got: %+v", v)
	}

	// Verify tampered subject digest
	vTampered := VerifySubjectDigest(attest, "nix-k8s-sentinel-bin", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if vTampered == nil || vTampered.RuleID != "SBOM-CHAIN-004" {
		t.Errorf("expected SBOM-CHAIN-004 violation for tampered digest, got: %+v", vTampered)
	}
}

func TestInTotoAttestationNonHermeticAndUnpinned(t *testing.T) {
	badAttestPayload := `{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [
			{
				"name": "unhardened-app",
				"digest": {"sha256": "aabbccddeeff"}
			}
		],
		"predicate": {
			"builder": {"id": "https://untrusted-builder.local"},
			"buildDefinition": {
				"systemParameters": {
					"hermetic": false
				}
			},
			"materials": [
				{"uri": "https://github.com/example/repo@refs/heads/main"}
			]
		}
	}`

	attest, vios, err := VerifyAttestationPayload([]byte(badAttestPayload), "bad-attestation.json")
	if err != nil {
		t.Fatalf("unexpected error parsing bad attestation: %v", err)
	}

	if attest.EvaluatedSLSALevel == SLSALevel3 {
		t.Errorf("bad attestation should not achieve SLSA Level 3")
	}

	foundUnpinned := false
	foundNonHermetic := false
	for _, v := range vios {
		if v.RuleID == "SBOM-CHAIN-005" {
			foundUnpinned = true
		}
		if v.RuleID == "SBOM-CHAIN-006" {
			foundNonHermetic = true
		}
	}

	if !foundUnpinned {
		t.Errorf("expected SBOM-CHAIN-005 (unpinned material) violation")
	}
	if !foundNonHermetic {
		t.Errorf("expected SBOM-CHAIN-006 (non-hermetic) violation")
	}
}

func TestSBOMDeltaReconciliation(t *testing.T) {
	doc := &SBOMDocument{
		Format: FormatCycloneDXv16,
		Components: []PackageComponent{
			{
				Name:     "nginx",
				Version:  "1.25.4",
				Checksum: "1111222233334444",
			},
			{
				Name:     "busybox",
				Version:  "1.36.1",
				Checksum: "5555666677778888",
			},
			{
				Name:     "curl",
				Version:  "8.5.0",
				Checksum: "99990000aaaabbbb",
			},
		},
	}

	runtimeState := []RuntimePackageState{
		{
			PackageName: "nginx",
			Version:     "1.25.4",
			SHA256:      "1111222233334444", // Clean match
		},
		{
			PackageName: "busybox",
			Version:     "1.37.0", // Version drift!
			SHA256:      "5555666677778888",
		},
		{
			PackageName: "netcat", // Undeclared runtime package / injection!
			Version:     "0.7.1",
			SHA256:      "ccccdddd",
		},
	}

	deltaItems, vios := GenerateSBOMDelta(doc, runtimeState)

	if len(deltaItems) != 4 { // nginx (match), busybox (drift), netcat (undeclared), curl (missing in runtime)
		t.Fatalf("expected 4 delta items, got %d", len(deltaItems))
	}

	statusCount := make(map[SBOMDeltaStatus]int)
	for _, item := range deltaItems {
		statusCount[item.Status]++
	}

	if statusCount[DeltaMatch] != 1 {
		t.Errorf("expected 1 DeltaMatch, got %d", statusCount[DeltaMatch])
	}
	if statusCount[DeltaVersionDrift] != 1 {
		t.Errorf("expected 1 DeltaVersionDrift, got %d", statusCount[DeltaVersionDrift])
	}
	if statusCount[DeltaUndeclaredRuntime] != 1 {
		t.Errorf("expected 1 DeltaUndeclaredRuntime, got %d", statusCount[DeltaUndeclaredRuntime])
	}
	if statusCount[DeltaMissingInRuntime] != 1 {
		t.Errorf("expected 1 DeltaMissingInRuntime, got %d", statusCount[DeltaMissingInRuntime])
	}

	if len(vios) != 2 { // busybox drift (SBOM-CHAIN-009) and netcat undeclared (SBOM-CHAIN-008)
		t.Errorf("expected 2 violations from delta, got %d: %+v", len(vios), vios)
	}
}

func TestFeedCorrelationAndScanner(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-sbom-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sbomFile := filepath.Join(tmpDir, "production-app.cyclonedx.json")
	sbomContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{
				"name": "ingress-nginx",
				"version": "1.9.0",
				"licenses": [{"license": {"id": "Apache-2.0"}}]
			},
			{
				"name": "unlicensed-util",
				"version": "0.1.0",
				"licenses": [{"license": {"id": "UNKNOWN"}}]
			}
		]
	}`
	if err := os.WriteFile(sbomFile, []byte(sbomContent), 0644); err != nil {
		t.Fatalf("failed to write test sbom file: %v", err)
	}

	feed := &intel.Feed{
		UpdatedAt: time.Now().UTC(),
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-21801",
				Title:       "Ingress-Nginx Path Traversal Vulnerability",
				Severity:    intel.SeverityCritical,
				CVSSScore:   9.8,
				Target:      "ingress-nginx",
				Description: "Arbitrary path traversal in ingress-nginx controller.",
				Mitigation:  "Upgrade ingress-nginx to >= 1.9.5",
			},
		},
	}

	scanner := NewSBOMScanner(feed)
	rep, err := scanner.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if rep.TotalFiles != 1 || len(rep.Documents) != 1 {
		t.Fatalf("expected 1 document in report, got %d", len(rep.Documents))
	}

	foundCVE := false
	foundLicense := false
	for _, v := range rep.Violations {
		if strings.Contains(v.Title, "CVE-2026-21801") {
			foundCVE = true
		}
		if v.RuleID == "SBOM-CHAIN-011" {
			foundLicense = true
		}
	}

	if !foundCVE {
		t.Errorf("expected CVE-2026-21801 correlation violation")
	}
	if !foundLicense {
		t.Errorf("expected SBOM-CHAIN-011 unknown license violation")
	}

	if rep.Summary.ComplianceScore >= 100.0 {
		t.Errorf("expected compliance score to be discounted due to violations, got: %f", rep.Summary.ComplianceScore)
	}
}

func TestDefensiveMemoryBounds(t *testing.T) {
	oversized := make([]byte, MaxSBOMBytes+1024)
	_, err := ParseSBOM(oversized, "huge.json")
	if err == nil {
		t.Errorf("expected error when parsing oversized SBOM payload")
	}
}
