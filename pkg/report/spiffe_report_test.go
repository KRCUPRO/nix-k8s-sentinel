package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/spiffe"
)

func TestBuildSARIFReport_SPIFFEViolations(t *testing.T) {
	spiffeViolations := []spiffe.SPIFFEViolation{
		{
			RuleID:       "SPIFFE-SVID-001",
			Title:        "Untrusted Foreign Trust Domain in SPIFFE ID",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.1,
			Category:     spiffe.CategoryTrustDomain,
			ResourceKind: "X509SVID",
			ResourceName: "rogue-runner",
			FilePath:     "fixtures/spiffe-telemetry.json",
			StartLine:    35,
			Message:      "Workload presents SVID for unauthorized foreign trust domain 'untrusted-external.net'",
			Remediation:  "Configure explicit SPIFFE federation relationships",
			SPIFFEID:     "spiffe://untrusted-external.net/ns/legacy/sa/rogue-runner",
			Workload:     "rogue-runner",
			MatchedCVE:   "CVE-2026-67210",
		},
		{
			RuleID:       "SPIFFE-SVID-004",
			Title:        "Permissive Wildcard Attestation Selector in SPIRE Registration Entry",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.3,
			Category:     spiffe.CategoryAttestation,
			ResourceKind: "SpireRegistrationEntry",
			ResourceName: "wildcard-app",
			Namespace:    "default",
			FilePath:     "fixtures/spiffe-manifests.yaml",
			StartLine:    15,
			Message:      "Registration entry declares wildcard attestation selector 'k8s:ns:*'",
			Remediation:  "Bind registration entries to concrete, immutable selectors",
			SPIFFEID:     "spiffe://cluster.local/ns/default/sa/wildcard-app",
			Workload:     "wildcard-app",
		},
		{
			RuleID:       "SPIFFE-SVID-006",
			Title:        "Missing mTLS Enforcement in Cilium Ingress Policy",
			Severity:     intel.SeverityHigh,
			CVSSScore:    8.2,
			Category:     spiffe.CategoryMicrosegment,
			ResourceKind: "CiliumNetworkPolicy",
			ResourceName: "unauthenticated-ingress-policy",
			Namespace:    "frontend",
			FilePath:     "fixtures/spiffe-manifests.yaml",
			StartLine:    40,
			Message:      "Policy permits ingress traffic without requiring mTLS authentication or io.spiffe.id matching",
			Remediation:  "Add 'authentication.mode: required' and match on 'io.spiffe.id'",
		},
	}

	opts := ReportOptions{
		Version:          "0.14.0",
		SPIFFEViolations: spiffeViolations,
		SPIFFEPath:       "fixtures/spiffe-manifests.yaml",
	}

	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report with SPIFFE violations: %v", err)
	}

	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run in SARIF log, got %d", len(sarifLog.Runs))
	}

	results := sarifLog.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("expected 3 results in SARIF run, got %d", len(results))
	}

	foundTrustDomain := false
	foundWildcard := false
	foundCilium := false

	for _, res := range results {
		if res.RuleID == "SPIFFE-SVID-001" {
			foundTrustDomain = true
			if res.Level != "error" {
				t.Errorf("expected level 'error' for critical rule SPIFFE-SVID-001, got %s", res.Level)
			}
			if !strings.Contains(res.Message.Text, "SPIFFE ID") {
				t.Errorf("expected SPIFFE ID in result message, got: %s", res.Message.Text)
			}
		}
		if res.RuleID == "SPIFFE-SVID-004" {
			foundWildcard = true
			if res.Level != "error" {
				t.Errorf("expected level 'error' for critical rule SPIFFE-SVID-004, got %s", res.Level)
			}
		}
		if res.RuleID == "SPIFFE-SVID-006" {
			foundCilium = true
			if res.Level != "error" {
				t.Errorf("expected level 'error' for high rule SPIFFE-SVID-006, got %s", res.Level)
			}
		}
	}

	if !foundTrustDomain || !foundWildcard || !foundCilium {
		t.Errorf("missing expected rules in SARIF results: trustDomain=%t, wildcard=%t, cilium=%t",
			foundTrustDomain, foundWildcard, foundCilium)
	}
}

func TestBuildJSONReport_SPIFFEViolations(t *testing.T) {
	spiffeViolations := []spiffe.SPIFFEViolation{
		{
			RuleID:       "SPIFFE-SVID-003",
			Title:        "SVID Approaching Expiration Without Renewal Window (< 15 Minutes Remaining)",
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.8,
			Category:     spiffe.CategorySVIDValidity,
			ResourceKind: "X509SVID",
			ResourceName: "vault-pod",
			Namespace:    "prod",
			Message:      "SVID for workload 'vault-pod' expires in 8 minutes",
			Remediation:  "Ensure SPIRE Agent workload attester is actively connected",
			SPIFFEID:     "spiffe://cluster.local/ns/prod/sa/vault",
			Workload:     "vault-pod",
			MatchedCVE:   "CVE-2026-67210",
		},
	}

	summary := &spiffe.SPIFFESummary{
		TotalChecks:               10,
		PassedChecks:              9,
		ComplianceScore:           90.0,
		HighCount:                 1,
		SVIDsAudited:              5,
		SVIDsValid:                4,
		SVIDsExpiredOrNearExpiry:  1,
		CiliumPoliciesSynthesized: 2,
	}

	opts := ReportOptions{
		Version:             "0.14.0",
		SPIFFEViolations:    spiffeViolations,
		SPIFFESummary:       summary,
		SPIFFETelemetryPath: "fixtures/spiffe-telemetry.json",
	}

	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report with SPIFFE data: %v", err)
	}

	if jsonRep.SPIFFESummary == nil {
		t.Fatalf("expected non-nil SPIFFESummary in JSON report")
	}
	if jsonRep.SPIFFESummary.ComplianceScore != 90.0 {
		t.Errorf("expected compliance score 90.0, got %.1f", jsonRep.SPIFFESummary.ComplianceScore)
	}
	if len(jsonRep.SPIFFEViolations) != 1 {
		t.Errorf("expected 1 SPIFFE violation, got %d", len(jsonRep.SPIFFEViolations))
	}
	if jsonRep.Telemetry.TotalSPIFFEViolations != 1 {
		t.Errorf("expected 1 TotalSPIFFEViolations in telemetry, got %d", jsonRep.Telemetry.TotalSPIFFEViolations)
	}

	// Verify serialization
	data, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	var roundtrip JSONAuditReport
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("roundtrip unmarshal failed: %v", err)
	}
	if len(roundtrip.SPIFFEViolations) != 1 {
		t.Errorf("expected 1 SPIFFEViolation in roundtrip, got %d", len(roundtrip.SPIFFEViolations))
	}
}

func TestGenerateBriefing_SPIFFESection(t *testing.T) {
	spiffeViolations := []spiffe.SPIFFEViolation{
		{
			RuleID:       "SPIFFE-SVID-001",
			Title:        "Untrusted Foreign Trust Domain in SPIFFE ID",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.1,
			Category:     spiffe.CategoryTrustDomain,
			ResourceKind: "X509SVID",
			ResourceName: "rogue-runner",
			Message:      "Workload presents unauthorized foreign trust domain",
			Remediation:  "Configure explicit SPIFFE federation relationships",
			Workload:     "rogue-runner",
			MatchedCVE:   "CVE-2026-67210",
		},
	}

	summary := &spiffe.SPIFFESummary{
		TotalChecks:               20,
		PassedChecks:              19,
		ComplianceScore:           95.0,
		CriticalCount:             1,
		SVIDsAudited:              8,
		SVIDsValid:                7,
		SVIDsExpiredOrNearExpiry:  1,
		CiliumPoliciesSynthesized: 3,
	}

	opts := BriefingOptions{
		Title:            "Weekly Threat Briefing with SPIFFE",
		Version:          "0.14.0",
		HourlyWindow:     time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC),
		SPIFFEViolations: spiffeViolations,
		SPIFFESummary:    summary,
	}

	rep, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}

	if !strings.Contains(rep.Content, "Zero-Trust Microsegmentation & SPIFFE/SPIRE Workload Attestation") {
		t.Errorf("missing SPIFFE/SPIRE section title in briefing")
	}
	if !strings.Contains(rep.Content, "Compliance Score:** `95.0%`") {
		t.Errorf("missing compliance score in briefing")
	}
	if !strings.Contains(rep.Content, "SPIFFE-SVID-001") {
		t.Errorf("missing SPIFFE-SVID-001 in briefing findings table")
	}
	if !strings.Contains(rep.Content, "CVE-2026-67210") {
		t.Errorf("missing CVE-2026-67210 tag in briefing findings table")
	}
	if !strings.Contains(rep.Content, "Validate SPIFFE/SPIRE X.509 SVID renewal windows") {
		t.Errorf("missing SPIFFE item in operational checklist")
	}

	// Verify file persistence
	tmpDir := t.TempDir()
	savedPath, err := WriteBriefingToFile(rep, tmpDir, "test-briefing.md")
	if err != nil {
		t.Fatalf("WriteBriefingToFile failed: %v", err)
	}

	content, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read written briefing: %v", err)
	}
	if !strings.Contains(string(content), "Zero-Trust Microsegmentation") {
		t.Errorf("written file does not contain expected section")
	}
	_ = filepath.Base(savedPath)
}
