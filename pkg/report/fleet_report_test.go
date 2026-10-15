package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/fleet"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestBuildSARIFReport_FleetViolations(t *testing.T) {
	fleetViolations := []fleet.FleetViolation{
		{
			RuleID:       "FLEET-RBAC-003",
			Title:        "Cluster-Admin Bound to Broad Authenticated or Anonymous Subject Groups",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.8,
			Category:     fleet.CategoryRBAC,
			ResourceKind: "ClusterRoleBinding",
			ResourceName: "all-authenticated-admins",
			ClusterID:    "prod-cluster-01",
			FilePath:     "fixtures/fleet-manifests.yaml",
			StartLine:    45,
			Message:      "ClusterRoleBinding binds cluster-admin to system:authenticated",
			Remediation:  "Scope bindings strictly to explicit users or service accounts",
			MatchedCVE:   "CVE-2026-60114",
		},
		{
			RuleID:       "FLEET-OIDC-001",
			Title:        "Insecure OIDC Token Signing Algorithm Permitting Forgery",
			Severity:     intel.SeverityCritical,
			CVSSScore:    9.6,
			Category:     fleet.CategoryOIDC,
			ResourceKind: "OIDCToken",
			ResourceName: "tok-insecure-001",
			ClusterID:    "prod-cluster-02",
			FilePath:     "fixtures/fleet-telemetry.json",
			StartLine:    1,
			Message:      "OIDC token uses signing algorithm 'none'",
			Remediation:  "Enforce asymmetric algorithms (RS256, ES256, EdDSA)",
			MatchedCVE:   "CVE-2026-60114",
		},
		{
			RuleID:       "FLEET-GITOPS-001",
			Title:        "GitOps Automated Self-Healing Disabled Permitting Silent Drift",
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.5,
			Category:     fleet.CategoryGitOpsDrift,
			ResourceKind: "Application",
			ResourceName: "payment-api",
			ClusterID:    "prod-cluster-01",
			FilePath:     "fixtures/fleet-manifests.yaml",
			StartLine:    80,
			Message:      "ArgoCD Application has automated selfHeal disabled",
			Remediation:  "Enable selfHeal: true in syncPolicy",
		},
	}

	opts := ReportOptions{
		Version:         "0.13.0",
		FleetViolations: fleetViolations,
	}

	log, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF with Fleet violations: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 Fleet SARIF results, got %d", len(run.Results))
	}

	for _, res := range run.Results {
		if res.Level != "error" {
			t.Errorf("expected error level for high/critical Fleet violations, got %s", res.Level)
		}
	}
}

func TestBuildJSONReport_FleetViolations(t *testing.T) {
	fleetViolations := []fleet.FleetViolation{
		{
			RuleID:       "FLEET-DRIFT-001",
			Title:        "Multi-Cluster Fleet Desynchronization or Degraded Health Detected",
			Severity:     intel.SeverityHigh,
			CVSSScore:    8.0,
			Category:     fleet.CategoryMultiCluster,
			ResourceKind: "GitOpsApplication",
			ResourceName: "checkout-frontend",
			ClusterID:    "eu-west-prod",
			Message:      "Application is OutOfSync with git revision",
			Remediation:  "Restore cluster sync parity",
		},
	}

	summary := &fleet.FleetSummary{
		TotalChecks:        20,
		PassedChecks:       18,
		ComplianceScore:    90.0,
		CriticalCount:      0,
		HighCount:          2,
		ClustersAudited:    3,
		ClustersInSync:     2,
		DriftingApps:       1,
		OIDCTokensVerified: 5,
	}

	opts := ReportOptions{
		Version:         "0.13.0",
		FleetViolations: fleetViolations,
		FleetSummary:    summary,
		FleetPath:       "fixtures/fleet-manifests.yaml",
		Pretty:          true,
	}

	rep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON with Fleet findings: %v", err)
	}

	if rep.ToolVersion != "0.13.0" {
		t.Errorf("expected version 0.13.0, got %s", rep.ToolVersion)
	}
	if len(rep.FleetViolations) != 1 {
		t.Errorf("expected 1 fleet violation in JSON report, got %d", len(rep.FleetViolations))
	}
	if rep.FleetSummary == nil || rep.FleetSummary.ClustersAudited != 3 {
		t.Errorf("expected FleetSummary with 3 clusters audited")
	}

	data, err := FormatJSON(rep, true)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "fleet-report.json")
	if err := WriteJSONToFile(rep, outFile, true); err != nil {
		t.Fatalf("failed to write JSON to file: %v", err)
	}

	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		t.Errorf("expected JSON file to exist at %s", outFile)
	}
}

func TestGenerateBriefing_FleetSection(t *testing.T) {
	opts := BriefingOptions{
		Title:        "Test Fleet Threat Briefing",
		Version:      "0.13.0",
		HourlyWindow: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC),
		FleetViolations: []fleet.FleetViolation{
			{
				RuleID:       "FLEET-OIDC-002",
				Title:        "Excessive or Unexpiring OIDC Federated Token TTL",
				Severity:     intel.SeverityHigh,
				CVSSScore:    7.8,
				Category:     fleet.CategoryOIDC,
				ResourceKind: "OIDCToken",
				ResourceName: "tok-ap-01",
				ClusterID:    "ap-southeast-dr",
				Message:      "OIDC token lifespan is 48.0 hours",
				Remediation:  "Enforce short-lived token lifetimes",
			},
		},
		FleetSummary: &fleet.FleetSummary{
			TotalChecks:        10,
			PassedChecks:       9,
			ComplianceScore:    90.0,
			ClustersAudited:    2,
			ClustersInSync:     1,
			DriftingApps:       1,
			OIDCTokensVerified: 3,
		},
	}

	rep, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("failed to generate briefing with fleet data: %v", err)
	}

	if !strings.Contains(rep.Content, "Multi-Cluster Fleet Synchronization & OIDC Token Radar") {
		t.Errorf("briefing content missing fleet synchronization section header")
	}
	if !strings.Contains(rep.Content, "FLEET-OIDC-002") {
		t.Errorf("briefing content missing FLEET-OIDC-002 rule ID")
	}
	if !strings.Contains(rep.Content, "Rotate federated OIDC identity tokens") && !strings.Contains(rep.Content, "rotate federated OIDC identity tokens") {
		t.Errorf("briefing content missing fleet operational checklist item")
	}
}
