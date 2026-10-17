package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/remediate"
)

func TestRemediateReportSerialization(t *testing.T) {
	findings := []remediate.RemediationFinding{
		{
			RuleID:           "REMEDIATE-AUTO-002",
			Target:           "kubernetes",
			ResourceKind:     "Deployment",
			ResourceName:     "payment-workload",
			Namespace:        "prod",
			Severity:         "HIGH",
			CVSSScore:        7.8,
			Title:            "Unhardened Workload Container SecurityContext Kustomize Hardening",
			Description:      "Container workload running without runAsNonRoot and readOnlyRootFilesystem",
			Remediation:      "Synthesize Kustomize strategic merge patch enforcing non-root",
			MatchedCVE:       "CVE-2026-20914",
			SynthesizedPatch: "spec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n",
			CanaryStatus:     remediate.CanaryPassed,
			SourceFile:       "fixtures/remediation/k8s-workload.yaml",
			LineNumber:       1,
		},
		{
			RuleID:           "REMEDIATE-AUTO-006",
			Target:           "nixos",
			ResourceKind:     "NixOSWireGuard",
			ResourceName:     "nixos-vulnerable.nix",
			Severity:         "HIGH",
			CVSSScore:        8.5,
			Title:            "Plaintext WireGuard Private Key Migration to Encrypted Runtime Secret",
			Description:      "Plaintext private key in /nix/store",
			Remediation:      "Migrate to /run/secrets/wireguard/key",
			MatchedCVE:       "CVE-2026-31048",
			SynthesizedPatch: "--- a/nixos.nix\n+++ b/nixos.nix\n",
			CanaryStatus:     remediate.CanaryPassed,
			SourceFile:       "fixtures/remediation/nixos-vulnerable.nix",
			LineNumber:       1,
		},
	}

	prs := []remediate.GitOpsPullRequest{
		{
			PRNumber:      42,
			Title:         "fix(security): apply declarative hardening patches",
			HeadBranch:    "remediation/hardening-42",
			BaseBranch:    "main",
			Summary:       "Automated declarative hardening against CVE-2026-20914 and CVE-2026-31048",
			CommitMessage: "fix(security): apply declarative hardening patches",
			CanaryPassed:  true,
			CreatedAt:     time.Now().UTC(),
		},
	}

	summary := &remediate.RemediationSummary{
		TotalFindings:           2,
		NixOSPatchCount:         1,
		KustomizePatchCount:     1,
		CanaryChecksTotal:       2,
		CanaryPassedCount:       2,
		CanaryFailedCount:       0,
		PullRequestsSynthesized: 1,
		RemediationScore:        100.0,
		Status:                  "PASSED",
	}

	opts := ReportOptions{
		Version:               "0.20.0",
		RemediateFindings:     findings,
		RemediatePullRequests: prs,
		RemediateSummary:      summary,
		RemediatePath:         "fixtures/remediation",
	}

	// 1. Verify SARIF serialization
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report: %v", err)
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(sarifLog.Runs[0].Results))
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("failed to format SARIF: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "REMEDIATE-AUTO-002") {
		t.Errorf("SARIF report missing REMEDIATE-AUTO-002")
	}
	if !strings.Contains(string(sarifBytes), "CVE-2026-20914") {
		t.Errorf("SARIF report missing CVE-2026-20914")
	}

	// 2. Verify JSON serialization
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}
	if len(jsonReport.RemediateFindings) != 2 {
		t.Fatalf("expected 2 remediate findings in JSON report, got %d", len(jsonReport.RemediateFindings))
	}
	if len(jsonReport.RemediatePullRequests) != 1 {
		t.Fatalf("expected 1 pull request in JSON report, got %d", len(jsonReport.RemediatePullRequests))
	}
	if jsonReport.RemediateSummary == nil || jsonReport.RemediateSummary.RemediationScore != 100.0 {
		t.Errorf("expected 100.0 remediation score in JSON report, got %+v", jsonReport.RemediateSummary)
	}

	jsonBytes, err := FormatJSON(jsonReport, true)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	var roundtrip JSONAuditReport
	if err := json.Unmarshal(jsonBytes, &roundtrip); err != nil {
		t.Fatalf("failed to unmarshal JSON roundtrip: %v", err)
	}
	if roundtrip.Telemetry.TotalRemediateFindings != 2 {
		t.Errorf("expected 2 total remediate findings in telemetry summary, got %d", roundtrip.Telemetry.TotalRemediateFindings)
	}

	// 3. Verify Threat Briefing generation
	briefingOpts := BriefingOptions{
		Version:               "0.20.0",
		RemediateFindings:     findings,
		RemediatePullRequests: prs,
		RemediateSummary:      summary,
	}
	rep, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate threat briefing: %v", err)
	}
	if !strings.Contains(rep.Content, "Autonomous Threat Remediation & GitOps Pull Request Posture") {
		t.Errorf("briefing content missing Autonomous Remediation section: %s", rep.Content)
	}
	if !strings.Contains(rep.Content, "REMEDIATE-AUTO-002") {
		t.Errorf("briefing content missing REMEDIATE-AUTO-002: %s", rep.Content)
	}
	if !strings.Contains(rep.Content, "remediation/hardening-42") {
		t.Errorf("briefing content missing head branch: %s", rep.Content)
	}
}
