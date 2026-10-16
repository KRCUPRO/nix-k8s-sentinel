package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/pqc"
)

func TestPQCReportSerialization(t *testing.T) {
	vios := []pqc.PQCViolation{
		{
			RuleID:      "PQC-TLS-001",
			Title:       "Insecure TLS Protocol Version Configured on Kubernetes Control Plane",
			Component:   "kube-apiserver",
			Target:      "kubernetes",
			Resource:    "kube-apiserver/tls-config",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.2,
			Description: "Component 'kube-apiserver' configures insecure TLS minimum version 'VersionTLS12'",
			Remediation: "Configure '--tls-min-version=VersionTLS13' on all control plane daemons",
			Location:    "fixtures/k8s-pqc-vulnerable.yaml",
			LineNumber:  10,
		},
		{
			RuleID:      "PQC-TLS-002",
			Title:       "Missing Hybrid Post-Quantum Key Encapsulation (Harvest-Now-Decrypt-Later Threat)",
			Component:   "kube-apiserver",
			Target:      "kubernetes",
			Resource:    "kube-apiserver/tls-config",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.8,
			Description: "Component 'kube-apiserver' lacks hybrid post-quantum key encapsulation groups",
			Remediation: "Enable hybrid post-quantum key encapsulation groups (X25519MLKEM768, SecP384r1MLKEM1024)",
			MatchedCVE:  "CVE-2026-94301",
			Location:    "fixtures/k8s-pqc-vulnerable.yaml",
			LineNumber:  12,
		},
	}

	summary := &pqc.PQCSummary{
		TotalEndpointsScanned: 2,
		TotalConfigsScanned:   1,
		TotalTelemetryEvents:  4,
		ViolationsCount:       2,
		CriticalCount:         0,
		HighCount:             2,
		HybridKEMPercentage:   50.0,
		TLS13Percentage:       75.0,
		CNSAComplianceScore:   70.0,
		AuditStatus:           "FAIL (Vulnerable to Harvest-Now-Decrypt-Later)",
	}

	opts := ReportOptions{
		Version:          "0.18.0",
		PQCViolations:    vios,
		PQCSummary:       summary,
		PQCPath:          "fixtures/k8s-pqc-vulnerable.yaml",
		PQCTelemetryPath: "fixtures/pqc-telemetry.json",
	}

	// 1. Validate SARIF Serialization
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("failed to build SARIF report: %v", err)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(sarifLog.Runs))
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 SARIF results for PQC violations, got %d", len(sarifLog.Runs[0].Results))
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("failed to format SARIF: %v", err)
	}
	sarifStr := string(sarifBytes)
	if !strings.Contains(sarifStr, "PQC-TLS-001") || !strings.Contains(sarifStr, "CVE-2026-94301") {
		t.Errorf("SARIF output missing expected PQC rule or CVE tag")
	}

	// 2. Validate JSON Report Serialization
	jsonRep, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("failed to build JSON report: %v", err)
	}
	if len(jsonRep.PQCViolations) != 2 {
		t.Fatalf("expected 2 PQC violations in JSON report, got %d", len(jsonRep.PQCViolations))
	}
	if jsonRep.Telemetry.TotalPQCViolations != 2 {
		t.Errorf("expected TotalPQCViolations=2, got %d", jsonRep.Telemetry.TotalPQCViolations)
	}

	jsonBytes, err := json.Marshal(jsonRep)
	if err != nil {
		t.Fatalf("failed to marshal JSON report: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "PQC-TLS-002") {
		t.Errorf("JSON output missing PQC-TLS-002")
	}

	// 3. Validate Threat Briefing Generation
	briefingOpts := BriefingOptions{
		Title:         "Automated Threat Intelligence Briefing",
		Version:       "0.18.0",
		HourlyWindow:  time.Now(),
		PQCViolations: vios,
		PQCSummary:    summary,
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate briefing: %v", err)
	}
	if !strings.Contains(briefing.Content, "Post-Quantum Cryptography (PQC) & CNSA 2.0 Cryptographic Readiness") {
		t.Errorf("briefing missing PQC section header")
	}
	if !strings.Contains(briefing.Content, "CVE-2026-94301") {
		t.Errorf("briefing missing CVE-2026-94301 advisory tag")
	}
}
