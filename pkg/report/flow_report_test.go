package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/flow"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestFlowReportSerialization(t *testing.T) {
	violations := []flow.FlowViolation{
		{
			RuleID:      "FLOW-RADAR-001",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.3,
			Title:       "UnrestrictedExternalDNSEgress",
			Description: "Pod egress allows unrestricted UDP port 53 traffic bypassing CoreDNS.",
			Remediation: "Enforce CiliumNetworkPolicy restricting DNS egress to kube-system CoreDNS.",
			FilePath:    "fixtures/cilium-flow-vulnerable.yaml",
			StartLine:   15,
			EndLine:     18,
			MatchedCVE:  "CVE-2026-10392",
		},
		{
			RuleID:      "FLOW-RADAR-003",
			Severity:    intel.SeverityHigh,
			CVSSScore:   8.9,
			Title:       "DNSQueryEntropyThresholdExceeded",
			Description: "High-entropy DNS query detected (Shannon H: 4.15 > 3.85).",
			Remediation: "Intercept high-entropy DNS tunnel sessions using eBPF socket drop filters.",
			FilePath:    "telemetry:pod/prod/payment-svc",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  "CVE-2026-10392",
		},
	}

	summary := flow.FlowSummary{
		TotalScanned:    2,
		CompliantCount:  0,
		ViolationCount:  2,
		ComplianceScore: 60.0,
		CriticalCount:   1,
		HighCount:       1,
	}

	telemetry := &flow.FlowTelemetryReport{
		HostName:              "worker-node-01",
		ClusterName:           "k8s-sentinel-fleet",
		CollectedAt:           time.Now().UTC(),
		TotalDNSQueries:       5000,
		SuspiciousQueries:     25,
		NXDomainCount:         450,
		NXDomainRatePercent:   9.0,
		PeakSocketConnectRate: 420,
		DroppedPackets:        0,
		BufferOverruns:        0,
		DropRatePercent:       0.0,
	}

	reportOpts := ReportOptions{
		Version:         "0.30.0",
		FlowViolations:  violations,
		FlowSummary:     &summary,
		FlowTelemetry:   telemetry,
		FlowPath:        "fixtures/cilium-flow-vulnerable.yaml",
		FlowSynthOut:    "policies/generated/flow",
		TargetFilter:    "kubernetes",
		Pretty:          true,
	}

	// 1. Verify JSON report export
	jsonRep, err := BuildJSONReport(reportOpts)
	if err != nil {
		t.Fatalf("failed to build JSON report with Flow data: %v", err)
	}
	if len(jsonRep.FlowViolations) != 2 {
		t.Errorf("expected 2 Flow violations in JSON report, got %d", len(jsonRep.FlowViolations))
	}
	if jsonRep.FlowSummary.ComplianceScore != 60.0 {
		t.Errorf("expected compliance score 60.0, got %f", jsonRep.FlowSummary.ComplianceScore)
	}

	jsonData, err := FormatJSON(jsonRep, true)
	if err != nil {
		t.Fatalf("failed to format JSON report: %v", err)
	}
	var unmarshaled JSONAuditReport
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("failed to parse generated JSON data: %v", err)
	}

	// 2. Verify SARIF v2.1.0 report export
	sarifLog, err := BuildSARIFReport(reportOpts)
	if err != nil {
		t.Fatalf("failed to build SARIF report with Flow data: %v", err)
	}
	if len(sarifLog.Runs) == 0 || len(sarifLog.Runs[0].Results) < 2 {
		t.Fatalf("expected at least 2 SARIF results for Flow, got %d", len(sarifLog.Runs[0].Results))
	}
	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("failed to format SARIF log: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "FLOW-RADAR-001") {
		t.Errorf("SARIF output does not contain FLOW-RADAR-001")
	}

	// 3. Verify Threat Briefing report export
	briefingOpts := BriefingOptions{
		Title:          "Test Briefing - Flow Domain",
		Version:        "0.30.0",
		FlowViolations: violations,
		FlowSummary:    &summary,
		FlowTelemetry:  telemetry,
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate threat briefing with Flow domain: %v", err)
	}
	if !strings.Contains(briefing.Content, "Cluster-Wide eBPF Network Flow & DNS Exfiltration Anomaly Profiler") {
		t.Errorf("briefing content missing Section 29 heading")
	}
	if !strings.Contains(briefing.Content, "FLOW-RADAR-001") {
		t.Errorf("briefing content missing violation FLOW-RADAR-001")
	}
}
