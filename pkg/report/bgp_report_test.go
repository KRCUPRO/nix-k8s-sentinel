package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/bgp"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestBGPSARIFAndJSONExport(t *testing.T) {
	violations := []bgp.BGPViolation{
		{
			RuleID:      "BGP-RADAR-001",
			PolicyName:  "cilium-bgp-vuln",
			PeerAddress: "192.168.100.1/32",
			Title:       "Unauthenticated BGP Peering Session Missing TCP MD5 or TCP-AO Authentication",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.3,
			Description: "BGP neighbor peering sessions configured without RFC 2385 TCP MD5 signatures allow prefix injection.",
			Remediation: "Configure authSecretRef with Kubernetes secret referencing TCP MD5 or TCP-AO password.",
			MatchedCVE:  "CVE-2026-70192",
			FilePath:    "fixtures/cilium-bgp-vulnerable.yaml",
			StartLine:   15,
		},
	}

	summary := &bgp.BGPSummary{
		TotalPolicies:      1,
		TotalPeers:         1,
		TotalIPAMPools:     1,
		TotalViolations:    1,
		CriticalCount:      1,
		ComplianceScore:    75.0,
		DualStackCompliant: false,
	}

	telemetry := &bgp.BGPTelemetryReport{
		ClusterName: "prod-baremetal",
		NodeID:      "worker-01",
		Timestamp:   time.Now().UTC(),
		Peers: []bgp.BGPPeerTelemetry{
			{
				PeerAddress:        "192.168.100.1/32",
				PeerASN:            65000,
				State:              bgp.StateEstablished,
				UptimeSeconds:      3600,
				PrefixesReceived:   20,
				PrefixesAdvertised: 5,
				ResetCount:         0,
				FlapDampingActive:  false,
			},
		},
		IPAMPools: []bgp.IPAMPoolTelemetry{
			{
				PoolName:     "default-pool",
				CIDR:         "10.244.0.0/16",
				Family:       bgp.FamilyIPv4,
				TotalIPs:     65536,
				AllocatedIPs: 12000,
				UsagePercent: 18.3,
			},
		},
	}

	opts := ReportOptions{
		Version:          "0.27.0",
		BGPViolations:    violations,
		BGPSummary:       summary,
		BGPTelemetry:     telemetry,
		BGPPath:          "fixtures/cilium-bgp-vulnerable.yaml",
		BGPTelemetryPath: "fixtures/bgp-telemetry.json",
		Pretty:           true,
	}

	// 1. Verify SARIF Generation
	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed: %v", err)
	}

	if len(sarifLog.Runs) != 1 || len(sarifLog.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 SARIF result, got %d", len(sarifLog.Runs[0].Results))
	}

	res := sarifLog.Runs[0].Results[0]
	if res.RuleID != "BGP-RADAR-001" || res.Level != "error" {
		t.Errorf("unexpected SARIF result: rule=%s, level=%s", res.RuleID, res.Level)
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "BGP-RADAR-001") {
		t.Errorf("SARIF output missing BGP-RADAR-001")
	}

	// 2. Verify JSON Audit Report
	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}

	if jsonReport.ToolVersion != "0.27.0" {
		t.Errorf("expected version 0.27.0, got %s", jsonReport.ToolVersion)
	}
	if len(jsonReport.BGPViolations) != 1 {
		t.Errorf("expected 1 BGP violation, got %d", len(jsonReport.BGPViolations))
	}
	if jsonReport.BGPSummary == nil || jsonReport.BGPSummary.ComplianceScore != 75.0 {
		t.Errorf("unexpected BGP summary in JSON report: %+v", jsonReport.BGPSummary)
	}

	jsonBytes, err := json.Marshal(jsonReport)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "CVE-2026-70192") {
		t.Errorf("JSON output missing CVE-2026-70192")
	}

	// 3. Verify Threat Briefing Synthesis
	briefingOpts := BriefingOptions{
		Title:         "Test BGP Radar Threat Briefing",
		Version:       "0.27.0",
		HourlyWindow:  time.Now().UTC(),
		BGPViolations: violations,
		BGPSummary:    summary,
		BGPTelemetry:  telemetry,
	}

	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}

	if !strings.Contains(briefing.Content, "Section 26: Kubernetes Service Mesh Dual-Stack IPv6 & Cilium BGP Peering Radar") {
		t.Errorf("Briefing missing Section 26 BGP Radar header")
	}
	if !strings.Contains(briefing.Content, "BGP-RADAR-001") {
		t.Errorf("Briefing missing BGP-RADAR-001 violation")
	}
	if !strings.Contains(briefing.Content, "192.168.100.1/32") {
		t.Errorf("Briefing missing neighbor address")
	}
}
