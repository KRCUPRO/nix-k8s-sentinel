package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/clustermesh"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestClusterMeshReportSerialization(t *testing.T) {
	violations := []clustermesh.MeshViolation{
		{
			RuleID:      "MESH-RADAR-001",
			Name:        "UnencryptedCrossClusterTunnel",
			Severity:    intel.SeverityCritical,
			Resource:    "prod-east-1",
			Cluster:     "prod-east-1",
			Message:     "Cross-cluster ClusterMesh interconnect uses unencrypted VXLAN tunnel encapsulation.",
			LineNumber:  15,
			FilePath:    "fixtures/cilium-clustermesh-vulnerable.yaml",
			Remediation: "Enable transparent WireGuard encryption.",
			MatchedCVE:  "CVE-2026-11483",
			CVSSScore:   9.4,
		},
		{
			RuleID:      "MESH-RADAR-004",
			Name:        "ServiceExportNamespaceCollision",
			Severity:    intel.SeverityHigh,
			Resource:    "tenant-db/postgres-svc",
			Cluster:     "prod-west-2",
			Message:     "ServiceExport collision detected for 'tenant-db/postgres-svc'.",
			LineNumber:  42,
			FilePath:    "fixtures/cilium-clustermesh-vulnerable.yaml",
			Remediation: "Enforce tenant-isolated namespaces.",
			MatchedCVE:  "CVE-2026-11483",
			CVSSScore:   8.8,
		},
	}

	summary := clustermesh.MeshSummary{
		TotalAudited:    4,
		TotalViolations: 2,
		CriticalCount:   1,
		HighCount:       1,
		ComplianceScore: 77.0,
		MeshHealthy:     false,
	}

	telemetry := &clustermesh.ClusterMeshTelemetryReport{
		LocalClusterName:     "prod-east-1",
		LocalClusterID:       1,
		SyncState:            clustermesh.SyncStateDegraded,
		SyncLatencyMs:        5200.0,
		ConnectedClusters:    []string{"prod-west-2"},
		DisconnectedClusters: []string{"dr-south-3"},
		TotalGlobalServices:  12,
		TotalMeshEndpoints:   128,
		EtcdSyncErrors:       2,
		Timestamp:            time.Now().UTC(),
	}

	reportOpts := ReportOptions{
		Version:                  "0.31.0",
		MeshViolations:           violations,
		MeshSummary:              &summary,
		MeshTelemetry:            telemetry,
		ClusterMeshPath:          "fixtures/cilium-clustermesh-vulnerable.yaml",
		ClusterMeshTelemetryPath: "fixtures/clustermesh-telemetry.json",
		ClusterMeshSynthOut:      "policies/generated/clustermesh",
		TargetFilter:             "kubernetes",
		Pretty:                   true,
	}

	// 1. Verify JSON report export
	jsonRep, err := BuildJSONReport(reportOpts)
	if err != nil {
		t.Fatalf("failed to build JSON report with ClusterMesh data: %v", err)
	}
	if len(jsonRep.MeshViolations) != 2 {
		t.Errorf("expected 2 ClusterMesh violations in JSON report, got %d", len(jsonRep.MeshViolations))
	}
	if jsonRep.MeshSummary.ComplianceScore != 77.0 {
		t.Errorf("expected compliance score 77.0, got %f", jsonRep.MeshSummary.ComplianceScore)
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
		t.Fatalf("failed to build SARIF report with ClusterMesh data: %v", err)
	}
	if len(sarifLog.Runs) == 0 || len(sarifLog.Runs[0].Results) < 2 {
		t.Fatalf("expected at least 2 SARIF results for ClusterMesh, got %d", len(sarifLog.Runs[0].Results))
	}
	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("failed to format SARIF log: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "MESH-RADAR-001") {
		t.Errorf("SARIF output does not contain MESH-RADAR-001")
	}

	// 3. Verify Threat Briefing report export
	briefingOpts := BriefingOptions{
		Title:          "Test Briefing - ClusterMesh Domain",
		Version:        "0.31.0",
		MeshViolations: violations,
		MeshSummary:    &summary,
		MeshTelemetry:  telemetry,
	}
	briefing, err := GenerateBriefing(briefingOpts)
	if err != nil {
		t.Fatalf("failed to generate threat briefing with ClusterMesh domain: %v", err)
	}
	if !strings.Contains(briefing.Content, "Multi-Tenant Cilium ClusterMesh & Global Service Discovery Radar") {
		t.Errorf("briefing content missing Section 30 heading")
	}
	if !strings.Contains(briefing.Content, "MESH-RADAR-001") {
		t.Errorf("briefing content missing violation MESH-RADAR-001")
	}
}
