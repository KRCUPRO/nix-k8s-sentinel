package clustermesh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalMeshRules(t *testing.T) {
	if len(CanonicalMeshRules) != 12 {
		t.Fatalf("expected 12 canonical rules, got %d", len(CanonicalMeshRules))
	}

	seenIDs := make(map[string]bool)
	for _, rule := range CanonicalMeshRules {
		if rule.ID == "" || seenIDs[rule.ID] {
			t.Errorf("duplicate or empty rule ID: %s", rule.ID)
		}
		seenIDs[rule.ID] = true

		if rule.Name == "" {
			t.Errorf("rule %s has empty Name", rule.ID)
		}
		if rule.Description == "" {
			t.Errorf("rule %s has empty Description", rule.ID)
		}
		if rule.Remediation == "" {
			t.Errorf("rule %s has empty Remediation", rule.ID)
		}
		if rule.CVSSScore < 7.0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", rule.ID, rule.CVSSScore)
		}
		if rule.MatchedCVE == "" {
			t.Errorf("rule %s missing MatchedCVE", rule.ID)
		}

		found := FindRuleByID(rule.ID)
		if found == nil || found.ID != rule.ID {
			t.Errorf("FindRuleByID failed for %s", rule.ID)
		}
	}

	if FindRuleByID("NON_EXISTENT") != nil {
		t.Errorf("expected nil for non-existent rule")
	}
}

func TestParseManifestFile_Hardened(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "hardened.yaml")

	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  cluster-name: "east-mesh-1"
  cluster-id: "1"
  encryption.type: "wireguard"
  tunnel-protocol: "vxlan"
  etcd-tls: "true"
  ca-cert: "/etc/clustermesh/ca.crt"
  client-cert: "/etc/clustermesh/tls.crt"
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-svc
  namespace: tenant-web
  annotations:
    io.cilium/global-service: "true"
    io.cilium/shared-service: "true"
spec:
  ports:
  - port: 80
---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: tenant-web-mesh-policy
spec:
  endpointSelector:
    matchLabels:
      k8s:io.kubernetes.pod.namespace: tenant-web
  ingress:
  - fromEndpoints:
    - matchLabels:
        io.cilium.k8s.policy.cluster: "west-mesh-2"
`
	if err := os.WriteFile(manifestPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test manifest: %v", err)
	}

	cfgs, svcs, pols, err := ParseManifestFile(manifestPath)
	if err != nil {
		t.Fatalf("ParseManifestFile failed: %v", err)
	}

	if len(cfgs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(cfgs))
	}
	if cfgs[0].ClusterName != "east-mesh-1" || cfgs[0].ClusterID != 1 {
		t.Errorf("unexpected config: %+v", cfgs[0])
	}
	if cfgs[0].TunnelEncryption != EncryptionWireGuard || !cfgs[0].EtcdTLS {
		t.Errorf("expected wireguard and etcd-tls true: %+v", cfgs[0])
	}

	if len(svcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(svcs))
	}
	if !svcs[0].IsGlobal || !svcs[0].IsShared {
		t.Errorf("expected global and shared service: %+v", svcs[0])
	}

	if len(pols) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(pols))
	}
	if pols[0].ClusterSelector != "west-mesh-2" {
		t.Errorf("expected cluster selector west-mesh-2, got %s", pols[0].ClusterSelector)
	}
}

func TestAuditMeshAssets_Violations(t *testing.T) {
	configs := []ClusterMeshConfig{
		{
			ClusterName:      "insecure-cluster-1",
			ClusterID:        0, // MESH-RADAR-002
			TunnelEncryption: EncryptionNone, // MESH-RADAR-001
			TunnelProtocol:   "vxlan",
			EtcdTLS:          false, // MESH-RADAR-003
			EtcdClientCert:   "",
			EtcdCACert:       "none", // MESH-RADAR-010
			LineNumber:       10,
			FilePath:         "insecure-1.yaml",
		},
		{
			ClusterName:      "insecure-cluster-2",
			ClusterID:        0, // MESH-RADAR-002 collision & zero
			TunnelEncryption: EncryptionNone, // MESH-RADAR-001
			EtcdTLS:          true,
			EtcdClientCert:   "cert.pem",
			EtcdCACert:       "", // MESH-RADAR-010
			LineNumber:       20,
			FilePath:         "insecure-2.yaml",
		},
	}

	services := []GlobalServiceConfig{
		{
			Name:          "prod-database", // MESH-RADAR-005 sensitive
			Namespace:     "prod-db",
			ClusterName:   "insecure-cluster-1",
			IsGlobal:      true,
			IsShared:      true,
			BackendCount:  2048, // MESH-RADAR-009 saturation
			LineNumber:    30,
			FilePath:      "svc-1.yaml",
		},
		{
			Name:          "prod-database", // MESH-RADAR-004 collision
			Namespace:     "prod-db",
			ClusterName:   "insecure-cluster-2",
			IsGlobal:      true,
			IsShared:      false, // MESH-RADAR-011 conflict
			LineNumber:    40,
			FilePath:      "svc-2.yaml",
		},
	}

	policies := []MeshNetworkPolicyConfig{
		{
			Name:            "wildcard-mesh-policy",
			Namespace:       "prod-db",
			ClusterSelector: "*", // MESH-RADAR-007 wildcard
			LineNumber:      50,
			FilePath:        "policy.yaml",
		},
	}

	telemetry := &ClusterMeshTelemetryReport{
		LocalClusterName:     "insecure-cluster-1",
		LocalClusterID:       0,
		SyncState:            SyncStateDegraded, // MESH-RADAR-008
		SyncLatencyMs:        6500.0,
		EtcdSyncErrors:       3,
		DisconnectedClusters: []string{"remote-west-1"}, // MESH-RADAR-012
		Timestamp:            time.Now(),
	}

	violations, summary := AuditMeshAssets(configs, services, policies, telemetry, nil)

	if len(violations) == 0 {
		t.Fatalf("expected multiple violations, got 0")
	}

	ruleHits := make(map[string]bool)
	for _, v := range violations {
		ruleHits[v.RuleID] = true
	}

	expectedRules := []string{
		"MESH-RADAR-001",
		"MESH-RADAR-002",
		"MESH-RADAR-003",
		"MESH-RADAR-004",
		"MESH-RADAR-005",
		"MESH-RADAR-007",
		"MESH-RADAR-008",
		"MESH-RADAR-009",
		"MESH-RADAR-010",
		"MESH-RADAR-011",
		"MESH-RADAR-012",
	}

	for _, ruleID := range expectedRules {
		if !ruleHits[ruleID] {
			t.Errorf("expected rule %s to be triggered, but was not", ruleID)
		}
	}

	if summary.ComplianceScore > 50.0 {
		t.Errorf("expected low compliance score for vulnerable setup, got %f", summary.ComplianceScore)
	}
	if summary.MeshHealthy {
		t.Errorf("expected MeshHealthy to be false")
	}
}

func TestAuditMeshAssets_Compliant(t *testing.T) {
	configs := []ClusterMeshConfig{
		{
			ClusterName:      "prod-east-1",
			ClusterID:        1,
			TunnelEncryption: EncryptionWireGuard,
			TunnelProtocol:   "vxlan",
			EtcdTLS:          true,
			EtcdClientCert:   "/etc/clustermesh/tls.crt",
			EtcdCACert:       "/etc/clustermesh/ca.crt",
			LineNumber:       1,
			FilePath:         "compliant-1.yaml",
		},
		{
			ClusterName:      "prod-west-2",
			ClusterID:        2,
			TunnelEncryption: EncryptionWireGuard,
			TunnelProtocol:   "vxlan",
			EtcdTLS:          true,
			EtcdClientCert:   "/etc/clustermesh/tls.crt",
			EtcdCACert:       "/etc/clustermesh/ca.crt",
			LineNumber:       1,
			FilePath:         "compliant-2.yaml",
		},
	}

	services := []GlobalServiceConfig{
		{
			Name:         "web-frontend",
			Namespace:    "web-apps",
			ClusterName:  "prod-east-1",
			ClusterID:    1,
			IsGlobal:     true,
			IsShared:     true,
			BackendCount: 16,
			LineNumber:   10,
			FilePath:     "web.yaml",
		},
	}

	policies := []MeshNetworkPolicyConfig{
		{
			Name:            "web-mesh-policy",
			Namespace:       "web-apps",
			ClusterSelector: "prod-west-2",
			LineNumber:      20,
			FilePath:        "policy.yaml",
		},
	}

	telemetry := &ClusterMeshTelemetryReport{
		LocalClusterName:     "prod-east-1",
		LocalClusterID:       1,
		SyncState:            SyncStateHealthy,
		SyncLatencyMs:        45.2,
		ConnectedClusters:    []string{"prod-west-2"},
		DisconnectedClusters: nil,
		TotalGlobalServices:  1,
		TotalMeshEndpoints:   16,
		EtcdSyncErrors:       0,
		Timestamp:            time.Now(),
	}

	violations, summary := AuditMeshAssets(configs, services, policies, telemetry, nil)

	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for compliant setup, got %d: %+v", len(violations), violations)
	}
	if summary.ComplianceScore != 100.0 {
		t.Errorf("expected 100.0 compliance score, got %f", summary.ComplianceScore)
	}
	if !summary.MeshHealthy {
		t.Errorf("expected MeshHealthy to be true")
	}
}

func TestSynthesizeHardenedClusterMesh(t *testing.T) {
	cfg := &ClusterMeshConfig{
		ClusterName: "test-cluster-alpha",
		ClusterID:   3,
	}

	helmOutput := SynthesizeHardenedClusterMeshConfig(cfg)
	if !strings.Contains(helmOutput, "name: test-cluster-alpha") || !strings.Contains(helmOutput, "id: 3") {
		t.Errorf("helm output missing cluster details: %s", helmOutput)
	}
	if !strings.Contains(helmOutput, "type: wireguard") {
		t.Errorf("helm output missing wireguard encryption: %s", helmOutput)
	}

	policyOutput := SynthesizeHardenedMeshPolicy("remote-cluster", "prod-ns")
	if !strings.Contains(policyOutput, "io.cilium.k8s.policy.cluster: remote-cluster") {
		t.Errorf("policy output missing cluster selector: %s", policyOutput)
	}

	alertOutput := SynthesizeMeshAlertRules()
	if !strings.Contains(alertOutput, "CiliumClusterMeshSyncLatencyDegraded") {
		t.Errorf("alert output missing latency rule: %s", alertOutput)
	}

	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "policies")
	written, err := WriteSynthesizedPolicies(outDir, cfg)
	if err != nil {
		t.Fatalf("WriteSynthesizedPolicies failed: %v", err)
	}
	if len(written) != 3 {
		t.Fatalf("expected 3 files written, got %d", len(written))
	}
	for _, f := range written {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected file %s to exist: %v", f, err)
		}
	}
}

func TestClusterMeshScanner(t *testing.T) {
	tmpDir := t.TempDir()
	manifestFile := filepath.Join(tmpDir, "manifest.yaml")
	telemFile := filepath.Join(tmpDir, "telem.json")

	manifestContent := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
data:
  cluster-name: "scanner-cluster"
  cluster-id: "5"
  encryption.type: "wireguard"
  etcd-tls: "true"
  ca-cert: "ca.crt"
  client-cert: "client.crt"
`
	if err := os.WriteFile(manifestFile, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	telem := ClusterMeshTelemetryReport{
		LocalClusterName:  "scanner-cluster",
		LocalClusterID:    5,
		SyncState:         SyncStateHealthy,
		SyncLatencyMs:     30.0,
		ConnectedClusters: []string{"remote-1"},
		Timestamp:         time.Now(),
	}
	telemBytes, _ := json.Marshal(telem)
	if err := os.WriteFile(telemFile, telemBytes, 0644); err != nil {
		t.Fatalf("failed to write telemetry: %v", err)
	}

	scanner := NewClusterMeshScanner()
	report, err := scanner.ScanClusterMeshTarget(tmpDir, telemFile, nil)
	if err != nil {
		t.Fatalf("ScanClusterMeshTarget failed: %v", err)
	}

	if report == nil {
		t.Fatalf("expected non-nil report")
	}
	if len(report.Configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(report.Configs))
	}
	if report.Telemetry == nil || report.Telemetry.LocalClusterName != "scanner-cluster" {
		t.Errorf("unexpected telemetry: %+v", report.Telemetry)
	}
}

func TestMemoryBoundsAndErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Non-existent file
	scanner := NewClusterMeshScanner()
	_, err := scanner.ScanClusterMeshTarget(filepath.Join(tmpDir, "missing.yaml"), "", nil)
	if err == nil {
		t.Errorf("expected error for missing manifest file")
	}

	// 2. Corrupt telemetry JSON
	corruptTelem := filepath.Join(tmpDir, "corrupt.json")
	if err := os.WriteFile(corruptTelem, []byte("{invalid-json"), 0644); err != nil {
		t.Fatalf("failed to write corrupt json: %v", err)
	}
	_, err = ParseClusterMeshTelemetryJSON(corruptTelem)
	if err == nil {
		t.Errorf("expected error for corrupt JSON")
	}
}
