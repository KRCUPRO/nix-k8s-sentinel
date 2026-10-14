package probe_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
)

func sampleFeed() *intel.Feed {
	return &intel.Feed{
		Version:   "1.0.0",
		UpdatedAt: time.Now().UTC(),
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-21801",
				Title:     "Kubernetes Ingress-Nginx Path Traversal Vulnerability",
				Component: "ingress-nginx",
				Target:    "kubernetes",
				Severity:  intel.SeverityHigh,
				CVSSScore: 8.4,
			},
			{
				ID:        "CVE-2026-19402",
				Title:     "NixOS Flake Lock Input Evaluation Hijack",
				Component: "nix",
				Target:    "nixos",
				Severity:  intel.SeverityMedium,
				CVSSScore: 6.1,
			},
		},
	}
}

func TestProbeInterfaceLifecycle(t *testing.T) {
	ev1 := probe.TelemetryEvent{
		ID:        "EVT-001",
		Timestamp: time.Now().UTC(),
		ProbeType: probe.ProbeTypeSocket,
		NodeName:  "nixos-worker-01",
		Comm:      "curl",
		EventType: "SOCKET_CONNECT",
		DestAddr:  "10.0.0.1:80",
	}

	p := probe.NewMockProbe("test-probe-01", probe.ProbeTypeSocket, "nixos-worker-01", []probe.TelemetryEvent{ev1})
	if p.Status() != probe.StatusUninitialized {
		t.Fatalf("expected status uninitialized, got %s", p.Status())
	}
	if p.Name() != "test-probe-01" {
		t.Fatalf("unexpected probe name: %s", p.Name())
	}
	if p.Type() != probe.ProbeTypeSocket {
		t.Fatalf("unexpected probe type: %s", p.Type())
	}
	if p.Node() != "nixos-worker-01" {
		t.Fatalf("unexpected node: %s", p.Node())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := p.Start(ctx); err != nil {
		t.Fatalf("failed to start probe: %v", err)
	}
	if p.Status() != probe.StatusRunning {
		t.Fatalf("expected status running, got %s", p.Status())
	}

	select {
	case ev, ok := <-p.Events():
		if !ok {
			t.Fatalf("event channel closed unexpectedly")
		}
		if ev.ID != "EVT-001" {
			t.Errorf("expected event EVT-001, got %s", ev.ID)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for probe event")
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("failed to stop probe: %v", err)
	}
	if p.Status() != probe.StatusStopped {
		t.Fatalf("expected status stopped, got %s", p.Status())
	}
}

func TestAnomalyDetectorVectors(t *testing.T) {
	detector := probe.NewAnomalyDetector()
	feed := sampleFeed()

	// Vector 1: Reverse shell
	revShellEv := probe.TelemetryEvent{
		ID:        "REV-01",
		ProbeType: probe.ProbeTypeSocket,
		EventType: "SOCKET_CONNECT",
		Comm:      "sh",
		DestAddr:  "198.51.100.50:4444",
	}
	detector.EvaluateEvent(&revShellEv, feed)
	if revShellEv.Severity != string(intel.SeverityCritical) {
		t.Errorf("expected critical severity for reverse shell, got %s", revShellEv.Severity)
	}
	if revShellEv.RiskScore < 9.0 {
		t.Errorf("expected risk score >= 9.0, got %.1f", revShellEv.RiskScore)
	}

	// Vector 2: Sensitive port probe
	etcdProbeEv := probe.TelemetryEvent{
		ID:        "ETCD-01",
		ProbeType: probe.ProbeTypeSocket,
		EventType: "SOCKET_CONNECT",
		Comm:      "unauthorized-app",
		DestAddr:  "10.0.0.10:2379",
	}
	detector.EvaluateEvent(&etcdProbeEv, feed)
	if etcdProbeEv.Severity != string(intel.SeverityHigh) {
		t.Errorf("expected high severity for etcd probe, got %s", etcdProbeEv.Severity)
	}

	// Vector 3: Immutable Store tampering
	storeTamperEv := probe.TelemetryEvent{
		ID:        "STORE-01",
		ProbeType: probe.ProbeTypeStorage,
		EventType: "STORE_TAMPER_ATTEMPT",
		Message:   "Modification attempted in /nix/store/pkg-abc",
	}
	detector.EvaluateEvent(&storeTamperEv, feed)
	if storeTamperEv.Severity != string(intel.SeverityHigh) {
		t.Errorf("expected high severity for store tampering, got %s", storeTamperEv.Severity)
	}

	// Vector 4: Container escape via ptrace
	ptraceEv := probe.TelemetryEvent{
		ID:        "ESC-01",
		ProbeType: probe.ProbeTypeSyscall,
		Namespace: "tenant-a",
		PodName:   "app-worker",
		Syscall:   "ptrace",
	}
	detector.EvaluateEvent(&ptraceEv, feed)
	if ptraceEv.Severity != string(intel.SeverityCritical) {
		t.Errorf("expected critical severity for container escape ptrace, got %s", ptraceEv.Severity)
	}
}

func TestEBPFManagerMultiNodeAggregation(t *testing.T) {
	feed := sampleFeed()
	mgr := probe.NewEBPFManager(feed)

	node1Events := []probe.TelemetryEvent{
		{ID: "E1", NodeName: "node-1", ProbeType: probe.ProbeTypeSocket, EventType: "SOCKET_CONNECT", Comm: "curl", DestAddr: "1.1.1.1:80"},
		{ID: "E2", NodeName: "node-1", ProbeType: probe.ProbeTypeStorage, EventType: "STORE_TAMPER", Message: "write /nix/store/x"},
	}
	node2Events := []probe.TelemetryEvent{
		{ID: "E3", NodeName: "node-2", ProbeType: probe.ProbeTypeSyscall, EventType: "SYSCALL", Syscall: "ptrace", Namespace: "prod", PodName: "backend"},
	}

	p1 := probe.NewMockProbe("p1", probe.ProbeTypeSocket, "node-1", node1Events)
	p2 := probe.NewMockProbe("p2", probe.ProbeTypeSyscall, "node-2", node2Events)

	if err := mgr.RegisterProbe(p1); err != nil {
		t.Fatalf("failed to register p1: %v", err)
	}
	if err := mgr.RegisterProbe(p2); err != nil {
		t.Fatalf("failed to register p2: %v", err)
	}
	if mgr.ActiveProbesCount() != 2 {
		t.Fatalf("expected 2 active probes, got %d", mgr.ActiveProbesCount())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}

	// Wait a moment for async consumption
	time.Sleep(100 * time.Millisecond)

	if err := mgr.Stop(); err != nil {
		t.Fatalf("failed to stop manager: %v", err)
	}

	stats := mgr.Stats()
	if stats.TotalEvents != 3 {
		t.Errorf("expected 3 total events, got %d", stats.TotalEvents)
	}
	if stats.EventsByNode["node-1"] != 2 {
		t.Errorf("expected 2 events from node-1, got %d", stats.EventsByNode["node-1"])
	}
	if stats.EventsByNode["node-2"] != 1 {
		t.Errorf("expected 1 event from node-2, got %d", stats.EventsByNode["node-2"])
	}

	snapshots := mgr.Snapshot()
	if len(snapshots) != 3 {
		t.Errorf("expected 3 snapshot events, got %d", len(snapshots))
	}
}

func TestLoadEventsFromFile(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "probe-telemetry.json")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("fixture not found at relative path")
	}

	events, err := probe.LoadEventsFromFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to load fixture: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected non-empty events from fixture")
	}

	// Verify reverse shell in first event
	if events[0].Comm != "sh" {
		t.Errorf("expected first event comm 'sh', got '%s'", events[0].Comm)
	}
}

func TestSimulateMultiNodeCluster(t *testing.T) {
	feed := sampleFeed()
	sampleEvents := []probe.TelemetryEvent{
		{ID: "S1", Comm: "nginx", DestAddr: "10.0.0.5:80"},
		{ID: "S2", Comm: "sh", DestAddr: "198.51.100.1:1337"},
		{ID: "S3", Comm: "kubelet", DestAddr: "10.0.0.1:6443"},
	}

	nodes := []string{"nixos-control-01", "nixos-worker-01"}
	mgr, err := probe.SimulateMultiNodeCluster(nodes, feed, sampleEvents)
	if err != nil {
		t.Fatalf("failed to simulate cluster: %v", err)
	}
	if mgr.ActiveProbesCount() != 2 {
		t.Fatalf("expected 2 node probes, got %d", mgr.ActiveProbesCount())
	}
}
