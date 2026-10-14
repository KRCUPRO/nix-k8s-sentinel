package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxFixtureBytes enforces strict size bounds on telemetry fixture files (10MB).
	MaxFixtureBytes int64 = 10 * 1024 * 1024
	// MaxFixtureEvents limits deserialization to prevent memory bloat.
	MaxFixtureEvents = 10000
)

// MockProbe provides a simulated eBPF probe for bare-metal testing and offline validation.
type MockProbe struct {
	mu        sync.RWMutex
	name      string
	pType     ProbeType
	node      string
	config    ProbeConfig
	events    []TelemetryEvent
	eventCh   chan TelemetryEvent
	status    ProbeStatus
	stopCh    chan struct{}
	stopped   bool
}

// NewMockProbe instantiates a mock probe populated with synthetic or replayed telemetry.
func NewMockProbe(name string, pType ProbeType, node string, events []TelemetryEvent) *MockProbe {
	return &MockProbe{
		name:    name,
		pType:   pType,
		node:    node,
		config:  DefaultProbeConfig(node),
		events:  events,
		eventCh: make(chan TelemetryEvent, len(events)+16),
		status:  StatusUninitialized,
		stopCh:  make(chan struct{}),
	}
}

func (m *MockProbe) Name() string       { return m.name }
func (m *MockProbe) Type() ProbeType    { return m.pType }
func (m *MockProbe) Node() string       { return m.node }
func (m *MockProbe) Status() ProbeStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *MockProbe) Events() <-chan TelemetryEvent {
	return m.eventCh
}

// Start begins emitting queued mock telemetry events into the event channel.
func (m *MockProbe) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.status == StatusRunning {
		m.mu.Unlock()
		return fmt.Errorf("mock probe %s is already running", m.name)
	}
	m.status = StatusRunning
	m.mu.Unlock()

	go func() {
		for _, ev := range m.events {
			select {
			case <-ctx.Done():
				m.Stop()
				return
			case <-m.stopCh:
				return
			case m.eventCh <- ev:
			}
		}
	}()

	return nil
}

// Stop gracefully stops the mock probe and closes its event channel.
func (m *MockProbe) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return nil
	}
	m.stopped = true
	m.status = StatusStopped
	close(m.stopCh)
	close(m.eventCh)
	return nil
}

// LoadEventsFromFile loads and parses a telemetry fixture from disk with bounds protection.
func LoadEventsFromFile(filePath string) ([]TelemetryEvent, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat telemetry fixture: %w", err)
	}
	if fi.Size() > MaxFixtureBytes {
		return nil, fmt.Errorf("fixture file %s exceeds bounds (%d > %d bytes)", filePath, fi.Size(), MaxFixtureBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read fixture file: %w", err)
	}

	var events []TelemetryEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("failed to unmarshal telemetry fixture: %w", err)
	}

	if len(events) > MaxFixtureEvents {
		events = events[:MaxFixtureEvents]
	}

	return events, nil
}

// SimulateMultiNodeCluster sets up an eBPF manager pre-registered with probes across multiple nodes.
func SimulateMultiNodeCluster(nodes []string, feed *intel.Feed, sampleEvents []TelemetryEvent) (*EBPFManager, error) {
	mgr := NewEBPFManager(feed)

	if len(nodes) == 0 {
		nodes = []string{"nixos-control-01", "nixos-worker-01", "nixos-worker-02"}
	}

	// Distribute events across nodes
	nodeEvents := make(map[string][]TelemetryEvent)
	for i, ev := range sampleEvents {
		targetNode := nodes[i%len(nodes)]
		ev.NodeName = targetNode
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now().UTC()
		}
		nodeEvents[targetNode] = append(nodeEvents[targetNode], ev)
	}

	for _, n := range nodes {
		evs := nodeEvents[n]
		probeName := fmt.Sprintf("ebpf-socket-probe-%s", n)
		mock := NewMockProbe(probeName, ProbeTypeSocket, n, evs)
		if err := mgr.RegisterProbe(mock); err != nil {
			return nil, err
		}
	}

	return mgr, nil
}
