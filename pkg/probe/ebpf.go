package probe

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// TelemetryStats summarizes aggregated metrics collected across all monitored nodes.
type TelemetryStats struct {
	TotalEvents     uint64         `json:"total_events"`
	CriticalCount   uint64         `json:"critical_count"`
	HighCount       uint64         `json:"high_count"`
	MediumCount     uint64         `json:"medium_count"`
	LowCount        uint64         `json:"low_count"`
	InfoCount       uint64         `json:"info_count"`
	EventsByNode    map[string]int `json:"events_by_node"`
	EventsByType    map[string]int `json:"events_by_type"`
	EventsBySyscall map[string]int `json:"events_by_syscall"`
}

// EBPFManager orchestrates multi-node kernel telemetry probes across bare-metal NixOS clusters.
type EBPFManager struct {
	mu           sync.RWMutex
	probes       map[string]Probe
	detector     *TelemetryAnomalyDetector
	feed         *intel.Feed
	events       chan TelemetryEvent
	snapshots    []TelemetryEvent
	stats        TelemetryStats
	isRunning    atomic.Bool
	stopCh       chan struct{}
	wg           sync.WaitGroup
	maxSnapshots int
}

// NewEBPFManager initializes a centralized multi-node telemetry aggregator.
func NewEBPFManager(feed *intel.Feed) *EBPFManager {
	return &EBPFManager{
		probes:       make(map[string]Probe),
		detector:     NewAnomalyDetector(),
		feed:         feed,
		events:       make(chan TelemetryEvent, 4096),
		stopCh:       make(chan struct{}),
		maxSnapshots: 10000,
		stats: TelemetryStats{
			EventsByNode:    make(map[string]int),
			EventsByType:    make(map[string]int),
			EventsBySyscall: make(map[string]int),
		},
	}
}

// RegisterProbe adds a node-level probe to the manager.
func (m *EBPFManager) RegisterProbe(p Probe) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning.Load() {
		return fmt.Errorf("cannot register probe '%s' while manager is actively running", p.Name())
	}

	key := fmt.Sprintf("%s:%s", p.Node(), p.Name())
	if _, exists := m.probes[key]; exists {
		return fmt.Errorf("probe '%s' already registered on node '%s'", p.Name(), p.Node())
	}

	m.probes[key] = p
	return nil
}

// Start launches all registered probes and begins asynchronous event aggregation.
func (m *EBPFManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.isRunning.Swap(true) {
		m.mu.Unlock()
		return fmt.Errorf("ebpf manager is already running")
	}

	for _, p := range m.probes {
		if err := p.Start(ctx); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("failed to start probe %s: %w", p.Name(), err)
		}

		m.wg.Add(1)
		go m.consumeProbeStream(p)
	}
	m.mu.Unlock()
	return nil
}

func (m *EBPFManager) consumeProbeStream(p Probe) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case ev, ok := <-p.Events():
			if !ok {
				return
			}
			m.processIncomingEvent(ev)
		}
	}
}

func (m *EBPFManager) processIncomingEvent(ev TelemetryEvent) {
	// Correlate with threat detector & feed
	m.detector.EvaluateEvent(&ev, m.feed)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats.TotalEvents++
	switch ev.Severity {
	case string(intel.SeverityCritical):
		m.stats.CriticalCount++
	case string(intel.SeverityHigh):
		m.stats.HighCount++
	case string(intel.SeverityMedium):
		m.stats.MediumCount++
	case string(intel.SeverityLow):
		m.stats.LowCount++
	default:
		m.stats.InfoCount++
	}

	m.stats.EventsByNode[ev.NodeName]++
	m.stats.EventsByType[string(ev.ProbeType)]++
	if ev.Syscall != "" {
		m.stats.EventsBySyscall[ev.Syscall]++
	}

	if len(m.snapshots) < m.maxSnapshots {
		m.snapshots = append(m.snapshots, ev)
	}

	select {
	case m.events <- ev:
	default:
		// Ring-buffer drop on channel saturation to prevent goroutine blocking
	}
}

// Stop gracefully stops all probes and shuts down the aggregation loop.
func (m *EBPFManager) Stop() error {
	if !m.isRunning.Swap(false) {
		return nil
	}

	close(m.stopCh)

	m.mu.RLock()
	var errs []error
	for _, p := range m.probes {
		if err := p.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	m.mu.RUnlock()

	m.wg.Wait()
	close(m.events)

	if len(errs) > 0 {
		return fmt.Errorf("probe shutdown encountered %d errors", len(errs))
	}
	return nil
}

// Events returns the aggregated multi-node event channel.
func (m *EBPFManager) Events() <-chan TelemetryEvent {
	return m.events
}

// Snapshot returns a copy of captured telemetry events.
func (m *EBPFManager) Snapshot() []TelemetryEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]TelemetryEvent, len(m.snapshots))
	copy(res, m.snapshots)
	return res
}

// Stats returns a copy of current aggregated statistics.
func (m *EBPFManager) Stats() TelemetryStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	byNode := make(map[string]int, len(m.stats.EventsByNode))
	for k, v := range m.stats.EventsByNode {
		byNode[k] = v
	}
	byType := make(map[string]int, len(m.stats.EventsByType))
	for k, v := range m.stats.EventsByType {
		byType[k] = v
	}
	bySys := make(map[string]int, len(m.stats.EventsBySyscall))
	for k, v := range m.stats.EventsBySyscall {
		bySys[k] = v
	}

	return TelemetryStats{
		TotalEvents:     m.stats.TotalEvents,
		CriticalCount:   m.stats.CriticalCount,
		HighCount:       m.stats.HighCount,
		MediumCount:     m.stats.MediumCount,
		LowCount:        m.stats.LowCount,
		InfoCount:       m.stats.InfoCount,
		EventsByNode:    byNode,
		EventsByType:    byType,
		EventsBySyscall: bySys,
	}
}

// ActiveProbesCount returns the number of registered probes.
func (m *EBPFManager) ActiveProbesCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.probes)
}
