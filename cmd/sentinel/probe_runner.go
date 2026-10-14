package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/probe"
)

// runProbeTelemetry coordinates bare-metal eBPF kernel telemetry simulation and anomaly detection.
func runProbeTelemetry(probeNodes string, probeFixture string, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) []probe.TelemetryEvent {
	logInfo("[+] Initializing Bare-Metal eBPF Telemetry Engine...\n")
	rawNodes := strings.Split(probeNodes, ",")
	var nodeList []string
	for _, n := range rawNodes {
		trimmed := strings.TrimSpace(n)
		if trimmed != "" {
			nodeList = append(nodeList, trimmed)
		}
	}

	var rawEvents []probe.TelemetryEvent
	if probeFixture != "" {
		if _, err := os.Stat(probeFixture); err == nil {
			loaded, err := probe.LoadEventsFromFile(probeFixture)
			if err != nil {
				logErr("[-] Failed to load probe fixture (%s): %v\n", probeFixture, err)
				os.Exit(1)
			}
			rawEvents = loaded
			logInfo("[+] Loaded %d telemetry records from fixture: %s\n", len(rawEvents), probeFixture)
		}
	}

	mgr, err := probe.SimulateMultiNodeCluster(nodeList, feed, rawEvents)
	if err != nil {
		logErr("[-] Failed to initialize multi-node cluster simulation: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		logErr("[-] Failed to start eBPF manager: %v\n", err)
		os.Exit(1)
	}

	time.Sleep(150 * time.Millisecond)

	if err := mgr.Stop(); err != nil {
		logErr("[-] Warning during eBPF probe shutdown: %v\n", err)
	}

	stats := mgr.Stats()
	probeSnapshots := mgr.Snapshot()

	logInfo("[+] Bare-Metal eBPF Probes Completed across %d nodes (Total Events: %d)\n", mgr.ActiveProbesCount(), stats.TotalEvents)
	logInfo("    Severity: Critical=%d | High=%d | Medium=%d | Low=%d | Info=%d\n",
		stats.CriticalCount, stats.HighCount, stats.MediumCount, stats.LowCount, stats.InfoCount)

	for _, ev := range probeSnapshots {
		if ev.RiskScore >= 7.0 || ev.Severity == "CRITICAL" || ev.Severity == "HIGH" {
			logInfo("  [!] [%s] %s on node %s: %s [Risk: %.1f]\n", ev.Severity, ev.EventType, ev.NodeName, ev.Message, ev.RiskScore)
			if len(ev.ThreatTags) > 0 {
				logInfo("      Tags: %s\n", strings.Join(ev.ThreatTags, ", "))
			}
		}
	}

	return probeSnapshots
}
