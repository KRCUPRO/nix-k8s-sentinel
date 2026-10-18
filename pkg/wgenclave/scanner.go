package wgenclave

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// ScanEnclavePeers executes full-spectrum scanning across manifests and runtime attestation telemetry.
func ScanEnclavePeers(manifestPath, telemetryPath string, strictMode bool, feed *intel.Feed) (*WGEnclaveAuditReport, error) {
	report := &WGEnclaveAuditReport{
		Configurations: []EnclavePeerConfig{},
		Reports:        []AttestationReport{},
		Peers:          []PeerTunnelStatus{},
		Violations:     []WGEnclaveViolation{},
		Summary: WGEnclaveSummary{
			RejectedPeerIDs: []string{},
		},
	}

	now := time.Now()

	// 1. Ingest Manifests
	if manifestPath != "" {
		cleanManifest := filepath.Clean(manifestPath)
		info, err := os.Stat(cleanManifest)
		if err != nil {
			return nil, fmt.Errorf("manifest path error: %w", err)
		}

		if info.IsDir() {
			err = filepath.Walk(cleanManifest, func(path string, fi os.FileInfo, walkErr error) error {
				if walkErr != nil || fi.IsDir() {
					return walkErr
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".nix" {
					peers, err := ParseNixOSEnclavePeer(path)
					if err == nil {
						report.Configurations = append(report.Configurations, peers...)
					}
				} else if ext == ".yaml" || ext == ".yml" {
					peers, err := ParseK8sEnclavePeerConfig(path)
					if err == nil {
						report.Configurations = append(report.Configurations, peers...)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("manifest directory walk error: %w", err)
			}
		} else {
			ext := strings.ToLower(filepath.Ext(cleanManifest))
			if ext == ".nix" {
				peers, err := ParseNixOSEnclavePeer(cleanManifest)
				if err != nil {
					return nil, fmt.Errorf("failed to parse NixOS manifest %s: %w", cleanManifest, err)
				}
				report.Configurations = append(report.Configurations, peers...)
			} else if ext == ".yaml" || ext == ".yml" {
				peers, err := ParseK8sEnclavePeerConfig(cleanManifest)
				if err != nil {
					return nil, fmt.Errorf("failed to parse K8s manifest %s: %w", cleanManifest, err)
				}
				report.Configurations = append(report.Configurations, peers...)
			}
		}
	}

	// 2. Ingest Runtime Telemetry
	if telemetryPath != "" {
		cleanTelemetry := filepath.Clean(telemetryPath)
		tel, err := ParseEnclaveTelemetryJSON(cleanTelemetry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse enclave telemetry %s: %w", cleanTelemetry, err)
		}
		report.Reports = tel.Reports
		report.Peers = tel.Peers
		if !tel.Timestamp.IsZero() {
			now = tel.Timestamp
		}
	}

	// 3. Audit Configurations
	for _, cfg := range report.Configurations {
		AuditEnclavePeerConfig(cfg, &report.Violations)
	}

	// 4. Audit Attestation Reports
	cfgMap := make(map[string]EnclavePeerConfig)
	for _, c := range report.Configurations {
		if c.PublicKey != "" {
			cfgMap[c.PublicKey] = c
		}
		if c.PeerName != "" {
			cfgMap[c.PeerName] = c
		}
	}

	for _, rep := range report.Reports {
		cfg, hasCfg := cfgMap[rep.PeerPublicKey]
		var cfgPtr *EnclavePeerConfig
		if hasCfg {
			cfgPtr = &cfg
		}
		AuditAttestationReport(rep, cfgPtr, now, &report.Violations, &report.Summary)
	}

	// 5. Reconcile Active Peer Tunnels
	report.Peers = ReconcilePeerTunnels(
		report.Peers,
		report.Reports,
		report.Configurations,
		now,
		&report.Violations,
		&report.Summary,
	)

	// 6. Threat Intelligence Correlation
	if feed != nil {
		for i := range report.Violations {
			v := &report.Violations[i]
			if v.MatchedCVE == "" {
				// Correlate against CVE items
				for _, item := range feed.Items {
					if strings.Contains(strings.ToLower(item.Title), "enclave") ||
						strings.Contains(strings.ToLower(item.Title), "attestation") ||
						strings.Contains(strings.ToLower(item.Component), "enclave") {
						v.MatchedCVE = item.ID
						break
					}
				}
			}
		}
	}

	// 7. Calculate Deterministic Compliance Score
	CalculateComplianceScore(&report.Summary, report.Violations)

	return report, nil
}
