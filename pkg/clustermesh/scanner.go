package clustermesh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// ClusterMeshScanner coordinates directory walking, manifest parsing, telemetry reconciliation, and auditing.
type ClusterMeshScanner struct{}

// NewClusterMeshScanner constructs an initialized ClusterMesh scanner.
func NewClusterMeshScanner() *ClusterMeshScanner {
	return &ClusterMeshScanner{}
}

// ScanClusterMeshTarget scans a manifest directory or single file, reconciles telemetry, and returns an audit report.
func (s *ClusterMeshScanner) ScanClusterMeshTarget(
	targetPath string,
	telemetryPath string,
	feed *intel.Feed,
) (*MeshAuditReport, error) {
	var (
		allConfigs  []ClusterMeshConfig
		allServices []GlobalServiceConfig
		allPolicies []MeshNetworkPolicyConfig
		telemetry   *ClusterMeshTelemetryReport
	)

	// 1. Process targetPath (file or directory)
	if targetPath != "" {
		cleanTarget := filepath.Clean(targetPath)
		fi, err := os.Stat(cleanTarget)
		if err != nil {
			return nil, fmt.Errorf("failed to stat ClusterMesh target path (%s): %w", cleanTarget, err)
		}

		if fi.IsDir() {
			err := filepath.Walk(cleanTarget, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".yaml" || ext == ".yml" || ext == ".nix" {
					cfgs, svcs, pols, pErr := ParseManifestFile(path)
					if pErr != nil {
						return pErr
					}
					allConfigs = append(allConfigs, cfgs...)
					allServices = append(allServices, svcs...)
					allPolicies = append(allPolicies, pols...)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("error walking ClusterMesh directory (%s): %w", cleanTarget, err)
			}
		} else {
			cfgs, svcs, pols, err := ParseManifestFile(cleanTarget)
			if err != nil {
				return nil, fmt.Errorf("failed to parse manifest file (%s): %w", cleanTarget, err)
			}
			allConfigs = append(allConfigs, cfgs...)
			allServices = append(allServices, svcs...)
			allPolicies = append(allPolicies, pols...)
		}
	}

	// 2. Process runtime telemetry if provided
	if telemetryPath != "" {
		cleanTelem := filepath.Clean(telemetryPath)
		telem, err := ParseClusterMeshTelemetryJSON(cleanTelem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ClusterMesh telemetry (%s): %w", cleanTelem, err)
		}
		telemetry = telem
	}

	// 3. Execute comprehensive audit
	violations, summary := AuditMeshAssets(allConfigs, allServices, allPolicies, telemetry, feed)

	report := &MeshAuditReport{
		Summary:     summary,
		Violations:  violations,
		Configs:     allConfigs,
		Services:    allServices,
		Policies:    allPolicies,
		Telemetry:   telemetry,
		GeneratedAt: time.Now().UTC(),
	}

	return report, nil
}
