package impermanence

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Scanner coordinates file/directory parsing, Kubernetes mount cross-checking, and telemetry auditing.
type Scanner struct {
	auditor *Auditor
	synth   *Synthesizer
}

// NewScanner creates a new Scanner instance.
func NewScanner() *Scanner {
	return &Scanner{
		auditor: NewAuditor(),
		synth:   NewSynthesizer(),
	}
}

// Scan processes a NixOS impermanence configuration file or directory, with optional cluster manifests and telemetry.
func (s *Scanner) Scan(targetPath string, k8sPath string, telemetryPath string) (*ImpermanenceAuditReport, error) {
	if targetPath == "" {
		return nil, fmt.Errorf("target path must not be empty")
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access target path %s: %w", targetPath, err)
	}

	var nixFiles []string
	if info.IsDir() {
		err = filepath.WalkDir(targetPath, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".nix") {
				if len(nixFiles) < MaxHosts {
					nixFiles = append(nixFiles, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking directory %s: %w", targetPath, err)
		}
	} else {
		nixFiles = append(nixFiles, targetPath)
	}

	if len(nixFiles) == 0 {
		return nil, fmt.Errorf("no Nix configuration files found at path %s", targetPath)
	}

	// Parse Kubernetes manifests for hostPath collisions if provided
	var clusterMounts []ClusterMountReference
	if k8sPath != "" {
		k8sInfo, kErr := os.Stat(k8sPath)
		if kErr == nil {
			if k8sInfo.IsDir() {
				_ = filepath.WalkDir(k8sPath, func(p string, d fs.DirEntry, walkErr error) error {
					if walkErr == nil && !d.IsDir() {
						lower := strings.ToLower(d.Name())
						if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
							data, rErr := ReadFileWithLimit(p, MaxManifestBytes)
							if rErr == nil {
								mounts, pErr := ParseK8sStorageMounts(string(data), p)
								if pErr == nil {
									clusterMounts = append(clusterMounts, mounts...)
								}
							}
						}
					}
					return nil
				})
			} else {
				data, rErr := ReadFileWithLimit(k8sPath, MaxManifestBytes)
				if rErr == nil {
					mounts, pErr := ParseK8sStorageMounts(string(data), k8sPath)
					if pErr == nil {
						clusterMounts = append(clusterMounts, mounts...)
					}
				}
			}
		}
	}

	// Ingest telemetry if provided
	var telemetry *ImpermanenceTelemetry
	if telemetryPath != "" {
		telemetryData, tErr := ReadFileWithLimit(telemetryPath, MaxTelemetryBytes)
		if tErr == nil {
			telemetry, _ = ParseImpermanenceTelemetryJSON(telemetryData)
		}
	}

	var hosts []ImpermanenceHostConfig
	var violations []ImpermanenceViolation

	for _, nFile := range nixFiles {
		data, rErr := ReadFileWithLimit(nFile, MaxManifestBytes)
		if rErr != nil {
			continue
		}
		host, pErr := ParseNixOSImpermanence(string(data), nFile)
		if pErr != nil {
			continue
		}
		hosts = append(hosts, *host)

		// Static audit
		v := s.auditor.AuditHost(host)
		violations = append(violations, v...)

		// Mount collision audit
		if len(clusterMounts) > 0 {
			mv := s.auditor.AuditClusterMountCollisions(host, clusterMounts)
			violations = append(violations, mv...)
		}

		// Telemetry audit
		if telemetry != nil {
			for _, node := range telemetry.Nodes {
				if strings.EqualFold(node.NodeName, host.HostName) || len(hosts) == 1 {
					tv := s.auditor.AuditTelemetry(host, &node)
					violations = append(violations, tv...)
				}
			}
		}
	}

	summary := ComputeSummary(hosts, violations)

	return &ImpermanenceAuditReport{
		Hosts:      hosts,
		Violations: violations,
		Summary:    summary,
		Telemetry:  telemetry,
	}, nil
}
