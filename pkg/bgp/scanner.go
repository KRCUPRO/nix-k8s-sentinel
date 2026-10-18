package bgp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BGPScanner orchestrates multi-document file scanning and runtime telemetry reconciliation.
type BGPScanner struct{}

// NewBGPScanner creates an initialized BGPScanner instance.
func NewBGPScanner() *BGPScanner {
	return &BGPScanner{}
}

// ScanTarget inspects manifests and telemetry files, executing full BGP radar audit.
func (s *BGPScanner) ScanTarget(manifestPath, telemetryPath string) (*BGPAuditReport, error) {
	report := &BGPAuditReport{
		Policies:   []CiliumBGPPeeringPolicyConfig{},
		IPPools:    []CiliumLoadBalancerIPPoolConfig{},
		NixOSHosts: []NixOSBGPConfig{},
		Violations: []BGPViolation{},
	}

	if manifestPath != "" {
		info, err := os.Stat(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat manifest path '%s': %w", manifestPath, err)
		}

		if info.IsDir() {
			err = filepath.Walk(manifestPath, func(path string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return err
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".yaml" || ext == ".yml" || ext == ".nix" {
					if err := s.scanFile(path, report); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("error walking manifest directory '%s': %w", manifestPath, err)
			}
		} else {
			if err := s.scanFile(manifestPath, report); err != nil {
				return nil, err
			}
		}
	}

	// Ingest runtime telemetry if provided
	if telemetryPath != "" {
		telData, err := os.ReadFile(telemetryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read BGP telemetry file '%s': %w", telemetryPath, err)
		}
		tel, err := ParseBGPTelemetryJSON(telData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse BGP telemetry '%s': %w", telemetryPath, err)
		}
		report.Telemetry = tel
	}

	// 1. Audit Cilium BGP Peering Policies
	if len(report.Policies) > 0 {
		polViolations := AuditCiliumBGPPeeringPolicies(report.Policies)
		report.Violations = append(report.Violations, polViolations...)
	}

	// 2. Audit Cilium Load Balancer IP Pools
	if len(report.IPPools) > 0 {
		poolViolations := AuditCiliumLoadBalancerIPPools(report.IPPools)
		report.Violations = append(report.Violations, poolViolations...)
	}

	// 3. Audit NixOS BGP Configurations
	for _, nixHost := range report.NixOSHosts {
		nixViolations := AuditNixOSBGP(&nixHost)
		report.Violations = append(report.Violations, nixViolations...)
	}

	// 4. Audit Runtime Telemetry
	if report.Telemetry != nil {
		configuredPeers := make(map[string]bool)
		for _, pol := range report.Policies {
			for _, vr := range pol.VirtualRouters {
				for _, n := range vr.Neighbors {
					configuredPeers[n.PeerAddress] = true
				}
			}
		}
		telViolations := AuditBGPTelemetry(report.Telemetry, configuredPeers)
		report.Violations = append(report.Violations, telViolations...)
	}

	// 5. Compute deterministic compliance summary
	report.Summary = ComputeBGPSummary(report.Policies, report.IPPools, report.Telemetry, report.Violations)

	return report, nil
}

func (s *BGPScanner) scanFile(filePath string, report *BGPAuditReport) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file '%s': %w", filePath, err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".yaml" || ext == ".yml" {
		pols, err := ParseCiliumBGPPeeringPolicy(data, filePath)
		if err == nil && len(pols) > 0 {
			report.Policies = append(report.Policies, pols...)
		}

		pools, err := ParseCiliumLoadBalancerIPPool(data, filePath)
		if err == nil && len(pools) > 0 {
			report.IPPools = append(report.IPPools, pools...)
		}
	} else if ext == ".nix" {
		nixCfg, err := ParseNixOSBGPModule(data, filePath)
		if err == nil && nixCfg != nil && (nixCfg.FRREnabled || nixCfg.TCP179Allowed || nixCfg.IPv6AcceptRA >= 0) {
			report.NixOSHosts = append(report.NixOSHosts, *nixCfg)
		}
	}

	return nil
}
