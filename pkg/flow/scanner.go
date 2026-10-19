package flow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// FlowScanner coordinates directory traversal, manifest parsing, telemetry reconciliation, and audit reporting.
type FlowScanner struct{}

// NewFlowScanner creates an initialized instance of FlowScanner.
func NewFlowScanner() *FlowScanner {
	return &FlowScanner{}
}

// ScanFlowTarget executes the end-to-end security audit for network flow policies and runtime telemetry.
func (s *FlowScanner) ScanFlowTarget(targetPath, telemetryPath string, feed *intel.Feed) (*FlowAuditReport, error) {
	report := &FlowAuditReport{
		HostName:  "cluster-flow-sentinel",
		ScannedAt: time.Now().UTC(),
	}

	scannedCount := 0
	var allViolations []FlowViolation

	// 1. Process Manifests (YAML / Nix)
	if targetPath != "" {
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("failed to access flow target path (%s): %w", targetPath, err)
		}

		processFile := func(path string) error {
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" && ext != ".nix" {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", path, err)
			}

			if ext == ".yaml" || ext == ".yml" {
				cfg, err := ParseCiliumPolicy(data, path)
				if err == nil && (cfg.Kind == "CiliumNetworkPolicy" || cfg.Kind == "CiliumClusterwideNetworkPolicy" || len(cfg.EgressRules) > 0) {
					scannedCount++
					report.CiliumConfigs = append(report.CiliumConfigs, cfg)
					vList := AuditCiliumPolicy(cfg)
					allViolations = append(allViolations, vList...)
				}
			} else if ext == ".nix" {
				nixCfg, err := ParseNixOSFlow(data, path)
				if err == nil && (nixCfg.FlowProfilerEnabled != nil || nixCfg.CiliumEnabled != nil) {
					scannedCount++
					report.NixOSConfigs = append(report.NixOSConfigs, nixCfg)
					vList := AuditNixOSFlow(nixCfg)
					allViolations = append(allViolations, vList...)
				}
			}
			return nil
		}

		if info.IsDir() {
			err := filepath.Walk(targetPath, func(path string, fi os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if fi.IsDir() {
					return nil
				}
				return processFile(path)
			})
			if err != nil {
				return nil, fmt.Errorf("error walking target path (%s): %w", targetPath, err)
			}
		} else {
			if err := processFile(targetPath); err != nil {
				return nil, err
			}
		}
	}

	// 2. Reconcile Runtime Telemetry (JSON)
	if telemetryPath != "" {
		telData, err := os.ReadFile(telemetryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read flow telemetry file (%s): %w", telemetryPath, err)
		}

		telReport, err := ParseFlowTelemetryJSON(telData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse flow telemetry (%s): %w", telemetryPath, err)
		}

		report.Telemetry = telReport
		scannedCount++
		if telReport.HostName != "" {
			report.HostName = telReport.HostName
		}

		telViolations := AuditFlowTelemetry(telReport)
		allViolations = append(allViolations, telViolations...)
	}

	// 3. Compile Final Summary & Deterministic Compliance Score
	report.Violations = allViolations
	report.Summary = ComputeFlowSummary(scannedCount, allViolations)

	return report, nil
}
