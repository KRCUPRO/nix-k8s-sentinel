package hsm

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// HSMScanner coordinates multi-file manifest scanning and runtime telemetry reconciliation.
type HSMScanner struct {
	Feed *intel.Feed
}

// NewHSMScanner creates an instance of HSMScanner with an optional threat feed.
func NewHSMScanner(feed *intel.Feed) *HSMScanner {
	return &HSMScanner{Feed: feed}
}

// ScanPath audits a file or directory for Kubernetes EncryptionConfiguration and NixOS HSM configs.
func (s *HSMScanner) ScanPath(rootPath string) (*HSMAuditReport, error) {
	report := &HSMAuditReport{
		Timestamp:  time.Now().UTC(),
		Violations: make([]HSMViolation, 0),
		Configs:    make([]KMSEncryptionConfig, 0),
		Telemetry:  make([]HSMRuntimeTelemetry, 0),
	}

	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", rootPath, err)
	}

	if !info.IsDir() {
		if err := s.auditSingleFile(rootPath, report); err != nil {
			return nil, err
		}
	} else {
		err := filepath.Walk(rootPath, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fi.IsDir() {
				name := fi.Name()
				if name == ".git" || name == "node_modules" || name == "target" || name == "temp" {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" || ext == ".nix" || ext == ".json" {
				_ = s.auditSingleFile(path, report)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error during directory walk: %w", err)
		}
	}

	s.computeSummary(report)
	return report, nil
}

// ScanTelemetryFile audits a JSON runtime telemetry file containing HSM or KMS metrics.
func (s *HSMScanner) ScanTelemetryFile(path string) (*HSMAuditReport, error) {
	report := &HSMAuditReport{
		Timestamp:  time.Now().UTC(),
		Violations: make([]HSMViolation, 0),
		Telemetry:  make([]HSMRuntimeTelemetry, 0),
	}

	data, err := ReadFileSafely(path, MaxTelemetryBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file: %w", err)
	}

	var list []HSMRuntimeTelemetry
	if err := json.Unmarshal(data, &list); err != nil {
		var single HSMRuntimeTelemetry
		if errSingle := json.Unmarshal(data, &single); errSingle != nil {
			return nil, fmt.Errorf("telemetry JSON does not match HSM schema: %w", err)
		}
		list = []HSMRuntimeTelemetry{single}
	}

	for _, item := range list {
		report.Telemetry = append(report.Telemetry, item)
		report.Summary.TotalKeysAudited += len(item.ActiveKeys)
		v := AuditTelemetry(&item, s.Feed)
		report.Violations = append(report.Violations, v...)
	}

	s.computeSummary(report)
	return report, nil
}

func (s *HSMScanner) auditSingleFile(path string, report *HSMAuditReport) error {
	ext := strings.ToLower(filepath.Ext(path))
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if ext == ".yaml" || ext == ".yml" {
		cfg, err := ParseK8sEncryptionConfig(f, path)
		if err == nil && (len(cfg.KMSProviders) > 0 || cfg.PrimaryProviderType != "" || strings.Contains(cfg.ApiVersion, "apiserver.config.k8s.io")) {
			report.Configs = append(report.Configs, *cfg)
			report.Summary.TotalConfigsScanned++
			v := AuditEncryptionConfig(cfg, s.Feed)
			report.Violations = append(report.Violations, v...)
		}
	} else if ext == ".nix" {
		p11s, nitros, p11On, nitroOn, err := ParseNixOSHSMConfig(f, path)
		if err == nil {
			report.Summary.TotalConfigsScanned++
			for _, p := range p11s {
				report.Violations = append(report.Violations, AuditPKCS11(&p, s.Feed)...)
			}
			hostV := AuditNixOSHost(p11s, nitros, p11On, nitroOn, path)
			report.Violations = append(report.Violations, hostV...)
		}
	} else if ext == ".json" {
		// Could be telemetry or JSON EncryptionConfiguration
		data, err := ReadFileSafely(path, MaxManifestBytes)
		if err == nil {
			var cfg KMSEncryptionConfig
			if errJson := json.Unmarshal(data, &cfg); errJson == nil && (len(cfg.KMSProviders) > 0 || cfg.PrimaryProviderType != "") {
				cfg.FilePath = path
				report.Configs = append(report.Configs, cfg)
				report.Summary.TotalConfigsScanned++
				report.Violations = append(report.Violations, AuditEncryptionConfig(&cfg, s.Feed)...)
			}
		}
	}

	return nil
}

func (s *HSMScanner) computeSummary(report *HSMAuditReport) {
	report.Summary.ViolationsCount = len(report.Violations)
	for _, v := range report.Violations {
		switch v.Severity {
		case intel.SeverityCritical:
			report.Summary.CriticalCount++
		case intel.SeverityHigh:
			report.Summary.HighCount++
		case intel.SeverityMedium:
			report.Summary.MediumCount++
		case intel.SeverityLow:
			report.Summary.LowCount++
		}
	}

	deductions := float64(report.Summary.CriticalCount)*25.0 +
		float64(report.Summary.HighCount)*12.0 +
		float64(report.Summary.MediumCount)*5.0 +
		float64(report.Summary.LowCount)*2.0

	score := math.Max(0.0, 100.0-deductions)
	report.Summary.ComplianceScore = math.Round(score*10.0) / 10.0

	switch {
	case report.Summary.CriticalCount > 0:
		report.Summary.AuditStatus = "CRITICAL_DEFECTS_DETECTED"
	case report.Summary.HighCount > 0:
		report.Summary.AuditStatus = "HIGH_RISK_DEFECTS_DETECTED"
	case report.Summary.ViolationsCount > 0:
		report.Summary.AuditStatus = "WARNINGS_DETECTED"
	default:
		report.Summary.AuditStatus = "COMPLIANT"
	}
}
