package webhook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// WebhookScanner manages declarative admission webhook configuration scans and telemetry reconciliation.
type WebhookScanner struct {
	MaxFiles int
}

// NewWebhookScanner creates a new WebhookScanner instance with default bounds.
func NewWebhookScanner() *WebhookScanner {
	return &WebhookScanner{
		MaxFiles: 1000,
	}
}

// ScanManifest parses and audits a single Kubernetes webhook configuration manifest.
func (s *WebhookScanner) ScanManifest(filePath string, feed *intel.Feed) ([]WebhookViolation, []WebhookConfig, error) {
	configs, err := ParseAdmissionWebhooksFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse admission webhooks from %s: %w", filePath, err)
	}

	var violations []WebhookViolation
	for _, cfg := range configs {
		v := AuditWebhookConfig(cfg, feed)
		violations = append(violations, v...)
	}

	return violations, configs, nil
}

// ScanDirectory traverses a directory recursively, parsing all YAML webhook manifests.
func (s *WebhookScanner) ScanDirectory(dirPath string, feed *intel.Feed) ([]WebhookViolation, []WebhookConfig, error) {
	var allConfigs []WebhookConfig
	var allViolations []WebhookViolation
	filesScanned := 0

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		filesScanned++
		if filesScanned > s.MaxFiles {
			return fmt.Errorf("exceeded maximum file scan limit (%d files)", s.MaxFiles)
		}

		violations, configs, scanErr := s.ScanManifest(path, feed)
		if scanErr != nil {
			// Skip files that do not contain valid webhook documents
			return nil
		}

		allConfigs = append(allConfigs, configs...)
		allViolations = append(allViolations, violations...)
		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("error walking manifest directory: %w", err)
	}

	return allViolations, allConfigs, nil
}

// ScanAll coordinates scanning either a single file or directory, and optionally reconciles telemetry.
func (s *WebhookScanner) ScanAll(manifestPath, telemetryPath string, feed *intel.Feed) (*WebhookAuditReport, error) {
	var configs []WebhookConfig

	if manifestPath != "" {
		info, err := os.Stat(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("cannot access manifest path %q: %w", manifestPath, err)
		}

		if info.IsDir() {
			_, c, err := s.ScanDirectory(manifestPath, feed)
			if err != nil {
				return nil, err
			}
			configs = c
		} else {
			_, c, err := s.ScanManifest(manifestPath, feed)
			if err != nil {
				return nil, err
			}
			configs = c
		}
	}

	var telemetry *WebhookTelemetry
	if telemetryPath != "" {
		data, err := os.ReadFile(telemetryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read webhook telemetry file %q: %w", telemetryPath, err)
		}
		tel, err := ParseWebhookTelemetryJSON(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse webhook telemetry JSON: %w", err)
		}
		telemetry = tel
	}

	report := GenerateWebhookAuditReport(configs, telemetry, feed)
	return report, nil
}

// ScanAdmissionWebhooks is a package-level entry point coordinating manifest scanning and telemetry reconciliation.
func ScanAdmissionWebhooks(manifestPath, telemetryPath string, strictMode bool, feed *intel.Feed) (*WebhookAuditReport, error) {
	scanner := NewWebhookScanner()
	return scanner.ScanAll(manifestPath, telemetryPath, feed)
}
