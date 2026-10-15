package gateway

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

// GatewayScanner coordinates static audits across Gateway API and Istio EnvoyFilter resources.
type GatewayScanner struct {
	Feed         *intel.Feed
	radar        *GatewayRadar
	envoyAuditor *EnvoyFilterAuditor
}

// NewGatewayScanner constructs a new scanner instance.
func NewGatewayScanner(feed *intel.Feed) *GatewayScanner {
	return &GatewayScanner{
		Feed:         feed,
		radar:        NewGatewayRadar(),
		envoyAuditor: NewEnvoyFilterAuditor(),
	}
}

// ScanFile scans an individual YAML manifest containing Gateway API or EnvoyFilter resources.
func (s *GatewayScanner) ScanFile(path string) (*GatewayAuditReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read gateway manifest file: %w", err)
	}

	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest payload exceeds maximum allowable size of %d bytes", MaxManifestBytes)
	}

	resources, err := k8s.ParseManifestDocuments(string(data))
	if err != nil {
		return nil, fmt.Errorf("error parsing manifest documents: %w", err)
	}

	report := &GatewayAuditReport{
		TargetPath: path,
		TotalFiles: 1,
	}

	// Pass 1: Register all ReferenceGrants
	s.radar.RegisterReferenceGrants(resources)
	report.ReferenceGrants = s.radar.ReferenceGrants()

	// Pass 2: Audit each resource
	for _, res := range resources {
		s.auditResource(res, path, report)
	}

	s.correlateWithFeed(report)
	s.computeSummary(report)

	return report, nil
}

// ScanDirectory walks a target directory and evaluates all YAML manifests against Gateway API radar rules.
func (s *GatewayScanner) ScanDirectory(root string) (*GatewayAuditReport, error) {
	report := &GatewayAuditReport{
		TargetPath: root,
	}

	type fileDoc struct {
		filePath  string
		resources []k8s.RawResource
	}

	var allFileDocs []fileDoc

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip unreadable file
		}

		if len(data) > MaxManifestBytes {
			return nil // Skip oversized files defensively
		}

		resources, err := k8s.ParseManifestDocuments(string(data))
		if err != nil {
			return nil
		}

		report.TotalFiles++
		allFileDocs = append(allFileDocs, fileDoc{filePath: path, resources: resources})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed walking directory %s: %w", root, err)
	}

	// Pass 1: Global ReferenceGrant Registration across all manifests
	for _, fd := range allFileDocs {
		s.radar.RegisterReferenceGrants(fd.resources)
	}
	report.ReferenceGrants = s.radar.ReferenceGrants()

	// Pass 2: Audit all resources with complete ReferenceGrant visibility
	for _, fd := range allFileDocs {
		for _, res := range fd.resources {
			s.auditResource(res, fd.filePath, report)
		}
	}

	s.correlateWithFeed(report)
	s.computeSummary(report)

	return report, nil
}

func (s *GatewayScanner) auditResource(res k8s.RawResource, filePath string, report *GatewayAuditReport) {
	kind := RouteKind(res.Kind)
	switch kind {
	case KindGateway:
		report.TotalResources++
		report.EvaluatedResources = append(report.EvaluatedResources, fmt.Sprintf("%s/%s", res.Kind, res.Name))
		v := s.radar.AuditGateway(res, filePath)
		report.Violations = append(report.Violations, v...)

	case KindHTTPRoute:
		report.TotalResources++
		report.EvaluatedResources = append(report.EvaluatedResources, fmt.Sprintf("%s/%s", res.Kind, res.Name))
		v := s.radar.AuditHTTPRoute(res, filePath)
		report.Violations = append(report.Violations, v...)

	case KindGRPCRoute:
		report.TotalResources++
		report.EvaluatedResources = append(report.EvaluatedResources, fmt.Sprintf("%s/%s", res.Kind, res.Name))
		v := s.radar.AuditGRPCRoute(res, filePath)
		report.Violations = append(report.Violations, v...)

	case KindTCPRoute, KindUDPRoute:
		report.TotalResources++
		report.EvaluatedResources = append(report.EvaluatedResources, fmt.Sprintf("%s/%s", res.Kind, res.Name))
		v := s.radar.AuditTCPRoute(res, filePath)
		report.Violations = append(report.Violations, v...)

	case KindEnvoyFilter:
		report.TotalResources++
		report.EvaluatedResources = append(report.EvaluatedResources, fmt.Sprintf("%s/%s", res.Kind, res.Name))
		v := s.envoyAuditor.AuditEnvoyFilter(res, filePath)
		report.Violations = append(report.Violations, v...)
	}
}

func (s *GatewayScanner) correlateWithFeed(report *GatewayAuditReport) {
	if s.Feed == nil {
		return
	}

	for i := range report.Violations {
		v := &report.Violations[i]
		if v.MatchedCVE != "" {
			continue
		}

		for _, item := range s.Feed.Items {
			// Correlate Gateway API cross-namespace or EnvoyFilter findings
			if (v.RuleID == "GW-RADAR-001" || v.RuleID == "GW-RADAR-002" || v.RuleID == "GW-RADAR-003") &&
				(strings.Contains(strings.ToLower(item.Title), "gateway") || strings.Contains(strings.ToLower(item.Component), "gateway") || strings.Contains(strings.ToLower(item.Component), "envoy")) {
				v.MatchedCVE = item.ID
				break
			}
		}
	}
}

func (s *GatewayScanner) computeSummary(report *GatewayAuditReport) {
	// Baseline checks: Each evaluated resource is audited against its applicable rule category checks (approx 5 checks per resource)
	estimatedChecks := report.TotalResources * 5
	if estimatedChecks == 0 {
		estimatedChecks = 1
	}

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

	totalViolations := len(report.Violations)
	if totalViolations > estimatedChecks {
		estimatedChecks = totalViolations
	}

	passedChecks := estimatedChecks - totalViolations
	if passedChecks < 0 {
		passedChecks = 0
	}

	complianceScore := (float64(passedChecks) / float64(estimatedChecks)) * 100.0
	complianceScore = math.Round(complianceScore*10) / 10

	report.Summary.TotalChecks = estimatedChecks
	report.Summary.PassedChecks = passedChecks
	report.Summary.ComplianceScore = complianceScore
}
