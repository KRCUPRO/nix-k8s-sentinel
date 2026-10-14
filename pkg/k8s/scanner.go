package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// ManifestAuditReport encapsulates comprehensive audit findings across scanned resources.
type ManifestAuditReport struct {
	TotalFiles     int         `json:"total_files"`
	TotalResources int         `json:"total_resources"`
	Violations     []Violation `json:"violations"`
}

// ManifestScanner orchestrates multi-engine security scans across Kubernetes manifests.
type ManifestScanner struct {
	Feed            *intel.Feed
	ingressAnalyzer *IngressAnalyzer
	cniAnalyzer     *CNIAnalyzer
}

// NewManifestScanner initializes a new scanner instance.
func NewManifestScanner(feed *intel.Feed) *ManifestScanner {
	return &ManifestScanner{
		Feed:            feed,
		ingressAnalyzer: NewIngressAnalyzer(),
		cniAnalyzer:     NewCNIAnalyzer(),
	}
}

// ScanFile audits an individual Kubernetes manifest file (YAML or JSON).
func (s *ManifestScanner) ScanFile(path string) (*ManifestAuditReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	report := &ManifestAuditReport{TotalFiles: 1}
	resources, err := ParseManifestDocuments(string(data))
	if err != nil {
		return nil, fmt.Errorf("error parsing manifest documents: %w", err)
	}

	report.TotalResources = len(resources)
	for _, res := range resources {
		if res.Kind == "Ingress" {
			v := s.ingressAnalyzer.AuditIngress(res)
			report.Violations = append(report.Violations, v...)
		} else if s.cniAnalyzer.IsNetworkPolicyResource(res.Kind) {
			v := s.cniAnalyzer.AuditNetworkPolicy(res)
			report.Violations = append(report.Violations, v...)
		}
	}

	// Posture audit across the parsed document collection
	defaultDenyViolations := s.cniAnalyzer.AuditDefaultDenyPostures(resources)
	report.Violations = append(report.Violations, defaultDenyViolations...)

	for i := range report.Violations {
		if report.Violations[i].FilePath == "" {
			report.Violations[i].FilePath = path
		}
		if report.Violations[i].StartLine <= 0 {
			report.Violations[i].StartLine = 1
		}
	}

	s.correlateWithFeed(report)
	return report, nil
}

// ScanDirectory walks a target directory to audit all .yaml, .yml, and .json manifests.
func (s *ManifestScanner) ScanDirectory(root string) (*ManifestAuditReport, error) {
	report := &ManifestAuditReport{}
	var allResources []RawResource

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

		resources, err := ParseManifestDocuments(string(data))
		if err != nil {
			return nil
		}

		report.TotalFiles++
		report.TotalResources += len(resources)

		for _, res := range resources {
			allResources = append(allResources, res)
			if res.Kind == "Ingress" {
				vList := s.ingressAnalyzer.AuditIngress(res)
				for i := range vList {
					vList[i].FilePath = path
					vList[i].StartLine = 1
				}
				report.Violations = append(report.Violations, vList...)
			} else if s.cniAnalyzer.IsNetworkPolicyResource(res.Kind) {
				vList := s.cniAnalyzer.AuditNetworkPolicy(res)
				for i := range vList {
					vList[i].FilePath = path
					vList[i].StartLine = 1
				}
				report.Violations = append(report.Violations, vList...)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed walking directory %s: %w", root, err)
	}

	// Cluster-level posture audits
	postureViolations := s.cniAnalyzer.AuditDefaultDenyPostures(allResources)
	for i := range postureViolations {
		postureViolations[i].FilePath = root
		postureViolations[i].StartLine = 1
	}
	report.Violations = append(report.Violations, postureViolations...)
	s.correlateWithFeed(report)

	return report, nil
}

// correlateWithFeed enhances discovered violations with intelligence from CVE feeds.
func (s *ManifestScanner) correlateWithFeed(report *ManifestAuditReport) {
	if s.Feed == nil {
		return
	}

	for i := range report.Violations {
		v := &report.Violations[i]
		if v.MatchedCVE != "" {
			continue
		}

		// Correlate ingress vulnerabilities with Ingress-Nginx advisories
		if v.ResourceKind == "Ingress" {
			for _, item := range s.Feed.FilterByTarget("kubernetes") {
				if item.Component == "ingress-nginx" {
					v.MatchedCVE = item.ID
					break
				}
			}
		}
	}
}
