package fleet

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	reDocKind      = regexp.MustCompile(`^\s*kind:\s*([A-Za-z0-9_-]+)`)
	reDocName      = regexp.MustCompile(`^\s*name:\s*([A-Za-z0-9_.-]+)`)
	reDocNamespace = regexp.MustCompile(`^\s*namespace:\s*([A-Za-z0-9_.-]+)`)
)

// FleetScanner coordinates static manifest analysis and runtime fleet telemetry reconciliation.
type FleetScanner struct {
	feed        *intel.Feed
	rbacAuditor *RBACOIDCAuditor
	gitAuditor  *GitOpsAuditor
}

// NewFleetScanner initializes a FleetScanner with active auditors.
func NewFleetScanner(feed *intel.Feed) *FleetScanner {
	return &FleetScanner{
		feed:        feed,
		rbacAuditor: NewRBACOIDCAuditor(feed),
		gitAuditor:  NewGitOpsAuditor(feed),
	}
}

// ScanFile parses a single manifest file and audits all contained documents.
func (s *FleetScanner) ScanFile(path string) (*FleetAuditReport, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("fleet scan stat failed for %s: %w", path, err)
	}
	if fi.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("manifest %s exceeds defensive size limit (%d > %d)", path, fi.Size(), MaxManifestBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open manifest %s: %w", path, err)
	}
	defer f.Close()

	var violations []FleetViolation
	scanner := bufio.NewScanner(f)
	var docLines []string
	startLine := 1
	currentLine := 1
	docCount := 0

	for scanner.Scan() {
		if currentLine > MaxScanLines {
			break
		}
		line := scanner.Text()

		if strings.HasPrefix(strings.TrimSpace(line), "---") {
			if len(docLines) > 0 {
				docCount++
				if docCount > MaxDocumentsPerStream {
					return nil, fmt.Errorf("stream exceeds maximum document count (%d)", MaxDocumentsPerStream)
				}
				v := s.auditRawDocument(docLines, startLine, path)
				violations = append(violations, v...)
				docLines = nil
			}
			startLine = currentLine + 1
		} else {
			docLines = append(docLines, line)
		}
		currentLine++
	}

	if len(docLines) > 0 {
		docCount++
		v := s.auditRawDocument(docLines, startLine, path)
		violations = append(violations, v...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading manifest %s: %w", path, err)
	}

	totalChecks := docCount * 4
	if totalChecks == 0 {
		totalChecks = 1
	}
	passedChecks := totalChecks - len(violations)
	if passedChecks < 0 {
		passedChecks = 0
	}
	score := math.Round((float64(passedChecks)/float64(totalChecks)*100.0)*10) / 10

	var crit, high, med, low int
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	return &FleetAuditReport{
		Timestamp:     time.Now().UTC(),
		TotalFiles:    1,
		TotalClusters: 1,
		Violations:    violations,
		Summary: FleetSummary{
			TotalChecks:     totalChecks,
			PassedChecks:    passedChecks,
			ComplianceScore: score,
			CriticalCount:   crit,
			HighCount:       high,
			MediumCount:     med,
			LowCount:        low,
			ClustersAudited: 1,
			ClustersInSync:  1,
		},
	}, nil
}

// ScanDirectory traverses a directory recursively and audits all YAML/JSON manifest files.
func (s *FleetScanner) ScanDirectory(dir string) (*FleetAuditReport, error) {
	var reports []*FleetAuditReport

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			rep, err := s.ScanFile(path)
			if err != nil {
				return err
			}
			reports = append(reports, rep)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("fleet directory walk failed: %w", err)
	}

	return s.MergeReports(reports...), nil
}

// ReconcileTelemetryFile inverts and inspects live runtime fleet telemetry reports.
func (s *FleetScanner) ReconcileTelemetryFile(path string) (*FleetAuditReport, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("fleet telemetry stat failed for %s: %w", path, err)
	}
	if fi.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("fleet telemetry %s exceeds limit (%d > %d)", path, fi.Size(), MaxTelemetryBytes)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry %s: %w", path, err)
	}

	var report FleetTelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse fleet telemetry JSON: %w", err)
	}

	var violations []FleetViolation
	totalChecks := 0
	passedChecks := 0
	clustersAudited := len(report.Clusters)
	clustersInSync := 0
	driftingApps := 0
	oidcVerified := 0

	// 1. Audit cluster connectivity and admin posture
	for _, cluster := range report.Clusters {
		totalChecks += 2
		if !cluster.Connected {
			rule, _ := LookupFleetRule("FLEET-DRIFT-001")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryMultiCluster,
				ResourceKind: "ClusterNode",
				ResourceName: cluster.ClusterID,
				ClusterID:    cluster.ClusterID,
				Message:      fmt.Sprintf("Cluster '%s' (%s | %s) is disconnected or unreachable in fleet pool", cluster.ClusterID, cluster.Region, cluster.Provider),
				Remediation:  rule.Remediation,
			})
		} else {
			passedChecks++
		}

		if cluster.RBACAdminRoles > 5 {
			rule, _ := LookupFleetRule("FLEET-RBAC-001")
			violations = append(violations, FleetViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Category:     CategoryRBAC,
				ResourceKind: "ClusterNode",
				ResourceName: cluster.ClusterID,
				ClusterID:    cluster.ClusterID,
				Message:      fmt.Sprintf("Cluster '%s' has %d cluster-admin roles defined, exceeding least-privilege baseline", cluster.ClusterID, cluster.RBACAdminRoles),
				Remediation:  rule.Remediation,
			})
		} else {
			passedChecks++
		}
	}

	// 2. Audit OIDC token telemetry
	for _, tok := range report.OIDCTokens {
		totalChecks += 3
		v := s.rbacAuditor.AuditOIDCToken(tok, tok.ClusterID)
		if len(v) == 0 {
			passedChecks += 3
			oidcVerified++
		} else {
			violations = append(violations, v...)
			passedChecks += int(math.Max(0, float64(3-len(v))))
		}
	}

	// 3. Audit GitOps synchronization telemetry
	for _, app := range report.GitOpsApps {
		totalChecks += 2
		v := s.gitAuditor.AuditSyncStatus(app)
		if len(v) == 0 {
			passedChecks += 2
		} else {
			violations = append(violations, v...)
			driftingApps++
		}
	}

	if len(report.GitOpsApps) > 0 && driftingApps == 0 {
		clustersInSync = clustersAudited
	} else if clustersAudited > 0 {
		clustersInSync = int(math.Max(0, float64(clustersAudited-driftingApps)))
	}

	if totalChecks == 0 {
		totalChecks = 1
		passedChecks = 1
	}

	score := math.Round((float64(passedChecks)/float64(totalChecks)*100.0)*10) / 10

	var crit, high, med, low int
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	return &FleetAuditReport{
		Timestamp:     report.Timestamp,
		TotalFiles:    1,
		TotalClusters: clustersAudited,
		Violations:    violations,
		Summary: FleetSummary{
			TotalChecks:        totalChecks,
			PassedChecks:       passedChecks,
			ComplianceScore:    score,
			CriticalCount:      crit,
			HighCount:          high,
			MediumCount:        med,
			LowCount:           low,
			ClustersAudited:    clustersAudited,
			ClustersInSync:     clustersInSync,
			DriftingApps:       driftingApps,
			OIDCTokensVerified: oidcVerified,
		},
	}, nil
}

// auditRawDocument inspects a single document block for metadata and routes to relevant auditors.
func (s *FleetScanner) auditRawDocument(lines []string, startLine int, filePath string) []FleetViolation {
	var kind, name, namespace string

	for _, line := range lines {
		if kind == "" {
			if m := reDocKind.FindStringSubmatch(line); len(m) > 1 {
				kind = strings.TrimSpace(m[1])
			}
		}
		if name == "" {
			if m := reDocName.FindStringSubmatch(line); len(m) > 1 {
				name = strings.TrimSpace(m[1])
			}
		}
		if namespace == "" {
			if m := reDocNamespace.FindStringSubmatch(line); len(m) > 1 {
				namespace = strings.TrimSpace(m[1])
			}
		}
	}

	if kind == "" {
		return nil
	}

	var violations []FleetViolation
	// Check RBAC kinds
	if kind == "ClusterRole" || kind == "Role" || kind == "ClusterRoleBinding" || kind == "RoleBinding" {
		violations = append(violations, s.rbacAuditor.AuditRBACDocument(lines, startLine, filePath, kind, name, namespace)...)
	}
	// Check GitOps kinds
	if kind == "Application" || kind == "ApplicationSet" || kind == "Kustomization" || kind == "GitRepository" || kind == "OCIRepository" || kind == "HelmRelease" {
		violations = append(violations, s.gitAuditor.AuditGitOpsDocument(lines, startLine, filePath, kind, name, namespace)...)
	}

	return violations
}

// MergeReports combines multiple FleetAuditReport results into a unified aggregate report.
func (s *FleetScanner) MergeReports(reports ...*FleetAuditReport) *FleetAuditReport {
	res := &FleetAuditReport{
		Timestamp: time.Now().UTC(),
	}

	for _, r := range reports {
		if r == nil {
			continue
		}
		res.TotalFiles += r.TotalFiles
		if r.TotalClusters > res.TotalClusters {
			res.TotalClusters = r.TotalClusters
		}
		res.Violations = append(res.Violations, r.Violations...)
		res.Summary.TotalChecks += r.Summary.TotalChecks
		res.Summary.PassedChecks += r.Summary.PassedChecks
		res.Summary.CriticalCount += r.Summary.CriticalCount
		res.Summary.HighCount += r.Summary.HighCount
		res.Summary.MediumCount += r.Summary.MediumCount
		res.Summary.LowCount += r.Summary.LowCount
		res.Summary.ClustersAudited += r.Summary.ClustersAudited
		res.Summary.ClustersInSync += r.Summary.ClustersInSync
		res.Summary.DriftingApps += r.Summary.DriftingApps
		res.Summary.OIDCTokensVerified += r.Summary.OIDCTokensVerified
	}

	if res.Summary.TotalChecks > 0 {
		res.Summary.ComplianceScore = math.Round((float64(res.Summary.PassedChecks)/float64(res.Summary.TotalChecks)*100.0)*10) / 10
	} else {
		res.Summary.ComplianceScore = 100.0
	}

	return res
}
