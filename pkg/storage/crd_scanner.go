package storage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// StorageScanner inspects declarative Rook Ceph manifests and storage definitions.
type StorageScanner struct {
	feed *intel.Feed
}

// NewStorageScanner instantiates a scanner with optional threat feed correlation.
func NewStorageScanner(feed *intel.Feed) *StorageScanner {
	return &StorageScanner{feed: feed}
}

// ScanManifest parses a YAML/JSON document stream and audits Rook Ceph resources.
func (s *StorageScanner) ScanManifest(content, filePath string) ([]StorageViolation, error) {
	if len(content) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest payload exceeds maximum allowable size of %d bytes", MaxManifestBytes)
	}

	docs := splitDocuments(content)
	if len(docs) > MaxDocumentsPerStream {
		return nil, fmt.Errorf("document count (%d) exceeds safety ceiling of %d", len(docs), MaxDocumentsPerStream)
	}

	var violations []StorageViolation
	lineOffset := 1

	for _, doc := range docs {
		trimmed := strings.TrimSpace(doc)
		if trimmed == "" {
			lineOffset += strings.Count(doc, "\n")
			continue
		}

		res := parseResourceMetadata(trimmed)
		resViolations := s.auditResource(res, trimmed, filePath, lineOffset)
		violations = append(violations, resViolations...)

		lineOffset += strings.Count(doc, "\n")
	}

	return violations, nil
}

// ScanFile reads and audits a manifest file on disk with path traversal safety.
func (s *StorageScanner) ScanFile(filePath string) ([]StorageViolation, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum allowable size of %d bytes", cleanPath, MaxManifestBytes)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", cleanPath, err)
	}

	return s.ScanManifest(string(data), cleanPath)
}

// ScanDirectory walks a directory tree auditing all YAML and JSON manifests.
func (s *StorageScanner) ScanDirectory(dirPath string) (*StorageAuditReport, error) {
	cleanDir := filepath.Clean(dirPath)
	report := &StorageAuditReport{
		Violations: make([]StorageViolation, 0),
	}

	err := filepath.Walk(cleanDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		report.TotalFiles++
		findings, scanErr := s.ScanFile(p)
		if scanErr != nil {
			return scanErr
		}
		report.Violations = append(report.Violations, findings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("directory audit failed on %s: %w", cleanDir, err)
	}

	return report, nil
}

type parsedResource struct {
	APIVersion string
	Kind       string
	Name       string
	Namespace  string
}

func (s *StorageScanner) auditResource(res parsedResource, content, filePath string, startLine int) []StorageViolation {
	var findings []StorageViolation

	switch res.Kind {
	case "CephCluster":
		findings = append(findings, s.auditCephCluster(res, content, filePath, startLine)...)
	case "CephBlockPool", "CephFilesystem":
		findings = append(findings, s.auditCephPool(res, content, filePath, startLine)...)
	case "StorageClass":
		findings = append(findings, auditStorageClassResource(res.Name, content, filePath, startLine)...)
	case "PersistentVolumeClaim":
		findings = append(findings, auditPVCResource(res.Name, res.Namespace, content, filePath, startLine)...)
	}

	return findings
}

func (s *StorageScanner) auditCephCluster(res parsedResource, content, filePath string, startLine int) []StorageViolation {
	var out []StorageViolation
	lower := strings.ToLower(content)

	// 1. ROOK-CEPH-001: Insecure Host Network Public Exposure
	if (strings.Contains(lower, "hostnetwork: true") || strings.Contains(lower, "hostnetwork:true")) &&
		!strings.Contains(lower, "publicnetwork:") && !strings.Contains(lower, "clusternetwork:") {
		rule, _ := GetStorageRule(RuleRookHostNetwork)
		out = append(out, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  rule.Description,
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    findPatternLine(content, `(?i)hostNetwork:\s*true`, startLine),
		})
	}

	// 2. ROOK-CEPH-002: In-Transit Encryption
	hasCrypto := strings.Contains(lower, "encryption: true") ||
		strings.Contains(lower, "crypto:\n        enabled: true") ||
		strings.Contains(lower, "ms_mode: secure") ||
		strings.Contains(lower, `ms_mode: "secure"`) ||
		strings.Contains(lower, "connections:\n      encryption: true")
	if !hasCrypto {
		rule, _ := GetStorageRule(RuleRookInTransitCrypto)
		out = append(out, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  rule.Description,
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    startLine,
		})
	}

	// 3. ROOK-CEPH-003: Encryption at Rest for OSD Storage
	hasAtRestCrypto := strings.Contains(lower, "encrypted: true") ||
		strings.Contains(lower, "encrypted:true") ||
		strings.Contains(lower, "devicepathfilter:") && strings.Contains(lower, "encrypted: true")
	if !hasAtRestCrypto {
		rule, _ := GetStorageRule(RuleRookAtRestEncryption)
		out = append(out, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  rule.Description,
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    startLine,
		})
	}

	// 4. ROOK-CEPH-005: MON Quorum
	monCount := extractIntPattern(content, `(?i)mon:\s*(?:\n\s+count:\s*(\d+)|\s+count:\s*(\d+))`)
	if monCount > 0 && (monCount < 3 || monCount%2 == 0) {
		rule, _ := GetStorageRule(RuleRookMonQuorum)
		out = append(out, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  fmt.Sprintf("CephCluster defines %d MONs. Minimum recommendation is 3 odd-numbered monitors to prevent quorum split-brain.", monCount),
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    findPatternLine(content, `(?i)count:\s*\d+`, startLine),
		})
	}

	// 5. ROOK-CEPH-006: Insecure Dashboard
	if strings.Contains(lower, "dashboard:\n      enabled: true") || strings.Contains(lower, "dashboard:\n    enabled: true") {
		if strings.Contains(lower, "ssl: false") || strings.Contains(lower, "ssl:false") {
			rule, _ := GetStorageRule(RuleRookDashboardInsecure)
			out = append(out, StorageViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Severity:     rule.Severity,
				CVSSScore:    rule.CVSSScore,
				Description:  rule.Description,
				Remediation:  rule.Remediation,
				FilePath:     filePath,
				StartLine:    findPatternLine(content, `(?i)ssl:\s*false`, startLine),
			})
		}
	}

	// 6. ROOK-CEPH-007: Privileged Daemon Security Context
	if strings.Contains(lower, "privileged: true") || strings.Contains(lower, "privileged:true") {
		rule, _ := GetStorageRule(RuleRookDaemonPrivileged)
		out = append(out, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  rule.Description,
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    findPatternLine(content, `(?i)privileged:\s*true`, startLine),
		})
	}

	return out
}

func (s *StorageScanner) auditCephPool(res parsedResource, content, filePath string, startLine int) []StorageViolation {
	var out []StorageViolation
	lower := strings.ToLower(content)

	// ROOK-CEPH-004: Replication Size & Failure Domain
	replicaSize := extractIntPattern(content, `(?i)replicated:\s*(?:\n\s+size:\s*(\d+)|\s+size:\s*(\d+))`)
	if replicaSize == 0 {
		replicaSize = extractIntPattern(content, `(?i)size:\s*(\d+)`)
	}

	isFailureDomainOSD := strings.Contains(lower, "failuredomain: osd") || strings.Contains(lower, `failuredomain: "osd"`)
	if (replicaSize > 0 && replicaSize < 3) || isFailureDomainOSD {
		rule, _ := GetStorageRule(RuleRookReplicationSize)
		desc := rule.Description
		if replicaSize > 0 && replicaSize < 3 {
			desc = fmt.Sprintf("Pool '%s' specifies replication size %d (< 3), creating high data loss probability upon disk failure.", res.Name, replicaSize)
		} else if isFailureDomainOSD {
			desc = fmt.Sprintf("Pool '%s' specifies failureDomain 'osd'. If an entire host fails, all replicas on that node are lost simultaneously.", res.Name)
		}

		out = append(out, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  desc,
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    startLine,
		})
	}

	return out
}

func splitDocuments(content string) []string {
	var docs []string
	var current strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "---") {
			if current.Len() > 0 {
				docs = append(docs, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
	}

	if current.Len() > 0 {
		docs = append(docs, current.String())
	}
	return docs
}

func parseResourceMetadata(doc string) parsedResource {
	var res parsedResource
	scanner := bufio.NewScanner(strings.NewReader(doc))
	inMetadata := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "apiVersion:") {
			res.APIVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "apiVersion:"))
		} else if strings.HasPrefix(trimmed, "kind:") {
			res.Kind = strings.TrimSpace(strings.TrimPrefix(trimmed, "kind:"))
		} else if strings.HasPrefix(trimmed, "metadata:") {
			inMetadata = true
		} else if inMetadata {
			if strings.HasPrefix(line, "  name:") {
				res.Name = strings.TrimSpace(strings.TrimPrefix(line, "  name:"))
			} else if strings.HasPrefix(line, "  namespace:") {
				res.Namespace = strings.TrimSpace(strings.TrimPrefix(line, "  namespace:"))
			} else if !strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, " ") {
				inMetadata = false
			}
		}
	}

	res.APIVersion = strings.Trim(res.APIVersion, `"'`)
	res.Kind = strings.Trim(res.Kind, `"'`)
	res.Name = strings.Trim(res.Name, `"'`)
	res.Namespace = strings.Trim(res.Namespace, `"'`)
	return res
}

func extractIntPattern(content, pattern string) int {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(content)
	for i := 1; i < len(matches); i++ {
		if matches[i] != "" {
			if n, err := strconv.Atoi(matches[i]); err == nil {
				return n
			}
		}
	}
	return 0
}

func findPatternLine(content, pattern string, baseLine int) int {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return baseLine
	}
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := baseLine
	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			return lineNum
		}
		lineNum++
	}
	return baseLine
}
