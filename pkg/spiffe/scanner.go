package spiffe

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

// SPIFFEScanner inspects declarative SPIRE/Cilium manifests and reconciles runtime SVID telemetry.
type SPIFFEScanner struct {
	feed               *intel.Feed
	primaryTrustDomain string
	federatedDomains   []string
}

// NewSPIFFEScanner instantiates a scanner with optional threat feed correlation.
func NewSPIFFEScanner(feed *intel.Feed) *SPIFFEScanner {
	return &SPIFFEScanner{
		feed:               feed,
		primaryTrustDomain: "cluster.local",
		federatedDomains:   []string{"partner-mesh.internal", "edge-cloud.net"},
	}
}

// SetTrustDomains configures the expected primary and federated SPIFFE trust domains.
func (s *SPIFFEScanner) SetTrustDomains(primary string, federated []string) {
	if primary != "" {
		s.primaryTrustDomain = strings.ToLower(primary)
	}
	s.federatedDomains = federated
}

// ScanFile inspects a single manifest file for SPIFFE/SPIRE and Cilium security postures.
func (s *SPIFFEScanner) ScanFile(filePath string) (*SPIFFEAuditReport, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access manifest file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("manifest file %s exceeds 10MB bounds limit (%d bytes)", cleanPath, info.Size())
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", cleanPath, err)
	}

	violations, resourcesCount := s.parseManifestContent(string(data), cleanPath)
	summary := s.compileSummary(violations, resourcesCount, 0, 0, 0)

	return &SPIFFEAuditReport{
		TotalFiles:     1,
		TotalResources: resourcesCount,
		Violations:     violations,
		Summary:        summary,
		ScannedPaths:   []string{cleanPath},
	}, nil
}

// ScanDirectory recursively audits all manifest files within a directory.
func (s *SPIFFEScanner) ScanDirectory(dirPath string) (*SPIFFEAuditReport, error) {
	cleanDir := filepath.Clean(dirPath)
	var allViolations []SPIFFEViolation
	var scannedPaths []string
	totalResources := 0
	totalFiles := 0

	err := filepath.Walk(cleanDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" && ext != ".nix" && ext != ".conf" {
			return nil
		}

		if info.Size() > MaxManifestBytes {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		violations, rCount := s.parseManifestContent(string(data), path)
		allViolations = append(allViolations, violations...)
		totalResources += rCount
		totalFiles++
		scannedPaths = append(scannedPaths, path)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", cleanDir, err)
	}

	summary := s.compileSummary(allViolations, totalResources, 0, 0, 0)
	return &SPIFFEAuditReport{
		TotalFiles:     totalFiles,
		TotalResources: totalResources,
		Violations:     allViolations,
		Summary:        summary,
		ScannedPaths:   scannedPaths,
	}, nil
}

// ReconcileTelemetryFile parses a runtime telemetry report JSON and audits active SVIDs.
func (s *SPIFFEScanner) ReconcileTelemetryFile(telemetryPath string) (*SPIFFEAuditReport, error) {
	cleanPath := filepath.Clean(telemetryPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access telemetry file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry file %s exceeds 5MB bounds limit (%d bytes)", cleanPath, info.Size())
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file %s: %w", cleanPath, err)
	}

	var report SPIFFETelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("malformed SPIFFE telemetry JSON in %s: %w", cleanPath, err)
	}

	return s.ReconcileTelemetry(report, cleanPath)
}

// ReconcileTelemetry inspects a live SPIFFETelemetryReport.
func (s *SPIFFEScanner) ReconcileTelemetry(report SPIFFETelemetryReport, sourcePath string) (*SPIFFEAuditReport, error) {
	var violations []SPIFFEViolation
	now := report.CapturedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	primaryTD := report.PrimaryTrustDomain
	if primaryTD == "" {
		primaryTD = s.primaryTrustDomain
	}
	federated := report.FederatedDomains
	if len(federated) == 0 {
		federated = s.federatedDomains
	}

	auditedSVIDs := 0
	validSVIDs := 0
	expiredOrNearExpiry := 0

	for _, svid := range report.SVIDs {
		if auditedSVIDs >= MaxSVIDCount {
			break
		}
		auditedSVIDs++

		svidViolations := AuditSVID(svid, primaryTD, federated, now)
		for i := range svidViolations {
			svidViolations[i].FilePath = sourcePath
		}
		allClean := len(svidViolations) == 0

		hasExpiryIssue := false
		for _, v := range svidViolations {
			if v.RuleID == "SPIFFE-SVID-003" {
				hasExpiryIssue = true
				break
			}
		}
		if hasExpiryIssue {
			expiredOrNearExpiry++
		}
		if allClean {
			validSVIDs++
		}

		violations = append(violations, svidViolations...)
	}

	// Audit agent admin sockets if present
	for _, sock := range report.AgentAdminSockets {
		if strings.Contains(sock, "0777") || strings.Contains(sock, "world-writable") {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-005",
				Title:        "Insecure SPIRE Agent Admin API Socket Exposure",
				Severity:     CanonicalRules[4].DefaultSeverity,
				CVSSScore:    CanonicalRules[4].BaseCVSS,
				Category:     CategoryAgentSecurity,
				ResourceKind: "AgentSocket",
				ResourceName: sock,
				FilePath:     sourcePath,
				Message:      fmt.Sprintf("Agent socket '%s' is configured with overly permissive permissions", sock),
				Remediation:  CanonicalRules[4].Remediation,
			})
		}
	}

	// Threat feed correlation
	s.correlateFeed(&violations)

	summary := s.compileSummary(violations, 0, auditedSVIDs, validSVIDs, expiredOrNearExpiry)

	return &SPIFFEAuditReport{
		TotalFiles:     1,
		TotalResources: auditedSVIDs,
		Violations:     violations,
		Summary:        summary,
		ScannedPaths:   []string{sourcePath},
	}, nil
}

// parseManifestContent performs streaming inspection of declarative YAML/JSON manifests.
func (s *SPIFFEScanner) parseManifestContent(content, filePath string) ([]SPIFFEViolation, int) {
	var violations []SPIFFEViolation
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	resourceCount := 0

	currentKind := ""
	currentName := ""
	currentNamespace := "default"
	currentSpiffeID := ""
	selectors := make(map[string]string)
	hasMTLS := false
	hasSpiffeSelector := false
	inIngress := false
	inAuthentication := false

	flushResource := func() {
		if currentKind == "" {
			return
		}
		resourceCount++

		// Check SpireRegistrationEntry
		if currentKind == "SpireRegistrationEntry" || currentKind == "RegistrationEntry" {
			ident := WorkloadIdentity{
				Name:      currentName,
				Namespace: currentNamespace,
				SPIFFEID:  currentSpiffeID,
				Selectors: selectors,
			}
			td, _, _ := ParseSPIFFEID(currentSpiffeID)
			ident.TrustDomain = td

			rViolations := AuditRegistrationEntry(ident, s.primaryTrustDomain, s.federatedDomains)
			for i := range rViolations {
				rViolations[i].FilePath = filePath
				rViolations[i].StartLine = lineNum
			}
			violations = append(violations, rViolations...)
		}

		// Check CiliumNetworkPolicy
		if currentKind == "CiliumNetworkPolicy" || currentKind == "CiliumClusterwideNetworkPolicy" {
			if inIngress && !hasMTLS && !hasSpiffeSelector {
				violations = append(violations, SPIFFEViolation{
					RuleID:       "SPIFFE-SVID-006",
					Title:        "Missing mTLS Enforcement in Cilium Ingress Policy",
					Severity:     CanonicalRules[5].DefaultSeverity,
					CVSSScore:    CanonicalRules[5].BaseCVSS,
					Category:     CategoryMicrosegment,
					ResourceKind: currentKind,
					ResourceName: currentName,
					Namespace:    currentNamespace,
					FilePath:     filePath,
					StartLine:    lineNum,
					Message:      fmt.Sprintf("%s '%s' specifies ingress rules without requiring mTLS authentication or io.spiffe.id matching", currentKind, currentName),
					Remediation:  CanonicalRules[5].Remediation,
				})
			}
		}

		// Reset resource state
		currentKind = ""
		currentName = ""
		currentNamespace = "default"
		currentSpiffeID = ""
		selectors = make(map[string]string)
		hasMTLS = false
		hasSpiffeSelector = false
		inIngress = false
		inAuthentication = false
	}

	reKind := regexp.MustCompile(`^\s*kind:\s*([A-Za-z0-9_-]+)`)
	reName := regexp.MustCompile(`^\s*name:\s*([A-Za-z0-9._-]+)`)
	reNS := regexp.MustCompile(`^\s*namespace:\s*([A-Za-z0-9._-]+)`)
	reSpiffeID := regexp.MustCompile(`^\s*spiffe_?id:\s*["']?([^"'\s]+)["']?`)
	reSelector := regexp.MustCompile(`^\s*-\s*([A-Za-z0-9:_-]+):([A-Za-z0-9:*_.-]+)`)
	reCiliumSpiffe := regexp.MustCompile(`io\.spiffe\.id`)
	reAuthRequired := regexp.MustCompile(`mode:\s*["']?required["']?`)

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxScanLines {
			break
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "---" {
			flushResource()
			continue
		}

		if m := reKind.FindStringSubmatch(line); len(m) > 1 {
			currentKind = m[1]
		}
		if m := reName.FindStringSubmatch(line); len(m) > 1 && currentName == "" {
			currentName = m[1]
		}
		if m := reNS.FindStringSubmatch(line); len(m) > 1 {
			currentNamespace = m[1]
		}
		if m := reSpiffeID.FindStringSubmatch(line); len(m) > 1 {
			currentSpiffeID = m[1]
		}

		// Check selector entries
		if m := reSelector.FindStringSubmatch(line); len(m) > 2 {
			selectors[m[1]] = m[2]
		}

		// Cilium markers
		if strings.HasPrefix(trimmed, "ingress:") {
			inIngress = true
		}
		if reCiliumSpiffe.MatchString(line) {
			hasSpiffeSelector = true
		}
		if strings.HasPrefix(trimmed, "authentication:") {
			inAuthentication = true
		}
		if inAuthentication && reAuthRequired.MatchString(line) {
			hasMTLS = true
		}

		// Wildcard selector check
		if (strings.Contains(line, "k8s:ns:*") || strings.Contains(line, "k8s:sa:*")) && currentKind != "" {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-004",
				Title:        "Permissive Wildcard Attestation Selector in SPIRE Registration Entry",
				Severity:     CanonicalRules[3].DefaultSeverity,
				CVSSScore:    CanonicalRules[3].BaseCVSS,
				Category:     CategoryAttestation,
				ResourceKind: currentKind,
				ResourceName: currentName,
				Namespace:    currentNamespace,
				FilePath:     filePath,
				StartLine:    lineNum,
				Message:      fmt.Sprintf("Wildcard attestation selector found in line %d: '%s'", lineNum, trimmed),
				Remediation:  CanonicalRules[3].Remediation,
			})
		}

		// Insecure admin socket check
		if strings.Contains(line, "spire-agent.sock") && (strings.Contains(line, "0777") || strings.Contains(line, "mode: 777")) {
			violations = append(violations, SPIFFEViolation{
				RuleID:       "SPIFFE-SVID-005",
				Title:        "Insecure SPIRE Agent Admin API Socket Exposure",
				Severity:     CanonicalRules[4].DefaultSeverity,
				CVSSScore:    CanonicalRules[4].BaseCVSS,
				Category:     CategoryAgentSecurity,
				ResourceKind: currentKind,
				ResourceName: currentName,
				Namespace:    currentNamespace,
				FilePath:     filePath,
				StartLine:    lineNum,
				Message:      fmt.Sprintf("Insecure socket permissions on spire-agent.sock at line %d", lineNum),
				Remediation:  CanonicalRules[4].Remediation,
			})
		}
	}
	flushResource()

	s.correlateFeed(&violations)
	return violations, resourceCount
}

// correlateFeed matches findings against CVE feed items.
func (s *SPIFFEScanner) correlateFeed(violations *[]SPIFFEViolation) {
	if s.feed == nil || len(s.feed.Items) == 0 {
		return
	}

	for _, item := range s.feed.Items {
		if item.ID == "CVE-2026-67210" {
			for i := range *violations {
				v := &(*violations)[i]
				if v.RuleID == "SPIFFE-SVID-003" || v.RuleID == "SPIFFE-SVID-006" {
					v.MatchedCVE = item.ID
				}
			}
		}
	}
}

// compileSummary computes compliance scorecards and severity breakdowns.
func (s *SPIFFEScanner) compileSummary(violations []SPIFFEViolation, totalResources, auditedSVIDs, validSVIDs, expiredSVIDs int) SPIFFESummary {
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	for _, v := range violations {
		switch strings.ToUpper(string(v.Severity)) {
		case "CRITICAL":
			critCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			medCount++
		case "LOW":
			lowCount++
		}
	}

	totalChecks := totalResources + auditedSVIDs
	if totalChecks < len(violations) {
		totalChecks = len(violations) + 5
	}
	if totalChecks == 0 {
		totalChecks = 10
	}

	passedChecks := totalChecks - len(violations)
	if passedChecks < 0 {
		passedChecks = 0
	}

	score := 100.0
	if totalChecks > 0 {
		score = math.Round((float64(passedChecks)/float64(totalChecks)*100.0)*10) / 10
	}

	return SPIFFESummary{
		TotalChecks:              totalChecks,
		PassedChecks:             passedChecks,
		ComplianceScore:          score,
		CriticalCount:            critCount,
		HighCount:                highCount,
		MediumCount:              medCount,
		LowCount:                 lowCount,
		SVIDsAudited:             auditedSVIDs,
		SVIDsValid:               validSVIDs,
		SVIDsExpiredOrNearExpiry: expiredSVIDs,
	}
}
