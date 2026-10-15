package attest

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	reNixSystemdBoot = regexp.MustCompile(`boot\.loader\.systemd-boot\.enable\s*=\s*(true|false)`)
	reNixInitrdSysd  = regexp.MustCompile(`boot\.initrd\.systemd\.enable\s*=\s*(true|false)`)
	reNixTPM2Enable  = regexp.MustCompile(`security\.tpm2\.enable\s*=\s*(true|false)`)
	reNixTPMPKCS11   = regexp.MustCompile(`security\.tpm2\.pkcs11\.enable\s*=\s*(true|false)`)
	reNixTrustedKeys = regexp.MustCompile(`nix\.settings\.trusted-public-keys\s*=`)
	reNixKernelParam = regexp.MustCompile(`boot\.kernelParams\s*=\s*\[([^\]]*)\]`)
	reNixLanzaboote  = regexp.MustCompile(`boot\.lanzaboote\.enable\s*=\s*(true|false)`)
	reNixUKIEnable   = regexp.MustCompile(`boot\.loader\.uki\.enable\s*=\s*(true|false)`)
)

// AttestationScanner audits NixOS declarative configurations for confidential computing and measured boot postures.
type AttestationScanner struct {
	feed *intel.Feed
}

// NewAttestationScanner initializes an attestation scanner with an optional threat intelligence feed.
func NewAttestationScanner(feed *intel.Feed) *AttestationScanner {
	return &AttestationScanner{feed: feed}
}

// ScanFile parses a single NixOS configuration file and returns identified attestation vulnerabilities.
func (s *AttestationScanner) ScanFile(filePath string) (*AttestationAuditReport, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", cleanPath, err)
	}

	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum permitted size of %d bytes", cleanPath, MaxManifestBytes)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", cleanPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > MaxScanLines {
			return nil, fmt.Errorf("file %s exceeds maximum line ceiling of %d lines", cleanPath, MaxScanLines)
		}
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error on file %s: %w", cleanPath, err)
	}

	violations, checksTotal, checksPassed := s.evaluateNixLines(lines, cleanPath)

	score := 100.0
	if checksTotal > 0 {
		score = math.Round((float64(checksPassed)/float64(checksTotal))*1000) / 10
	}

	summary := AttestationSummary{
		TotalChecks:     checksTotal,
		PassedChecks:    checksPassed,
		ComplianceScore: score,
		NodesAttested:   1,
		NodesVerified:   0,
	}

	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
		case intel.SeverityHigh:
			summary.HighCount++
		case intel.SeverityMedium:
			summary.MediumCount++
		case intel.SeverityLow:
			summary.LowCount++
		}
	}

	if len(violations) == 0 {
		summary.NodesVerified = 1
	}

	report := &AttestationAuditReport{
		TargetPath: cleanPath,
		TotalFiles: 1,
		TotalNodes: 1,
		Violations: violations,
		Summary:    summary,
		EvaluatedNodes: []string{
			filepath.Base(cleanPath),
		},
	}

	return report, nil
}

// ScanDirectory traverses a directory recursively and compiles an audit report across all .nix configurations.
func (s *AttestationScanner) ScanDirectory(dirPath string) (*AttestationAuditReport, error) {
	cleanDir := filepath.Clean(dirPath)
	info, err := os.Stat(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat directory %s: %w", cleanDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target %s is not a directory", cleanDir)
	}

	aggregateReport := &AttestationAuditReport{
		TargetPath: cleanDir,
		Violations: make([]AttestationViolation, 0),
		Summary: AttestationSummary{
			ComplianceScore: 100.0,
		},
		EvaluatedNodes: make([]string, 0),
	}

	err = filepath.Walk(cleanDir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if f.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(f.Name()), ".nix") {
			return nil
		}

		rep, err := s.ScanFile(path)
		if err != nil {
			return err
		}

		aggregateReport.TotalFiles++
		aggregateReport.TotalNodes++
		aggregateReport.Violations = append(aggregateReport.Violations, rep.Violations...)
		aggregateReport.Summary.TotalChecks += rep.Summary.TotalChecks
		aggregateReport.Summary.PassedChecks += rep.Summary.PassedChecks
		aggregateReport.Summary.CriticalCount += rep.Summary.CriticalCount
		aggregateReport.Summary.HighCount += rep.Summary.HighCount
		aggregateReport.Summary.MediumCount += rep.Summary.MediumCount
		aggregateReport.Summary.LowCount += rep.Summary.LowCount
		aggregateReport.Summary.NodesAttested += rep.Summary.NodesAttested
		aggregateReport.Summary.NodesVerified += rep.Summary.NodesVerified
		aggregateReport.EvaluatedNodes = append(aggregateReport.EvaluatedNodes, rep.EvaluatedNodes...)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", cleanDir, err)
	}

	if aggregateReport.Summary.TotalChecks > 0 {
		aggregateReport.Summary.ComplianceScore = math.Round(
			(float64(aggregateReport.Summary.PassedChecks)/float64(aggregateReport.Summary.TotalChecks))*1000,
		) / 10
	}

	return aggregateReport, nil
}

// evaluateNixLines parses the file content lines and audits against canonical attestation rules.
func (s *AttestationScanner) evaluateNixLines(lines []string, filePath string) ([]AttestationViolation, int, int) {
	var violations []AttestationViolation
	checksTotal := 0
	checksPassed := 0

	content := strings.Join(lines, "\n")
	hasAmdHardware := strings.Contains(content, "kvm_amd") || strings.Contains(content, "sev") || strings.Contains(content, "amd")
	hasIntelHardware := strings.Contains(content, "kvm_intel") || strings.Contains(content, "tdx") || strings.Contains(content, "intel")

	// 1. AMD SEV-SNP check
	if hasAmdHardware {
		checksTotal++
		sevFound := false
		for i, line := range lines {
			if strings.Contains(line, "kvm_amd.sev=1") || (strings.Contains(line, "mem_encrypt=on") && strings.Contains(line, "kvm_amd")) {
				sevFound = true
				break
			}
			if strings.Contains(line, "kvm_amd.sev=0") {
				rule := GetAttestationRule("ATTEST-BOOT-001")
				violations = append(violations, s.newViolation(rule, filePath, i+1, "AMD SEV-SNP explicitly disabled in kernel arguments (kvm_amd.sev=0)"))
				break
			}
		}
		if sevFound {
			checksPassed++
		} else if !strings.Contains(content, "kvm_amd.sev=0") {
			rule := GetAttestationRule("ATTEST-BOOT-001")
			violations = append(violations, s.newViolation(rule, filePath, 1, "AMD SEV-SNP memory encryption kernel parameters (mem_encrypt=on kvm_amd.sev=1) missing in host configuration"))
		}
	}

	// 2. Intel TDX check
	if hasIntelHardware {
		checksTotal++
		tdxFound := false
		for i, line := range lines {
			if strings.Contains(line, "kvm_intel.tdx=1") || (strings.Contains(line, "intel_iommu=on") && strings.Contains(line, "tdx")) {
				tdxFound = true
				break
			}
			if strings.Contains(line, "kvm_intel.tdx=0") {
				rule := GetAttestationRule("ATTEST-BOOT-002")
				violations = append(violations, s.newViolation(rule, filePath, i+1, "Intel TDX explicitly disabled in kernel arguments (kvm_intel.tdx=0)"))
				break
			}
		}
		if tdxFound {
			checksPassed++
		} else if !strings.Contains(content, "kvm_intel.tdx=0") {
			rule := GetAttestationRule("ATTEST-BOOT-002")
			violations = append(violations, s.newViolation(rule, filePath, 1, "Intel TDX Trust Domain execution parameters (intel_iommu=on kvm_intel.tdx=1) missing in host configuration"))
		}
	}

	// 3. Systemd-boot & Measured Bootloader
	checksTotal++
	mBoot := reNixSystemdBoot.FindStringSubmatch(content)
	mInitrd := reNixInitrdSysd.FindStringSubmatch(content)
	if (len(mBoot) > 1 && mBoot[1] == "true") && (len(mInitrd) > 1 && mInitrd[1] == "true") {
		checksPassed++
	} else {
		lineNum := 1
		for i, line := range lines {
			if strings.Contains(line, "boot.loader") {
				lineNum = i + 1
				break
			}
		}
		rule := GetAttestationRule("ATTEST-BOOT-007")
		violations = append(violations, s.newViolation(rule, filePath, lineNum, "NixOS bootloader missing systemd-boot and systemd in initrd for measured boot chain"))
	}

	// 4. TPM 2.0 and PKCS#11 configuration
	checksTotal++
	mTpm := reNixTPM2Enable.FindStringSubmatch(content)
	hasTPM := (len(mTpm) > 1 && mTpm[1] == "true") || (strings.Contains(content, "security.tpm2") && strings.Contains(content, "enable = true"))
	if hasTPM {
		checksPassed++
	} else {
		lineNum := 1
		for i, line := range lines {
			if strings.Contains(line, "security.tpm2") {
				lineNum = i + 1
				break
			}
		}
		rule := GetAttestationRule("ATTEST-BOOT-009")
		violations = append(violations, s.newViolation(rule, filePath, lineNum, "NixOS security.tpm2 is not enabled; bare-metal hardware root-of-trust is unmanaged"))
	}

	// 5. Nix Store Path Signatures / UKI
	checksTotal++
	hasTrustedKeys := reNixTrustedKeys.MatchString(content)
	hasLanzaboote := strings.Contains(content, "lanzaboote") || reNixLanzaboote.MatchString(content) || reNixUKIEnable.MatchString(content)
	if hasTrustedKeys && hasLanzaboote {
		checksPassed++
	} else {
		rule := GetAttestationRule("ATTEST-BOOT-006")
		lineNum := 1
		if !hasTrustedKeys {
			violations = append(violations, s.newViolation(rule, filePath, lineNum, "NixOS configuration lacks nix.settings.trusted-public-keys cryptographic signature verification"))
		} else {
			ruleUKI := GetAttestationRule("ATTEST-BOOT-004")
			violations = append(violations, s.newViolation(ruleUKI, filePath, lineNum, "NixOS configuration lacks declarative Lanzaboote / UKI measured boot closure integration"))
		}
	}

	// 6. Unsanitized or insecure kernel parameters (nokaslr, single, init=/bin/sh)
	checksTotal++
	dangerousKernelParamFound := false
	inKernelParams := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "boot.kernelParams") {
			inKernelParams = true
		}
		if inKernelParams {
			if strings.Contains(trimmed, "nokaslr") || strings.Contains(trimmed, "init=/bin/sh") || strings.Contains(trimmed, "single") {
				dangerousKernelParamFound = true
				rule := GetAttestationRule("ATTEST-BOOT-010")
				violations = append(violations, s.newViolation(rule, filePath, i+1, "Dangerous debug kernel command-line argument detected compromising measured boot immutability"))
				break
			}
			if strings.Contains(trimmed, "]") && !strings.Contains(trimmed, "boot.kernelParams") {
				inKernelParams = false
			} else if strings.Contains(trimmed, "];") {
				inKernelParams = false
			}
		}
	}
	if !dangerousKernelParamFound {
		checksPassed++
	}

	return violations, checksTotal, checksPassed
}

func (s *AttestationScanner) newViolation(rule AttestationRule, filePath string, line int, message string) AttestationViolation {
	matchedCVE := ""
	if s.feed != nil {
		for _, item := range s.feed.Items {
			if strings.EqualFold(item.Component, "amd-sev") || strings.EqualFold(item.Component, "intel-tdx") || strings.EqualFold(item.Component, "tpm2") {
				matchedCVE = item.ID
				break
			}
		}
	}

	return AttestationViolation{
		RuleID:       rule.ID,
		Title:        rule.Title,
		Severity:     rule.Severity,
		CVSSScore:    rule.CVSSScore,
		Category:     rule.Category,
		Target:       filepath.Base(filePath),
		Technology:   rule.Technology,
		FilePath:     filePath,
		StartLine:    line,
		Message:      message,
		Remediation:  rule.Remediation,
		MatchedCVE:   matchedCVE,
	}
}
