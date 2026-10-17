package remediate

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// RemediationScanner coordinates scanning manifests, identifying remediable flaws, synthesizing patches, and running canary tests.
type RemediationScanner struct {
	Feed      *intel.Feed
	Validator *CanaryValidator
}

// NewRemediationScanner constructs an initialized RemediationScanner.
func NewRemediationScanner(feed *intel.Feed) *RemediationScanner {
	return &RemediationScanner{
		Feed:      feed,
		Validator: NewCanaryValidator(true),
	}
}

// ScanManifestPath audits a target file or directory for declarative remediation opportunities.
func (rs *RemediationScanner) ScanManifestPath(targetPath string) (*RemediationAuditReport, error) {
	cleanPath := filepath.Clean(targetPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat target path (%s): %w", cleanPath, err)
	}

	var findings []RemediationFinding
	var nixPatches []NixOSPatch
	var k8sPatches []KustomizePatch

	if info.IsDir() {
		err = filepath.Walk(cleanPath, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil || fi.IsDir() {
				return walkErr
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".nix" || ext == ".yaml" || ext == ".yml" {
				f, np, kp, scanErr := rs.scanFile(path)
				if scanErr != nil {
					return scanErr
				}
				findings = append(findings, f...)
				nixPatches = append(nixPatches, np...)
				k8sPatches = append(k8sPatches, kp...)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		f, np, kp, scanErr := rs.scanFile(cleanPath)
		if scanErr != nil {
			return nil, scanErr
		}
		findings = append(findings, f...)
		nixPatches = append(nixPatches, np...)
		k8sPatches = append(k8sPatches, kp...)
	}

	// Bundle into a synthesized GitOps pull request
	var prs []GitOpsPullRequest
	if len(nixPatches) > 0 || len(k8sPatches) > 0 {
		pr := SynthesizeGitOpsPR(
			"fix(security): automated declarative hardening for detected vulnerabilities",
			fmt.Sprintf("remediation/hardening-%d", time.Now().Unix()),
			"main",
			nixPatches,
			k8sPatches,
			rs.Validator,
		)
		prs = append(prs, *pr)
	}

	summary := rs.ComputeRemediationSummary(findings, prs)

	return &RemediationAuditReport{
		Findings:     findings,
		PullRequests: prs,
		Summary:      summary,
		GeneratedAt:  time.Now().UTC(),
	}, nil
}

// scanFile scans a single declarative manifest file and synthesizes patches.
func (rs *RemediationScanner) scanFile(filePath string) ([]RemediationFinding, []NixOSPatch, []KustomizePatch, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	var findings []RemediationFinding
	var nixPatches []NixOSPatch
	var k8sPatches []KustomizePatch

	scanner := bufio.NewScanner(file)
	lineCount := 0
	var lines []string

	for scanner.Scan() {
		lineCount++
		if lineCount > MaxAllowedScanLines {
			break
		}
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, err
	}

	fullText := strings.Join(lines, "\n")
	ext := strings.ToLower(filepath.Ext(filePath))
	baseName := filepath.Base(filePath)

	if ext == ".nix" {
		// Rule 001: Flake input lock / pure evaluation
		if strings.Contains(fullText, "inputs.nixpkgs.url") && !strings.Contains(fullText, "narHash") {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-001")
			np := SynthesizeNixOSPatch(rule, baseName, "inputs.nixpkgs.inputs.nixpkgs.follows", "\"\"", "\"nixpkgs\"", "inputs.nixpkgs.locked.narHash = \"sha256-pinned...\"")
			canary := rs.Validator.ValidateNixOSPatch(&np)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "nixos",
				ResourceKind:     "NixModule",
				ResourceName:     baseName,
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: np.DiffContent,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			nixPatches = append(nixPatches, np)
		}

		// Rule 006: Plaintext WireGuard key
		if strings.Contains(fullText, "privateKey =") && !strings.Contains(fullText, "privateKeyFile") {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-006")
			np := SynthesizeNixOSPatch(rule, baseName, "networking.wireguard.interfaces.wg0.privateKeyFile", "\"/nix/store/...\"", "\"/run/secrets/wireguard/key\"", "")
			canary := rs.Validator.ValidateNixOSPatch(&np)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "nixos",
				ResourceKind:     "NixOSWireGuard",
				ResourceName:     baseName,
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: np.DiffContent,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			nixPatches = append(nixPatches, np)
		}

		// Rule 005: Ceph requireMsgr2
		if strings.Contains(fullText, "services.ceph") && !strings.Contains(fullText, "requireMsgr2 = true") {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-005")
			np := SynthesizeNixOSPatch(rule, baseName, "services.ceph.requireMsgr2", "false", "true", "")
			canary := rs.Validator.ValidateNixOSPatch(&np)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "nixos",
				ResourceKind:     "NixOSCeph",
				ResourceName:     baseName,
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: np.DiffContent,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			nixPatches = append(nixPatches, np)
		}

		// Rule 012: MicroVM jailer
		if strings.Contains(fullText, "microvm.vms") && (strings.Contains(fullText, "jailer.enable = false") || !strings.Contains(fullText, "jailer.enable")) {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-012")
			np := SynthesizeNixOSPatch(rule, baseName, "microvm.vms.detonation.jailer.enable", "false", "true", "")
			canary := rs.Validator.ValidateNixOSPatch(&np)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "nixos",
				ResourceKind:     "NixOSMicroVM",
				ResourceName:     baseName,
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: np.DiffContent,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			nixPatches = append(nixPatches, np)
		}
	} else if ext == ".yaml" || ext == ".yml" {
		// Rule 002: Insecure Container SecurityContext
		if strings.Contains(fullText, "kind: Deployment") || strings.Contains(fullText, "kind: Pod") {
			if !strings.Contains(fullText, "runAsNonRoot: true") || strings.Contains(fullText, "privileged: true") {
				rule, _ := GetRuleByID("REMEDIATE-AUTO-002")
				patchBody := "spec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n      containers:\n        - name: app\n          securityContext:\n            readOnlyRootFilesystem: true\n            capabilities:\n              drop:\n                - ALL\n"
				kp := SynthesizeKustomizeStrategicMerge(rule, "apps/v1", "Deployment", "workload", "default", patchBody)
				canary := rs.Validator.ValidateKustomizePatch(&kp)
				findings = append(findings, RemediationFinding{
					RuleID:           rule.ID,
					Target:           "kubernetes",
					ResourceKind:     "Deployment",
					ResourceName:     "workload",
					Namespace:        "default",
					Severity:         string(rule.Severity),
					CVSSScore:        rule.CVSSScore,
					Title:            rule.Title,
					Description:      rule.Description,
					Remediation:      rule.SuggestedRemediation,
					MatchedCVE:       rule.MatchedCVE,
					SynthesizedPatch: kp.PatchYAML,
					CanaryStatus:     canary.Status,
					SourceFile:       filePath,
					LineNumber:       1,
				})
				k8sPatches = append(k8sPatches, kp)
			}
		}

		// Rule 003: Ingress custom snippet injection
		if strings.Contains(fullText, "kind: Ingress") && strings.Contains(fullText, "configuration-snippet") {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-003")
			kp := SynthesizeKustomizeJSONPatch(rule, "networking.k8s.io/v1", "Ingress", "ingress-route", "default", "remove", "/metadata/annotations/nginx.ingress.kubernetes.io~1configuration-snippet", "")
			canary := rs.Validator.ValidateKustomizePatch(&kp)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "kubernetes",
				ResourceKind:     "Ingress",
				ResourceName:     "ingress-route",
				Namespace:        "default",
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: kp.PatchYAML,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			k8sPatches = append(k8sPatches, kp)
		}

		// Rule 010: Unconfined seccomp profile
		if strings.Contains(fullText, "seccompProfile") && strings.Contains(fullText, "type: Unconfined") {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-010")
			patchBody := "spec:\n  template:\n    spec:\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n"
			kp := SynthesizeKustomizeStrategicMerge(rule, "apps/v1", "Deployment", "bpf-workload", "default", patchBody)
			canary := rs.Validator.ValidateKustomizePatch(&kp)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "kubernetes",
				ResourceKind:     "Deployment",
				ResourceName:     "bpf-workload",
				Namespace:        "default",
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: kp.PatchYAML,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			k8sPatches = append(k8sPatches, kp)
		}

		// Rule 011: Classical TLS 1.2
		if strings.Contains(fullText, "tls-min-version") && (strings.Contains(fullText, "VersionTLS10") || strings.Contains(fullText, "VersionTLS12")) {
			rule, _ := GetRuleByID("REMEDIATE-AUTO-011")
			patchBody := "spec:\n  containers:\n    - name: kube-apiserver\n      command:\n        - --tls-min-version=VersionTLS13\n        - --tls-cipher-suites=TLS_AES_256_GCM_SHA384\n"
			kp := SynthesizeKustomizeStrategicMerge(rule, "v1", "Pod", "kube-apiserver", "kube-system", patchBody)
			canary := rs.Validator.ValidateKustomizePatch(&kp)
			findings = append(findings, RemediationFinding{
				RuleID:           rule.ID,
				Target:           "kubernetes",
				ResourceKind:     "Pod",
				ResourceName:     "kube-apiserver",
				Namespace:        "kube-system",
				Severity:         string(rule.Severity),
				CVSSScore:        rule.CVSSScore,
				Title:            rule.Title,
				Description:      rule.Description,
				Remediation:      rule.SuggestedRemediation,
				MatchedCVE:       rule.MatchedCVE,
				SynthesizedPatch: kp.PatchYAML,
				CanaryStatus:     canary.Status,
				SourceFile:       filePath,
				LineNumber:       1,
			})
			k8sPatches = append(k8sPatches, kp)
		}
	}

	return findings, nixPatches, k8sPatches, nil
}

// ComputeRemediationSummary tallies remediation and canary statistics.
func (rs *RemediationScanner) ComputeRemediationSummary(findings []RemediationFinding, prs []GitOpsPullRequest) RemediationSummary {
	sum := RemediationSummary{
		TotalFindings:           len(findings),
		PullRequestsSynthesized: len(prs),
		Status:                  "PASSED",
	}

	for _, f := range findings {
		if f.Target == "nixos" {
			sum.NixOSPatchCount++
		} else {
			sum.KustomizePatchCount++
		}
	}

	for _, pr := range prs {
		for _, c := range pr.CanaryResults {
			sum.CanaryChecksTotal++
			if c.Status == CanaryPassed {
				sum.CanaryPassedCount++
			} else if c.Status == CanaryFailed {
				sum.CanaryFailedCount++
			}
		}
	}

	// Score calculation: 100 base, penalize failed canaries heavily (-20 each), unremediated findings (-5 each)
	score := 100.0
	if sum.CanaryFailedCount > 0 {
		score -= float64(sum.CanaryFailedCount) * 20.0
	}
	if sum.TotalFindings > (sum.NixOSPatchCount + sum.KustomizePatchCount) {
		unremediated := sum.TotalFindings - (sum.NixOSPatchCount + sum.KustomizePatchCount)
		score -= float64(unremediated) * 5.0
	}

	sum.RemediationScore = math.Max(0.0, math.Min(100.0, score))

	if sum.CanaryFailedCount > 0 || sum.RemediationScore < 60.0 {
		sum.Status = "FAILED"
	} else if sum.RemediationScore < 85.0 {
		sum.Status = "DEGRADED"
	}

	return sum
}
