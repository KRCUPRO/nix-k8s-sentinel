package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/remediate"
)

// runRemediationAudit coordinates Autonomous Threat Remediation and GitOps PR synthesis.
func runRemediationAudit(manifestPath, synthOut string, canaryStrict bool, feed *intel.Feed, logInfo func(string, ...any), logErr func(string, ...any)) ([]remediate.RemediationFinding, []remediate.GitOpsPullRequest, *remediate.RemediationSummary) {
	if manifestPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	scanner := remediate.NewRemediationScanner(feed)
	scanner.Validator.StrictMode = canaryStrict

	var allFindings []remediate.RemediationFinding
	var allPRs []remediate.GitOpsPullRequest

	// 1. Declarative Manifest Audit & Automated Patch Synthesis
	if manifestPath != "" {
		logInfo("[+] Auditing Declarative Manifests for Autonomous Remediation: %s\n", manifestPath)
		rep, err := scanner.ScanManifestPath(manifestPath)
		if err != nil {
			logErr("[-] Failed to audit manifests at %s: %v\n", manifestPath, err)
			os.Exit(1)
		}

		allFindings = append(allFindings, rep.Findings...)
		allPRs = append(allPRs, rep.PullRequests...)

		logInfo("[+] Evaluated declarative manifests: %d remediable findings identified across NixOS & Kubernetes\n", len(rep.Findings))

		for i, f := range rep.Findings {
			cveSuffix := ""
			if f.MatchedCVE != "" {
				cveSuffix = " [" + f.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f, Canary: %s)\n",
				i+1, f.RuleID, f.Title, cveSuffix, f.Description, f.Severity, f.CVSSScore, f.CanaryStatus)
		}

		for j, pr := range rep.PullRequests {
			canaryState := "PASSED"
			if !pr.CanaryPassed {
				canaryState = "FAILED"
			}
			logInfo("[+] Synthesized GitOps PR #%d [%s]: '%s' (%d patches, Canary: %s)\n",
				j+1, pr.HeadBranch, pr.Title, len(pr.NixPatches)+len(pr.K8sPatches), canaryState)
		}
	}

	// 2. Export Synthesized Patches & GitOps PR Artifacts to Disk
	if synthOut != "" && len(allPRs) > 0 {
		logInfo("[+] Writing Synthesized Remediation Artifacts into: %s\n", synthOut)
		written, err := remediate.WriteRemediationArtifacts(synthOut, &allPRs[0])
		if err != nil {
			logErr("[-] Failed to write remediation artifacts: %v\n", err)
			os.Exit(1)
		}
		for key, path := range written {
			logInfo("  -> Generated %s: %s\n", key, path)
		}
	}

	summary := scanner.ComputeRemediationSummary(allFindings, allPRs)
	logInfo("[+] Remediation Audit Complete: Score %.1f%% (Status: %s) | %d NixOS Patches, %d Kustomize Overlays | Canary: %d Passed, %d Failed\n",
		summary.RemediationScore, summary.Status, summary.NixOSPatchCount, summary.KustomizePatchCount, summary.CanaryPassedCount, summary.CanaryFailedCount)

	return allFindings, allPRs, &summary
}
