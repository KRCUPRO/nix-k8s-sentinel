package remediate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SynthesizeNixOSPatch generates a declarative NixOS module diff and flake override.
func SynthesizeNixOSPatch(rule RemediationRule, targetModule, optionKey, oldValue, newValue, flakeOverride string) NixOSPatch {
	cleanModule := targetModule
	if cleanModule == "" {
		cleanModule = "configuration.nix"
	}

	diffBuilder := strings.Builder{}
	diffBuilder.WriteString(fmt.Sprintf("--- a/%s\n", cleanModule))
	diffBuilder.WriteString(fmt.Sprintf("+++ b/%s\n", cleanModule))
	diffBuilder.WriteString("@@ -1,3 +1,3 @@\n")
	diffBuilder.WriteString(" {\n")
	if oldValue != "" {
		diffBuilder.WriteString(fmt.Sprintf("-   %s = %s;\n", optionKey, oldValue))
	}
	diffBuilder.WriteString(fmt.Sprintf("+   %s = %s;\n", optionKey, newValue))
	diffBuilder.WriteString(" }\n")

	desc := rule.SuggestedRemediation
	if desc == "" {
		desc = fmt.Sprintf("Hardened %s to %s", optionKey, newValue)
	}

	return NixOSPatch{
		TargetModule:  cleanModule,
		OptionPath:    optionKey,
		OldValue:      oldValue,
		NewValue:      newValue,
		FlakeOverride: flakeOverride,
		DiffContent:   diffBuilder.String(),
		MitigatedCVE:  rule.MatchedCVE,
		Description:   desc,
	}
}

// SynthesizeKustomizeStrategicMerge generates a Kubernetes strategic merge patch.
func SynthesizeKustomizeStrategicMerge(rule RemediationRule, apiVersion, kind, name, namespace, patchBody string) KustomizePatch {
	yamlBuilder := strings.Builder{}
	yamlBuilder.WriteString(fmt.Sprintf("apiVersion: %s\n", apiVersion))
	yamlBuilder.WriteString(fmt.Sprintf("kind: %s\n", kind))
	yamlBuilder.WriteString("metadata:\n")
	yamlBuilder.WriteString(fmt.Sprintf("  name: %s\n", name))
	if namespace != "" {
		yamlBuilder.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	}

	// Indent patch body cleanly under resource root
	for _, line := range strings.Split(patchBody, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		yamlBuilder.WriteString(line + "\n")
	}

	targetRes := fmt.Sprintf("%s/%s", strings.ToLower(kind), name)
	if namespace != "" {
		targetRes = fmt.Sprintf("%s/%s/%s", namespace, strings.ToLower(kind), name)
	}

	desc := rule.SuggestedRemediation
	if desc == "" {
		desc = fmt.Sprintf("Applied strategic merge patch to %s", targetRes)
	}

	return KustomizePatch{
		TargetResource: targetRes,
		APIVersion:     apiVersion,
		Kind:           kind,
		Name:           name,
		Namespace:      namespace,
		PatchType:      "strategic-merge",
		PatchYAML:      yamlBuilder.String(),
		TargetFile:     fmt.Sprintf("patch-%s.yaml", strings.ToLower(name)),
		MitigatedCVE:   rule.MatchedCVE,
		Description:    desc,
	}
}

// SynthesizeKustomizeJSONPatch generates a RFC 6902 JSONPatch for Kubernetes manifests.
func SynthesizeKustomizeJSONPatch(rule RemediationRule, apiVersion, kind, name, namespace, op, path, value string) KustomizePatch {
	yamlBuilder := strings.Builder{}
	yamlBuilder.WriteString(fmt.Sprintf("- op: %s\n", op))
	yamlBuilder.WriteString(fmt.Sprintf("  path: %s\n", path))
	if value != "" {
		if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
			yamlBuilder.WriteString(fmt.Sprintf("  value: %s\n", value))
		} else {
			yamlBuilder.WriteString(fmt.Sprintf("  value: \"%s\"\n", value))
		}
	}

	targetRes := fmt.Sprintf("%s/%s", strings.ToLower(kind), name)
	if namespace != "" {
		targetRes = fmt.Sprintf("%s/%s/%s", namespace, strings.ToLower(kind), name)
	}

	return KustomizePatch{
		TargetResource: targetRes,
		APIVersion:     apiVersion,
		Kind:           kind,
		Name:           name,
		Namespace:      namespace,
		PatchType:      "json6902",
		PatchYAML:      yamlBuilder.String(),
		TargetFile:     fmt.Sprintf("jsonpatch-%s.yaml", strings.ToLower(name)),
		MitigatedCVE:   rule.MatchedCVE,
		Description:    rule.SuggestedRemediation,
	}
}

// FormatKustomizationFile generates a declarative kustomization.yaml file containing all patches.
func FormatKustomizationFile(patches []KustomizePatch) string {
	b := strings.Builder{}
	b.WriteString("apiVersion: kustomize.config.k8s.io/v1beta1\n")
	b.WriteString("kind: Kustomization\n\n")
	b.WriteString("resources:\n")
	b.WriteString("  - ../base\n\n")

	if len(patches) > 0 {
		b.WriteString("patches:\n")
		for _, p := range patches {
			b.WriteString(fmt.Sprintf("  - path: %s\n", p.TargetFile))
			b.WriteString("    target:\n")
			b.WriteString(fmt.Sprintf("      group: %s\n", strings.Split(p.APIVersion, "/")[0]))
			b.WriteString(fmt.Sprintf("      version: %s\n", strings.Split(p.APIVersion, "/")[len(strings.Split(p.APIVersion, "/"))-1]))
			b.WriteString(fmt.Sprintf("      kind: %s\n", p.Kind))
			b.WriteString(fmt.Sprintf("      name: %s\n", p.Name))
			if p.Namespace != "" {
				b.WriteString(fmt.Sprintf("      namespace: %s\n", p.Namespace))
			}
		}
	}

	return b.String()
}

// SynthesizeGitOpsPR bundles patches into a GitOps pull request with summary and canary tests.
func SynthesizeGitOpsPR(title, headBranch, baseBranch string, nixPatches []NixOSPatch, k8sPatches []KustomizePatch, validator *CanaryValidator) *GitOpsPullRequest {
	if title == "" {
		title = "fix(security): declarative infrastructure threat mitigations"
	}
	if headBranch == "" {
		headBranch = fmt.Sprintf("remediation/hardening-%d", time.Now().Unix())
	}
	if baseBranch == "" {
		baseBranch = "main"
	}

	pr := &GitOpsPullRequest{
		PRNumber:      101, // Mock PR sequence
		Title:         title,
		HeadBranch:    headBranch,
		BaseBranch:    baseBranch,
		CommitMessage: fmt.Sprintf("%s\n\nAutomated declarative hardening against discovered CVE findings.", title),
		NixPatches:    nixPatches,
		K8sPatches:    k8sPatches,
		CreatedAt:     time.Now().UTC(),
	}

	// Build summary
	summaryBuilder := strings.Builder{}
	summaryBuilder.WriteString(fmt.Sprintf("## 🛡️ Autonomous Security Remediation Pull Request\n\n"))
	summaryBuilder.WriteString(fmt.Sprintf("**Target Base:** `%s` | **Head Branch:** `%s`\n\n", baseBranch, headBranch))
	summaryBuilder.WriteString("### Summary of Declarative Patches:\n\n")

	if len(nixPatches) > 0 {
		summaryBuilder.WriteString(fmt.Sprintf("#### NixOS System Patches (%d)\n\n", len(nixPatches)))
		summaryBuilder.WriteString("| Target Module | Option Path | Mitigated CVE | Description |\n")
		summaryBuilder.WriteString("| :--- | :--- | :---: | :--- |\n")
		for _, np := range nixPatches {
			cve := np.MitigatedCVE
			if cve == "" {
				cve = "N/A"
			}
			summaryBuilder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n", np.TargetModule, np.OptionPath, cve, np.Description))
		}
		summaryBuilder.WriteString("\n")
	}

	if len(k8sPatches) > 0 {
		summaryBuilder.WriteString(fmt.Sprintf("#### Kubernetes Kustomize Overlays (%d)\n\n", len(k8sPatches)))
		summaryBuilder.WriteString("| Target Resource | Patch Type | Mitigated CVE | Description |\n")
		summaryBuilder.WriteString("| :--- | :---: | :---: | :--- |\n")
		for _, kp := range k8sPatches {
			cve := kp.MitigatedCVE
			if cve == "" {
				cve = "N/A"
			}
			summaryBuilder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n", kp.TargetResource, kp.PatchType, cve, kp.Description))
		}
		summaryBuilder.WriteString("\n")
	}

	pr.Summary = summaryBuilder.String()

	// Execute pre-flight canary validation
	if validator != nil {
		validator.ValidateGitOpsPR(pr)
	}

	return pr
}

// WriteRemediationArtifacts exports synthesized patches and PR summary to an output directory.
func WriteRemediationArtifacts(outDir string, pr *GitOpsPullRequest) (map[string]string, error) {
	if pr == nil {
		return nil, fmt.Errorf("pull request cannot be nil")
	}

	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create remediation directory (%s): %w", cleanDir, err)
	}

	written := make(map[string]string)

	// 1. Write NixOS patches if present
	if len(pr.NixPatches) > 0 {
		nixPath := filepath.Join(cleanDir, "remediation-patches.nix")
		b := strings.Builder{}
		b.WriteString("# Autonomous NixOS Security Remediation Module\n")
		b.WriteString("{ config, lib, pkgs, ... }:\n{\n")
		for _, np := range pr.NixPatches {
			b.WriteString(fmt.Sprintf("  # Mitigates %s: %s\n", np.MitigatedCVE, np.Description))
			b.WriteString(fmt.Sprintf("  %s = %s;\n\n", np.OptionPath, np.NewValue))
		}
		b.WriteString("}\n")
		if err := os.WriteFile(nixPath, []byte(b.String()), 0644); err != nil {
			return nil, err
		}
		written["nixos-remediation"] = nixPath
	}

	// 2. Write Kustomize patches and kustomization.yaml if present
	if len(pr.K8sPatches) > 0 {
		for _, kp := range pr.K8sPatches {
			pPath := filepath.Join(cleanDir, kp.TargetFile)
			if err := os.WriteFile(pPath, []byte(kp.PatchYAML), 0644); err != nil {
				return nil, err
			}
			written[kp.TargetFile] = pPath
		}

		kustPath := filepath.Join(cleanDir, "kustomization.yaml")
		kustContent := FormatKustomizationFile(pr.K8sPatches)
		if err := os.WriteFile(kustPath, []byte(kustContent), 0644); err != nil {
			return nil, err
		}
		written["kustomization"] = kustPath
	}

	// 3. Write PR summary markdown
	summaryPath := filepath.Join(cleanDir, "PR_SUMMARY.md")
	if err := os.WriteFile(summaryPath, []byte(pr.Summary), 0644); err != nil {
		return nil, err
	}
	written["pr-summary"] = summaryPath

	return written, nil
}
