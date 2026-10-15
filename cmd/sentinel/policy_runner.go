package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/policy"
)

// runPolicySynthesis generates Falco and OPA Gatekeeper security policies from discovered vulnerabilities.
func runPolicySynthesis(policyOut, policyEngine, enforceAction string, feed *intel.Feed, k8sReport *k8s.ManifestAuditReport, logInfo func(string, ...any), logErr func(string, ...any)) {
	if policyOut == "" {
		return
	}

	logInfo("[+] Synthesizing Declarative Security Policies (Engine: %s, Action: %s)...\n", policyEngine, enforceAction)
	var violations []k8s.Violation
	if k8sReport != nil {
		violations = k8sReport.Violations
	}

	policyOpts := policy.DefaultSynthesisOptions()
	policyOpts.EnforcementAction = enforceAction
	policyOpts.TargetEngines = []string{policyEngine}

	policySet, err := policy.SynthesizePolicies(feed, violations, policyOpts)
	if err != nil {
		logErr("[-] Failed to synthesize security policies: %v\n", err)
		os.Exit(1)
	}

	written, err := policy.WritePoliciesToDir(policySet, policyOut)
	if err != nil {
		logErr("[-] Failed to write security policies: %v\n", err)
		os.Exit(1)
	}

	logInfo("[+] Policy Synthesis Complete (Total: %d Falco Rules, %d Gatekeeper Templates, %d Constraints)\n",
		policySet.TotalFalcoRules, policySet.TotalOPAConstraintTemplates, policySet.TotalOPAConstraints)
	for engine, p := range written {
		logInfo("    -> [%s] Policy Exported: %s\n", engine, p)
	}
}
