package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

// SynthesizePolicies orchestrates multi-engine declarative policy compilation.
func SynthesizePolicies(feed *intel.Feed, violations []k8s.Violation, opts SynthesisOptions) (*SyntheticPolicySet, error) {
	if len(opts.TargetEngines) == 0 {
		opts.TargetEngines = []string{EngineAll}
	}
	if opts.EnforcementAction == "" {
		opts.EnforcementAction = EnforceDeny
	}

	buildFalco := containsEngine(opts.TargetEngines, EngineFalco) || containsEngine(opts.TargetEngines, EngineAll)
	buildGatekeeper := containsEngine(opts.TargetEngines, EngineGatekeeper) || containsEngine(opts.TargetEngines, "opa") || containsEngine(opts.TargetEngines, EngineAll)

	set := &SyntheticPolicySet{
		GeneratedAt: time.Now().UTC(),
	}

	if buildFalco {
		rules := BuildFalcoRuleSet(feed, violations, opts.CustomTags)
		// Apply rule exclusion filter if specified
		var filteredRules []FalcoRule
		for _, r := range rules {
			if !isRuleExcluded(r.Rule, opts.ExcludedRuleIDs) {
				filteredRules = append(filteredRules, r)
			}
		}
		set.FalcoRules = filteredRules
		set.TotalFalcoRules = len(filteredRules)
	}

	if buildGatekeeper {
		templates, constraints := SynthesizeGatekeeperPolicies(feed, violations, opts)
		set.GatekeeperTemplates = templates
		set.GatekeeperConstraints = constraints
		set.TotalOPAConstraintTemplates = len(templates)
		set.TotalOPAConstraints = len(constraints)
	}

	return set, nil
}

// ToFalcoYAML serializes the Falco rules within the policy set into YAML format.
func (s *SyntheticPolicySet) ToFalcoYAML(includeComments bool) string {
	return FormatFalcoYAML(s.FalcoRules, includeComments)
}

// ToGatekeeperYAML serializes the Gatekeeper templates and constraints into YAML format.
func (s *SyntheticPolicySet) ToGatekeeperYAML(includeComments bool) string {
	return FormatGatekeeperYAML(s.GatekeeperTemplates, s.GatekeeperConstraints, includeComments)
}

// WritePoliciesToDir safely persists compiled policy files into the target directory.
func WritePoliciesToDir(set *SyntheticPolicySet, outputDir string) (map[string]string, error) {
	if set == nil {
		return nil, fmt.Errorf("cannot write nil policy set")
	}

	cleanDir := filepath.Clean(outputDir)
	if err := os.MkdirAll(cleanDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create policy output directory (%s): %w", cleanDir, err)
	}

	written := make(map[string]string)

	if len(set.FalcoRules) > 0 {
		falcoPath := filepath.Join(cleanDir, "falco-sentinel-rules.yaml")
		falcoContent := set.ToFalcoYAML(true)
		if err := os.WriteFile(falcoPath, []byte(falcoContent), 0644); err != nil {
			return nil, fmt.Errorf("failed to write falco rules to %s: %w", falcoPath, err)
		}
		written[EngineFalco] = falcoPath
	}

	if len(set.GatekeeperTemplates) > 0 || len(set.GatekeeperConstraints) > 0 {
		opaPath := filepath.Join(cleanDir, "opa-gatekeeper-constraints.yaml")
		opaContent := set.ToGatekeeperYAML(true)
		if err := os.WriteFile(opaPath, []byte(opaContent), 0644); err != nil {
			return nil, fmt.Errorf("failed to write gatekeeper constraints to %s: %w", opaPath, err)
		}
		written[EngineGatekeeper] = opaPath
	}

	return written, nil
}

func containsEngine(engines []string, target string) bool {
	for _, e := range engines {
		if strings.EqualFold(e, target) {
			return true
		}
	}
	return false
}
