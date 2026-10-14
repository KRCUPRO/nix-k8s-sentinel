package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

// ConstraintTemplate represents an OPA Gatekeeper v1beta1 ConstraintTemplate CRD.
type ConstraintTemplate struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   PolicyMetadata         `json:"metadata"`
	Spec       ConstraintTemplateSpec `json:"spec"`
}

// ConstraintTemplateSpec holds the CRD definition and Rego target implementation.
type ConstraintTemplateSpec struct {
	CRD     CRDSpec          `json:"crd"`
	Targets []TemplateTarget `json:"targets"`
}

// CRDSpec defines the metadata and OpenAPI schema for the generated constraint.
type CRDSpec struct {
	Names CRDNames `json:"names"`
}

// CRDNames holds the Kind name of the synthesized constraint.
type CRDNames struct {
	Kind string `json:"kind"`
}

// TemplateTarget maps admission targets to their respective Rego policies.
type TemplateTarget struct {
	Target string `json:"target"`
	Rego   string `json:"rego"`
}

// Constraint models an active Gatekeeper constraint instance bound to resources.
type Constraint struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   PolicyMetadata `json:"metadata"`
	Spec       ConstraintSpec `json:"spec"`
}

// ConstraintSpec defines enforcement behavior and resource selector filters.
type ConstraintSpec struct {
	EnforcementAction string        `json:"enforcementAction"`
	Match             ResourceMatch `json:"match"`
}

// ResourceMatch defines kind, apiGroup, and namespace admission selectors.
type ResourceMatch struct {
	Kinds      []KindSelector `json:"kinds"`
	Namespaces []string       `json:"namespaces,omitempty"`
}

// KindSelector pairs API groups with concrete Kubernetes resource kinds.
type KindSelector struct {
	APIGroups []string `json:"apiGroups"`
	Kinds     []string `json:"kinds"`
}

// PolicyMetadata captures object identification for declarative policies.
type PolicyMetadata struct {
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// GatekeeperPolicyPair groups a ConstraintTemplate with its corresponding active Constraint.
type GatekeeperPolicyPair struct {
	ID          string
	Template    ConstraintTemplate
	Constraint  Constraint
	Description string
}

// SynthesizeGatekeeperPolicies compiles admission policies from feeds and findings.
func SynthesizeGatekeeperPolicies(feed *intel.Feed, violations []k8s.Violation, opts SynthesisOptions) ([]ConstraintTemplate, []Constraint) {
	action := opts.EnforcementAction
	if action == "" {
		action = EnforceDeny
	}

	templatesMap := make(map[string]ConstraintTemplate)
	constraintsMap := make(map[string]Constraint)

	// Baseline security policies always synthesized for cloud-native clusters
	pairs := []GatekeeperPolicyPair{
		buildDenyCustomSnippetsPair(action, opts.NamespaceFilter),
		buildDenyPathTraversalPair(action, opts.NamespaceFilter),
		buildRequireSSLRedirectPair(action, opts.NamespaceFilter),
		buildDenyWideOpenEgressPair(action, opts.NamespaceFilter),
		buildDenySensitiveHostPortsPair(action, opts.NamespaceFilter),
		buildEnforceCgroupLimitsPair(action, opts.NamespaceFilter),
	}

	for _, pair := range pairs {
		if isRuleExcluded(pair.ID, opts.ExcludedRuleIDs) {
			continue
		}
		templatesMap[pair.Template.Metadata.Name] = pair.Template
		constraintsMap[pair.Constraint.Metadata.Name] = pair.Constraint
	}

	var templates []ConstraintTemplate
	for _, t := range templatesMap {
		templates = append(templates, t)
	}
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Metadata.Name < templates[j].Metadata.Name
	})

	var constraints []Constraint
	for _, c := range constraintsMap {
		constraints = append(constraints, c)
	}
	sort.Slice(constraints, func(i, j int) bool {
		return constraints[i].Metadata.Name < constraints[j].Metadata.Name
	})

	return templates, constraints
}

func buildDenyCustomSnippetsPair(action string, namespaces []string) GatekeeperPolicyPair {
	rego := `package k8sdenycustomsnippets

violation[{"msg": msg}] {
  input.review.kind.kind == "Ingress"
  annotations := object.get(input.review.object.metadata, "annotations", {})
  forbidden := [
    "nginx.ingress.kubernetes.io/configuration-snippet",
    "nginx.ingress.kubernetes.io/server-snippet",
    "nginx.ingress.kubernetes.io/auth-snippet",
    "nginx.ingress.kubernetes.io/modsecurity-snippet"
  ]
  some key
  annotations[key]
  key == forbidden[_]
  msg := sprintf("Ingress '%v' uses prohibited custom snippet annotation '%v' (CVE-2023-5044 / CVE-2026-21801 mitigation)", [input.review.object.metadata.name, key])
}`

	template := ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1beta1",
		Kind:       "ConstraintTemplate",
		Metadata: PolicyMetadata{
			Name: "k8sdenycustomsnippets",
			Annotations: map[string]string{
				"description": "Denies Ingress configurations using custom snippet annotations that permit code execution.",
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Names: CRDNames{Kind: "K8sDenyCustomSnippets"},
			},
			Targets: []TemplateTarget{
				{Target: "admission.k8s.gatekeeper.sh", Rego: rego},
			},
		},
	}

	constraint := Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       "K8sDenyCustomSnippets",
		Metadata: PolicyMetadata{
			Name: "sentinel-enforce-deny-snippets",
		},
		Spec: ConstraintSpec{
			EnforcementAction: action,
			Match: ResourceMatch{
				Kinds: []KindSelector{
					{APIGroups: []string{"networking.k8s.io"}, Kinds: []string{"Ingress"}},
				},
				Namespaces: namespaces,
			},
		},
	}

	return GatekeeperPolicyPair{
		ID:          "K8S-ING-001",
		Template:    template,
		Constraint:  constraint,
		Description: "Ingress custom snippet injection mitigation",
	}
}

func buildDenyPathTraversalPair(action string, namespaces []string) GatekeeperPolicyPair {
	rego := `package k8sdenypathtraversal

violation[{"msg": msg}] {
  input.review.kind.kind == "Ingress"
  rules := object.get(input.review.object.spec, "rules", [])
  some r
  http := object.get(rules[r], "http", {})
  paths := object.get(http, "paths", [])
  some p
  pathVal := object.get(paths[p], "path", "")
  contains(pathVal, "..")
  msg := sprintf("Ingress '%v' specifies path traversal sequence '..' in path '%v' (CVE-2026-21801 mitigation)", [input.review.object.metadata.name, pathVal])
}`

	template := ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1beta1",
		Kind:       "ConstraintTemplate",
		Metadata: PolicyMetadata{
			Name: "k8sdenypathtraversal",
			Annotations: map[string]string{
				"description": "Denies Ingress paths containing directory traversal patterns or unanchored dot-dot sequences.",
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Names: CRDNames{Kind: "K8sDenyPathTraversal"},
			},
			Targets: []TemplateTarget{
				{Target: "admission.k8s.gatekeeper.sh", Rego: rego},
			},
		},
	}

	constraint := Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       "K8sDenyPathTraversal",
		Metadata: PolicyMetadata{
			Name: "sentinel-enforce-deny-path-traversal",
		},
		Spec: ConstraintSpec{
			EnforcementAction: action,
			Match: ResourceMatch{
				Kinds: []KindSelector{
					{APIGroups: []string{"networking.k8s.io"}, Kinds: []string{"Ingress"}},
				},
				Namespaces: namespaces,
			},
		},
	}

	return GatekeeperPolicyPair{
		ID:          "K8S-ING-003",
		Template:    template,
		Constraint:  constraint,
		Description: "Ingress path traversal rejection",
	}
}

func buildRequireSSLRedirectPair(action string, namespaces []string) GatekeeperPolicyPair {
	rego := `package k8srequiresslredirect

violation[{"msg": msg}] {
  input.review.kind.kind == "Ingress"
  annotations := object.get(input.review.object.metadata, "annotations", {})
  val := object.get(annotations, "nginx.ingress.kubernetes.io/ssl-redirect", "false")
  val != "true"
  msg := sprintf("Ingress '%v' must explicitly enforce SSL redirect via 'nginx.ingress.kubernetes.io/ssl-redirect: \"true\"'", [input.review.object.metadata.name])
}`

	template := ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1beta1",
		Kind:       "ConstraintTemplate",
		Metadata: PolicyMetadata{
			Name: "k8srequiresslredirect",
			Annotations: map[string]string{
				"description": "Requires all Ingress resources to strictly enforce HTTPS redirection.",
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Names: CRDNames{Kind: "K8sRequireSSLRedirect"},
			},
			Targets: []TemplateTarget{
				{Target: "admission.k8s.gatekeeper.sh", Rego: rego},
			},
		},
	}

	constraint := Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       "K8sRequireSSLRedirect",
		Metadata: PolicyMetadata{
			Name: "sentinel-enforce-ssl-redirect",
		},
		Spec: ConstraintSpec{
			EnforcementAction: action,
			Match: ResourceMatch{
				Kinds: []KindSelector{
					{APIGroups: []string{"networking.k8s.io"}, Kinds: []string{"Ingress"}},
				},
				Namespaces: namespaces,
			},
		},
	}

	return GatekeeperPolicyPair{
		ID:          "K8S-ING-005",
		Template:    template,
		Constraint:  constraint,
		Description: "Ingress SSL redirect requirement",
	}
}

func buildDenyWideOpenEgressPair(action string, namespaces []string) GatekeeperPolicyPair {
	rego := `package k8sdenywideopenegress

violation[{"msg": msg}] {
  input.review.kind.kind == "NetworkPolicy"
  egressRules := object.get(input.review.object.spec, "egress", [])
  some e
  toList := object.get(egressRules[e], "to", [])
  some t
  ipBlock := object.get(toList[t], "ipBlock", {})
  cidr := object.get(ipBlock, "cidr", "")
  cidr == "0.0.0.0/0"
  msg := sprintf("NetworkPolicy '%v' contains unconstrained egress to 0.0.0.0/0 violating zero-trust egress policy", [input.review.object.metadata.name])
}`

	template := ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1beta1",
		Kind:       "ConstraintTemplate",
		Metadata: PolicyMetadata{
			Name: "k8sdenywideopenegress",
			Annotations: map[string]string{
				"description": "Denies NetworkPolicy rules configuring wide-open egress to 0.0.0.0/0 without explicit exemption.",
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Names: CRDNames{Kind: "K8sDenyWideOpenEgress"},
			},
			Targets: []TemplateTarget{
				{Target: "admission.k8s.gatekeeper.sh", Rego: rego},
			},
		},
	}

	constraint := Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       "K8sDenyWideOpenEgress",
		Metadata: PolicyMetadata{
			Name: "sentinel-enforce-deny-wide-open-egress",
		},
		Spec: ConstraintSpec{
			EnforcementAction: action,
			Match: ResourceMatch{
				Kinds: []KindSelector{
					{APIGroups: []string{"networking.k8s.io"}, Kinds: []string{"NetworkPolicy"}},
				},
				Namespaces: namespaces,
			},
		},
	}

	return GatekeeperPolicyPair{
		ID:          "K8S-CNI-002",
		Template:    template,
		Constraint:  constraint,
		Description: "Wide-open 0.0.0.0/0 egress rejection",
	}
}

func buildDenySensitiveHostPortsPair(action string, namespaces []string) GatekeeperPolicyPair {
	rego := `package k8sdenysensitivehostports

violation[{"msg": msg}] {
  input.review.kind.kind == "NetworkPolicy"
  ingressRules := object.get(input.review.object.spec, "ingress", [])
  sensitivePorts := [2379, 2380, 10250, 6789]
  some i
  ports := object.get(ingressRules[i], "ports", [])
  some p
  portVal := object.get(ports[p], "port", 0)
  sensitivePorts[_] == portVal
  msg := sprintf("NetworkPolicy '%v' exposes sensitive control plane port '%v' (etcd/kubelet/ceph)", [input.review.object.metadata.name, portVal])
}`

	template := ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1beta1",
		Kind:       "ConstraintTemplate",
		Metadata: PolicyMetadata{
			Name: "k8sdenysensitivehostports",
			Annotations: map[string]string{
				"description": "Denies network policy rules exposing internal control plane and storage ports (2379, 2380, 10250, 6789).",
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Names: CRDNames{Kind: "K8sDenySensitiveHostPorts"},
			},
			Targets: []TemplateTarget{
				{Target: "admission.k8s.gatekeeper.sh", Rego: rego},
			},
		},
	}

	constraint := Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       "K8sDenySensitiveHostPorts",
		Metadata: PolicyMetadata{
			Name: "sentinel-enforce-deny-sensitive-ports",
		},
		Spec: ConstraintSpec{
			EnforcementAction: action,
			Match: ResourceMatch{
				Kinds: []KindSelector{
					{APIGroups: []string{"networking.k8s.io"}, Kinds: []string{"NetworkPolicy"}},
				},
				Namespaces: namespaces,
			},
		},
	}

	return GatekeeperPolicyPair{
		ID:          "K8S-CNI-003",
		Template:    template,
		Constraint:  constraint,
		Description: "Sensitive infrastructure port exposure rejection",
	}
}

func buildEnforceCgroupLimitsPair(action string, namespaces []string) GatekeeperPolicyPair {
	rego := `package k8senforcecgrouplimits

violation[{"msg": msg}] {
  input.review.kind.kind == "Pod"
  containers := object.get(input.review.object.spec, "containers", [])
  some c
  container := containers[c]
  resources := object.get(container, "resources", {})
  limits := object.get(resources, "limits", {})
  not limits.memory
  msg := sprintf("Pod '%v' container '%v' lacks explicit memory limit, exposing node to cgroup attachment races (CVE-2026-20914 mitigation)", [input.review.object.metadata.name, container.name])
}`

	template := ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1beta1",
		Kind:       "ConstraintTemplate",
		Metadata: PolicyMetadata{
			Name: "k8senforcecgrouplimits",
			Annotations: map[string]string{
				"description": "Enforces memory resource limits on all Pod containers to mitigate cgroup attachment race conditions.",
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Names: CRDNames{Kind: "K8sEnforceCgroupLimits"},
			},
			Targets: []TemplateTarget{
				{Target: "admission.k8s.gatekeeper.sh", Rego: rego},
			},
		},
	}

	constraint := Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       "K8sEnforceCgroupLimits",
		Metadata: PolicyMetadata{
			Name: "sentinel-enforce-cgroup-limits",
		},
		Spec: ConstraintSpec{
			EnforcementAction: action,
			Match: ResourceMatch{
				Kinds: []KindSelector{
					{APIGroups: []string{""}, Kinds: []string{"Pod"}},
				},
				Namespaces: namespaces,
			},
		},
	}

	return GatekeeperPolicyPair{
		ID:          "CVE-2026-20914",
		Template:    template,
		Constraint:  constraint,
		Description: "Containerd cgroup memory limit enforcement",
	}
}

// FormatGatekeeperYAML serializes templates and constraints into multi-document Kubernetes YAML.
func FormatGatekeeperYAML(templates []ConstraintTemplate, constraints []Constraint, includeComments bool) string {
	var sb strings.Builder

	if includeComments {
		sb.WriteString("# ====================================================================\n")
		sb.WriteString("# OPA Gatekeeper Admission Control ConstraintTemplates & Constraints\n")
		sb.WriteString("# Generated automatically by nix-k8s-sentinel Policy Synthesis Engine\n")
		sb.WriteString("# ====================================================================\n")
	}

	firstDoc := true

	for _, t := range templates {
		if !firstDoc {
			sb.WriteString("---\n")
		}
		firstDoc = false

		sb.WriteString(fmt.Sprintf("apiVersion: %s\n", t.APIVersion))
		sb.WriteString(fmt.Sprintf("kind: %s\n", t.Kind))
		sb.WriteString("metadata:\n")
		sb.WriteString(fmt.Sprintf("  name: %s\n", t.Metadata.Name))
		if len(t.Metadata.Annotations) > 0 {
			sb.WriteString("  annotations:\n")
			for k, v := range t.Metadata.Annotations {
				sb.WriteString(fmt.Sprintf("    %s: %s\n", k, escapeYAMLString(v)))
			}
		}
		sb.WriteString("spec:\n")
		sb.WriteString("  crd:\n    spec:\n      names:\n")
		sb.WriteString(fmt.Sprintf("        kind: %s\n", t.Spec.CRD.Names.Kind))
		sb.WriteString("  targets:\n")
		for _, tgt := range t.Spec.Targets {
			sb.WriteString(fmt.Sprintf("    - target: %s\n", tgt.Target))
			sb.WriteString("      rego: |\n")
			regoLines := strings.Split(tgt.Rego, "\n")
			for _, line := range regoLines {
				if line == "" {
					sb.WriteString("\n")
				} else {
					sb.WriteString(fmt.Sprintf("        %s\n", line))
				}
			}
		}
	}

	for _, c := range constraints {
		if !firstDoc {
			sb.WriteString("---\n")
		}
		firstDoc = false

		sb.WriteString(fmt.Sprintf("apiVersion: %s\n", c.APIVersion))
		sb.WriteString(fmt.Sprintf("kind: %s\n", c.Kind))
		sb.WriteString("metadata:\n")
		sb.WriteString(fmt.Sprintf("  name: %s\n", c.Metadata.Name))
		sb.WriteString("spec:\n")
		sb.WriteString(fmt.Sprintf("  enforcementAction: %s\n", c.Spec.EnforcementAction))
		sb.WriteString("  match:\n    kinds:\n")
		for _, k := range c.Spec.Match.Kinds {
			sb.WriteString("      - apiGroups:\n")
			for _, g := range k.APIGroups {
				if g == "" {
					sb.WriteString("          - \"\"\n")
				} else {
					sb.WriteString(fmt.Sprintf("          - %s\n", escapeYAMLString(g)))
				}
			}
			sb.WriteString("        kinds:\n")
			for _, kindName := range k.Kinds {
				sb.WriteString(fmt.Sprintf("          - %s\n", kindName))
			}
		}
		if len(c.Spec.Match.Namespaces) > 0 {
			sb.WriteString("    namespaces:\n")
			for _, ns := range c.Spec.Match.Namespaces {
				sb.WriteString(fmt.Sprintf("      - %s\n", ns))
			}
		}
	}

	return sb.String()
}

func isRuleExcluded(ruleID string, excluded []string) bool {
	for _, ex := range excluded {
		if strings.EqualFold(ruleID, ex) {
			return true
		}
	}
	return false
}
