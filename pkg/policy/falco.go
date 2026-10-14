package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
)

// FalcoRule models a declarative CNCF Falco runtime detection rule.
type FalcoRule struct {
	Rule      string   `json:"rule"`
	Desc      string   `json:"desc"`
	Condition string   `json:"condition"`
	Output    string   `json:"output"`
	Priority  string   `json:"priority"`
	Tags      []string `json:"tags"`
	Source    string   `json:"source,omitempty"`
}

// SynthesizeFalcoFromThreat maps a normalized threat advisory into a concrete Falco runtime rule.
func SynthesizeFalcoFromThreat(item intel.ThreatItem, customTags []string) *FalcoRule {
	priority := MapSeverityToFalcoPriority(item.Severity)
	tags := []string{"sentinel", "threat-intel", strings.ToLower(item.ID)}
	if item.Component != "" {
		tags = append(tags, strings.ToLower(item.Component))
	}
	if item.Target != "" {
		tags = append(tags, strings.ToLower(item.Target))
	}
	tags = append(tags, customTags...)

	switch item.ID {
	case "CVE-2026-21801":
		return &FalcoRule{
			Rule:      "K8S Ingress Controller Shell Spawn Defense",
			Desc:      fmt.Sprintf("Detects execution of shell or interpreter binaries inside Ingress-Nginx controller pods (mitigating %s).", item.ID),
			Condition: "spawned_process and container.image.repository contains \"ingress-nginx\" and (proc.name in (shell_binaries) or proc.cmdline contains \"lua\")",
			Output:    fmt.Sprintf("Suspicious shell or script spawned in Ingress controller (cve=%s user=%%user.name command=%%proc.cmdline pod=%%k8s.pod.name ns=%%k8s.ns.name)", item.ID),
			Priority:  priority,
			Tags:      dedupTags(append(tags, "ingress-nginx", "cve-2026-21801", "mitre_execution")),
			Source:    "syscall",
		}

	case "CVE-2026-20914":
		return &FalcoRule{
			Rule:      "Containerd Cgroup Memory Subsystem Tampering",
			Desc:      fmt.Sprintf("Detects unprivileged process writes to /sys/fs/cgroup/memory during pod creation storms (mitigating %s).", item.ID),
			Condition: "(evt.type in (open, openat, openat2) and evt.is_open_write=true and fd.name startswith \"/sys/fs/cgroup/memory\" and not proc.name in (\"containerd\", \"systemd\", \"kubelet\", \"runc\") and container.id != \"host\")",
			Output:    fmt.Sprintf("Anomalous cgroup memory write detected outside CRI daemon (cve=%s comm=%%proc.name path=%%fd.name container=%%container.name)", item.ID),
			Priority:  FalcoPriorityCritical,
			Tags:      dedupTags(append(tags, "containerd", "cgroup", "cve-2026-20914", "mitre_privilege_escalation")),
			Source:    "syscall",
		}

	case "CVE-2026-19402":
		return &FalcoRule{
			Rule:      "Nix Daemon Unrestricted Evaluation Egress",
			Desc:      fmt.Sprintf("Detects Nix build daemon establishing unauthorized outbound network sockets during pure evaluation (mitigating %s).", item.ID),
			Condition: "(evt.type = connect and proc.name in (\"nix-daemon\", \"nix-build\") and not fd.rip in (\"127.0.0.1\", \"::1\") and fd.typechar in (4, 6))",
			Output:    fmt.Sprintf("Nix evaluation daemon initiated remote network egress (cve=%s comm=%%proc.name rip=%%fd.rip rport=%%fd.rport)", item.ID),
			Priority:  priority,
			Tags:      dedupTags(append(tags, "nixos", "nix", "supply_chain", "cve-2026-19402")),
			Source:    "syscall",
		}

	case "CVE-2026-15509":
		return &FalcoRule{
			Rule:      "Ceph OSD Storage Daemon Lethal Signal Termination",
			Desc:      fmt.Sprintf("Detects Ceph OSD storage daemon terminated unexpectedly by SIGKILL, SIGABRT, or SIGBUS under NVMe direct I/O flushes (mitigating %s).", item.ID),
			Condition: "(evt.type = signal and sig.name in (\"SIGKILL\", \"SIGABRT\", \"SIGBUS\") and proc.name = \"ceph-osd\")",
			Output:    fmt.Sprintf("Ceph OSD daemon terminated by lethal signal (cve=%s sig=%%sig.name comm=%%proc.name pid=%%proc.pid)", item.ID),
			Priority:  priority,
			Tags:      dedupTags(append(tags, "nixos", "ceph", "storage", "cve-2026-15509")),
			Source:    "syscall",
		}

	default:
		// Generic baseline rule derived from advisory
		ruleName := fmt.Sprintf("%s Runtime Mitigation Shield", item.ID)
		condition := fmt.Sprintf("spawned_process and container.name contains \"%s\" and proc.name in (shell_binaries)", strings.ToLower(item.Component))
		output := fmt.Sprintf("Threat activity detected matching %s (component=%s user=%%user.name command=%%proc.cmdline)", item.ID, item.Component)

		return &FalcoRule{
			Rule:      ruleName,
			Desc:      fmt.Sprintf("Synthesized runtime guard mitigating %s: %s", item.ID, item.Title),
			Condition: condition,
			Output:    output,
			Priority:  priority,
			Tags:      dedupTags(tags),
			Source:    "syscall",
		}
	}
}

// SynthesizeFalcoFromViolation converts a Kubernetes static violation into an active runtime detection rule.
func SynthesizeFalcoFromViolation(v k8s.Violation, customTags []string) *FalcoRule {
	priority := MapSeverityToFalcoPriority(v.Severity)
	tags := []string{"sentinel", "k8s-manifest", strings.ToLower(v.RuleID)}
	tags = append(tags, customTags...)

	switch v.RuleID {
	case "K8S-ING-001", "K8S-ING-002":
		return &FalcoRule{
			Rule:      fmt.Sprintf("%s Ingress Snippet Injection Shield", v.RuleID),
			Desc:      fmt.Sprintf("Detects arbitrary shell execution inside Ingress controller triggered by snippet directives (%s).", v.RuleID),
			Condition: "spawned_process and container.image.repository contains \"ingress\" and proc.name in (shell_binaries)",
			Output:    fmt.Sprintf("Ingress pod spawned untrusted shell process in violation of snippet policy (rule=%s command=%%proc.cmdline pod=%%k8s.pod.name ns=%%k8s.ns.name)", v.RuleID),
			Priority:  priority,
			Tags:      dedupTags(append(tags, "ingress", "snippet-injection")),
			Source:    "syscall",
		}

	case "K8S-ING-003", "K8S-ING-004":
		return &FalcoRule{
			Rule:      fmt.Sprintf("%s Ingress Directory Traversal Shield", v.RuleID),
			Desc:      fmt.Sprintf("Detects Ingress controller accessing filesystem paths with directory traversal sequences (%s).", v.RuleID),
			Condition: "(evt.type in (open, openat) and (fd.name contains \"/..\" or fd.name contains \"../\") and container.image.repository contains \"ingress\")",
			Output:    fmt.Sprintf("Ingress controller accessed path containing directory traversal sequence (rule=%s path=%%fd.name comm=%%proc.name pod=%%k8s.pod.name)", v.RuleID),
			Priority:  priority,
			Tags:      dedupTags(append(tags, "ingress", "path-traversal")),
			Source:    "syscall",
		}

	case "K8S-CNI-002":
		return &FalcoRule{
			Rule:      "K8S-CNI-002 Unrestricted Public Internet Egress Shield",
			Desc:      "Detects container initiating outbound TCP/UDP connection to non-RFC1918 public IP address violating CNI zero-trust egress.",
			Condition: "(evt.type = connect and (fd.typechar = 4 or fd.typechar = 6) and not fd.rip in (\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\", \"127.0.0.1\") and container.id != \"host\")",
			Output:    "Container established unconstrained external egress connection to public IP (rule=K8S-CNI-002 comm=%proc.name rip=%fd.rip rport=%fd.rport pod=%k8s.pod.name)",
			Priority:  FalcoPriorityError,
			Tags:      dedupTags(append(tags, "cni", "egress", "network-policy")),
			Source:    "syscall",
		}

	case "K8S-CNI-003":
		return &FalcoRule{
			Rule:      "K8S-CNI-003 Sensitive Control Plane Port Shield",
			Desc:      "Detects container workloads attempting unauthorized connections to protected cluster control plane ports (etcd, Kubelet, Ceph).",
			Condition: "(evt.type = connect and fd.rport in (2379, 2380, 10250, 6789) and not proc.name in (\"kube-apiserver\", \"kubelet\", \"etcd\") and container.id != \"host\")",
			Output:    "Workload attempted connection to protected cluster control plane port (rule=K8S-CNI-003 port=%fd.rport comm=%proc.name pod=%k8s.pod.name)",
			Priority:  FalcoPriorityCritical,
			Tags:      dedupTags(append(tags, "cni", "control-plane", "etcd", "kubelet")),
			Source:    "syscall",
		}

	default:
		return nil
	}
}

// BuildFalcoRuleSet compiles a deduplicated list of Falco rules from threat feeds and violation findings.
func BuildFalcoRuleSet(feed *intel.Feed, violations []k8s.Violation, customTags []string) []FalcoRule {
	seenRules := make(map[string]bool)
	var rules []FalcoRule

	if feed != nil {
		for _, item := range feed.Items {
			rule := SynthesizeFalcoFromThreat(item, customTags)
			if rule != nil && !seenRules[rule.Rule] {
				seenRules[rule.Rule] = true
				rules = append(rules, *rule)
			}
		}
	}

	for _, v := range violations {
		rule := SynthesizeFalcoFromViolation(v, customTags)
		if rule != nil && !seenRules[rule.Rule] {
			seenRules[rule.Rule] = true
			rules = append(rules, *rule)
		}
	}

	// Sort deterministically by rule name
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Rule < rules[j].Rule
	})

	return rules
}

// FormatFalcoYAML converts FalcoRule slice into clean, schema-conforming YAML text.
func FormatFalcoYAML(rules []FalcoRule, includeComments bool) string {
	var sb strings.Builder

	if includeComments {
		sb.WriteString("# ====================================================================\n")
		sb.WriteString("# CNCF Falco Runtime Threat Mitigation Ruleset\n")
		sb.WriteString("# Generated automatically by nix-k8s-sentinel Policy Synthesis Engine\n")
		sb.WriteString("# ====================================================================\n\n")
	}

	if len(rules) == 0 {
		sb.WriteString("# No active runtime rules synthesized.\n")
		return sb.String()
	}

	for i, r := range rules {
		sb.WriteString(fmt.Sprintf("- rule: %s\n", escapeYAMLString(r.Rule)))
		sb.WriteString(fmt.Sprintf("  desc: %s\n", escapeYAMLString(r.Desc)))
		sb.WriteString(fmt.Sprintf("  condition: >-\n    %s\n", r.Condition))
		sb.WriteString(fmt.Sprintf("  output: %s\n", escapeYAMLString(r.Output)))
		sb.WriteString(fmt.Sprintf("  priority: %s\n", r.Priority))
		if len(r.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("  tags: [%s]\n", strings.Join(quoteTags(r.Tags), ", ")))
		}
		if r.Source != "" {
			sb.WriteString(fmt.Sprintf("  source: %s\n", r.Source))
		}
		if i < len(rules)-1 {
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func dedupTags(tags []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, t := range tags {
		clean := strings.ToLower(strings.TrimSpace(t))
		if clean != "" && !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	sort.Strings(out)
	return out
}

func quoteTags(tags []string) []string {
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = fmt.Sprintf("\"%s\"", t)
	}
	return out
}

func escapeYAMLString(s string) string {
	if strings.ContainsAny(s, ":#\n\"'") || strings.HasPrefix(s, "-") {
		escaped := strings.ReplaceAll(s, "\"", "\\\"")
		return fmt.Sprintf("\"%s\"", escaped)
	}
	return s
}
