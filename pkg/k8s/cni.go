package k8s

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	sensitivePortMap = map[int]string{
		2379:  "etcd client communication",
		2380:  "etcd peer synchronization",
		6443:  "Kubernetes API server",
		6789:  "Ceph monitor cluster service",
		10250: "Kubelet authenticated API",
		10255: "Kubelet read-only port",
		9200:  "Elasticsearch unauthenticated cluster endpoint",
		6379:  "Redis in-memory database",
	}

	portRegex   = regexp.MustCompile(`port:\s*([0-9]+)`)
	cidr0Regex  = regexp.MustCompile(`(?:cidr|nets|toCIDR):\s*["']?0\.0\.0\.0/0["']?`)
	entityAllRe = regexp.MustCompile(`(?:toEntities|fromEntities):\s*\[?\s*["']?(?:all|world)["']?`)
)

// CNIAnalyzer inspects Calico, Cilium, and standard Kubernetes NetworkPolicies.
type CNIAnalyzer struct{}

// NewCNIAnalyzer returns a new CNIAnalyzer instance.
func NewCNIAnalyzer() *CNIAnalyzer {
	return &CNIAnalyzer{}
}

// IsNetworkPolicyResource verifies if a resource kind matches CNI network policy types.
func (c *CNIAnalyzer) IsNetworkPolicyResource(kind string) bool {
	switch kind {
	case "NetworkPolicy", "GlobalNetworkPolicy",
		"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy":
		return true
	default:
		return false
	}
}

// AuditNetworkPolicy performs security analysis across Calico, Cilium, and K8s policies.
func (c *CNIAnalyzer) AuditNetworkPolicy(res RawResource) []Violation {
	if !c.IsNetworkPolicyResource(res.Kind) {
		return nil
	}

	var violations []Violation

	// 1. Audit Unrestricted 0.0.0.0/0 Egress
	violations = append(violations, c.checkUnrestrictedEgress(res)...)

	// 2. Audit Sensitive Port Exposure
	violations = append(violations, c.checkSensitivePortExposure(res)...)

	// 3. Audit Wide-Open Ingress (All Sources Allowed)
	violations = append(violations, c.checkWideOpenIngress(res)...)

	// 4. Audit Cilium L7 Wildcard Bypasses
	violations = append(violations, c.checkCiliumL7Wildcards(res)...)

	// 5. Audit Calico Untracked Packet Bypasses
	violations = append(violations, c.checkCalicoUntracked(res)...)

	return violations
}

// AuditDefaultDenyPostures audits a list of resources to identify namespaces lacking default-deny policies.
func (c *CNIAnalyzer) AuditDefaultDenyPostures(resources []RawResource) []Violation {
	var violations []Violation
	namespaceHasDeny := make(map[string]bool)

	for _, res := range resources {
		if !c.IsNetworkPolicyResource(res.Kind) {
			continue
		}

		if c.isDefaultDenyPolicy(res) {
			namespaceHasDeny[res.Namespace] = true
		}
	}

	// Identify namespaces referenced by resources that lack a default-deny
	inspectedNamespaces := make(map[string]bool)
	for _, res := range resources {
		if res.Namespace == "" || inspectedNamespaces[res.Namespace] {
			continue
		}
		inspectedNamespaces[res.Namespace] = true

		if !namespaceHasDeny[res.Namespace] {
			violations = append(violations, Violation{
				RuleID:       "K8S-CNI-001",
				Title:        "Namespace Lacks Default-Deny Network Isolation",
				ResourceKind: "Namespace",
				ResourceName: res.Namespace,
				Namespace:    res.Namespace,
				Severity:     intel.SeverityMedium,
				CVSSScore:    6.2,
				Description:  fmt.Sprintf("Namespace '%s' contains workloads but no default-deny Ingress/Egress NetworkPolicy was detected.", res.Namespace),
				Remediation:  "Deploy a baseline default-deny NetworkPolicy (spec.podSelector: {}, policyTypes: [Ingress, Egress]) to enforce zero-trust isolation.",
			})
		}
	}

	return violations
}

func (c *CNIAnalyzer) isDefaultDenyPolicy(res RawResource) bool {
	raw := res.RawContent
	hasEmptySelector := strings.Contains(raw, "podSelector: {}") || strings.Contains(raw, "podSelector:\n")
	hasPolicyTypes := strings.Contains(raw, "policyTypes:") && strings.Contains(raw, "Ingress")

	// Canonical default deny has no ingress/egress rules or explicit empty array
	hasNoIngressRules := !strings.Contains(raw, "from:") && !strings.Contains(raw, "- ports:")
	return hasEmptySelector && hasPolicyTypes && hasNoIngressRules
}

func (c *CNIAnalyzer) checkUnrestrictedEgress(res RawResource) []Violation {
	var violations []Violation
	raw := res.RawContent

	if cidr0Regex.MatchString(raw) || entityAllRe.MatchString(raw) {
		// Check if it occurs in an egress context
		if strings.Contains(raw, "egress:") || strings.Contains(raw, "toCIDR") || strings.Contains(raw, "toEntities") {
			violations = append(violations, Violation{
				RuleID:       "K8S-CNI-002",
				Title:        "Unrestricted Global Egress (0.0.0.0/0 / All Entities Allowed)",
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Severity:     intel.SeverityHigh,
				CVSSScore:    7.8,
				Description:  "Network policy permits egress to 0.0.0.0/0 without restricted target scopes, risking data exfiltration or reverse shell callbacks.",
				Remediation:  "Constrain egress to explicit CIDR blocks, DNS/FQDN selectors, or internal cluster namespaces.",
			})
		}
	}

	return violations
}

func (c *CNIAnalyzer) checkSensitivePortExposure(res RawResource) []Violation {
	var violations []Violation
	scanner := bufio.NewScanner(strings.NewReader(res.RawContent))

	inIngress := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ingress:") {
			inIngress = true
		} else if strings.HasPrefix(line, "egress:") {
			inIngress = false
		}

		matches := portRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			portNum, err := strconv.Atoi(matches[1])
			if err == nil {
				if serviceName, isSensitive := sensitivePortMap[portNum]; isSensitive && inIngress {
					violations = append(violations, Violation{
						RuleID:       "K8S-CNI-003",
						Title:        fmt.Sprintf("Sensitive Infrastructure Port %d Allowed in Ingress", portNum),
						ResourceKind: res.Kind,
						ResourceName: res.Name,
						Namespace:    res.Namespace,
						Severity:     intel.SeverityHigh,
						CVSSScore:    8.3,
						Description:  fmt.Sprintf("Network policy permits traffic to critical port %d (%s).", portNum, serviceName),
						Remediation:  "Isolate infrastructure ports via strict mTLS and allow only authorized controller namespaces.",
					})
				}
			}
		}
	}

	return violations
}

func (c *CNIAnalyzer) checkWideOpenIngress(res RawResource) []Violation {
	var violations []Violation
	raw := res.RawContent

	// In Kubernetes NetworkPolicy, an ingress rule with an empty from list (- {}) allows all traffic
	if strings.Contains(raw, "ingress:") && (strings.Contains(raw, "- from: []") || strings.Contains(raw, "- {}")) {
		violations = append(violations, Violation{
			RuleID:       "K8S-CNI-004",
			Title:        "Wide-Open Ingress Rule (All Pods and External IPs Allowed)",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityHigh,
			CVSSScore:    7.4,
			Description:  "Ingress contains an unrestricted catch-all selector, exposing target workloads to all cluster namespaces and external sources.",
			Remediation:  "Specify explicit namespaceSelector and podSelector requirements within ingress.from blocks.",
		})
	}

	return violations
}

func (c *CNIAnalyzer) checkCiliumL7Wildcards(res RawResource) []Violation {
	var violations []Violation
	raw := res.RawContent

	if !strings.HasPrefix(res.Kind, "Cilium") {
		return nil
	}

	// Cilium L7 policy with wildcard HTTP method or unbounded regex path
	if strings.Contains(raw, "method: \"*\"") || strings.Contains(raw, "method: '*'") {
		violations = append(violations, Violation{
			RuleID:       "K8S-CNI-005",
			Title:        "Cilium L7 Wildcard HTTP Method Policy Bypass",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityMedium,
			CVSSScore:    6.0,
			Description:  "CiliumNetworkPolicy specifies wildcard HTTP method '*', weakening application-layer access controls.",
			Remediation:  "Explicitly restrict HTTP methods (e.g., GET, POST) for sensitive API paths.",
		})
	}

	return violations
}

func (c *CNIAnalyzer) checkCalicoUntracked(res RawResource) []Violation {
	var violations []Violation
	raw := res.RawContent

	if !strings.Contains(res.APIVersion, "projectcalico") && res.Kind != "GlobalNetworkPolicy" {
		return nil
	}

	if strings.Contains(raw, "doNotTrack: true") {
		violations = append(violations, Violation{
			RuleID:       "K8S-CNI-006",
			Title:        "Calico Untracked Packet Policy (Conntrack Bypassed)",
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Severity:     intel.SeverityMedium,
			CVSSScore:    5.8,
			Description:  "Policy sets 'doNotTrack: true', bypassing Linux kernel conntrack state tables and stateful firewall inspection.",
			Remediation:  "Use tracked policies unless strictly required for high-throughput stateless border gateways.",
		})
	}

	return violations
}
