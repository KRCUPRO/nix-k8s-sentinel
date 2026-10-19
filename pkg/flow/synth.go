package flow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SynthesizeHardenedCiliumPolicy generates a declarative production-hardened CiliumNetworkPolicy.
func SynthesizeHardenedCiliumPolicy(namespace, name, podApp string, allowedDomains []string) string {
	if namespace == "" {
		namespace = "default"
	}
	if name == "" {
		name = "flow-sentinel-egress-hardened"
	}
	if podApp == "" {
		podApp = "workload"
	}

	if len(allowedDomains) == 0 {
		allowedDomains = []string{
			"*.internal.cluster.local",
			"*.svc.cluster.local",
			"api.github.com",
			"pkg.nixos.org",
		}
	}

	var sb strings.Builder
	sb.WriteString("apiVersion: cilium.io/v2\n")
	sb.WriteString("kind: CiliumNetworkPolicy\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	sb.WriteString("  annotations:\n")
	sb.WriteString("    io.cilium/enable-dns-proxy: \"true\"\n")
	sb.WriteString("    security.k8s.io/hardened-by: \"nix-k8s-sentinel\"\n")
	sb.WriteString("spec:\n")
	sb.WriteString("  endpointSelector:\n")
	sb.WriteString("    matchLabels:\n")
	sb.WriteString(fmt.Sprintf("      app: %s\n", podApp))
	sb.WriteString("  egress:\n")
	sb.WriteString("  # 1. Restrict DNS egress exclusively to kube-system CoreDNS with L7 inspection\n")
	sb.WriteString("  - toEndpoints:\n")
	sb.WriteString("    - matchLabels:\n")
	sb.WriteString("        io.kubernetes.pod.namespace: kube-system\n")
	sb.WriteString("        k8s-app: kube-dns\n")
	sb.WriteString("    toPorts:\n")
	sb.WriteString("    - ports:\n")
	sb.WriteString("      - port: \"53\"\n")
	sb.WriteString("        protocol: UDP\n")
	sb.WriteString("      - port: \"53\"\n")
	sb.WriteString("        protocol: TCP\n")
	sb.WriteString("      rules:\n")
	sb.WriteString("        dns:\n")
	for _, domain := range allowedDomains {
		sb.WriteString(fmt.Sprintf("        - matchPattern: %q\n", domain))
	}
	sb.WriteString("  # 2. Allow whitelisted HTTPS egress to attested endpoints\n")
	sb.WriteString("  - toFQDNs:\n")
	for _, domain := range allowedDomains {
		sb.WriteString(fmt.Sprintf("    - matchPattern: %q\n", domain))
	}
	sb.WriteString("    toPorts:\n")
	sb.WriteString("    - ports:\n")
	sb.WriteString("      - port: \"443\"\n")
	sb.WriteString("        protocol: TCP\n")

	return sb.String()
}

// SynthesizeNixOSFlowModule generates a production-grade NixOS eBPF flow profiling host module.
func SynthesizeNixOSFlowModule(hostName string) string {
	if hostName == "" {
		hostName = "sentinel-node"
	}

	var sb strings.Builder
	sb.WriteString("# NixOS Hardened eBPF Network Flow & DNS Exfiltration Profiler Module\n")
	sb.WriteString("# Generated autonomously by nix-k8s-sentinel\n")
	sb.WriteString("{\n")
	sb.WriteString("  services.cilium = {\n")
	sb.WriteString("    enable = true;\n")
	sb.WriteString("    debug = false;\n")
	sb.WriteString("  };\n\n")
	sb.WriteString("  programs.ebpf.flowProfiler = {\n")
	sb.WriteString("    enable = true;\n")
	sb.WriteString("    bpfConnectMonitoring = true;\n")
	sb.WriteString("    maxSocketRate = 250;\n")
	sb.WriteString("    dnsProxyPort = 10053;\n")
	sb.WriteString("    ringBufferSizeKB = 65536;\n")
	sb.WriteString("    dropThresholdPercent = 0.5;\n")
	sb.WriteString("  };\n\n")
	sb.WriteString("  boot.kernelParams = [\n")
	sb.WriteString("    \"bpf_jit_enable=1\"\n")
	sb.WriteString("    \"bpf_jit_harden=2\"\n")
	sb.WriteString("  ];\n")
	sb.WriteString("}\n")

	return sb.String()
}

// SynthesizeFlowAlertRules generates Prometheus alerting rules for DNS exfiltration and socket bursts.
func SynthesizeFlowAlertRules() string {
	return `groups:
- name: eBPFNetworkFlowAndDNSAlerts
  rules:
  - alert: DNSHighEntropyTunnelingDetected
    expr: rate(cilium_dns_high_entropy_queries_total[2m]) > 5
    for: 1m
    labels:
      severity: critical
      subsystem: eBPF-flow-radar
    annotations:
      summary: "High-entropy DNS queries detected from internal pod"
      description: "Pod is generating DNS queries with Shannon entropy > 3.85, indicating active data tunneling."

  - alert: DGABeaconingBurstDetected
    expr: rate(cilium_dns_nxdomain_responses_total[2m]) / rate(cilium_dns_queries_total[2m]) > 0.25
    for: 2m
    labels:
      severity: critical
      subsystem: eBPF-flow-radar
    annotations:
      summary: "Potential DGA C2 beaconing detected"
      description: "NXDOMAIN response rate exceeds 25.0% of total DNS traffic across namespace."

  - alert: SocketConnectStormAnomaly
    expr: rate(ebpf_kernel_socket_connect_total[1m]) > 500
    for: 30s
    labels:
      severity: warning
      subsystem: eBPF-flow-radar
    annotations:
      summary: "Anomalous kernel socket connection storm"
      description: "Container cgroup connect rate exceeds 500 connections/sec."

  - alert: EBPFFlowRingBufferLoss
    expr: rate(ebpf_flow_ring_buffer_overruns_total[2m]) > 0
    for: 1m
    labels:
      severity: warning
      subsystem: eBPF-flow-radar
    annotations:
      summary: "Kernel eBPF flow ring buffer event drops"
      description: "Telemetry collector is dropping kernel flow traces due to buffer pressure."
`
}

// WriteSynthesizedPolicies persists hardened policies and alert rules into the specified output directory.
func WriteSynthesizedPolicies(outDir string, ciliumCfg *CiliumNetworkPolicyConfig) ([]string, error) {
	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create policy synthesis output directory: %w", err)
	}

	var writtenFiles []string

	ns := "default"
	name := "cilium-flow-hardened"
	app := "secure-workload"
	if ciliumCfg != nil {
		if ciliumCfg.Namespace != "" {
			ns = ciliumCfg.Namespace
		}
		if ciliumCfg.Name != "" {
			name = ciliumCfg.Name + "-hardened"
		}
	}

	// 1. Hardened Cilium Network Policy
	ciliumContent := SynthesizeHardenedCiliumPolicy(ns, name, app, nil)
	ciliumFile := filepath.Join(cleanDir, "cilium-flow-hardened.yaml")
	if err := os.WriteFile(ciliumFile, []byte(ciliumContent), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write hardened Cilium policy: %w", err)
	}
	writtenFiles = append(writtenFiles, ciliumFile)

	// 2. Hardened NixOS Module
	nixosContent := SynthesizeNixOSFlowModule("sentinel-worker-node")
	nixosFile := filepath.Join(cleanDir, "nixos-flow-profiler-hardened.nix")
	if err := os.WriteFile(nixosFile, []byte(nixosContent), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write hardened NixOS flow module: %w", err)
	}
	writtenFiles = append(writtenFiles, nixosFile)

	// 3. Prometheus Alert Rules
	alertsContent := SynthesizeFlowAlertRules()
	alertsFile := filepath.Join(cleanDir, "flow-alerts.yaml")
	if err := os.WriteFile(alertsFile, []byte(alertsContent), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write flow alert rules: %w", err)
	}
	writtenFiles = append(writtenFiles, alertsFile)

	return writtenFiles, nil
}
