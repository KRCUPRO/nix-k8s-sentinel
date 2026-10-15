package spiffe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SynthesizeDefaultDenyPolicy generates a baseline CiliumNetworkPolicy enforcing default-deny ingress and egress with strict DNS-only egress.
func SynthesizeDefaultDenyPolicy(namespace string) string {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "default"
	}

	return fmt.Sprintf(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: default-deny-spiffe-microsegmentation
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: nix-k8s-sentinel
    security.sentinel/default-deny: "true"
    security.sentinel/zero-trust: "true"
spec:
  description: "Enforces default-deny microsegmentation posture for non-attested traffic"
  endpointSelector: {}
  ingress: []
  egress:
    - toEndpoints:
        - matchLabels:
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
`, ns)
}

// SynthesizeCiliumPolicy synthesizes a CiliumNetworkPolicy enforcing mutual TLS and SPIFFE ID authentication.
func SynthesizeCiliumPolicy(workload WorkloadIdentity, allowedInboundSPIFFEIDs []string, allowedOutboundSPIFFEIDs []string) string {
	ns := workload.Namespace
	if ns == "" {
		ns = "default"
	}
	name := workload.Name
	if name == "" {
		name = "workload"
	}

	var buf bytes.Buffer
	buf.WriteString("apiVersion: cilium.io/v2\n")
	buf.WriteString("kind: CiliumNetworkPolicy\n")
	buf.WriteString("metadata:\n")
	buf.WriteString(fmt.Sprintf("  name: %s-spiffe-attested\n", name))
	buf.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	buf.WriteString("  labels:\n")
	buf.WriteString("    app.kubernetes.io/managed-by: nix-k8s-sentinel\n")
	buf.WriteString("    security.sentinel/zero-trust: \"true\"\n")
	buf.WriteString(fmt.Sprintf("    security.sentinel/spiffe-attested: \"%t\"\n", workload.Attested))
	buf.WriteString("spec:\n")
	buf.WriteString(fmt.Sprintf("  description: \"Enforces cryptographically attested SPIFFE identity for %s\"\n", name))
	buf.WriteString("  endpointSelector:\n")
	buf.WriteString("    matchLabels:\n")
	buf.WriteString(fmt.Sprintf("      app: %s\n", name))

	// Ingress section
	buf.WriteString("  ingress:\n")
	if len(allowedInboundSPIFFEIDs) > 0 {
		for _, inboundID := range allowedInboundSPIFFEIDs {
			buf.WriteString("    - fromEndpoints:\n")
			buf.WriteString("        - matchLabels:\n")
			buf.WriteString(fmt.Sprintf("            \"io.spiffe.id\": \"%s\"\n", inboundID))
			buf.WriteString("      authentication:\n")
			buf.WriteString("        mode: required\n")
		}
	} else if workload.SPIFFEID != "" {
		buf.WriteString("    - fromEndpoints:\n")
		buf.WriteString("        - matchLabels:\n")
		buf.WriteString(fmt.Sprintf("            \"io.spiffe.id\": \"%s\"\n", workload.SPIFFEID))
		buf.WriteString("      authentication:\n")
		buf.WriteString("        mode: required\n")
	}

	// Egress section
	buf.WriteString("  egress:\n")
	if len(allowedOutboundSPIFFEIDs) > 0 {
		for _, outboundID := range allowedOutboundSPIFFEIDs {
			buf.WriteString("    - toEndpoints:\n")
			buf.WriteString("        - matchLabels:\n")
			buf.WriteString(fmt.Sprintf("            \"io.spiffe.id\": \"%s\"\n", outboundID))
			buf.WriteString("      authentication:\n")
			buf.WriteString("        mode: required\n")
		}
	}
	// Always allow core DNS egress
	buf.WriteString("    - toEndpoints:\n")
	buf.WriteString("        - matchLabels:\n")
	buf.WriteString("            k8s-app: kube-dns\n")
	buf.WriteString("      toPorts:\n")
	buf.WriteString("        - ports:\n")
	buf.WriteString("            - port: \"53\"\n")
	buf.WriteString("              protocol: UDP\n")

	return buf.String()
}

// SynthesizeCiliumPoliciesForWorkloads builds a multi-document YAML stream with default-deny and workload policies.
func SynthesizeCiliumPoliciesForWorkloads(workloads []WorkloadIdentity) string {
	if len(workloads) == 0 {
		return SynthesizeDefaultDenyPolicy("default")
	}

	var docs []string
	seenNamespaces := make(map[string]bool)

	for _, w := range workloads {
		ns := w.Namespace
		if ns == "" {
			ns = "default"
		}
		if !seenNamespaces[ns] {
			docs = append(docs, strings.TrimSpace(SynthesizeDefaultDenyPolicy(ns)))
			seenNamespaces[ns] = true
		}
		docs = append(docs, strings.TrimSpace(SynthesizeCiliumPolicy(w, nil, nil)))
	}

	return strings.Join(docs, "\n---\n") + "\n"
}

// WriteCiliumPoliciesToDir writes the synthesized policies to a designated file or directory.
func WriteCiliumPoliciesToDir(policiesYAML string, destPath string) (string, error) {
	cleanPath := filepath.Clean(destPath)
	fileInfo, err := os.Stat(cleanPath)
	targetFile := cleanPath
	if err == nil && fileInfo.IsDir() {
		targetFile = filepath.Join(cleanPath, "cilium-spiffe-policies.yaml")
	} else if err != nil && (filepath.Ext(cleanPath) == "" || strings.HasSuffix(destPath, string(filepath.Separator))) {
		targetFile = filepath.Join(cleanPath, "cilium-spiffe-policies.yaml")
	}

	dir := filepath.Dir(targetFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory for Cilium policies (%s): %w", dir, err)
	}

	if err := os.WriteFile(targetFile, []byte(policiesYAML), 0644); err != nil {
		return "", fmt.Errorf("failed to write Cilium policies to %s: %w", targetFile, err)
	}

	return targetFile, nil
}
