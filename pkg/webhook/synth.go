package webhook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SynthesizeHardenedValidatingWebhook synthesizes a production-hardened ValidatingWebhookConfiguration.
func SynthesizeHardenedValidatingWebhook(name, serviceName, namespace, path string, port int32) string {
	if port <= 0 {
		port = 443
	}
	if path == "" {
		path = "/validate"
	}
	if namespace == "" {
		namespace = "sentinel-system"
	}

	var sb strings.Builder
	sb.WriteString("apiVersion: admissionregistration.k8s.io/v1\n")
	sb.WriteString("kind: ValidatingWebhookConfiguration\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", name))
	sb.WriteString("  annotations:\n")
	sb.WriteString(fmt.Sprintf("    cert-manager.io/inject-ca-from: %s/%s-ca\n", namespace, name))
	sb.WriteString("    sentinel.defense.io/hardened-by: nix-k8s-sentinel\n")
	sb.WriteString("webhooks:\n")
	sb.WriteString(fmt.Sprintf("  - name: %s.%s.svc\n", name, namespace))
	sb.WriteString("    admissionReviewVersions: [\"v1\"]\n")
	sb.WriteString("    clientConfig:\n")
	sb.WriteString("      service:\n")
	sb.WriteString(fmt.Sprintf("        name: %s\n", serviceName))
	sb.WriteString(fmt.Sprintf("        namespace: %s\n", namespace))
	sb.WriteString(fmt.Sprintf("        path: %s\n", path))
	sb.WriteString(fmt.Sprintf("        port: %d\n", port))
	sb.WriteString("    failurePolicy: Fail\n")
	sb.WriteString("    timeoutSeconds: 3\n")
	sb.WriteString("    sideEffects: None\n")
	sb.WriteString("    matchPolicy: Equivalent\n")
	sb.WriteString("    namespaceSelector:\n")
	sb.WriteString("      matchExpressions:\n")
	sb.WriteString("        - key: kubernetes.io/metadata.name\n")
	sb.WriteString("          operator: NotIn\n")
	sb.WriteString("          values: [\"kube-system\", \"kube-node-lease\", \"kube-public\"]\n")
	sb.WriteString("    rules:\n")
	sb.WriteString("      - operations: [\"CREATE\", \"UPDATE\"]\n")
	sb.WriteString("        apiGroups: [\"*\", \"apps\", \"batch\"]\n")
	sb.WriteString("        apiVersions: [\"v1\"]\n")
	sb.WriteString("        resources: [\"pods\", \"deployments\", \"statefulsets\", \"daemonsets\", \"jobs\"]\n")
	sb.WriteString("        scope: Namespaced\n")

	return sb.String()
}

// SynthesizeCertManagerCABundleRefresher synthesizes an automated cert-manager CA rotation Certificate resource.
func SynthesizeCertManagerCABundleRefresher(name, namespace, issuerName string) string {
	if namespace == "" {
		namespace = "sentinel-system"
	}
	if issuerName == "" {
		issuerName = "sentinel-ca-issuer"
	}

	var sb strings.Builder
	sb.WriteString("apiVersion: cert-manager.io/v1\n")
	sb.WriteString("kind: Certificate\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s-ca\n", name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	sb.WriteString("  labels:\n")
	sb.WriteString("    app.kubernetes.io/managed-by: cert-manager\n")
	sb.WriteString("    sentinel.defense.io/rotation-radar: active\n")
	sb.WriteString("spec:\n")
	sb.WriteString(fmt.Sprintf("  secretName: %s-ca-tls\n", name))
	sb.WriteString("  duration: 2160h # 90 days\n")
	sb.WriteString("  renewBefore: 720h # 30 days renewal buffer\n")
	sb.WriteString("  isCA: true\n")
	sb.WriteString("  privateKey:\n")
	sb.WriteString("    algorithm: ECDSA\n")
	sb.WriteString("    size: 384\n")
	sb.WriteString("    rotationPolicy: Always\n")
	sb.WriteString(fmt.Sprintf("  commonName: %s-root-ca\n", name))
	sb.WriteString("  dnsNames:\n")
	sb.WriteString(fmt.Sprintf("    - %s\n", name))
	sb.WriteString(fmt.Sprintf("    - %s.%s\n", name, namespace))
	sb.WriteString(fmt.Sprintf("    - %s.%s.svc\n", name, namespace))
	sb.WriteString(fmt.Sprintf("    - %s.%s.svc.cluster.local\n", name, namespace))
	sb.WriteString("  issuerRef:\n")
	sb.WriteString(fmt.Sprintf("    name: %s\n", issuerName))
	sb.WriteString("    kind: ClusterIssuer\n")
	sb.WriteString("    group: cert-manager.io\n")

	return sb.String()
}

// SynthesizeWebhookAPIServerAlertRule synthesizes a PrometheusRule for admission webhook latency and certificate alerts.
func SynthesizeWebhookAPIServerAlertRule(name, webhookName, namespace string) string {
	if namespace == "" {
		namespace = "monitoring"
	}

	var sb strings.Builder
	sb.WriteString("apiVersion: monitoring.coreos.com/v1\n")
	sb.WriteString("kind: PrometheusRule\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s-webhook-alerts\n", name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	sb.WriteString("  labels:\n")
	sb.WriteString("    role: alert-rules\n")
	sb.WriteString("    sentinel.defense.io/radar: admission-webhook\n")
	sb.WriteString("spec:\n")
	sb.WriteString("  groups:\n")
	sb.WriteString(fmt.Sprintf("    - name: %s-admission-webhook.rules\n", name))
	sb.WriteString("      rules:\n")
	sb.WriteString("        - alert: AdmissionWebhookLatencyStall\n")
	sb.WriteString(fmt.Sprintf("          expr: histogram_quantile(0.99, sum(rate(apiserver_admission_webhook_admission_duration_seconds_bucket{name=~\"%s.*\"}[5m])) by (le, name)) > 0.5\n", webhookName))
	sb.WriteString("          for: 5m\n")
	sb.WriteString("          labels:\n")
	sb.WriteString("            severity: warning\n")
	sb.WriteString("          annotations:\n")
	sb.WriteString("            summary: Admission webhook p99 latency exceeds 500ms ceiling\n")
	sb.WriteString("            description: Webhook {{ $labels.name }} is taking longer than 500ms to evaluate admission requests, risking API server request queue saturation.\n")
	sb.WriteString("        - alert: AdmissionWebhookRejectionSpike\n")
	sb.WriteString(fmt.Sprintf("          expr: sum(rate(apiserver_admission_webhook_rejection_count{name=~\"%s.*\"}[5m])) by (name) > 5\n", webhookName))
	sb.WriteString("          for: 5m\n")
	sb.WriteString("          labels:\n")
	sb.WriteString("            severity: critical\n")
	sb.WriteString("          annotations:\n")
	sb.WriteString("            summary: Admission webhook error or rejection spike detected\n")
	sb.WriteString("            description: Webhook {{ $labels.name }} is rejecting admission requests at an elevated rate (> 5/s).\n")
	sb.WriteString("        - alert: AdmissionWebhookCAExpiringSoon\n")
	sb.WriteString(fmt.Sprintf("          expr: (certmanager_certificate_expiration_timestamp_seconds{name=~\"%s.*\"} - time()) < (30 * 24 * 3600)\n", webhookName))
	sb.WriteString("          for: 1h\n")
	sb.WriteString("          labels:\n")
	sb.WriteString("            severity: critical\n")
	sb.WriteString("          annotations:\n")
	sb.WriteString("            summary: Admission webhook CA certificate expiring in fewer than 30 days\n")
	sb.WriteString("            description: The CA certificate for {{ $labels.name }} expires within 30 days. Verify cert-manager automated rotation.\n")

	return sb.String()
}

// WriteSynthesizedPolicies persists declarative webhook policies, cert-manager configs, and Prometheus alert rules to target directory.
func WriteSynthesizedPolicies(outDir, name, serviceName, namespace, path string, port int32) error {
	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory for synthesized webhook policies: %w", err)
	}

	whYAML := SynthesizeHardenedValidatingWebhook(name, serviceName, namespace, path, port)
	certYAML := SynthesizeCertManagerCABundleRefresher(name, namespace, "sentinel-ca-issuer")
	alertYAML := SynthesizeWebhookAPIServerAlertRule("sentinel", name, "monitoring")

	whPath := filepath.Join(cleanDir, "webhook-hardened.yaml")
	certPath := filepath.Join(cleanDir, "cert-manager-ca.yaml")
	alertPath := filepath.Join(cleanDir, "webhook-alerts.yaml")

	if err := os.WriteFile(whPath, []byte(whYAML), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", whPath, err)
	}
	if err := os.WriteFile(certPath, []byte(certYAML), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", certPath, err)
	}
	if err := os.WriteFile(alertPath, []byte(alertYAML), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", alertPath, err)
	}

	return nil
}
