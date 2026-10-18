package webhook

import "github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"

// Canonical Dynamic Admission Webhook and CA Rotation Radar rule catalog (WH-RADAR-001 through WH-RADAR-012).
var rulesCatalog = map[string]WebhookRule{
	"WH-RADAR-001": {
		ID:          "WH-RADAR-001",
		Title:       "Security-Critical Admission Webhook Configured with failurePolicy: Ignore",
		Description: "Admission webhook enforcing security, policy, or validation gates is configured with failurePolicy: Ignore, allowing complete admission validation bypass under webhook failure, timeout, or network partition.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.2,
		Remediation: "Set failurePolicy to Fail for security-critical webhooks and ensure high-availability webhook replica deployment with podAntiAffinity.",
		MatchedCVE:  "CVE-2026-52194",
	},
	"WH-RADAR-002": {
		ID:          "WH-RADAR-002",
		Title:       "Missing clientConfig.caBundle or Insecure Skip TLS Verification Enabled",
		Description: "The admission webhook clientConfig is missing caBundle or specifies insecureSkipTLSVerify: true, permitting Man-in-the-Middle (MitM) TLS interception or spoofed admission payloads.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.0,
		Remediation: "Inject trusted root CA bundle into clientConfig.caBundle via cert-manager (cert-manager.io/inject-ca-from) and enforce TLS verification.",
	},
	"WH-RADAR-003": {
		ID:          "WH-RADAR-003",
		Title:       "Admission Webhook CA Certificate is Expired in caBundle",
		Description: "The X.509 CA certificate in clientConfig.caBundle has expired, triggering TLS handshake failures; with failurePolicy: Fail, this blocks cluster workload admissions.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.4,
		Remediation: "Immediately rotate expired CA certificates using cert-manager or internal PKI and update the caBundle in WebhookConfiguration manifests.",
	},
	"WH-RADAR-004": {
		ID:          "WH-RADAR-004",
		Title:       "Admission Webhook CA Certificate Expiring Soon (< 30 Days)",
		Description: "The X.509 CA certificate in clientConfig.caBundle will expire in fewer than 30 days without automated rotation, risking cluster-wide admission disruption.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Remediation: "Establish automated CA rotation schedules and renew CA certificate before reaching the 30-day renewal threshold.",
	},
	"WH-RADAR-005": {
		ID:          "WH-RADAR-005",
		Title:       "Admission Webhook timeoutSeconds Exceeds Safe Threshold (> 3s)",
		Description: "Webhook timeoutSeconds is set above the recommended threshold (> 3s, up to 30s), causing API server request queue saturation and thread starvation during workload creation bursts.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.3,
		Remediation: "Reduce timeoutSeconds to 3 seconds or fewer, optimize webhook admission logic, and ensure asynchronous processing for non-blocking audits.",
		MatchedCVE:  "CVE-2026-52194",
	},
	"WH-RADAR-006": {
		ID:          "WH-RADAR-006",
		Title:       "failurePolicy: Fail Webhook Lacks kube-system Namespace Exemption",
		Description: "Webhook with failurePolicy: Fail intercepts core system namespaces without namespaceSelector exemption for kube-system, risking cluster bootstrap deadlock during control-plane recovery.",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Remediation: "Add namespaceSelector to exclude kube-system (e.g. kubernetes.io/metadata.name NotIn [kube-system]) to prevent control plane deadlocks.",
	},
	"WH-RADAR-007": {
		ID:          "WH-RADAR-007",
		Title:       "Deprecated Admission Webhook API Version (v1beta1)",
		Description: "Webhook configuration declares admission.k8s.io/v1beta1 admissionReviewVersions, which is deprecated and removed in recent Kubernetes releases.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.5,
		Remediation: "Upgrade admission webhook review versions to admission.k8s.io/v1 in admissionReviewVersions array.",
	},
	"WH-RADAR-008": {
		ID:          "WH-RADAR-008",
		Title:       "Mutating Webhook Lacks reinvocationPolicy or Granular Object Scope",
		Description: "MutatingWebhookConfiguration intercepts broad cluster resources without setting reinvocationPolicy: IfNeeded, leading to non-deterministic mutation order or conflicting mutations.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.0,
		Remediation: "Set reinvocationPolicy to IfNeeded or narrow objectSelector / rules to specific resources requiring declarative mutation.",
	},
	"WH-RADAR-009": {
		ID:          "WH-RADAR-009",
		Title:       "Admission Webhook sideEffects Not Set to None or NoneOnDryRun",
		Description: "Webhook declares sideEffects: Some or Unknown, preventing Kubernetes API server dry-run requests from safely validating admission without mutating external state.",
		Severity:    intel.SeverityMedium,
		CVSSScore:   5.8,
		Remediation: "Refactor admission webhook handlers to eliminate external out-of-band side effects and declare sideEffects: None or NoneOnDryRun.",
	},
	"WH-RADAR-010": {
		ID:          "WH-RADAR-010",
		Title:       "Runtime Webhook Telemetry Shows P99 Latency Stall (> 500ms)",
		Description: "Runtime telemetry indicates admission webhook p99 latency exceeds 500ms, degrading API server admission responsiveness and triggering pod scheduling stalls.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.9,
		Remediation: "Scale webhook pod replicas, tune CPU/memory requests, enable connection keep-alive, and profile webhook internal handler execution times.",
	},
	"WH-RADAR-011": {
		ID:          "WH-RADAR-011",
		Title:       "Runtime Webhook Telemetry Shows Elevated Admission Error/Timeout Rate (> 5%)",
		Description: "Runtime telemetry indicates webhook error or timeout percentage exceeds 5%, causing unexpected workload creation rejections and degraded cluster availability.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Remediation: "Investigate webhook pod health, check network policies between API server and webhook service, and review admission controller logs.",
	},
	"WH-RADAR-012": {
		ID:          "WH-RADAR-012",
		Title:       "Admission Webhook Direct URL Targets Insecure HTTP or Unauthenticated External IP",
		Description: "Webhook clientConfig specifies a direct URL targeting an insecure plaintext HTTP endpoint or unauthenticated external IP address instead of an in-cluster HTTPS Service.",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Remediation: "Migrate webhook endpoint to an in-cluster Kubernetes Service with TLS termination and mutual authentication.",
	},
}

// GetRule retrieves a canonical admission webhook rule by identifier.
func GetRule(id string) (WebhookRule, bool) {
	rule, exists := rulesCatalog[id]
	return rule, exists
}

// AllRules returns a copy of the canonical admission webhook rule catalog.
func AllRules() []WebhookRule {
	list := make([]WebhookRule, 0, len(rulesCatalog))
	for _, rule := range rulesCatalog {
		list = append(list, rule)
	}
	return list
}
