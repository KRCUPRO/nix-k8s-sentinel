package webhook

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditWebhookConfig evaluates a single admission webhook against canonical security rules.
func AuditWebhookConfig(cfg WebhookConfig, feed *intel.Feed) []WebhookViolation {
	var violations []WebhookViolation

	addViolation := func(ruleID, desc, remediation string) {
		rule, ok := GetRule(ruleID)
		if !ok {
			return
		}
		cve := rule.MatchedCVE
		if cve == "" && feed != nil {
			for _, item := range feed.Items {
				if item.Component == "admission-webhook" && strings.EqualFold(string(item.Severity), string(rule.Severity)) {
					cve = item.ID
					break
				}
			}
		}

		violations = append(violations, WebhookViolation{
			RuleID:      ruleID,
			WebhookName: cfg.Name,
			WebhookType: cfg.Type,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Title:       rule.Title,
			Description: desc,
			Remediation: remediation,
			MatchedCVE:  cve,
			FilePath:    cfg.FilePath,
			StartLine:   cfg.StartLine,
		})
	}

	// 1. WH-RADAR-001: failurePolicy: Ignore on security-critical admission webhooks
	isSecurityGate := isSecurityCriticalWebhook(cfg.Name)
	if cfg.FailurePolicy == FailurePolicyIgnore && isSecurityGate {
		addViolation(
			"WH-RADAR-001",
			fmt.Sprintf("Webhook %q operates with failurePolicy: Ignore, permitting total admission bypass during webhook failures", cfg.Name),
			"Configure failurePolicy: Fail for security-critical webhooks and ensure multi-replica high availability",
		)
	}

	// 2. WH-RADAR-002: Missing caBundle or insecureSkipTLSVerify enabled
	if cfg.CABundleRaw == "" || cfg.InsecureSkipTLSVerify {
		addViolation(
			"WH-RADAR-002",
			fmt.Sprintf("Webhook %q is missing clientConfig.caBundle or has insecureSkipTLSVerify=true", cfg.Name),
			"Inject trusted cluster CA bundle via cert-manager.io/inject-ca-from annotation and disallow insecure TLS bypass",
		)
	}

	// 3. WH-RADAR-003: CA Certificate expired in caBundle
	if cfg.CAExpired {
		addViolation(
			"WH-RADAR-003",
			fmt.Sprintf("Webhook %q clientConfig.caBundle certificate expired on %s", cfg.Name, cfg.CAExpiration.Format("2006-01-02")),
			"Rotate expired CA certificate immediately using cert-manager or internal PKI to restore admission validation",
		)
	} else if cfg.CAValid && cfg.CADaysRemaining < MinCARenewalWindowDays {
		// 4. WH-RADAR-004: CA Certificate expiring soon (< 30 days)
		addViolation(
			"WH-RADAR-004",
			fmt.Sprintf("Webhook %q clientConfig.caBundle certificate expires in %d days (%s)", cfg.Name, cfg.CADaysRemaining, cfg.CAExpiration.Format("2006-01-02")),
			"Trigger automated CA rotation before certificate enters critical expiration window (< 30 days)",
		)
	}

	// 5. WH-RADAR-005: timeoutSeconds exceeds safe threshold (> 3s)
	if cfg.TimeoutSeconds > MaxSafeTimeoutSeconds {
		addViolation(
			"WH-RADAR-005",
			fmt.Sprintf("Webhook %q specifies timeoutSeconds=%d (exceeds safe %ds ceiling), risking API server queue saturation", cfg.Name, cfg.TimeoutSeconds, MaxSafeTimeoutSeconds),
			"Reduce timeoutSeconds to <= 3s to prevent API server thread pool exhaustion during pod creation bursts",
		)
	}

	// 6. WH-RADAR-006: failurePolicy: Fail lacks kube-system exemption
	if cfg.FailurePolicy == FailurePolicyFail && !cfg.ExemptsKubeSystem {
		addViolation(
			"WH-RADAR-006",
			fmt.Sprintf("Webhook %q uses failurePolicy: Fail without exempting kube-system namespace, risking control-plane deadlock", cfg.Name),
			"Add namespaceSelector excluding kube-system (kubernetes.io/metadata.name NotIn [kube-system])",
		)
	}

	// 7. WH-RADAR-007: Deprecated admissionReviewVersions (v1beta1)
	for _, ver := range cfg.AdmissionReviewVersions {
		if strings.EqualFold(ver, "v1beta1") {
			addViolation(
				"WH-RADAR-007",
				fmt.Sprintf("Webhook %q declares deprecated admissionReviewVersion %q", cfg.Name, ver),
				"Upgrade admission review versions to admission.k8s.io/v1",
			)
			break
		}
	}

	// 8. WH-RADAR-008: Mutating webhook lacks reinvocationPolicy: IfNeeded
	if cfg.Type == WebhookTypeMutating && cfg.ReinvocationPolicy != ReinvocationIfNeeded {
		addViolation(
			"WH-RADAR-008",
			fmt.Sprintf("Mutating webhook %q is missing reinvocationPolicy: IfNeeded", cfg.Name),
			"Set reinvocationPolicy: IfNeeded to guarantee idempotent ordering across mutating webhook invocations",
		)
	}

	// 9. WH-RADAR-009: sideEffects not None or NoneOnDryRun
	if cfg.SideEffects != SideEffectNone && cfg.SideEffects != SideEffectNoneOnDryRun {
		addViolation(
			"WH-RADAR-009",
			fmt.Sprintf("Webhook %q declares sideEffects=%q, preventing safe dry-run request evaluation", cfg.Name, cfg.SideEffects),
			"Ensure admission webhook produces no out-of-band side-effects and declare sideEffects: None",
		)
	}

	// 10. WH-RADAR-012: Direct URL targets plaintext HTTP or raw external IP
	if cfg.URL != "" {
		if strings.HasPrefix(strings.ToLower(cfg.URL), "http://") || isRawIPEndpoint(cfg.URL) {
			addViolation(
				"WH-RADAR-012",
				fmt.Sprintf("Webhook %q specifies direct URL endpoint targeting plaintext HTTP or raw external IP (%s)", cfg.Name, cfg.URL),
				"Migrate webhook endpoint to an in-cluster Kubernetes Service with mutual TLS termination",
			)
		}
	}

	return violations
}

// AuditWebhookTelemetry reconciles runtime latency and error metrics against admission webhooks.
func AuditWebhookTelemetry(tel *WebhookTelemetry, configs []WebhookConfig) []WebhookViolation {
	var violations []WebhookViolation
	if tel == nil {
		return violations
	}

	configMap := make(map[string]WebhookConfig)
	for _, cfg := range configs {
		configMap[cfg.Name] = cfg
	}

	for _, m := range tel.Metrics {
		cfg, exists := configMap[m.WebhookName]
		whType := WebhookTypeValidating
		filePath := ""
		lineNum := 1
		if exists {
			whType = cfg.Type
			filePath = cfg.FilePath
			lineNum = cfg.StartLine
		}

		// WH-RADAR-010: P99 Latency stall > 500ms
		if m.P99Ms > CriticalP99LatencyMs || m.StallWarning {
			rule, _ := GetRule("WH-RADAR-010")
			violations = append(violations, WebhookViolation{
				RuleID:      "WH-RADAR-010",
				WebhookName: m.WebhookName,
				WebhookType: whType,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Runtime telemetry shows webhook %q p99 latency is %.1fms (exceeds %.0fms threshold)", m.WebhookName, m.P99Ms, CriticalP99LatencyMs),
				Remediation: rule.Remediation,
				FilePath:    filePath,
				StartLine:   lineNum,
			})
		}

		// WH-RADAR-011: Elevated error/timeout rate > 5%
		if m.ErrorRatePercent > MaxAcceptableErrorRate || m.TimeoutCount > 10 {
			rule, _ := GetRule("WH-RADAR-011")
			violations = append(violations, WebhookViolation{
				RuleID:      "WH-RADAR-011",
				WebhookName: m.WebhookName,
				WebhookType: whType,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Runtime telemetry shows webhook %q error/timeout rate is %.1f%% (exceeds %.0f%% baseline)", m.WebhookName, m.ErrorRatePercent, MaxAcceptableErrorRate),
				Remediation: rule.Remediation,
				FilePath:    filePath,
				StartLine:   lineNum,
			})
		}
	}

	// Inspect CA certificates in telemetry
	for _, cert := range tel.CACertificates {
		if cert.IsExpired {
			rule, _ := GetRule("WH-RADAR-003")
			violations = append(violations, WebhookViolation{
				RuleID:      "WH-RADAR-003",
				WebhookName: cert.CertName,
				WebhookType: WebhookTypeValidating,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Runtime CA certificate %q (issuer: %s) expired on %s", cert.CertName, cert.Issuer, cert.NotAfter.Format("2006-01-02")),
				Remediation: rule.Remediation,
			})
		} else if cert.DaysRemaining < MinCARenewalWindowDays && !cert.AutoRotationEnabled {
			rule, _ := GetRule("WH-RADAR-004")
			violations = append(violations, WebhookViolation{
				RuleID:      "WH-RADAR-004",
				WebhookName: cert.CertName,
				WebhookType: WebhookTypeValidating,
				Severity:    rule.Severity,
				CVSSScore:   rule.CVSSScore,
				Title:       rule.Title,
				Description: fmt.Sprintf("Runtime CA certificate %q expires in %d days without automated cert-manager rotation", cert.CertName, cert.DaysRemaining),
				Remediation: rule.Remediation,
			})
		}
	}

	return violations
}

// ComputeWebhookCompliance calculates a deterministic compliance score (0.0% to 100.0%).
func ComputeWebhookCompliance(totalWebhooks int, violations []WebhookViolation) float64 {
	if totalWebhooks <= 0 && len(violations) == 0 {
		return 100.0
	}

	deductions := 0.0
	ruleSeen := make(map[string]bool)

	for _, v := range violations {
		key := fmt.Sprintf("%s:%s", v.WebhookName, v.RuleID)
		if ruleSeen[key] {
			continue
		}
		ruleSeen[key] = true

		switch v.Severity {
		case intel.SeverityCritical:
			deductions += 25.0
		case intel.SeverityHigh:
			deductions += 10.0
		case intel.SeverityMedium:
			deductions += 4.0
		case intel.SeverityLow:
			deductions += 1.0
		}
	}

	score := 100.0 - deductions
	if score < 0.0 {
		score = 0.0
	}
	return math.Round(score*10) / 10
}

// GenerateWebhookAuditReport aggregates findings, summaries, and scores across webhooks.
func GenerateWebhookAuditReport(configs []WebhookConfig, tel *WebhookTelemetry, feed *intel.Feed) *WebhookAuditReport {
	var allViolations []WebhookViolation

	for _, cfg := range configs {
		allViolations = append(allViolations, AuditWebhookConfig(cfg, feed)...)
	}

	if tel != nil {
		allViolations = append(allViolations, AuditWebhookTelemetry(tel, configs)...)
	}

	summary := WebhookSummary{
		TotalWebhooksScanned: len(configs),
	}

	highRiskMap := make(map[string]bool)
	totalP99 := 0.0
	p99Count := 0

	for _, cfg := range configs {
		if cfg.Type == WebhookTypeMutating {
			summary.MutatingCount++
		} else {
			summary.ValidatingCount++
		}
	}

	for _, v := range allViolations {
		switch v.Severity {
		case intel.SeverityCritical:
			summary.CriticalCount++
			highRiskMap[v.WebhookName] = true
		case intel.SeverityHigh:
			summary.HighCount++
			highRiskMap[v.WebhookName] = true
		case intel.SeverityMedium:
			summary.MediumCount++
		case intel.SeverityLow:
			summary.LowCount++
		}

		if v.RuleID == "WH-RADAR-001" {
			summary.BypassRiskCount++
		}
		if v.RuleID == "WH-RADAR-003" {
			summary.ExpiredCACount++
		}
		if v.RuleID == "WH-RADAR-004" {
			summary.ExpiringCACount++
		}
		if v.RuleID == "WH-RADAR-005" || v.RuleID == "WH-RADAR-010" {
			summary.TimeoutRiskCount++
		}
	}

	if tel != nil {
		for _, m := range tel.Metrics {
			totalP99 += m.P99Ms
			p99Count++
		}
	}
	if p99Count > 0 {
		summary.AverageP99LatencyMs = math.Round((totalP99/float64(p99Count))*10) / 10
	}

	for name := range highRiskMap {
		if name != "" {
			summary.HighRiskWebhookNames = append(summary.HighRiskWebhookNames, name)
		}
	}

	summary.ComplianceScore = ComputeWebhookCompliance(len(configs), allViolations)
	if len(allViolations) == 0 {
		summary.CompliantWebhooks = len(configs)
	} else {
		// Count webhooks without critical or high violations
		violatingWebhooks := make(map[string]bool)
		for _, v := range allViolations {
			violatingWebhooks[v.WebhookName] = true
		}
		compliant := 0
		for _, c := range configs {
			if !violatingWebhooks[c.Name] {
				compliant++
			}
		}
		summary.CompliantWebhooks = compliant
	}

	return &WebhookAuditReport{
		Configurations: configs,
		Violations:     allViolations,
		Summary:        summary,
		Telemetry:      tel,
	}
}

func isSecurityCriticalWebhook(name string) bool {
	lower := strings.ToLower(name)
	keywords := []string{"gatekeeper", "kyverno", "security", "sentinel", "policy", "validate", "auth", "admission"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isRawIPEndpoint(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return net.ParseIP(host) != nil
}
