package main

import (
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/webhook"
)

// runWebhookAudit coordinates Kubernetes Dynamic Admission Webhook and CA Rotation Radar auditing.
func runWebhookAudit(
	manifestPath, telemetryPath, synthOut string,
	strictMode bool,
	feed *intel.Feed,
	logInfo func(string, ...any),
	logErr func(string, ...any),
) ([]webhook.WebhookViolation, *webhook.WebhookSummary, *webhook.WebhookTelemetry) {
	if manifestPath == "" && telemetryPath == "" && synthOut == "" {
		return nil, nil, nil
	}

	report, err := webhook.ScanAdmissionWebhooks(manifestPath, telemetryPath, strictMode, feed)
	if err != nil {
		logErr("[-] Failed to audit admission webhook manifests/telemetry: %v\n", err)
		os.Exit(1)
	}

	if manifestPath != "" {
		logInfo("[+] Audited Kubernetes Admission Webhook Manifests: %s (%d webhooks configured)\n", manifestPath, len(report.Configurations))
	}

	if telemetryPath != "" && report.Telemetry != nil {
		logInfo("[+] Reconciled Webhook Telemetry & CA Health: %s (%d metrics, %d CA certs)\n",
			telemetryPath, len(report.Telemetry.Metrics), len(report.Telemetry.CACertificates))
	}

	if len(report.Violations) > 0 {
		logInfo("[-] Identified %d Kubernetes admission webhook & CA rotation violations:\n", len(report.Violations))
		for i, v := range report.Violations {
			cveTag := ""
			if v.MatchedCVE != "" {
				cveTag = " [" + v.MatchedCVE + "]"
			}
			logInfo("  [%d] [%s] %s%s: %s (Severity: %s, CVSS: %.1f)\n",
				i+1, v.RuleID, v.WebhookName, cveTag, v.Description, v.Severity, v.CVSSScore)
		}
	} else {
		logInfo("[+] Zero Kubernetes admission webhook violations detected.\n")
	}

	if synthOut != "" {
		logInfo("[+] Synthesizing Hardened Admission Webhook Policies into: %s\n", synthOut)
		whName := "sentinel-validating-webhook"
		svcName := "sentinel-webhook-service"
		ns := "sentinel-system"
		path := "/validate"
		port := int32(443)

		if len(report.Configurations) > 0 {
			cfg := report.Configurations[0]
			whName = cfg.Name
			if cfg.Service != nil {
				svcName = cfg.Service.Name
				ns = cfg.Service.Namespace
				path = cfg.Service.Path
				port = cfg.Service.Port
			}
		}

		if err := webhook.WriteSynthesizedPolicies(synthOut, whName, svcName, ns, path, port); err != nil {
			logErr("[-] Failed to synthesize admission webhook policies: %v\n", err)
			os.Exit(1)
		}
		logInfo("  -> Generated ValidatingWebhookConfiguration, cert-manager CA renewal Certificate, and PrometheusRule alert policies.\n")
	}

	logInfo("[+] Admission Webhook Posture: Compliance Score: %.1f%% (Validating: %d, Mutating: %d, Expired CA: %d, Timeout Risk: %d, Avg P99: %.1fms)\n",
		report.Summary.ComplianceScore,
		report.Summary.ValidatingCount,
		report.Summary.MutatingCount,
		report.Summary.ExpiredCACount,
		report.Summary.TimeoutRiskCount,
		report.Summary.AverageP99LatencyMs,
	)

	if strictMode && (report.Summary.CriticalCount > 0 || report.Summary.ComplianceScore < 70.0) {
		logErr("[-] FATAL: Admission Webhook posture NON_COMPLIANT in strict mode (Critical violation or Score < 70%%)\n")
		os.Exit(1)
	}

	return report.Violations, &report.Summary, report.Telemetry
}
