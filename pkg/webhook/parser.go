package webhook

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reDocKindWebhook      = regexp.MustCompile(`(?i)^kind:\s*(ValidatingWebhookConfiguration|MutatingWebhookConfiguration)`)
	reWebhookName         = regexp.MustCompile(`(?i)^\s*-\s*name:\s*["']?([^"'\s]+)["']?`)
	reFailurePolicy       = regexp.MustCompile(`(?i)^\s*failurePolicy:\s*["']?([a-zA-Z]+)["']?`)
	reTimeoutSeconds      = regexp.MustCompile(`(?i)^\s*timeoutSeconds:\s*(\d+)`)
	reSideEffects         = regexp.MustCompile(`(?i)^\s*sideEffects:\s*["']?([a-zA-Z]+)["']?`)
	reReinvocationPolicy  = regexp.MustCompile(`(?i)^\s*reinvocationPolicy:\s*["']?([a-zA-Z]+)["']?`)
	reCABundle            = regexp.MustCompile(`(?i)^\s*caBundle:\s*["']?([^"'\s]+)["']?`)
	reInsecureSkipTLS     = regexp.MustCompile(`(?i)^\s*insecureSkipTLSVerify:\s*(true|false)`)
	reServiceName         = regexp.MustCompile(`(?i)^\s*name:\s*["']?([^"'\s]+)["']?`)
	reServiceNamespace    = regexp.MustCompile(`(?i)^\s*namespace:\s*["']?([^"'\s]+)["']?`)
	reServicePath         = regexp.MustCompile(`(?i)^\s*path:\s*["']?([^"'\s]+)["']?`)
	reServicePort         = regexp.MustCompile(`(?i)^\s*port:\s*(\d+)`)
	reDirectURL           = regexp.MustCompile(`(?i)^\s*url:\s*["']?([^"'\s]+)["']?`)
	reAdmissionReviewVer  = regexp.MustCompile(`(?i)^\s*-\s*["']?([a-zA-Z0-9_]+)["']?`)
	reNamespaceExemption  = regexp.MustCompile(`(?i)(kube-system|control-plane)`)
)

// ParseAdmissionWebhooks parses Kubernetes admission webhook configurations with memory safety invariants.
func ParseAdmissionWebhooks(content, filePath string) ([]WebhookConfig, error) {
	if int64(len(content)) > MaxManifestBytes {
		return nil, fmt.Errorf("admission webhook manifest payload exceeds maximum size limit (%d bytes)", MaxManifestBytes)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	var configs []WebhookConfig

	var currentKind WebhookType
	var inWebhooksBlock bool
	var currentWH *WebhookConfig
	var inClientConfig bool
	var inServiceBlock bool
	var inNamespaceSelector bool
	var inReviewVersions bool

	flushCurrent := func() {
		if currentWH != nil && currentWH.Name != "" {
			finalizeWebhookConfig(currentWH)
			configs = append(configs, *currentWH)
			currentWH = nil
		}
	}

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)

		// Document delimiter
		if strings.HasPrefix(trimmed, "---") {
			flushCurrent()
			currentKind = ""
			inWebhooksBlock = false
			inClientConfig = false
			inServiceBlock = false
			inNamespaceSelector = false
			inReviewVersions = false
			continue
		}

		if m := reDocKindWebhook.FindStringSubmatch(trimmed); len(m) > 1 {
			flushCurrent()
			if strings.EqualFold(m[1], "MutatingWebhookConfiguration") {
				currentKind = WebhookTypeMutating
			} else {
				currentKind = WebhookTypeValidating
			}
			continue
		}

		if strings.HasPrefix(trimmed, "webhooks:") {
			flushCurrent()
			inWebhooksBlock = true
			continue
		}

		if !inWebhooksBlock || currentKind == "" {
			continue
		}

		// New webhook entry: - name: ...
		if m := reWebhookName.FindStringSubmatch(rawLine); len(m) > 1 {
			flushCurrent()
			currentWH = &WebhookConfig{
				Name:                    m[1],
				Type:                    currentKind,
				FailurePolicy:           FailurePolicyFail, // K8s default is Fail
				TimeoutSeconds:          10,                // K8s default is 10s
				SideEffects:             SideEffectSome,
				AdmissionReviewVersions: make([]string, 0),
				NamespaceSelector:       make(map[string]string),
				FilePath:                filePath,
				StartLine:               lineNum,
			}
			inClientConfig = false
			inServiceBlock = false
			inNamespaceSelector = false
			inReviewVersions = false
			continue
		}

		if currentWH == nil {
			continue
		}

		// State tracking for nested blocks
		if strings.HasPrefix(trimmed, "clientConfig:") {
			inClientConfig = true
			inServiceBlock = false
			inNamespaceSelector = false
			inReviewVersions = false
			continue
		}
		if inClientConfig && strings.HasPrefix(trimmed, "service:") {
			inServiceBlock = true
			if currentWH.Service == nil {
				currentWH.Service = &WebhookServiceRef{Port: 443}
			}
			continue
		}
		if strings.HasPrefix(trimmed, "namespaceSelector:") {
			inNamespaceSelector = true
			inClientConfig = false
			inServiceBlock = false
			inReviewVersions = false
			continue
		}
		if strings.HasPrefix(trimmed, "admissionReviewVersions:") {
			inReviewVersions = true
			inClientConfig = false
			inServiceBlock = false
			inNamespaceSelector = false
			continue
		}

		// Extract failurePolicy
		if m := reFailurePolicy.FindStringSubmatch(trimmed); len(m) > 1 {
			if strings.EqualFold(m[1], "Ignore") {
				currentWH.FailurePolicy = FailurePolicyIgnore
			} else {
				currentWH.FailurePolicy = FailurePolicyFail
			}
			continue
		}

		// Extract timeoutSeconds
		if m := reTimeoutSeconds.FindStringSubmatch(trimmed); len(m) > 1 {
			if sec, err := strconv.Atoi(m[1]); err == nil {
				currentWH.TimeoutSeconds = sec
			}
			continue
		}

		// Extract sideEffects
		if m := reSideEffects.FindStringSubmatch(trimmed); len(m) > 1 {
			switch strings.ToLower(m[1]) {
			case "none":
				currentWH.SideEffects = SideEffectNone
			case "noneondryrun":
				currentWH.SideEffects = SideEffectNoneOnDryRun
			default:
				currentWH.SideEffects = SideEffectSome
			}
			continue
		}

		// Extract reinvocationPolicy
		if m := reReinvocationPolicy.FindStringSubmatch(trimmed); len(m) > 1 {
			if strings.EqualFold(m[1], "IfNeeded") {
				currentWH.ReinvocationPolicy = ReinvocationIfNeeded
			} else {
				currentWH.ReinvocationPolicy = ReinvocationNever
			}
			continue
		}

		// Extract clientConfig fields
		if inClientConfig {
			if m := reCABundle.FindStringSubmatch(trimmed); len(m) > 1 {
				currentWH.CABundleRaw = m[1]
				continue
			}
			if m := reInsecureSkipTLS.FindStringSubmatch(trimmed); len(m) > 1 {
				currentWH.InsecureSkipTLSVerify = strings.EqualFold(m[1], "true")
				continue
			}
			if m := reDirectURL.FindStringSubmatch(trimmed); len(m) > 1 {
				currentWH.URL = m[1]
				continue
			}
			if inServiceBlock && currentWH.Service != nil {
				if m := reServiceName.FindStringSubmatch(trimmed); len(m) > 1 {
					currentWH.Service.Name = m[1]
					continue
				}
				if m := reServiceNamespace.FindStringSubmatch(trimmed); len(m) > 1 {
					currentWH.Service.Namespace = m[1]
					continue
				}
				if m := reServicePath.FindStringSubmatch(trimmed); len(m) > 1 {
					currentWH.Service.Path = m[1]
					continue
				}
				if m := reServicePort.FindStringSubmatch(trimmed); len(m) > 1 {
					if p, err := strconv.Atoi(m[1]); err == nil {
						currentWH.Service.Port = int32(p)
					}
					continue
				}
			}
		}

		// Extract namespaceSelector exemption
		if inNamespaceSelector {
			if reNamespaceExemption.MatchString(trimmed) {
				currentWH.ExemptsKubeSystem = true
			}
		}

		// Extract admissionReviewVersions
		if inReviewVersions {
			if m := reAdmissionReviewVer.FindStringSubmatch(trimmed); len(m) > 1 {
				currentWH.AdmissionReviewVersions = append(currentWH.AdmissionReviewVersions, m[1])
				continue
			}
		}
	}

	flushCurrent()
	return configs, nil
}

// ParseAdmissionWebhooksFile reads and parses a Kubernetes manifest file.
func ParseAdmissionWebhooksFile(filePath string) ([]WebhookConfig, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat manifest file: %w", err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("manifest file size (%d) exceeds %d bytes limit", info.Size(), MaxManifestBytes)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}
	return ParseAdmissionWebhooks(string(data), filePath)
}

// ParseWebhookTelemetryJSON unmarshals runtime admission webhook telemetry JSON.
func ParseWebhookTelemetryJSON(data []byte) (*WebhookTelemetry, error) {
	if int64(len(data)) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload exceeds %d bytes limit", MaxTelemetryBytes)
	}
	var tel WebhookTelemetry
	if err := json.Unmarshal(data, &tel); err != nil {
		return nil, fmt.Errorf("failed to parse webhook telemetry JSON: %w", err)
	}
	if len(tel.Metrics) > MaxTelemetryEvents {
		tel.Metrics = tel.Metrics[:MaxTelemetryEvents]
	}
	return &tel, nil
}

// finalizeWebhookConfig evaluates cryptographic CA certificate validity and remaining lifetime.
func finalizeWebhookConfig(cfg *WebhookConfig) {
	if cfg.CABundleRaw == "" {
		cfg.CAValid = false
		return
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(cfg.CABundleRaw)
	if err != nil {
		cfg.CAValid = false
		return
	}

	var certDER []byte
	block, _ := pem.Decode(decodedBytes)
	if block != nil {
		certDER = block.Bytes
	} else {
		certDER = decodedBytes
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		cfg.CAValid = false
		return
	}

	cfg.CAExpiration = cert.NotAfter
	now := time.Now()
	cfg.CADaysRemaining = int(cert.NotAfter.Sub(now).Hours() / 24)
	if now.After(cert.NotAfter) {
		cfg.CAExpired = true
		cfg.CAValid = false
	} else {
		cfg.CAExpired = false
		cfg.CAValid = true
	}
}
