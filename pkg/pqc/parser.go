package pqc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reK8sArg     = regexp.MustCompile(`^\s*-\s*--([a-zA-Z0-9_-]+)(?:=|\s+)(.*)$`)
	reNixAttr    = regexp.MustCompile(`^\s*([a-zA-Z0-9_."]+)\s*=\s*(.*?);?\s*$`)
	reNixListStr = regexp.MustCompile(`"([^"]+)"`)
)

// ParseK8sControlPlaneManifest parses Kubernetes pod/manifest YAML files for control plane TLS flags.
func ParseK8sControlPlaneManifest(filePath string) (*K8sControlPlaneTLSConfig, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat manifest file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("manifest file %s exceeds safety limit of %d bytes", cleanPath, MaxManifestBytes)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open manifest file %s: %w", cleanPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	cfg := &K8sControlPlaneTLSConfig{
		FilePath:  cleanPath,
		StartLine: 1,
		RawArgs:   make(map[string]string),
	}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		line := scanner.Text()

		// Detect component name from metadata or command
		if strings.Contains(line, "name: kube-apiserver") || strings.Contains(line, "- kube-apiserver") {
			if cfg.Component == "" {
				cfg.Component = "kube-apiserver"
			}
		} else if strings.Contains(line, "name: etcd") || strings.Contains(line, "- etcd") {
			if cfg.Component == "" {
				cfg.Component = "etcd"
			}
		} else if strings.Contains(line, "name: kubelet") || strings.Contains(line, "kind: KubeletConfiguration") {
			if cfg.Component == "" {
				cfg.Component = "kubelet"
			}
		}

		// Extract CLI flag arguments
		matches := reK8sArg.FindStringSubmatch(line)
		if len(matches) == 3 {
			argName := strings.TrimSpace(matches[1])
			argVal := strings.Trim(strings.TrimSpace(matches[2]), `"'`)
			cfg.RawArgs[argName] = argVal

			switch argName {
			case "tls-min-version":
				cfg.TLSMinVersion = argVal
			case "tls-cipher-suites":
				cfg.TLSCipherSuites = splitCleanList(argVal)
			case "tls-key-exchange-groups", "tls-curves":
				cfg.KeyExchangeGroups = splitCleanList(argVal)
			case "peer-tls-min-version":
				cfg.PeerTLSMinVersion = argVal
			case "peer-tls-cipher-suites":
				cfg.PeerTLSCipherSuites = splitCleanList(argVal)
			case "client-ca-file":
				cfg.ClientCAFile = argVal
			case "tls-cert-file":
				cfg.TLSCertFile = argVal
			case "tls-private-key-file":
				cfg.TLSPrivateKeyFile = argVal
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading %s: %w", cleanPath, err)
	}

	if cfg.Component == "" {
		base := strings.ToLower(filepath.Base(cleanPath))
		if strings.Contains(base, "apiserver") {
			cfg.Component = "kube-apiserver"
		} else if strings.Contains(base, "etcd") {
			cfg.Component = "etcd"
		} else if strings.Contains(base, "kubelet") {
			cfg.Component = "kubelet"
		} else {
			cfg.Component = "control-plane-tls"
		}
	}

	return cfg, nil
}

// ParseNixOSCryptoConfig parses declarative NixOS expressions for OpenSSL and GnuTLS configurations.
func ParseNixOSCryptoConfig(filePath string) (*NixOSCryptoConfig, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat NixOS crypto config %s: %w", cleanPath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("NixOS config %s exceeds safety limit of %d bytes", cleanPath, MaxManifestBytes)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open NixOS config %s: %w", cleanPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	cfg := &NixOSCryptoConfig{
		FilePath:  cleanPath,
		StartLine: 1,
	}

	lineNum := 0
	inOpenSSLProviders := false
	inOpenSSLGroups := false

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "security.pki") {
			cfg.SecurityPKIEnabled = true
		}

		// Check for provider lists: providers = [ "default" "oqsprovider" ]
		if strings.Contains(trimmed, "providers") && strings.Contains(trimmed, "[") {
			inOpenSSLProviders = true
		}
		if inOpenSSLProviders {
			matches := reNixListStr.FindAllStringSubmatch(trimmed, -1)
			for _, m := range matches {
				if len(m) == 2 {
					cfg.OpenSSLProviders = append(cfg.OpenSSLProviders, m[1])
				}
			}
			if strings.Contains(trimmed, "]") {
				inOpenSSLProviders = false
			}
		}

		// Check for default groups in OpenSSL or system config
		if (strings.Contains(trimmed, "default_groups") || strings.Contains(trimmed, "Groups") || strings.Contains(trimmed, "curves")) && strings.Contains(trimmed, "[") {
			inOpenSSLGroups = true
		}
		if inOpenSSLGroups {
			matches := reNixListStr.FindAllStringSubmatch(trimmed, -1)
			for _, m := range matches {
				if len(m) == 2 {
					cfg.OpenSSLDefaultGroups = append(cfg.OpenSSLDefaultGroups, m[1])
				}
			}
			if strings.Contains(trimmed, "]") {
				inOpenSSLGroups = false
			}
		}

		// Check for single string groups (e.g. Groups = "X25519MLKEM768:x25519_kyber768:P-256";)
		if (strings.Contains(trimmed, "Groups =") || strings.Contains(trimmed, "default_groups =")) && strings.Contains(trimmed, `"`) {
			parts := reNixListStr.FindAllStringSubmatch(trimmed, -1)
			for _, p := range parts {
				if len(p) == 2 {
					for _, item := range strings.Split(p[1], ":") {
						itemClean := strings.TrimSpace(item)
						if itemClean != "" {
							cfg.OpenSSLDefaultGroups = append(cfg.OpenSSLDefaultGroups, itemClean)
						}
					}
				}
			}
		}

		// Check for OpenSSL MinProtocol
		if strings.Contains(trimmed, "MinProtocol") || strings.Contains(trimmed, "min_protocol") {
			parts := reNixListStr.FindAllStringSubmatch(trimmed, -1)
			if len(parts) > 0 && len(parts[0]) == 2 {
				cfg.OpenSSLMinProtocol = parts[0][1]
			}
		}

		// Check for GnuTLS priority string
		if strings.Contains(trimmed, "gnutls.priority") || strings.Contains(trimmed, "priorityString") {
			parts := reNixListStr.FindAllStringSubmatch(trimmed, -1)
			if len(parts) > 0 && len(parts[0]) == 2 {
				cfg.GnuTLSPriorityString = parts[0][1]
				// Parse any inline groups
				for _, token := range strings.Split(parts[0][1], ":") {
					if strings.HasPrefix(token, "+GROUP-") {
						cfg.GnuTLSGroups = append(cfg.GnuTLSGroups, strings.TrimPrefix(token, "+GROUP-"))
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading NixOS config %s: %w", cleanPath, err)
	}

	return cfg, nil
}

// ParsePQCTelemetryJSON parses runtime TLS handshake telemetry.
func ParsePQCTelemetryJSON(filePath string) (*PQCRuntimeTelemetry, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat PQC telemetry file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("PQC telemetry %s exceeds safety limit of %d bytes", cleanPath, MaxTelemetryBytes)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PQC telemetry file %s: %w", cleanPath, err)
	}

	var telemetry PQCRuntimeTelemetry
	if err := json.Unmarshal(data, &telemetry); err != nil {
		return nil, fmt.Errorf("failed to parse PQC telemetry JSON %s: %w", cleanPath, err)
	}

	if len(telemetry.Handshakes) > MaxEndpoints {
		telemetry.Handshakes = telemetry.Handshakes[:MaxEndpoints]
	}

	return &telemetry, nil
}

// splitCleanList splits a comma- or colon-delimited string into sanitized tokens.
func splitCleanList(raw string) []string {
	var tokens []string
	delimiter := ","
	if !strings.Contains(raw, ",") && strings.Contains(raw, ":") {
		delimiter = ":"
	}
	for _, part := range strings.Split(raw, delimiter) {
		clean := strings.TrimSpace(part)
		if clean != "" {
			tokens = append(tokens, clean)
		}
	}
	return tokens
}
