package clustermesh

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	rxClusterName     = regexp.MustCompile(`(?i)(?:cluster-name|clusterName)\s*[:=]\s*["']?([a-zA-Z0-9_-]+)["']?`)
	rxClusterID       = regexp.MustCompile(`(?i)(?:cluster-id|clusterID)\s*[:=]\s*["']?([0-9]+)["']?`)
	rxEncryptionType  = regexp.MustCompile(`(?i)(?:encryption\.type|encryptionType|encryption-mode|encryption)\s*[:=]\s*["']?([a-zA-Z0-9_-]+)["']?`)
	rxTunnelProtocol  = regexp.MustCompile(`(?i)(?:tunnel-protocol|tunnelProtocol|tunnel)\s*[:=]\s*["']?([a-zA-Z0-9_-]+)["']?`)
	rxEtcdTLS         = regexp.MustCompile(`(?i)(?:etcd-tls|etcdTLS|tls\.enabled)\s*[:=]\s*["']?(true|false)["']?`)
	rxCACert          = regexp.MustCompile(`(?i)(?:ca-cert|caCert|ca\.crt|cacert)\s*[:=]\s*["']?([^"'\s]+)["']?`)
	rxClientCert      = regexp.MustCompile(`(?i)(?:client-cert|clientCert|tls\.crt)\s*[:=]\s*["']?([^"'\s]+)["']?`)
	rxGlobalService   = regexp.MustCompile(`(?i)io\.cilium/global-service\s*[:=]\s*["']?(true|false)["']?`)
	rxSharedService   = regexp.MustCompile(`(?i)io\.cilium/shared-service\s*[:=]\s*["']?(true|false)["']?`)
	rxKind            = regexp.MustCompile(`(?i)^kind\s*:\s*([a-zA-Z0-9]+)`)
	rxMetadataName    = regexp.MustCompile(`(?i)^[ \t]*name\s*:\s*["']?([a-zA-Z0-9_-]+)["']?`)
	rxNamespace       = regexp.MustCompile(`(?i)^[ \t]*namespace\s*:\s*["']?([a-zA-Z0-9_-]+)["']?`)
	rxClusterSelector = regexp.MustCompile(`(?i)(?:cluster|@cluster)\s*[:=]\s*["']?([a-zA-Z0-9_*-]+)["']?`)
	rxBackendCount    = regexp.MustCompile(`(?i)(?:backend-count|backendCount|endpoints)\s*[:=]\s*["']?([0-9]+)["']?`)
)

// ParseManifestFile parses Kubernetes YAML and NixOS expressions, returning extracted configs, services, and policies.
func ParseManifestFile(filePath string) ([]ClusterMeshConfig, []GlobalServiceConfig, []MeshNetworkPolicyConfig, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to stat manifest file: %w", err)
	}
	if fi.Size() > MaxManifestBytes {
		return nil, nil, nil, fmt.Errorf("manifest file %s exceeds %d bytes ceiling (size: %d)", filePath, MaxManifestBytes, fi.Size())
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open manifest file: %w", err)
	}
	defer f.Close()

	var (
		configs  []ClusterMeshConfig
		services []GlobalServiceConfig
		policies []MeshNetworkPolicyConfig
	)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	lineNum := 0
	docLines := make([]string, 0, 100)
	docStartLine := 1

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			return nil, nil, nil, fmt.Errorf("manifest file %s exceeds %d lines ceiling", filePath, MaxAllowedScanLines)
		}
		text := scanner.Text()

		if strings.TrimSpace(text) == "---" {
			if len(docLines) > 0 {
				cfgs, svcs, pols := parseDocument(docLines, docStartLine, filePath)
				configs = append(configs, cfgs...)
				services = append(services, svcs...)
				policies = append(policies, pols...)
				docLines = docLines[:0]
			}
			docStartLine = lineNum + 1
			continue
		}
		docLines = append(docLines, text)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("error reading manifest file: %w", err)
	}

	if len(docLines) > 0 {
		cfgs, svcs, pols := parseDocument(docLines, docStartLine, filePath)
		configs = append(configs, cfgs...)
		services = append(services, svcs...)
		policies = append(policies, pols...)
	}

	return configs, services, policies, nil
}

func parseDocument(lines []string, startLine int, filePath string) ([]ClusterMeshConfig, []GlobalServiceConfig, []MeshNetworkPolicyConfig) {
	var (
		configs  []ClusterMeshConfig
		services []GlobalServiceConfig
		policies []MeshNetworkPolicyConfig

		currentKind      string
		currentName      string
		currentNamespace string = "default"
		clusterName      string
		clusterID        int = -1
		encMode          TunnelEncryptionMode = EncryptionNone
		tunnelProto      string
		etcdTLS          bool
		etcdTLSFound     bool
		caCert           string
		clientCert       string
		isGlobal         bool
		isShared         bool = true
		isExport         bool
		backendCount     int
		clusterSelector  string
		inMetadata       bool
		inAnnotations    bool
		lineOfKind       int = startLine
	)

	for i, line := range lines {
		absLine := startLine + i
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if m := rxKind.FindStringSubmatch(trimmed); len(m) > 1 {
			currentKind = m[1]
			lineOfKind = absLine
		}

		if strings.HasPrefix(trimmed, "metadata:") {
			inMetadata = true
			inAnnotations = false
			continue
		}

		if inMetadata {
			if strings.HasPrefix(line, "  annotations:") || strings.HasPrefix(line, "    annotations:") {
				inAnnotations = true
				continue
			}
			if inAnnotations {
				if m := rxGlobalService.FindStringSubmatch(trimmed); len(m) > 1 {
					isGlobal = strings.ToLower(m[1]) == "true"
				}
				if m := rxSharedService.FindStringSubmatch(trimmed); len(m) > 1 {
					isShared = strings.ToLower(m[1]) == "true"
				}
				if !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && !strings.HasPrefix(line, "  ") {
					inAnnotations = false
				}
			}
			if m := rxMetadataName.FindStringSubmatch(line); len(m) > 1 && currentName == "" {
				currentName = m[1]
			}
			if m := rxNamespace.FindStringSubmatch(line); len(m) > 1 {
				currentNamespace = m[1]
			}
		}

		if m := rxClusterName.FindStringSubmatch(trimmed); len(m) > 1 {
			clusterName = m[1]
		}
		if m := rxClusterID.FindStringSubmatch(trimmed); len(m) > 1 {
			if id, err := strconv.Atoi(m[1]); err == nil {
				clusterID = id
			}
		}
		if m := rxEncryptionType.FindStringSubmatch(trimmed); len(m) > 1 {
			val := strings.ToLower(m[1])
			if strings.Contains(val, "wireguard") {
				encMode = EncryptionWireGuard
			} else if strings.Contains(val, "ipsec") {
				encMode = EncryptionIPsec
			} else if val == "none" || val == "disabled" {
				encMode = EncryptionNone
			}
		}
		if m := rxTunnelProtocol.FindStringSubmatch(trimmed); len(m) > 1 {
			tunnelProto = strings.ToLower(m[1])
		}
		if m := rxEtcdTLS.FindStringSubmatch(trimmed); len(m) > 1 {
			etcdTLSFound = true
			etcdTLS = strings.ToLower(m[1]) == "true"
		}
		if m := rxCACert.FindStringSubmatch(trimmed); len(m) > 1 {
			caCert = m[1]
		}
		if m := rxClientCert.FindStringSubmatch(trimmed); len(m) > 1 {
			clientCert = m[1]
		}
		if m := rxBackendCount.FindStringSubmatch(trimmed); len(m) > 1 {
			if bc, err := strconv.Atoi(m[1]); err == nil {
				backendCount = bc
			}
		}
		if m := rxClusterSelector.FindStringSubmatch(trimmed); len(m) > 1 {
			clusterSelector = m[1]
		}
	}

	// 1. Check for ClusterMesh / Cilium Configuration Document
	isCiliumConfig := strings.Contains(strings.ToLower(currentName), "cilium") ||
		strings.Contains(strings.ToLower(currentKind), "configmap") ||
		strings.Contains(strings.ToLower(currentKind), "helm") ||
		clusterName != "" || clusterID >= 0 || etcdTLSFound

	if isCiliumConfig && (clusterName != "" || clusterID >= 0 || etcdTLSFound || encMode != EncryptionNone || tunnelProto != "") {
		if clusterID < 0 {
			clusterID = 0
		}
		configs = append(configs, ClusterMeshConfig{
			ClusterName:      clusterName,
			ClusterID:        clusterID,
			EtcdTLS:          etcdTLS,
			EtcdClientCert:   clientCert,
			EtcdCACert:       caCert,
			TunnelEncryption: encMode,
			TunnelProtocol:   tunnelProto,
			LineNumber:       lineOfKind,
			FilePath:         filePath,
		})
	}

	// 2. Check for ServiceExport / ServiceImport or Global Service
	if strings.EqualFold(currentKind, "ServiceExport") || strings.EqualFold(currentKind, "ServiceImport") {
		isExport = true
		isGlobal = true
	}

	if isGlobal || isExport || (currentKind == "Service" && (isGlobal || !isShared)) {
		services = append(services, GlobalServiceConfig{
			Name:          currentName,
			Namespace:     currentNamespace,
			ClusterName:   clusterName,
			ClusterID:     clusterID,
			IsGlobal:      isGlobal,
			IsShared:      isShared,
			ServiceExport: isExport,
			BackendCount:  backendCount,
			LineNumber:    lineOfKind,
			FilePath:      filePath,
		})
	}

	// 3. Check for CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy
	if strings.EqualFold(currentKind, "CiliumNetworkPolicy") || strings.EqualFold(currentKind, "CiliumClusterwideNetworkPolicy") {
		policies = append(policies, MeshNetworkPolicyConfig{
			Name:            currentName,
			Namespace:       currentNamespace,
			ClusterSelector: clusterSelector,
			IsClusterwide:   strings.EqualFold(currentKind, "CiliumClusterwideNetworkPolicy"),
			LineNumber:      lineOfKind,
			FilePath:        filePath,
		})
	}

	return configs, services, policies
}

// ParseClusterMeshTelemetryJSON unmarshals and validates runtime ClusterMesh telemetry payloads.
func ParseClusterMeshTelemetryJSON(filePath string) (*ClusterMeshTelemetryReport, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat telemetry file: %w", err)
	}
	if fi.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry file %s exceeds %d bytes ceiling (size: %d)", filePath, MaxTelemetryBytes, fi.Size())
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry file: %w", err)
	}

	var report ClusterMeshTelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal telemetry JSON: %w", err)
	}

	if report.LocalClusterName == "" {
		report.LocalClusterName = "cluster-unknown"
	}
	if report.SyncState == "" {
		report.SyncState = SyncStateHealthy
	}

	return &report, nil
}
