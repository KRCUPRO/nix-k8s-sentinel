package flow

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// CalculateShannonEntropy calculates the Shannon entropy in bits per character for a string.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	charCounts := make(map[rune]int)
	totalChars := 0
	for _, r := range strings.ToLower(s) {
		// Only count alphanumeric characters in domain name entropy
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			charCounts[r]++
			totalChars++
		}
	}

	if totalChars == 0 {
		return 0.0
	}

	var entropy float64
	totalFloat := float64(totalChars)
	for _, count := range charCounts {
		p := float64(count) / totalFloat
		entropy -= p * math.Log2(p)
	}

	return math.Round(entropy*100) / 100
}

// AnalyzeDomainQuery performs forensic evaluation of domain labels, entropy, and exfiltration vectors.
func AnalyzeDomainQuery(queryName string) (entropy float64, maxLabelLen int, isDGA bool, isTunneling bool) {
	clean := strings.TrimSuffix(strings.TrimSpace(queryName), ".")
	if clean == "" {
		return 0.0, 0, false, false
	}

	labels := strings.Split(clean, ".")
	for _, label := range labels {
		if len(label) > maxLabelLen {
			maxLabelLen = len(label)
		}
	}

	// Compute entropy on the substantive prefix (subdomains excluding common public TLDs)
	subdomainTarget := clean
	if len(labels) > 2 {
		subdomainTarget = strings.Join(labels[:len(labels)-2], ".")
	}

	entropy = CalculateShannonEntropy(subdomainTarget)

	// Tunneling signature: High entropy or long subdomain labels
	if entropy >= DefaultEntropyThreshold || maxLabelLen >= MaxLabelLengthThreshold || len(clean) >= MaxQueryLengthThreshold {
		isTunneling = true
	}

	// DGA signature: High consonant-to-vowel ratio, pseudo-random hex strings, or elevated entropy
	consonants := 0
	vowels := 0
	digits := 0
	for _, r := range strings.ToLower(subdomainTarget) {
		switch r {
		case 'a', 'e', 'i', 'o', 'u':
			vowels++
		default:
			if unicode.IsLetter(r) {
				consonants++
			} else if unicode.IsDigit(r) {
				digits++
			}
		}
	}

	totalLetters := consonants + vowels
	if totalLetters >= 8 && vowels > 0 {
		consonantRatio := float64(consonants) / float64(totalLetters)
		if consonantRatio >= 0.75 && entropy >= 3.4 {
			isDGA = true
		}
	} else if totalLetters >= 10 && vowels == 0 {
		isDGA = true
	}

	return entropy, maxLabelLen, isDGA, isTunneling
}

var (
	reYAMLKV    = regexp.MustCompile(`^\s*([a-zA-Z0-9_-]+)\s*:\s*(.*)$`)
	reNixAttrKV = regexp.MustCompile(`^\s*([a-zA-Z0-9_.-]+)\s*=\s*([^;]+);`)
)

// ParseCiliumPolicy parses a CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy manifest.
func ParseCiliumPolicy(manifestBytes []byte, filePath string) (*CiliumNetworkPolicyConfig, error) {
	if len(manifestBytes) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds maximum memory limit of %d bytes: %s", MaxManifestBytes, filePath)
	}

	cfg := &CiliumNetworkPolicyConfig{
		FilePath:         filePath,
		EndpointSelector: make(map[string]string),
		LineNumbers:      make(map[string]int),
	}

	scanner := bufio.NewScanner(bytes.NewReader(manifestBytes))
	lineNum := 0
	inEgress := false
	inToPorts := false
	inToFQDNs := false
	inDNSProxy := false

	var currentPort *PortRuleConfig
	var currentEgress *EgressRuleConfig

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}

		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level metadata
		if strings.HasPrefix(trimmed, "apiVersion:") {
			cfg.APIVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "apiVersion:"))
			cfg.LineNumbers["apiVersion"] = lineNum
		} else if strings.HasPrefix(trimmed, "kind:") {
			cfg.Kind = strings.TrimSpace(strings.TrimPrefix(trimmed, "kind:"))
			cfg.LineNumbers["kind"] = lineNum
		} else if strings.HasPrefix(trimmed, "name:") && cfg.Name == "" {
			cfg.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			cfg.LineNumbers["name"] = lineNum
		} else if strings.HasPrefix(trimmed, "namespace:") && cfg.Namespace == "" {
			cfg.Namespace = strings.TrimSpace(strings.TrimPrefix(trimmed, "namespace:"))
			cfg.LineNumbers["namespace"] = lineNum
		}

		// DNS proxy annotation check
		if strings.Contains(line, "enable-dns-proxy") {
			cfg.LineNumbers["enable_dns_proxy"] = lineNum
			val := strings.Contains(strings.ToLower(line), "true")
			cfg.EnableDNSProxy = &val
		}

		// Egress blocks
		if strings.HasPrefix(trimmed, "egress:") {
			inEgress = true
			inToPorts = false
			inToFQDNs = false
			currentEgress = &EgressRuleConfig{LineNumber: lineNum}
			cfg.EgressRules = append(cfg.EgressRules, *currentEgress)
			continue
		}

		if inEgress {
			if strings.HasPrefix(trimmed, "toPorts:") {
				inToPorts = true
				inToFQDNs = false
				continue
			}
			if strings.HasPrefix(trimmed, "toFQDNs:") {
				inToFQDNs = true
				inToPorts = false
				continue
			}

			if inToPorts {
				if strings.Contains(trimmed, "port:") {
					parts := strings.Split(trimmed, "port:")
					if len(parts) > 1 {
						pStr := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						if pVal, err := strconv.Atoi(pStr); err == nil {
							currentPort = &PortRuleConfig{
								Port:       pVal,
								Protocol:   FlowProtocolTCP,
								LineNumber: lineNum,
							}
							if len(cfg.EgressRules) > 0 {
								idx := len(cfg.EgressRules) - 1
								cfg.EgressRules[idx].ToPorts = append(cfg.EgressRules[idx].ToPorts, *currentPort)
							}
						}
					}
				}
				if strings.Contains(trimmed, "protocol:") && currentPort != nil {
					parts := strings.Split(trimmed, "protocol:")
					if len(parts) > 1 {
						protoStr := strings.ToUpper(strings.Trim(strings.TrimSpace(parts[1]), `"'`))
						currentPort.Protocol = FlowProtocol(protoStr)
						if len(cfg.EgressRules) > 0 && len(cfg.EgressRules[len(cfg.EgressRules)-1].ToPorts) > 0 {
							pIdx := len(cfg.EgressRules[len(cfg.EgressRules)-1].ToPorts) - 1
							cfg.EgressRules[len(cfg.EgressRules)-1].ToPorts[pIdx].Protocol = FlowProtocol(protoStr)
						}
					}
				}
				if strings.Contains(trimmed, "rules:") {
					inDNSProxy = true
				}
				if inDNSProxy && strings.Contains(trimmed, "matchPattern:") {
					parts := strings.Split(trimmed, "matchPattern:")
					if len(parts) > 1 && len(cfg.EgressRules) > 0 {
						pat := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						eIdx := len(cfg.EgressRules) - 1
						for pIdx := range cfg.EgressRules[eIdx].ToPorts {
							cfg.EgressRules[eIdx].ToPorts[pIdx].DNSRules = append(
								cfg.EgressRules[eIdx].ToPorts[pIdx].DNSRules,
								DNSRuleConfig{MatchPattern: pat, LineNumber: lineNum},
							)
						}
					}
				}
			}

			if inToFQDNs {
				if strings.Contains(trimmed, "matchPattern:") {
					parts := strings.Split(trimmed, "matchPattern:")
					if len(parts) > 1 && len(cfg.EgressRules) > 0 {
						pat := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						idx := len(cfg.EgressRules) - 1
						cfg.EgressRules[idx].ToFQDNs = append(cfg.EgressRules[idx].ToFQDNs, FQDNRule{
							MatchPattern: pat,
							LineNumber:   lineNum,
						})
					}
				} else if strings.Contains(trimmed, "matchName:") {
					parts := strings.Split(trimmed, "matchName:")
					if len(parts) > 1 && len(cfg.EgressRules) > 0 {
						nameVal := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						idx := len(cfg.EgressRules) - 1
						cfg.EgressRules[idx].ToFQDNs = append(cfg.EgressRules[idx].ToFQDNs, FQDNRule{
							MatchName:  nameVal,
							LineNumber: lineNum,
						})
					}
				}
			}

			if strings.Contains(trimmed, "toCIDR:") || strings.Contains(trimmed, "- ") && strings.Contains(trimmed, "/") {
				cidrVal := strings.Trim(strings.TrimPrefix(trimmed, "-"), ` "'`)
				if strings.Contains(cidrVal, "/") && len(cfg.EgressRules) > 0 {
					idx := len(cfg.EgressRules) - 1
					cfg.EgressRules[idx].ToCIDRs = append(cfg.EgressRules[idx].ToCIDRs, cidrVal)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading manifest file %s: %w", filePath, err)
	}

	return cfg, nil
}

// ParseNixOSFlow parses declarative NixOS eBPF flow profiler configurations.
func ParseNixOSFlow(manifestBytes []byte, filePath string) (*NixOSFlowConfig, error) {
	if len(manifestBytes) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds maximum memory limit of %d bytes: %s", MaxManifestBytes, filePath)
	}

	cfg := &NixOSFlowConfig{
		FilePath:    filePath,
		LineNumbers: make(map[string]int),
	}

	scanner := bufio.NewScanner(bytes.NewReader(manifestBytes))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}

		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		m := reNixAttrKV.FindStringSubmatch(trimmed)
		if len(m) == 3 {
			attr := strings.TrimSpace(m[1])
			val := strings.TrimSpace(m[2])

			switch attr {
			case "services.cilium.enable":
				b := val == "true"
				cfg.CiliumEnabled = &b
				cfg.LineNumbers["cilium_enabled"] = lineNum
			case "programs.ebpf.flowProfiler.enable":
				b := val == "true"
				cfg.FlowProfilerEnabled = &b
				cfg.LineNumbers["flow_profiler_enabled"] = lineNum
			case "programs.ebpf.flowProfiler.bpfConnectMonitoring":
				b := val == "true"
				cfg.BPFConnectMonitoring = &b
				cfg.LineNumbers["bpf_connect_monitoring"] = lineNum
			case "programs.ebpf.flowProfiler.maxSocketRate":
				if iVal, err := strconv.Atoi(val); err == nil {
					cfg.MaxSocketRate = iVal
					cfg.LineNumbers["max_socket_rate"] = lineNum
				}
			case "programs.ebpf.flowProfiler.dnsProxyPort":
				if iVal, err := strconv.Atoi(val); err == nil {
					cfg.DNSProxyPort = iVal
					cfg.LineNumbers["dns_proxy_port"] = lineNum
				}
			case "programs.ebpf.flowProfiler.ringBufferSizeKB":
				if iVal, err := strconv.Atoi(val); err == nil {
					cfg.RingBufferSizeKB = iVal
					cfg.LineNumbers["ring_buffer_size_kb"] = lineNum
				}
			case "programs.ebpf.flowProfiler.dropThresholdPercent":
				if fVal, err := strconv.ParseFloat(val, 64); err == nil {
					cfg.DropThresholdPercent = fVal
					cfg.LineNumbers["drop_threshold_percent"] = lineNum
				}
			case "networking.hostName":
				cfg.HostName = strings.Trim(val, `"`)
				cfg.LineNumbers["host_name"] = lineNum
			}
		}
	}

	return cfg, scanner.Err()
}

// ParseFlowTelemetryJSON unmarshals and validates runtime eBPF network flow and DNS telemetry.
func ParseFlowTelemetryJSON(data []byte) (*FlowTelemetryReport, error) {
	if len(data) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry data exceeds memory safety threshold of %d bytes", MaxTelemetryBytes)
	}

	var report FlowTelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal flow telemetry JSON: %w", err)
	}

	// Enforce telemetry events memory ceiling
	if len(report.Queries) > MaxTelemetryEvents {
		report.Queries = report.Queries[:MaxTelemetryEvents]
	}
	if len(report.SocketEvents) > MaxTelemetryEvents {
		report.SocketEvents = report.SocketEvents[:MaxTelemetryEvents]
	}

	// Recompute totals and rates
	if report.TotalDNSQueries > 0 {
		report.NXDomainRatePercent = math.Round((float64(report.NXDomainCount)/float64(report.TotalDNSQueries))*1000) / 10
	}

	// Re-evaluate query events for entropy and anomalies
	for i := range report.Queries {
		q := &report.Queries[i]
		if q.Entropy <= 0.0 && q.QueryName != "" {
			ent, maxLen, dga, tun := AnalyzeDomainQuery(q.QueryName)
			q.Entropy = ent
			q.MaxLabelLength = maxLen
			if tun {
				q.Vector = VectorTunneling
				q.IsAnomaly = true
			} else if dga {
				q.Vector = VectorDGA
				q.IsAnomaly = true
			}
		}
	}

	return &report, nil
}
