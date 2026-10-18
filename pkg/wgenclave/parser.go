package wgenclave

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	rxNixIface    = regexp.MustCompile(`networking\.wireguard\.interfaces\.([a-zA-Z0-9_-]+)`)
	rxNixPeerName = regexp.MustCompile(`(?:#\s*peer:\s*([a-zA-Z0-9_-]+)|name\s*=\s*"([^"]+)")`)
	rxNixPubKey   = regexp.MustCompile(`publicKey\s*=\s*"([^"]+)"`)
	rxNixEndpoint = regexp.MustCompile(`endpoint\s*=\s*"([^"]+)"`)
	rxNixPlatform = regexp.MustCompile(`(?:enclave\.)?platform\s*=\s*"([^"]+)"`)
	rxNixTCBSVN   = regexp.MustCompile(`(?:enclave\.)?minTcbSvn\s*=\s*([0-9]+)`)
	rxNixSession  = regexp.MustCompile(`(?:enclave\.)?requireSessionKeyBinding\s*=\s*(true|false)`)
	rxNixDebug    = regexp.MustCompile(`(?:enclave\.)?allowDebug\s*=\s*(true|false)`)
	rxNixHwRoot   = regexp.MustCompile(`(?:enclave\.)?requireHardwareRoot\s*=\s*(true|false)`)
	rxNixGolden   = regexp.MustCompile(`(?:enclave\.)?goldenImageDigest\s*=\s*"([^"]+)"`)
	rxNixAge      = regexp.MustCompile(`(?:enclave\.)?maxAttestationAgeSec\s*=\s*([0-9]+)`)
	rxNixPCR      = regexp.MustCompile(`(?:enclave\.)?pcrs\."?([0-9]+)"?\s*=\s*"([^"]+)"`)
	rxNixRTMR     = regexp.MustCompile(`(?:enclave\.)?rtmrs\."?([0-9]+)"?\s*=\s*"([^"]+)"`)
)

// ParseNixOSEnclavePeer scans a NixOS configuration file for WireGuard enclave peer declarations.
func ParseNixOSEnclavePeer(filePath string) ([]EnclavePeerConfig, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", filePath, err)
	}
	if fileInfo.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum manifest size (%d bytes)", filePath, MaxManifestBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %w", filePath, err)
	}

	return ParseNixOSEnclavePeerBytes(data, filePath)
}

// ParseNixOSEnclavePeerBytes parses byte data into EnclavePeerConfig slice with line tracking.
func ParseNixOSEnclavePeerBytes(data []byte, filePath string) ([]EnclavePeerConfig, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var peers []EnclavePeerConfig
	currentIface := "wg0"
	var currentPeer *EnclavePeerConfig
	lineNum := 0

	commitCurrent := func() {
		if currentPeer != nil && (currentPeer.PublicKey != "" || currentPeer.PeerName != "") {
			if currentPeer.InterfaceName == "" {
				currentPeer.InterfaceName = currentIface
			}
			if currentPeer.PeerName == "" {
				currentPeer.PeerName = fmt.Sprintf("peer-%d", len(peers)+1)
			}
			peers = append(peers, *currentPeer)
		}
		currentPeer = nil
	}

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		line := strings.TrimSpace(scanner.Text())

		if m := rxNixIface.FindStringSubmatch(line); len(m) > 1 {
			currentIface = m[1]
		}

		if strings.Contains(line, "peers = [") || strings.Contains(line, "peers=[") || strings.HasPrefix(line, "{") && strings.Contains(line, "publicKey") {
			commitCurrent()
			currentPeer = &EnclavePeerConfig{
				InterfaceName:     currentIface,
				FilePath:          filePath,
				StartLine:         lineNum,
				RequiredPCRs:      make(map[int]string),
				RequiredRTMRs:     make(map[int]string),
				MinTCBSVN:         DefaultMinTCBSVN,
				SessionKeyBinding: false,
			}
		}

		if currentPeer == nil && (strings.Contains(line, "publicKey") || strings.Contains(line, "enclave")) {
			currentPeer = &EnclavePeerConfig{
				InterfaceName:     currentIface,
				FilePath:          filePath,
				StartLine:         lineNum,
				RequiredPCRs:      make(map[int]string),
				RequiredRTMRs:     make(map[int]string),
				MinTCBSVN:         DefaultMinTCBSVN,
				SessionKeyBinding: false,
			}
		}

		if currentPeer != nil {
			if m := rxNixPeerName.FindStringSubmatch(line); len(m) > 1 {
				if m[1] != "" {
					currentPeer.PeerName = m[1]
				} else if len(m) > 2 && m[2] != "" {
					currentPeer.PeerName = m[2]
				}
			}
			if m := rxNixPubKey.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.PublicKey = m[1]
			}
			if m := rxNixEndpoint.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.Endpoint = m[1]
			}
			if m := rxNixPlatform.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.Platform = EnclavePlatform(strings.ToUpper(m[1]))
			}
			if m := rxNixTCBSVN.FindStringSubmatch(line); len(m) > 1 {
				if n, err := strconv.ParseUint(m[1], 10, 32); err == nil {
					currentPeer.MinTCBSVN = uint32(n)
				}
			}
			if m := rxNixSession.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.SessionKeyBinding = (m[1] == "true")
			}
			if m := rxNixDebug.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.AllowDebug = (m[1] == "true")
			}
			if m := rxNixHwRoot.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.RequireHardwareRoot = (m[1] == "true")
			}
			if m := rxNixGolden.FindStringSubmatch(line); len(m) > 1 {
				currentPeer.GoldenImageDigest = m[1]
			}
			if m := rxNixAge.FindStringSubmatch(line); len(m) > 1 {
				if a, err := strconv.Atoi(m[1]); err == nil {
					currentPeer.MaxAttestationAgeSec = a
				}
			}
			if m := rxNixPCR.FindStringSubmatch(line); len(m) > 2 {
				if pcrIdx, err := strconv.Atoi(m[1]); err == nil {
					currentPeer.RequiredPCRs[pcrIdx] = m[2]
				}
			}
			if m := rxNixRTMR.FindStringSubmatch(line); len(m) > 2 {
				if rtmrIdx, err := strconv.Atoi(m[1]); err == nil {
					currentPeer.RequiredRTMRs[rtmrIdx] = m[2]
				}
			}

			if strings.HasPrefix(line, "}") || strings.HasPrefix(line, "};") {
				commitCurrent()
			}
		}
	}
	commitCurrent()

	return peers, scanner.Err()
}

// ParseK8sEnclavePeerConfig scans a Kubernetes YAML manifest for EnclaveWireGuardPeer resources.
func ParseK8sEnclavePeerConfig(filePath string) ([]EnclavePeerConfig, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", filePath, err)
	}
	if fileInfo.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum manifest size (%d bytes)", filePath, MaxManifestBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %w", filePath, err)
	}

	return ParseK8sEnclavePeerBytes(data, filePath)
}

// ParseK8sEnclavePeerBytes parses YAML text lines into EnclavePeerConfig slice.
func ParseK8sEnclavePeerBytes(data []byte, filePath string) ([]EnclavePeerConfig, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var peers []EnclavePeerConfig
	var current *EnclavePeerConfig
	lineNum := 0
	inEnclaveSpec := false
	inPCRs := false
	inRTMRs := false

	commit := func() {
		if current != nil && (current.PeerName != "" || current.PublicKey != "") {
			peers = append(peers, *current)
		}
		current = nil
		inEnclaveSpec = false
		inPCRs = false
		inRTMRs = false
	}

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		if strings.HasPrefix(line, "---") {
			commit()
			continue
		}

		if strings.HasPrefix(line, "kind: EnclaveWireGuardPeer") || strings.HasPrefix(line, "kind: WireGuardEnclavePeer") {
			commit()
			current = &EnclavePeerConfig{
				FilePath:          filePath,
				StartLine:         lineNum,
				InterfaceName:     "wg0",
				RequiredPCRs:      make(map[int]string),
				RequiredRTMRs:     make(map[int]string),
				MinTCBSVN:         DefaultMinTCBSVN,
				SessionKeyBinding: false,
			}
			continue
		}

		if current != nil {
			if strings.HasPrefix(line, "spec:") {
				inEnclaveSpec = true
				continue
			}

			if !inEnclaveSpec && strings.HasPrefix(line, "name:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					current.PeerName = strings.Trim(strings.TrimSpace(parts[1]), "\"")
				}
				continue
			}

			if inEnclaveSpec {
				if strings.HasPrefix(line, "requiredPCRs:") || strings.HasPrefix(line, "pcrs:") {
					inPCRs = true
					inRTMRs = false
					continue
				}
				if strings.HasPrefix(line, "requiredRTMRs:") || strings.HasPrefix(line, "rtmrs:") {
					inRTMRs = true
					inPCRs = false
					continue
				}

				if inPCRs && strings.HasPrefix(line, "\"") || (inPCRs && strings.Contains(line, ":")) {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.Trim(strings.TrimSpace(parts[0]), "\" ")
						val := strings.Trim(strings.TrimSpace(parts[1]), "\" ")
						if idx, err := strconv.Atoi(key); err == nil {
							current.RequiredPCRs[idx] = val
						}
					}
					continue
				}

				if inRTMRs && strings.HasPrefix(line, "\"") || (inRTMRs && strings.Contains(line, ":")) {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.Trim(strings.TrimSpace(parts[0]), "\" ")
						val := strings.Trim(strings.TrimSpace(parts[1]), "\" ")
						if idx, err := strconv.Atoi(key); err == nil {
							current.RequiredRTMRs[idx] = val
						}
					}
					continue
				}

				if !strings.HasPrefix(rawLine, "    ") && !strings.HasPrefix(rawLine, "\t\t") {
					inPCRs = false
					inRTMRs = false
				}

				if strings.HasPrefix(line, "interfaceName:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.InterfaceName = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				} else if strings.HasPrefix(line, "publicKey:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.PublicKey = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				} else if strings.HasPrefix(line, "endpoint:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.Endpoint = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				} else if strings.HasPrefix(line, "platform:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.Platform = EnclavePlatform(strings.ToUpper(strings.Trim(strings.TrimSpace(parts[1]), "\"")))
					}
				} else if strings.HasPrefix(line, "minTcbSvn:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						if n, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32); err == nil {
							current.MinTCBSVN = uint32(n)
						}
					}
				} else if strings.HasPrefix(line, "sessionKeyBinding:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.SessionKeyBinding = (strings.TrimSpace(parts[1]) == "true")
					}
				} else if strings.HasPrefix(line, "allowDebug:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.AllowDebug = (strings.TrimSpace(parts[1]) == "true")
					}
				} else if strings.HasPrefix(line, "requireHardwareRoot:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.RequireHardwareRoot = (strings.TrimSpace(parts[1]) == "true")
					}
				} else if strings.HasPrefix(line, "goldenImageDigest:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						current.GoldenImageDigest = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				} else if strings.HasPrefix(line, "maxAttestationAgeSec:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						if a, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
							current.MaxAttestationAgeSec = a
						}
					}
				}
			}
		}
	}
	commit()

	return peers, scanner.Err()
}

// ParseEnclaveTelemetryJSON parses runtime enclave attestation telemetry JSON with defensive bounds.
func ParseEnclaveTelemetryJSON(filePath string) (*EnclaveTelemetry, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", filePath, err)
	}
	if fileInfo.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry file %s exceeds maximum size (%d bytes)", filePath, MaxTelemetryBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %w", filePath, err)
	}

	return ParseEnclaveTelemetryBytes(data)
}

// ParseEnclaveTelemetryBytes unmarshals JSON telemetry into EnclaveTelemetry with bounds validation.
func ParseEnclaveTelemetryBytes(data []byte) (*EnclaveTelemetry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var tel EnclaveTelemetry
	if err := dec.Decode(&tel); err != nil {
		// Fallback without DisallowUnknownFields to handle minor forward schema drift
		if err2 := json.Unmarshal(data, &tel); err2 != nil {
			return nil, fmt.Errorf("failed to unmarshal enclave telemetry JSON: %w", err)
		}
	}

	if len(tel.Reports) > MaxTelemetryEvents {
		tel.Reports = tel.Reports[:MaxTelemetryEvents]
	}
	if len(tel.Peers) > MaxTelemetryEvents {
		tel.Peers = tel.Peers[:MaxTelemetryEvents]
	}

	return &tel, nil
}
