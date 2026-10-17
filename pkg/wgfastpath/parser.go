package wgfastpath

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
	reNixIfaceHeader = regexp.MustCompile(`(?:networking\.wireguard\.interfaces|services\.wireguard)\.([a-zA-Z0-9_\-]+)\s*=\s*\{`)
	reNixMTU         = regexp.MustCompile(`mtu\s*=\s*([0-9]+);`)
	reNixRingBuffer  = regexp.MustCompile(`ringBufferSize\s*=\s*([0-9]+);`)
	reNixQueues      = regexp.MustCompile(`queueCount\s*=\s*([0-9]+);`)
	reNixFastPath    = regexp.MustCompile(`(?:fastpath\.enable\s*=\s*(true|false)|fastpath\s*=\s*(true|false));`)
	reNixMode        = regexp.MustCompile(`(?:fastpath\.mode|fastPathMode)\s*=\s*"([^"]+)";`)
	reNixCrypto      = regexp.MustCompile(`(?:cryptoVector|crypto\.vector)\s*=\s*"([^"]+)";`)
	reNixOffload     = regexp.MustCompile(`(?:hardwareOffload|ethtool\.offload)\s*=\s*(true|false);`)
	reNixXDPDriver   = regexp.MustCompile(`xdpDriver\s*=\s*"([^"]+)";`)

	reK8sKind       = regexp.MustCompile(`kind:\s*(CiliumWireGuardFastPath|WireGuardFastPathConfig|NetworkConfig)`)
	reK8sIface      = regexp.MustCompile(`(?:interfaceName|interface):\s*([a-zA-Z0-9_\-]+)`)
	reK8sMTU        = regexp.MustCompile(`mtu:\s*([0-9]+)`)
	reK8sMode       = regexp.MustCompile(`(?:fastPathMode|mode):\s*"?([a-zA-Z0-9_\-]+)"?`)
	reK8sCrypto     = regexp.MustCompile(`(?:cryptoVector|vector):\s*"?([a-zA-Z0-9_\-]+)"?`)
	reK8sRingBuffer = regexp.MustCompile(`ringBufferSize:\s*([0-9]+)`)
	reK8sQueues     = regexp.MustCompile(`queueCount:\s*([0-9]+)`)
	reK8sOffload    = regexp.MustCompile(`(?:hardwareOffload|offload):\s*(true|false)`)
	reK8sXDPDriver  = regexp.MustCompile(`xdpDriver:\s*"?([a-zA-Z0-9_\-]+)"?`)
)

// ParseFastPathManifest parses a NixOS or Kubernetes configuration file and extracts fast-path interface models.
func ParseFastPathManifest(filePath string) ([]WireGuardInterfaceFastPathConfig, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if fi.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file size %d exceeds maximum allowed limit %d", fi.Size(), MaxManifestBytes)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	var configs []WireGuardInterfaceFastPathConfig
	scanner := bufio.NewScanner(f)
	lineNum := 0

	var currentCfg *WireGuardInterfaceFastPathConfig
	inK8sResource := false

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		line := strings.TrimSpace(scanner.Text())

		// Check for NixOS interface header
		if m := reNixIfaceHeader.FindStringSubmatch(line); len(m) > 1 {
			if currentCfg != nil && currentCfg.InterfaceName != "" {
				configs = append(configs, *currentCfg)
			}
			currentCfg = &WireGuardInterfaceFastPathConfig{
				InterfaceName:   m[1],
				MTU:             1420,
				FastPathMode:    ModeNone,
				RingBufferSize:  1024,
				HardwareOffload: false,
				QueueCount:      1,
				CryptoVector:    VectorScalar,
				FilePath:        filePath,
				StartLine:       lineNum,
			}
			continue
		}

		// Check for K8s Kind header
		if reK8sKind.MatchString(line) {
			if currentCfg != nil && currentCfg.InterfaceName != "" {
				configs = append(configs, *currentCfg)
			}
			inK8sResource = true
			currentCfg = &WireGuardInterfaceFastPathConfig{
				InterfaceName:   "wg0",
				MTU:             1420,
				FastPathMode:    ModeNone,
				RingBufferSize:  1024,
				HardwareOffload: false,
				QueueCount:      1,
				CryptoVector:    VectorScalar,
				FilePath:        filePath,
				StartLine:       lineNum,
			}
			continue
		}

		if currentCfg == nil {
			continue
		}

		// Check interface fields
		if m := reNixMTU.FindStringSubmatch(line); len(m) > 1 {
			if val, err := strconv.Atoi(m[1]); err == nil {
				currentCfg.MTU = val
			}
		} else if m := reK8sMTU.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			if val, err := strconv.Atoi(m[1]); err == nil {
				currentCfg.MTU = val
			}
		}

		if m := reK8sIface.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			currentCfg.InterfaceName = m[1]
		}

		if m := reNixRingBuffer.FindStringSubmatch(line); len(m) > 1 {
			if val, err := strconv.Atoi(m[1]); err == nil {
				currentCfg.RingBufferSize = val
			}
		} else if m := reK8sRingBuffer.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			if val, err := strconv.Atoi(m[1]); err == nil {
				currentCfg.RingBufferSize = val
			}
		}

		if m := reNixQueues.FindStringSubmatch(line); len(m) > 1 {
			if val, err := strconv.Atoi(m[1]); err == nil {
				currentCfg.QueueCount = val
			}
		} else if m := reK8sQueues.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			if val, err := strconv.Atoi(m[1]); err == nil {
				currentCfg.QueueCount = val
			}
		}

		if m := reNixFastPath.FindStringSubmatch(line); len(m) > 1 {
			boolVal := m[1]
			if boolVal == "" {
				boolVal = m[2]
			}
			if boolVal == "true" && currentCfg.FastPathMode == ModeNone {
				currentCfg.FastPathMode = ModeNativeXDP
			}
		}

		if m := reNixMode.FindStringSubmatch(line); len(m) > 1 {
			currentCfg.FastPathMode = normalizeFastPathMode(m[1])
		} else if m := reK8sMode.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			currentCfg.FastPathMode = normalizeFastPathMode(m[1])
		}

		if m := reNixCrypto.FindStringSubmatch(line); len(m) > 1 {
			currentCfg.CryptoVector = normalizeCryptoVector(m[1])
		} else if m := reK8sCrypto.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			currentCfg.CryptoVector = normalizeCryptoVector(m[1])
		}

		if m := reNixOffload.FindStringSubmatch(line); len(m) > 1 {
			currentCfg.HardwareOffload = (m[1] == "true")
		} else if m := reK8sOffload.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			currentCfg.HardwareOffload = (m[1] == "true")
		}

		if m := reNixXDPDriver.FindStringSubmatch(line); len(m) > 1 {
			currentCfg.XDPDriver = m[1]
		} else if m := reK8sXDPDriver.FindStringSubmatch(line); len(m) > 1 && inK8sResource {
			currentCfg.XDPDriver = m[1]
		}
	}

	if currentCfg != nil && currentCfg.InterfaceName != "" {
		configs = append(configs, *currentCfg)
	}

	return configs, scanner.Err()
}

// ParseFastPathTelemetry parses runtime telemetry for packet flows, ring buffers, and crypto benchmarks.
func ParseFastPathTelemetry(filePath string) ([]FastPathTelemetry, []CryptoBenchmarkTelemetry, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat telemetry file: %w", err)
	}
	if fi.Size() > MaxTelemetryBytes {
		return nil, nil, fmt.Errorf("telemetry file size %d exceeds limit %d", fi.Size(), MaxTelemetryBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read telemetry: %w", err)
	}

	type rootTelemetry struct {
		Telemetry        []FastPathTelemetry        `json:"telemetry"`
		CryptoBenchmarks []CryptoBenchmarkTelemetry `json:"crypto_benchmarks"`
	}

	var root rootTelemetry
	if err := json.Unmarshal(data, &root); err == nil && (len(root.Telemetry) > 0 || len(root.CryptoBenchmarks) > 0) {
		if len(root.Telemetry) > MaxTelemetryEvents {
			root.Telemetry = root.Telemetry[:MaxTelemetryEvents]
		}
		if len(root.CryptoBenchmarks) > MaxTelemetryEvents {
			root.CryptoBenchmarks = root.CryptoBenchmarks[:MaxTelemetryEvents]
		}
		return root.Telemetry, root.CryptoBenchmarks, nil
	}

	// Try parsing as raw slice of FastPathTelemetry
	var slice []FastPathTelemetry
	if err := json.Unmarshal(data, &slice); err == nil {
		if len(slice) > MaxTelemetryEvents {
			slice = slice[:MaxTelemetryEvents]
		}
		return slice, nil, nil
	}

	// Try single telemetry item
	var single FastPathTelemetry
	if err := json.Unmarshal(data, &single); err == nil && single.InterfaceName != "" {
		return []FastPathTelemetry{single}, nil, nil
	}

	return nil, nil, fmt.Errorf("unrecognized telemetry format in %s", filePath)
}

func normalizeFastPathMode(val string) FastPathMode {
	upper := strings.ToUpper(strings.TrimSpace(val))
	switch upper {
	case "NATIVE_XDP", "NATIVE", "XDP":
		return ModeNativeXDP
	case "OFFLOAD_XDP", "OFFLOAD":
		return ModeOffloadXDP
	case "GENERIC_BPF", "GENERIC":
		return ModeGenericBPF
	case "TC_INGRESS", "TC":
		return ModeTCIngress
	default:
		return ModeNone
	}
}

func normalizeCryptoVector(val string) CryptoVector {
	upper := strings.ToUpper(strings.TrimSpace(val))
	switch upper {
	case "AVX512", "AVX-512":
		return VectorAVX512
	case "AVX2", "AVX-2":
		return VectorAVX2
	case "ARM_NEON", "NEON":
		return VectorARMNeon
	default:
		return VectorScalar
	}
}
