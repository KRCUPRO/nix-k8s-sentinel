package sandbox

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
	reNixMicroVMBlock = regexp.MustCompile(`microvm\.vms\.([a-zA-Z0-9_\-]+)\s*=\s*\{`)
	reNixHypervisor   = regexp.MustCompile(`hypervisor\s*=\s*"([^"]+)"`)
	reNixVCPUs        = regexp.MustCompile(`vcpu\s*=\s*([0-9]+)`)
	reNixMem          = regexp.MustCompile(`mem\s*=\s*([0-9]+)`)
	reNixKernel       = regexp.MustCompile(`kernelPath\s*=\s*"([^"]+)"`)
	reNixRootFS       = regexp.MustCompile(`rootfsPath\s*=\s*"([^"]+)"`)
	reNixJailer       = regexp.MustCompile(`jailer\.enable\s*=\s*(true|false)`)
	reNixReadOnly     = regexp.MustCompile(`readOnly\s*=\s*(true|false)`)
	reNixEgressIso    = regexp.MustCompile(`isolateEgress\s*=\s*(true|false)`)
	reNixKVMDevice    = regexp.MustCompile(`kvmDevice\s*=\s*"([^"]+)"`)

	reK8sKind         = regexp.MustCompile(`^kind:\s*([a-zA-Z0-9_\-]+)`)
	reK8sAPIVersion   = regexp.MustCompile(`^apiVersion:\s*([a-zA-Z0-9_\-\./]+)`)
	reK8sName         = regexp.MustCompile(`^\s*name:\s*([a-zA-Z0-9_\-]+)`)
	reK8sHypervisor   = regexp.MustCompile(`^\s*hypervisor:\s*([a-zA-Z0-9_\-]+)`)
	reK8sVCPUs        = regexp.MustCompile(`^\s*vcpus:\s*([0-9]+)`)
	reK8sMemoryMiB    = regexp.MustCompile(`^\s*memoryMib:\s*([0-9]+)`)
	reK8sJailer       = regexp.MustCompile(`^\s*jailerEnabled:\s*(true|false)`)
	reK8sEgress       = regexp.MustCompile(`^\s*egressIsolated:\s*(true|false)`)
	reK8sReadOnly     = regexp.MustCompile(`^\s*readOnlyRootfs:\s*(true|false)`)
	reK8sPayload      = regexp.MustCompile(`^\s*payloadDigest:\s*"?([a-zA-Z0-9_:\-]+)"?`)
)

// ParseNixOSMicroVMConfig parses a declarative NixOS microvm configuration file.
func ParseNixOSMicroVMConfig(filePath string) ([]MicroVMConfig, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", filePath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum manifest size (%d bytes)", filePath, MaxManifestBytes)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open failed for %s: %w", filePath, err)
	}
	defer file.Close()

	var configs []MicroVMConfig
	scanner := bufio.NewScanner(file)
	lineNum := 0

	var current *MicroVMConfig
	braceDepth := 0

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		// Ignore comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Detect microvm block
		if m := reNixMicroVMBlock.FindStringSubmatch(line); len(m) > 1 {
			if current != nil {
				configs = append(configs, *current)
			}
			current = &MicroVMConfig{
				VMID:             m[1],
				Hypervisor:       HypervisorFirecracker,
				VCPUs:            1,
				MemoryMiB:        1024,
				JailerEnabled:    false,
				KVMDevice:        "/dev/kvm",
				EgressIsolated:   false,
				ReadOnlyRootFS:   false,
				Metadata:         make(map[string]string),
				SourceFile:       filePath,
				LineNumber:       lineNum,
			}
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if current != nil {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if m := reNixHypervisor.FindStringSubmatch(line); len(m) > 1 {
				current.Hypervisor = HypervisorType(strings.ToLower(m[1]))
			}
			if m := reNixVCPUs.FindStringSubmatch(line); len(m) > 1 {
				if v, err := strconv.Atoi(m[1]); err == nil && v > 0 && v <= MaxVCPUsAllowed {
					current.VCPUs = v
				}
			}
			if m := reNixMem.FindStringSubmatch(line); len(m) > 1 {
				if v, err := strconv.Atoi(m[1]); err == nil && v > 0 && v <= MaxMemoryMiBAllowed {
					current.MemoryMiB = v
				}
			}
			if m := reNixKernel.FindStringSubmatch(line); len(m) > 1 {
				current.KernelPath = m[1]
			}
			if m := reNixRootFS.FindStringSubmatch(line); len(m) > 1 {
				current.RootFSPath = m[1]
			}
			if m := reNixJailer.FindStringSubmatch(line); len(m) > 1 {
				current.JailerEnabled = (m[1] == "true")
			}
			if m := reNixReadOnly.FindStringSubmatch(line); len(m) > 1 {
				current.ReadOnlyRootFS = (m[1] == "true")
			}
			if m := reNixEgressIso.FindStringSubmatch(line); len(m) > 1 {
				current.EgressIsolated = (m[1] == "true")
			}
			if m := reNixKVMDevice.FindStringSubmatch(line); len(m) > 1 {
				current.KVMDevice = m[1]
			}

			if braceDepth <= 0 {
				configs = append(configs, *current)
				current = nil
			}
		}
	}

	if current != nil {
		configs = append(configs, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error for %s: %w", filePath, err)
	}

	return configs, nil
}

// ParseK8sDetonationJob parses Kubernetes DetonationJob or MicroVMSandbox manifests.
func ParseK8sDetonationJob(filePath string) ([]MicroVMConfig, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", filePath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum manifest size (%d bytes)", filePath, MaxManifestBytes)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %w", filePath, err)
	}

	var configs []MicroVMConfig
	docs := strings.Split(string(content), "---")
	lineOffset := 1

	for _, doc := range docs {
		trimmedDoc := strings.TrimSpace(doc)
		if trimmedDoc == "" {
			lineOffset += strings.Count(doc, "\n")
			continue
		}

		lines := strings.Split(doc, "\n")
		isSandboxKind := false
		var cfg MicroVMConfig
		cfg.VCPUs = 2
		cfg.MemoryMiB = 2048
		cfg.Hypervisor = HypervisorFirecracker
		cfg.KVMDevice = "/dev/kvm"
		cfg.SourceFile = filePath
		cfg.Metadata = make(map[string]string)

		for idx, rawLine := range lines {
			line := strings.TrimSpace(rawLine)
			if strings.HasPrefix(line, "#") {
				continue
			}

			if m := reK8sKind.FindStringSubmatch(line); len(m) > 1 {
				k := strings.ToLower(m[1])
				if k == "detonationjob" || k == "microvmsandbox" || k == "firecrackersandbox" {
					isSandboxKind = true
					cfg.LineNumber = lineOffset + idx
				}
			}
			if m := reK8sName.FindStringSubmatch(line); len(m) > 1 && cfg.VMID == "" {
				cfg.VMID = m[1]
			}
			if m := reK8sHypervisor.FindStringSubmatch(line); len(m) > 1 {
				cfg.Hypervisor = HypervisorType(strings.ToLower(m[1]))
			}
			if m := reK8sVCPUs.FindStringSubmatch(line); len(m) > 1 {
				if v, err := strconv.Atoi(m[1]); err == nil && v > 0 {
					cfg.VCPUs = v
				}
			}
			if m := reK8sMemoryMiB.FindStringSubmatch(line); len(m) > 1 {
				if v, err := strconv.Atoi(m[1]); err == nil && v > 0 {
					cfg.MemoryMiB = v
				}
			}
			if m := reK8sJailer.FindStringSubmatch(line); len(m) > 1 {
				cfg.JailerEnabled = (m[1] == "true")
			}
			if m := reK8sEgress.FindStringSubmatch(line); len(m) > 1 {
				cfg.EgressIsolated = (m[1] == "true")
			}
			if m := reK8sReadOnly.FindStringSubmatch(line); len(m) > 1 {
				cfg.ReadOnlyRootFS = (m[1] == "true")
			}
			if m := reK8sPayload.FindStringSubmatch(line); len(m) > 1 {
				cfg.Metadata["payloadDigest"] = m[1]
			}
		}

		if isSandboxKind {
			if cfg.VMID == "" {
				cfg.VMID = fmt.Sprintf("k8s-sandbox-%d", len(configs)+1)
			}
			configs = append(configs, cfg)
		}

		lineOffset += len(lines)
	}

	return configs, nil
}

// ParseDetonationTelemetryJSON parses runtime microVM detonation and honeypot interaction telemetry.
func ParseDetonationTelemetryJSON(filePath string) ([]DetonationTelemetry, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat failed for %s: %w", filePath, err)
	}
	if info.Size() > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry %s exceeds maximum size (%d bytes)", filePath, MaxTelemetryBytes)
	}

	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %w", filePath, err)
	}

	// Try array first
	var telemetryList []DetonationTelemetry
	if err := json.Unmarshal(bytes, &telemetryList); err == nil {
		if len(telemetryList) > MaxDetonations {
			telemetryList = telemetryList[:MaxDetonations]
		}
		return telemetryList, nil
	}

	// Try single object
	var single DetonationTelemetry
	if err := json.Unmarshal(bytes, &single); err == nil {
		return []DetonationTelemetry{single}, nil
	}

	// Try wrapped object { "detonations": [...] }
	var wrapped struct {
		Detonations []DetonationTelemetry `json:"detonations"`
	}
	if err := json.Unmarshal(bytes, &wrapped); err == nil && len(wrapped.Detonations) > 0 {
		if len(wrapped.Detonations) > MaxDetonations {
			wrapped.Detonations = wrapped.Detonations[:MaxDetonations]
		}
		return wrapped.Detonations, nil
	}

	return nil, fmt.Errorf("invalid or unrecognized detonation telemetry JSON format in %s", filePath)
}
