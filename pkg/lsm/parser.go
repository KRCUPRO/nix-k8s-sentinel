package lsm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reKernelParams   = regexp.MustCompile(`boot\.kernelParams\s*=\s*\[([^\]]*)\]`)
	reSecurityLSM    = regexp.MustCompile(`security\.lsm\s*=\s*\[([^\]]*)\]`)
	reSysctlUnprivBPF = regexp.MustCompile(`kernel\.unprivileged_bpf_disabled["\s]*=\s*([0-9]+)`)
	reSysctlGeneric  = regexp.MustCompile(`boot\.kernel\.sysctl\.["']?([a-zA-Z0-9_\.]+)["']?\s*=\s*([^;]+);`)
	reSystemdUnit    = regexp.MustCompile(`systemd\.services\.([a-zA-Z0-9_\-]+)`)
)

// ParseNixOSLSMConfig parses a declarative NixOS host configuration looking for eBPF LSM parameters.
func ParseNixOSLSMConfig(content string, filename string) (*NixOSLSMConfig, error) {
	if len(content) > MaxManifestBytes {
		return nil, fmt.Errorf("nixos manifest size (%d bytes) exceeds maximum ceiling of %d bytes", len(content), MaxManifestBytes)
	}

	cfg := &NixOSLSMConfig{
		SourceFile:      filename,
		KernelParams:    make([]string, 0),
		LSMOrder:        make([]string, 0),
		SystemdUnits:    make([]string, 0),
		HardenedSysctls: make(map[string]string),
		KernelPatches:   make([]string, 0),
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineCount := 0

	var inKernelParams bool
	var inSecurityLSM bool
	var inSystemdService string

	for scanner.Scan() {
		lineCount++
		if lineCount > MaxAllowedScanLines {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Detect boot.kernelParams multi-line or single-line
		if strings.Contains(line, "boot.kernelParams") {
			inKernelParams = true
		}
		if inKernelParams {
			matches := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				param := m[1]
				cfg.KernelParams = append(cfg.KernelParams, param)
				if strings.HasPrefix(param, "lsm=") {
					parts := strings.Split(strings.TrimPrefix(param, "lsm="), ",")
					for _, p := range parts {
						p = strings.TrimSpace(p)
						if p != "" {
							cfg.LSMOrder = append(cfg.LSMOrder, p)
							if p == "bpf" {
								cfg.BPFLSMEnabled = true
							}
						}
					}
				}
			}
			if strings.Contains(line, "]") {
				inKernelParams = false
			}
		}

		// Detect security.lsm
		if strings.Contains(line, "security.lsm") {
			inSecurityLSM = true
		}
		if inSecurityLSM {
			matches := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				val := m[1]
				cfg.LSMOrder = append(cfg.LSMOrder, val)
				if val == "bpf" {
					cfg.BPFLSMEnabled = true
				}
			}
			if strings.Contains(line, "]") {
				inSecurityLSM = false
			}
		}

		// Detect unprivileged_bpf_disabled sysctl
		if m := reSysctlUnprivBPF.FindStringSubmatch(line); len(m) > 1 {
			val, _ := strconv.Atoi(m[1])
			if val == 1 {
				cfg.UnprivilegedBPFDisabled = true
			}
		}

		// Detect generic sysctls
		if m := reSysctlGeneric.FindStringSubmatch(line); len(m) > 2 {
			cfg.HardenedSysctls[m[1]] = strings.TrimSpace(m[2])
			if m[1] == "kernel.unprivileged_bpf_disabled" && strings.Contains(m[2], "1") {
				cfg.UnprivilegedBPFDisabled = true
			}
		}

		// Detect systemd eBPF LSM units
		if m := reSystemdUnit.FindStringSubmatch(line); len(m) > 1 {
			inSystemdService = m[1]
			cfg.SystemdUnits = append(cfg.SystemdUnits, inSystemdService)
		}
		if inSystemdService != "" && (strings.Contains(line, "BPFLSM") || strings.Contains(line, "ebpf-lsm")) {
			cfg.BPFLSMEnabled = true
		}
	}

	return cfg, nil
}

// ParseK8sMACProfile parses Kubernetes workloads and ContainerMACProfile custom resource manifests.
func ParseK8sMACProfile(content string, filename string) ([]ContainerMACProfile, error) {
	if len(content) > MaxManifestBytes {
		return nil, fmt.Errorf("kubernetes manifest size (%d bytes) exceeds maximum ceiling of %d bytes", len(content), MaxManifestBytes)
	}

	var profiles []ContainerMACProfile

	docs := strings.Split(content, "\n---")
	for docIdx, doc := range docs {
		trimmed := strings.TrimSpace(doc)
		if trimmed == "" {
			continue
		}

		p := ContainerMACProfile{
			SourceFile:      filename,
			LineNumber:      docIdx*20 + 1,
			Capabilities:    make([]string, 0),
			BlockedHooks:    make([]LSMHookType, 0),
			ProtectedPaths:  make([]string, 0),
			AllowedSyscalls: make([]string, 0),
		}

		scanner := bufio.NewScanner(strings.NewReader(trimmed))
		lineNum := 0
		var inMetadata, inSecurityContext, inCapabilitiesAdd bool

		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}

			if strings.HasPrefix(line, "metadata:") {
				inMetadata = true
				continue
			}
			if inMetadata {
				if strings.HasPrefix(line, "name:") {
					p.WorkloadName = strings.Trim(strings.TrimPrefix(line, "name:"), ` "'`)
				}
				if strings.HasPrefix(line, "namespace:") {
					p.Namespace = strings.Trim(strings.TrimPrefix(line, "namespace:"), ` "'`)
				}
				if strings.Contains(line, "lsm.security.alpha.kubernetes.io/profile") || strings.Contains(line, "mac.bpf.kubernetes.io/enforce") {
					p.MACEnforced = true
				}
				if strings.HasPrefix(line, "spec:") || strings.HasPrefix(line, "labels:") {
					inMetadata = false
				}
			}

			if strings.Contains(line, "securityContext:") {
				inSecurityContext = true
			}
			if inSecurityContext {
				if strings.Contains(line, "privileged: true") {
					p.Privileged = true
				}
				if strings.Contains(line, "add:") {
					inCapabilitiesAdd = true
					continue
				}
			}

			if inCapabilitiesAdd {
				if strings.HasPrefix(line, "-") {
					capName := strings.Trim(strings.TrimPrefix(line, "-"), ` "'`)
					p.Capabilities = append(p.Capabilities, capName)
				} else if strings.Contains(line, ":") {
					inCapabilitiesAdd = false
				}
			}

			if strings.Contains(line, "hostPID: true") {
				p.HostPID = true
			}
			if strings.Contains(line, "hostIPC: true") {
				p.HostIPC = true
			}

			// Parse custom ContainerMACProfile CRD specifications
			if strings.Contains(line, "blockedHooks:") || strings.Contains(line, "blocked_hooks:") {
				// following lines might contain hooks
			}
			if strings.Contains(line, "- bprm_check_security") {
				p.BlockedHooks = append(p.BlockedHooks, HookBprmCheckSecurity)
			}
			if strings.Contains(line, "- file_open") {
				p.BlockedHooks = append(p.BlockedHooks, HookFileOpen)
			}
			if strings.Contains(line, "- socket_create") {
				p.BlockedHooks = append(p.BlockedHooks, HookSocketCreate)
			}
			if strings.Contains(line, "- bpf") {
				p.BlockedHooks = append(p.BlockedHooks, HookSecurityBPF)
			}
			if strings.Contains(line, "- ptrace_access_check") {
				p.BlockedHooks = append(p.BlockedHooks, HookPtraceAccessCheck)
			}
			if strings.Contains(line, "- task_fix_setuid") {
				p.BlockedHooks = append(p.BlockedHooks, HookTaskFixSetuid)
			}
		}

		if p.WorkloadName == "" {
			p.WorkloadName = fmt.Sprintf("workload-%d", len(profiles)+1)
		}
		if p.Namespace == "" {
			p.Namespace = "default"
		}

		profiles = append(profiles, p)
	}

	return profiles, nil
}

// ParseLSMTelemetryJSON parses a runtime eBPF LSM telemetry events stream from JSON.
func ParseLSMTelemetryJSON(data []byte) ([]LSMTelemetryEvent, error) {
	if len(data) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload (%d bytes) exceeds maximum ceiling of %d bytes", len(data), MaxTelemetryBytes)
	}

	var rawEvents []struct {
		Timestamp   string `json:"timestamp"`
		Node        string `json:"node"`
		ContainerID string `json:"container_id"`
		Cgroup      string `json:"cgroup"`
		Hook        string `json:"hook"`
		Syscall     string `json:"syscall"`
		Comm        string `json:"comm"`
		TargetPath  string `json:"target_path"`
		ReturnCode  int    `json:"return_code"`
		Blocked     bool   `json:"blocked"`
		Action      string `json:"action"`
	}

	if err := json.Unmarshal(data, &rawEvents); err != nil {
		return nil, fmt.Errorf("failed to unmarshal lsm telemetry json: %w", err)
	}

	if len(rawEvents) > MaxTelemetryEvents {
		rawEvents = rawEvents[:MaxTelemetryEvents]
	}

	events := make([]LSMTelemetryEvent, 0, len(rawEvents))
	for _, r := range rawEvents {
		ts, err := time.Parse(time.RFC3339, r.Timestamp)
		if err != nil {
			ts = time.Now()
		}

		action := ActionDeny
		if r.Action != "" {
			action = LSMAction(r.Action)
		}

		events = append(events, LSMTelemetryEvent{
			Timestamp:   ts,
			Node:        r.Node,
			ContainerID: r.ContainerID,
			Cgroup:      r.Cgroup,
			Hook:        LSMHookType(r.Hook),
			Syscall:     r.Syscall,
			Comm:        r.Comm,
			TargetPath:  r.TargetPath,
			ReturnCode:  r.ReturnCode,
			Blocked:     r.Blocked,
			Action:      action,
		})
	}

	return events, nil
}
