package bpf

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
	reK8sKind         = regexp.MustCompile(`(?i)^\s*kind:\s*([A-Za-z0-9_-]+)`)
	reK8sName         = regexp.MustCompile(`(?i)^\s*name:\s*([A-Za-z0-9_.-]+)`)
	reK8sNamespace    = regexp.MustCompile(`(?i)^\s*namespace:\s*([A-Za-z0-9_.-]+)`)
	reSeccompUnconf   = regexp.MustCompile(`(?i)type:\s*["']?Unconfined["']?`)
	reSeccompDefault  = regexp.MustCompile(`(?i)type:\s*["']?RuntimeDefault["']?`)
	reSeccompLocal    = regexp.MustCompile(`(?i)type:\s*["']?Localhost["']?`)
	reHostPID         = regexp.MustCompile(`(?i)hostPID:\s*true`)
	reHostIPC         = regexp.MustCompile(`(?i)hostIPC:\s*true`)
	reCapNetRaw       = regexp.MustCompile(`(?i)(?:CAP_)?NET_RAW`)
	reCapSysAdmin     = regexp.MustCompile(`(?i)(?:CAP_)?SYS_ADMIN`)
	reCapSysPtrace    = regexp.MustCompile(`(?i)(?:CAP_)?SYS_PTRACE`)
	reCapSysModule    = regexp.MustCompile(`(?i)(?:CAP_)?SYS_MODULE`)
	reNixSysctlBPF    = regexp.MustCompile(`(?i)["']?kernel\.unprivileged_bpf_disabled["']?\s*=\s*([0-9]+)`)
	reNixLSM          = regexp.MustCompile(`(?i)security\.lsm\s*=\s*\[([^\]]*)\]`)
	reNixSyscallFilt  = regexp.MustCompile(`(?i)SystemCallFilter\s*=`)
	reNixSyscallArch  = regexp.MustCompile(`(?i)SystemCallArchitectures\s*=\s*["']?native["']?`)
	reNixServiceDecl  = regexp.MustCompile(`(?i)systemd\.services\.([A-Za-z0-9_.-]+)`)
)

// ParseManifestFile parses either a Kubernetes manifest, a NixOS host config, or a raw Seccomp JSON profile.
func ParseManifestFile(filePath string) ([]BPFViolation, int, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat manifest file %s: %w", cleanPath, err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, 0, fmt.Errorf("manifest file %s exceeds %d byte limit (%d bytes)", cleanPath, MaxManifestBytes, info.Size())
	}

	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case ".json":
		return parseJSONProfile(cleanPath)
	case ".nix":
		return parseNixOSFile(cleanPath)
	default:
		return parseK8sManifest(cleanPath)
	}
}

// parseJSONProfile evaluates standalone seccomp profile JSON documents.
func parseJSONProfile(cleanPath string) ([]BPFViolation, int, error) {
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read JSON profile %s: %w", cleanPath, err)
	}

	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		// Not a seccomp profile JSON, ignore gracefully
		return nil, 0, nil
	}

	var violations []BPFViolation
	if profile.DefaultAction == ActionAllow {
		r, _ := LookupBPFRule("BPF-SEC-009")
		violations = append(violations, BPFViolation{
			RuleID:      r.RuleID,
			Title:       r.Title,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			ResourceURI: cleanPath,
			StartLine:   1,
			Description: "Seccomp profile declares defaultAction 'SCMP_ACT_ALLOW', permitting all unlisted syscalls.",
			Remediation: r.Remediation,
		})
	}

	for _, rule := range profile.Syscalls {
		if rule.Action == ActionAllow {
			for _, name := range rule.Names {
				switch strings.ToLower(name) {
				case "ptrace", "process_vm_writev", "kexec_load", "reboot", "pivot_root":
					r, _ := LookupBPFRule("BPF-SEC-002")
					violations = append(violations, BPFViolation{
						RuleID:      r.RuleID,
						Title:       r.Title,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						ResourceURI: cleanPath,
						StartLine:   1,
						Description: fmt.Sprintf("High-privilege syscall '%s' is explicitly allowed in seccomp profile.", name),
						Remediation: r.Remediation,
					})
				case "init_module", "finit_module", "delete_module":
					r, _ := LookupBPFRule("BPF-SEC-010")
					violations = append(violations, BPFViolation{
						RuleID:      r.RuleID,
						Title:       r.Title,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						ResourceURI: cleanPath,
						StartLine:   1,
						Description: fmt.Sprintf("Kernel module management syscall '%s' is explicitly allowed.", name),
						Remediation: r.Remediation,
					})
				case "bpf", "perf_event_open":
					r, _ := LookupBPFRule("BPF-SEC-008")
					violations = append(violations, BPFViolation{
						RuleID:      r.RuleID,
						Title:       r.Title,
						Severity:    r.Severity,
						CVSSScore:   r.CVSSScore,
						ResourceURI: cleanPath,
						StartLine:   1,
						Description: fmt.Sprintf("Unrestricted '%s' syscall allowed in seccomp filter.", name),
						Remediation: r.Remediation,
					})
				}
			}
		}
	}

	return violations, 1, nil
}

// parseK8sManifest performs streaming audit on Kubernetes YAML declarations.
func parseK8sManifest(cleanPath string) ([]BPFViolation, int, error) {
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open k8s manifest %s: %w", cleanPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var violations []BPFViolation
	lineNum := 0
	workloadCount := 0

	currentKind := ""
	currentName := ""
	currentNamespace := "default"
	hasSeccomp := false
	isUnconfined := false
	hasHostPID := false
	hasHostIPC := false
	hasCapNetRaw := false
	hasCapSysAdmin := false
	hasCapSysModule := false
	workloadStartLine := 1

	flushWorkload := func() {
		if currentKind == "" {
			return
		}
		workloadCount++

		if isUnconfined {
			r, _ := LookupBPFRule("BPF-SEC-001")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    workloadStartLine,
				WorkloadName: currentName,
				Namespace:    currentNamespace,
				Description:  fmt.Sprintf("%s/%s explicitly sets seccompProfile type: Unconfined", currentKind, currentName),
				Remediation:  r.Remediation,
			})
		} else if !hasSeccomp && (currentKind == "Pod" || currentKind == "Deployment" || currentKind == "DaemonSet" || currentKind == "StatefulSet") {
			r, _ := LookupBPFRule("BPF-SEC-001")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    workloadStartLine,
				WorkloadName: currentName,
				Namespace:    currentNamespace,
				Description:  fmt.Sprintf("%s/%s omits seccompProfile configuration; host default unconfined risk", currentKind, currentName),
				Remediation:  r.Remediation,
			})
		}

		if hasHostPID || hasHostIPC {
			r, _ := LookupBPFRule("BPF-SEC-006")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    workloadStartLine,
				WorkloadName: currentName,
				Namespace:    currentNamespace,
				Description:  fmt.Sprintf("%s/%s configures hostPID/hostIPC namespace sharing", currentKind, currentName),
				Remediation:  r.Remediation,
			})
		}

		if hasCapNetRaw {
			r, _ := LookupBPFRule("BPF-SEC-003")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    workloadStartLine,
				WorkloadName: currentName,
				Namespace:    currentNamespace,
				Description:  fmt.Sprintf("%s/%s adds CAP_NET_RAW capability without verified BPF LSM enforcement", currentKind, currentName),
				Remediation:  r.Remediation,
			})
		}

		if hasCapSysAdmin {
			r, _ := LookupBPFRule("BPF-SEC-002")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    workloadStartLine,
				WorkloadName: currentName,
				Namespace:    currentNamespace,
				Description:  fmt.Sprintf("%s/%s grants CAP_SYS_ADMIN, granting access to privileged syscalls", currentKind, currentName),
				Remediation:  r.Remediation,
			})
		}

		if hasCapSysModule {
			r, _ := LookupBPFRule("BPF-SEC-010")
			violations = append(violations, BPFViolation{
				RuleID:       r.RuleID,
				Title:        r.Title,
				Severity:     r.Severity,
				CVSSScore:    r.CVSSScore,
				ResourceURI:  cleanPath,
				StartLine:    workloadStartLine,
				WorkloadName: currentName,
				Namespace:    currentNamespace,
				Description:  fmt.Sprintf("%s/%s grants CAP_SYS_MODULE allowing arbitrary kernel module injection", currentKind, currentName),
				Remediation:  r.Remediation,
			})
		}

		// Reset flags for next document
		currentKind = ""
		currentName = ""
		currentNamespace = "default"
		hasSeccomp = false
		isUnconfined = false
		hasHostPID = false
		hasHostIPC = false
		hasCapNetRaw = false
		hasCapSysAdmin = false
		hasCapSysModule = false
	}

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		line := scanner.Text()

		if strings.HasPrefix(line, "---") {
			flushWorkload()
			continue
		}

		if m := reK8sKind.FindStringSubmatch(line); len(m) > 1 {
			currentKind = m[1]
			workloadStartLine = lineNum
		}
		if m := reK8sName.FindStringSubmatch(line); len(m) > 1 && currentName == "" {
			currentName = m[1]
		}
		if m := reK8sNamespace.FindStringSubmatch(line); len(m) > 1 {
			currentNamespace = m[1]
		}

		if reSeccompUnconf.MatchString(line) {
			isUnconfined = true
			hasSeccomp = true
		} else if reSeccompDefault.MatchString(line) || reSeccompLocal.MatchString(line) {
			hasSeccomp = true
		}

		if reHostPID.MatchString(line) {
			hasHostPID = true
		}
		if reHostIPC.MatchString(line) {
			hasHostIPC = true
		}
		if reCapNetRaw.MatchString(line) {
			hasCapNetRaw = true
		}
		if reCapSysAdmin.MatchString(line) || reCapSysPtrace.MatchString(line) {
			hasCapSysAdmin = true
		}
		if reCapSysModule.MatchString(line) {
			hasCapSysModule = true
		}
	}

	flushWorkload()
	return violations, workloadCount, scanner.Err()
}

// parseNixOSFile performs static inspection of NixOS host configuration expressions.
func parseNixOSFile(cleanPath string) ([]BPFViolation, int, error) {
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read NixOS config %s: %w", cleanPath, err)
	}

	content := string(data)
	var violations []BPFViolation
	configCount := 1

	// 1. Audit kernel.unprivileged_bpf_disabled
	bpfSysctlMatch := reNixSysctlBPF.FindStringSubmatch(content)
	if len(bpfSysctlMatch) > 1 {
		val := bpfSysctlMatch[1]
		if val != "1" && val != "2" {
			r, _ := LookupBPFRule("BPF-SEC-008")
			violations = append(violations, BPFViolation{
				RuleID:      r.RuleID,
				Title:       r.Title,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				ResourceURI: cleanPath,
				StartLine:   1,
				Description: fmt.Sprintf("NixOS sysctl kernel.unprivileged_bpf_disabled set to insecure value '%s'", val),
				Remediation: r.Remediation,
			})
		}
	} else {
		// Missing parameter implies default (0 on unhardened kernels)
		r, _ := LookupBPFRule("BPF-SEC-008")
		violations = append(violations, BPFViolation{
			RuleID:      r.RuleID,
			Title:       r.Title,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			ResourceURI: cleanPath,
			StartLine:   1,
			Description: "NixOS host configuration omits 'boot.kernel.sysctl.\"kernel.unprivileged_bpf_disabled\" = 1;'",
			Remediation: r.Remediation,
		})
	}

	// 2. Audit security.lsm
	lsmMatch := reNixLSM.FindStringSubmatch(content)
	if len(lsmMatch) > 1 {
		lsmList := lsmMatch[1]
		if !strings.Contains(lsmList, "bpf") {
			r, _ := LookupBPFRule("BPF-SEC-005")
			violations = append(violations, BPFViolation{
				RuleID:      r.RuleID,
				Title:       r.Title,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				ResourceURI: cleanPath,
				StartLine:   1,
				Description: "NixOS 'security.lsm' is configured but lacks '\"bpf\"' LSM module attachment.",
				Remediation: r.Remediation,
			})
		}
	} else {
		r, _ := LookupBPFRule("BPF-SEC-005")
		violations = append(violations, BPFViolation{
			RuleID:      r.RuleID,
			Title:       r.Title,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			ResourceURI: cleanPath,
			StartLine:   1,
			Description: "NixOS host configuration does not explicitly declare 'security.lsm' containing '\"bpf\"'",
			Remediation: r.Remediation,
		})
	}

	// 3. Audit systemd service SystemCallFilter
	serviceMatches := reNixServiceDecl.FindAllStringSubmatch(content, -1)
	if len(serviceMatches) > 0 {
		hasFilter := reNixSyscallFilt.MatchString(content)
		hasArch := reNixSyscallArch.MatchString(content)
		if !hasFilter || !hasArch {
			r, _ := LookupBPFRule("BPF-SEC-011")
			violations = append(violations, BPFViolation{
				RuleID:      r.RuleID,
				Title:       r.Title,
				Severity:    r.Severity,
				CVSSScore:   r.CVSSScore,
				ResourceURI: cleanPath,
				StartLine:   1,
				Description: "NixOS systemd service definitions lack SystemCallFilter or native architecture restriction",
				Remediation: r.Remediation,
			})
		}
	}

	return violations, configCount, nil
}
