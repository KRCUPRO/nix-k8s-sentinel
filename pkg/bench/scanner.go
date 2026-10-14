package bench

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	flagRegex = regexp.MustCompile(`--([a-zA-Z0-9_-]+)(?:=([^\s"';]+)|(?:\s+([^\s"';]+)))?`)
	nixAssignRegex = regexp.MustCompile(`^\s*services\.kubernetes\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_.-]+)\s*=\s*(.+?);?\s*$`)
	nixExtraOptsRegex = regexp.MustCompile(`services\.kubernetes\.([a-zA-Z0-9_-]+)\.extraOpts\s*=\s*"([^"]+)"`)
	yamlKVRegex = regexp.MustCompile(`^\s*([a-zA-Z0-9_-]+):\s*(.+?)\s*$`)
)

// CISScanner inspects NixOS configuration modules and Kubernetes configuration manifests against the CIS Benchmark.
type CISScanner struct {
	Feed *intel.Feed
}

// NewCISScanner constructs an initialized CIS benchmark scanner instance.
func NewCISScanner(feed *intel.Feed) *CISScanner {
	return &CISScanner{Feed: feed}
}

// ScanFile parses a single file (NixOS configuration or Kubernetes YAML) and evaluates benchmark compliance.
func (s *CISScanner) ScanFile(filePath string) (*CISAuditReport, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", cleanPath, err)
	}

	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("file %s exceeds maximum benchmark size limit (%d bytes)", cleanPath, MaxManifestBytes)
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", cleanPath, err)
	}

	components, err := s.ExtractComponents(string(content), cleanPath)
	if err != nil {
		return nil, err
	}

	violations, summary := s.EvaluateComponents(components, cleanPath)

	return &CISAuditReport{
		AuditTime:  time.Now().UTC(),
		TotalFiles: 1,
		Components: components,
		Violations: violations,
		Summary:    summary,
	}, nil
}

// ScanDirectory walks a directory hierarchy and audits all NixOS and Kubernetes configuration files.
func (s *CISScanner) ScanDirectory(dirPath string) (*CISAuditReport, error) {
	cleanDir := filepath.Clean(dirPath)
	var allComponents []ComponentDeclaration
	totalFiles := 0

	err := filepath.Walk(cleanDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".nix" && ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		if info.Size() > MaxManifestBytes {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		components, err := s.ExtractComponents(string(content), path)
		if err == nil && len(components) > 0 {
			allComponents = append(allComponents, components...)
			totalFiles++
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", cleanDir, err)
	}

	violations, summary := s.EvaluateComponents(allComponents, cleanDir)

	return &CISAuditReport{
		AuditTime:  time.Now().UTC(),
		TotalFiles: totalFiles,
		Components: allComponents,
		Violations: violations,
		Summary:    summary,
	}, nil
}

// ExtractComponents discovers Kubernetes control plane and worker components in Nix or YAML definitions.
func (s *CISScanner) ExtractComponents(content string, filePath string) ([]ComponentDeclaration, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".nix" {
		return s.extractNixComponents(content, filePath), nil
	}
	return s.extractYAMLComponents(content, filePath), nil
}

// extractNixComponents parses Nix expressions looking for services.kubernetes.* and systemd units.
func (s *CISScanner) extractNixComponents(content string, filePath string) []ComponentDeclaration {
	compMap := make(map[ComponentType]*ComponentDeclaration)

	getOrCreate := func(ct ComponentType, line int) *ComponentDeclaration {
		if decl, exists := compMap[ct]; exists {
			return decl
		}
		decl := &ComponentDeclaration{
			Component: ct,
			FilePath:  filePath,
			StartLine: line,
			Flags:     make(map[string]string),
		}
		compMap[ct] = decl
		return decl
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	var currentComp ComponentType

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxScanLines {
			break
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect nested component block start
		switch {
		case strings.HasPrefix(trimmed, "apiserver = {") || strings.Contains(line, "services.kubernetes.apiserver"):
			currentComp = ComponentAPIServer
			getOrCreate(currentComp, lineNum)
		case strings.HasPrefix(trimmed, "controllerManager = {") || strings.Contains(line, "services.kubernetes.controllerManager"):
			currentComp = ComponentControllerManager
			getOrCreate(currentComp, lineNum)
		case strings.HasPrefix(trimmed, "scheduler = {") || strings.Contains(line, "services.kubernetes.scheduler"):
			currentComp = ComponentScheduler
			getOrCreate(currentComp, lineNum)
		case strings.HasPrefix(trimmed, "kubelet = {") || strings.Contains(line, "services.kubernetes.kubelet"):
			currentComp = ComponentKubelet
			getOrCreate(currentComp, lineNum)
		case strings.HasPrefix(trimmed, "services.etcd = {") || strings.HasPrefix(trimmed, "etcd = {"):
			currentComp = ComponentEtcd
			getOrCreate(currentComp, lineNum)
		}

		// Check for services.kubernetes.<component>.extraOpts
		if matches := nixExtraOptsRegex.FindStringSubmatch(line); len(matches) == 3 {
			compName := strings.ToLower(matches[1])
			flagStr := matches[2]
			ct := mapComponentName(compName)
			if ct != "" {
				decl := getOrCreate(ct, lineNum)
				s.extractFlagsFromString(flagStr, decl.Flags)
			}
			continue
		}

		// Check for direct services.kubernetes.<comp>.<option> = <value>;
		if matches := nixAssignRegex.FindStringSubmatch(line); len(matches) == 4 {
			compName := strings.ToLower(matches[1])
			option := strings.TrimSpace(matches[2])
			val := strings.Trim(strings.TrimSpace(matches[3]), `";`)
			ct := mapComponentName(compName)
			if ct != "" {
				decl := getOrCreate(ct, lineNum)
				s.mapNixOptionToFlag(option, val, decl.Flags)
			}
			continue
		}

		// If inside a component block, inspect properties and extraOpts
		if currentComp != "" {
			decl := getOrCreate(currentComp, lineNum)

			if strings.Contains(line, "extraOpts") && strings.Contains(line, "=") {
				s.extractFlagsFromString(line, decl.Flags)
			} else if strings.Contains(line, "=") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					opt := strings.TrimSpace(parts[0])
					val := strings.Trim(strings.TrimSpace(parts[1]), `";`)
					s.mapNixOptionToFlag(opt, val, decl.Flags)
				}
			}

			if strings.Contains(line, "--") {
				s.extractFlagsFromString(line, decl.Flags)
			}
		}

		// Check for systemd service ExecStart flags
		if strings.Contains(line, "kube-apiserver") {
			decl := getOrCreate(ComponentAPIServer, lineNum)
			s.extractFlagsFromString(line, decl.Flags)
		} else if strings.Contains(line, "kube-controller-manager") {
			decl := getOrCreate(ComponentControllerManager, lineNum)
			s.extractFlagsFromString(line, decl.Flags)
		} else if strings.Contains(line, "kube-scheduler") {
			decl := getOrCreate(ComponentScheduler, lineNum)
			s.extractFlagsFromString(line, decl.Flags)
		} else if strings.Contains(line, "etcd.service") {
			decl := getOrCreate(ComponentEtcd, lineNum)
			s.extractFlagsFromString(line, decl.Flags)
		}
	}

	result := make([]ComponentDeclaration, 0, len(compMap))
	for _, decl := range compMap {
		result = append(result, *decl)
	}
	return result
}

// extractYAMLComponents parses KubeletConfiguration or component manifests.
func (s *CISScanner) extractYAMLComponents(content string, filePath string) []ComponentDeclaration {
	var decls []ComponentDeclaration
	flags := make(map[string]string)
	compType := ComponentKubelet
	startLine := 1

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	inAnonymousBlock := false
	inAuthBlock := false

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxScanLines {
			break
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.Contains(line, "kind: KubeletConfiguration") {
			compType = ComponentKubelet
			startLine = lineNum
		} else if strings.Contains(line, "kind: KubeSchedulerConfiguration") {
			compType = ComponentScheduler
			startLine = lineNum
		}

		// Extract flags from command lines or args arrays
		if strings.Contains(line, "--") {
			s.extractFlagsFromString(line, flags)
		}

		// Track indentation blocks for KubeletConfiguration YAML
		if strings.HasPrefix(line, "authentication:") {
			inAuthBlock = true
			continue
		}
		if inAuthBlock && strings.HasPrefix(trimmed, "anonymous:") {
			inAnonymousBlock = true
			continue
		}
		if inAnonymousBlock && strings.HasPrefix(trimmed, "enabled:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				flags["anonymous-auth"] = val
			}
			inAnonymousBlock = false
			continue
		}

		// Kubelet direct yaml keys
		if matches := yamlKVRegex.FindStringSubmatch(line); len(matches) == 3 {
			k := strings.ToLower(matches[1])
			v := strings.Trim(strings.TrimSpace(matches[2]), `"'`)
			switch k {
			case "readonlyport":
				flags["read-only-port"] = v
			case "protectkerneldefaults":
				flags["protect-kernel-defaults"] = v
			case "rotatecertificates":
				flags["rotate-certificates"] = v
			case "mode":
				if strings.EqualFold(v, "webhook") || strings.EqualFold(v, "alwaysallow") {
					flags["authorization-mode"] = v
				}
			}
		}
	}

	if len(flags) > 0 {
		decls = append(decls, ComponentDeclaration{
			Component: compType,
			FilePath:  filePath,
			StartLine: startLine,
			Flags:     flags,
		})
	}

	return decls
}

func (s *CISScanner) extractFlagsFromString(str string, dest map[string]string) {
	matches := flagRegex.FindAllStringSubmatch(str, -1)
	for _, m := range matches {
		if len(m) > 1 {
			flagKey := strings.ToLower(m[1])
			flagVal := "true"
			if len(m) > 2 && m[2] != "" {
				flagVal = m[2]
			} else if len(m) > 3 && m[3] != "" {
				flagVal = m[3]
			}
			dest[flagKey] = flagVal
		}
	}
}

func (s *CISScanner) mapNixOptionToFlag(option, val string, dest map[string]string) {
	optLower := strings.ToLower(option)
	switch {
	case strings.Contains(optLower, "anonymousauth"):
		dest["anonymous-auth"] = val
	case strings.Contains(optLower, "authorizationmode"):
		dest["authorization-mode"] = val
	case strings.Contains(optLower, "kubelethttps"):
		dest["kubelet-https"] = val
	case strings.Contains(optLower, "kubeletclientcertfile"):
		dest["kubelet-client-certificate"] = val
	case strings.Contains(optLower, "kubeletclientkeyfile"):
		dest["kubelet-client-key"] = val
	case strings.Contains(optLower, "kubeletcafile"):
		dest["kubelet-certificate-authority"] = val
	case strings.Contains(optLower, "clientcertauth"):
		dest["client-cert-auth"] = val
	case strings.Contains(optLower, "peercertfile"):
		dest["peer-cert-file"] = val
	case strings.Contains(optLower, "peerkeyfile"):
		dest["peer-key-file"] = val
	case strings.Contains(optLower, "certfile"):
		dest["cert-file"] = val
	case strings.Contains(optLower, "keyfile"):
		dest["key-file"] = val
	case strings.Contains(optLower, "serviceaccountkeyfile"):
		dest["service-account-private-key-file"] = val
	case strings.Contains(optLower, "rootcafile"):
		dest["root-ca-file"] = val
	}
}

func mapComponentName(name string) ComponentType {
	switch strings.ToLower(name) {
	case "apiserver", "kube-apiserver":
		return ComponentAPIServer
	case "controllermanager", "controller-manager", "kube-controller-manager":
		return ComponentControllerManager
	case "scheduler", "kube-scheduler":
		return ComponentScheduler
	case "etcd":
		return ComponentEtcd
	case "kubelet":
		return ComponentKubelet
	default:
		return ""
	}
}

// EvaluateComponents verifies the parsed flags of each component against CIS Benchmark rules.
func (s *CISScanner) EvaluateComponents(components []ComponentDeclaration, defaultPath string) ([]CISViolation, CISSummary) {
	var violations []CISViolation
	rules := AllCISRules()

	compPresence := make(map[ComponentType]*ComponentDeclaration)
	for i := range components {
		c := &components[i]
		compPresence[c.Component] = c
	}

	compPassed := make(map[ComponentType]int)
	compTotal := make(map[ComponentType]int)

	for _, rule := range rules {
		compTotal[rule.Component]++
		decl, exists := compPresence[rule.Component]

		filePath := defaultPath
		startLine := 1
		if exists {
			filePath = decl.FilePath
			startLine = decl.StartLine
		}

		passed, actualVal := s.checkRule(rule, decl)
		if passed {
			compPassed[rule.Component]++
			continue
		}

		matchedCVE := ""
		if s.Feed != nil {
			matchedCVE = s.correlateCVE(rule)
		}

		viol := CISViolation{
			RuleID:         rule.ID,
			Section:        rule.Section,
			Component:      rule.Component,
			FilePath:       filePath,
			StartLine:      startLine,
			Severity:       rule.Severity,
			CVSSScore:      rule.CVSSScore,
			Title:          rule.Title,
			Description:    rule.Description,
			FlagName:       rule.FlagName,
			ActualValue:    actualVal,
			ExpectedValue:  rule.ExpectedValue,
			Remediation:    rule.Rationale,
			RemediationNix: rule.RemediationNix,
			MatchedCVE:     matchedCVE,
		}
		violations = append(violations, viol)
	}

	// Compute summary metrics
	totalChecks := len(rules)
	failedChecks := len(violations)
	passedChecks := totalChecks - failedChecks

	complianceScore := 0.0
	if totalChecks > 0 {
		complianceScore = math.Round((float64(passedChecks)/float64(totalChecks))*1000) / 10
	}

	compScores := make(map[string]float64)
	for ct, tot := range compTotal {
		pass := compPassed[ct]
		if tot > 0 {
			compScores[string(ct)] = math.Round((float64(pass)/float64(tot))*1000) / 10
		}
	}

	crit, high, med, low := 0, 0, 0, 0
	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			crit++
		case intel.SeverityHigh:
			high++
		case intel.SeverityMedium:
			med++
		case intel.SeverityLow:
			low++
		}
	}

	summary := CISSummary{
		TotalChecks:     totalChecks,
		PassedChecks:    passedChecks,
		FailedChecks:    failedChecks,
		ComplianceScore: complianceScore,
		CriticalCount:   crit,
		HighCount:       high,
		MediumCount:     med,
		LowCount:        low,
		ComponentScores: compScores,
	}

	return violations, summary
}

func (s *CISScanner) checkRule(rule CISRule, decl *ComponentDeclaration) (bool, string) {
	if decl == nil {
		return false, "<component-not-configured>"
	}

	val, exists := decl.Flags[rule.FlagName]

	switch rule.ID {
	case "CIS-1.2.1", "CIS-4.2.1": // anonymous-auth=false
		if !exists {
			return false, "<unset, defaults to true>"
		}
		if strings.EqualFold(val, "false") {
			return true, val
		}
		return false, val

	case "CIS-1.2.2": // token-auth-file must not be set
		if !exists || val == "" {
			return true, "<unset>"
		}
		return false, val

	case "CIS-1.2.3": // kubelet-https=true
		if !exists {
			return false, "<unset>"
		}
		return strings.EqualFold(val, "true"), val

	case "CIS-1.2.6": // authorization-mode Node,RBAC and not AlwaysAllow
		if !exists {
			return false, "<unset>"
		}
		if strings.Contains(strings.ToLower(val), "alwaysallow") {
			return false, val
		}
		if strings.Contains(strings.ToLower(val), "rbac") {
			return true, val
		}
		return false, val

	case "CIS-4.2.2": // Kubelet authorization-mode Webhook
		if !exists {
			return false, "<unset>"
		}
		if strings.EqualFold(val, "alwaysallow") {
			return false, "AlwaysAllow"
		}
		return strings.EqualFold(val, "webhook"), val

	case "CIS-4.2.4": // read-only-port=0
		if !exists {
			return false, "<unset, defaults to 10255>"
		}
		return val == "0", val

	case "CIS-1.2.14", "CIS-1.3.2", "CIS-1.4.1": // profiling=false
		if !exists {
			return false, "<unset, defaults to true>"
		}
		return strings.EqualFold(val, "false"), val

	case "CIS-1.3.7", "CIS-1.4.2": // bind-address=127.0.0.1
		if !exists {
			return false, "<unset, defaults to 0.0.0.0>"
		}
		return val == "127.0.0.1", val

	case "CIS-2.7": // auto-tls must not be true
		if !exists {
			return true, "<unset>"
		}
		return !strings.EqualFold(val, "true"), val

	case "CIS-1.3.3", "CIS-2.2", "CIS-4.2.6", "CIS-4.2.10": // flags expecting true
		if !exists {
			return false, "<unset>"
		}
		return strings.EqualFold(val, "true"), val

	default: // general flags requiring being set
		if rule.ExpectedValue == "<set>" || rule.ExpectedValue == "<strong-ciphers>" || rule.ExpectedValue == "<positive-int>" {
			if !exists || val == "" {
				return false, "<unset>"
			}
			return true, val
		}
		if !exists {
			return false, "<unset>"
		}
		return strings.EqualFold(val, rule.ExpectedValue), val
	}
}

func (s *CISScanner) correlateCVE(rule CISRule) string {
	for _, item := range s.Feed.Items {
		switch rule.ID {
		case "CIS-4.2.1", "CIS-4.2.2", "CIS-4.2.4":
			if strings.EqualFold(item.Component, "kubelet") {
				return item.ID
			}
		case "CIS-1.2.1", "CIS-1.2.6":
			if strings.EqualFold(item.Component, "apiserver") || strings.EqualFold(item.Component, "kubernetes") {
				return item.ID
			}
		}
	}
	return ""
}
