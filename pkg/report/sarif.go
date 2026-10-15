package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// SARIFSchemaURI defines the official OASIS SARIF v2.1.0 JSON schema specification.
	SARIFSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	// SARIFVersion specifies the standard specification version.
	SARIFVersion = "2.1.0"
	// ToolInformationURI points to the official repository.
	ToolInformationURI = "https://github.com/KRCUPRO/nix-k8s-sentinel"
)

// SARIFLog represents the top-level SARIF v2.1.0 document.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun describes an individual execution of an analysis tool.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool encapsulates metadata about the scanning utility.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the core analysis engine and its declarative ruleset.
type SARIFDriver struct {
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	SemanticVersion string                `json:"semanticVersion,omitempty"`
	InformationURI  string                `json:"informationUri"`
	Rules           []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor defines a SARIF rule metadata entry.
type ReportingDescriptor struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name,omitempty"`
	ShortDescription     *MultiformatMessage     `json:"shortDescription,omitempty"`
	FullDescription      *MultiformatMessage     `json:"fullDescription,omitempty"`
	DefaultConfiguration *ReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Help                 *MultiformatMessage     `json:"help,omitempty"`
	HelpURI              string                  `json:"helpUri,omitempty"`
	Properties           map[string]any          `json:"properties,omitempty"`
}

// MultiformatMessage provides plain text and optional markdown descriptions.
type MultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// ReportingConfiguration specifies default severity levels.
type ReportingConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note", "none"
}

// SARIFResult represents an individual security finding.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage encapsulates finding text.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes the physical and logical position of a finding.
type SARIFLocation struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation describes the file and line range of a finding.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation specifies the file URI.
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region describes the line and column boundaries.
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// LogicalLocation describes logical resource context.
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	Kind               string `json:"kind,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

// BuildSARIFReport synthesizes an OASIS SARIF v2.1.0 document from audit results.
func BuildSARIFReport(opts ReportOptions) (*SARIFLog, error) {
	ver := opts.Version
	if ver == "" {
		ver = "0.8.0"
	}

	driver := SARIFDriver{
		Name:            "nix-k8s-sentinel",
		Version:         ver,
		SemanticVersion: ver,
		InformationURI:  ToolInformationURI,
		Rules:           make([]ReportingDescriptor, 0),
	}

	ruleIndexMap := make(map[string]int)

	getOrCreateRule := func(ruleID, title, description, remediation string, sev intel.Severity, cvss float64, tags []string) int {
		if idx, exists := ruleIndexMap[ruleID]; exists {
			return idx
		}

		level := SeverityToSARIFLevel(string(sev), cvss)
		cvssStr := NormalizeCVSSString(cvss)

		helpMarkdown := fmt.Sprintf("### %s (%s)\n\n**Severity:** %s (CVSS %s)\n\n%s\n\n#### Remediation Guidance\n%s\n",
			title, ruleID, string(sev), cvssStr, description, remediation)

		rule := ReportingDescriptor{
			ID:   ruleID,
			Name: FormatRuleName(ruleID, title),
			ShortDescription: &MultiformatMessage{
				Text: title,
			},
			FullDescription: &MultiformatMessage{
				Text: description,
			},
			DefaultConfiguration: &ReportingConfiguration{
				Level: level,
			},
			Help: &MultiformatMessage{
				Text:     fmt.Sprintf("%s. Mitigation: %s", description, remediation),
				Markdown: helpMarkdown,
			},
			HelpURI: ToolInformationURI,
			Properties: map[string]any{
				"security-severity": cvssStr,
				"precision":         "high",
				"problem.severity":  level,
				"tags":              tags,
			},
		}

		idx := len(driver.Rules)
		driver.Rules = append(driver.Rules, rule)
		ruleIndexMap[ruleID] = idx
		return idx
	}

	results := make([]SARIFResult, 0)

	// 1. Process Kubernetes Manifest Violations
	if opts.K8sReport != nil && len(opts.K8sReport.Violations) > 0 {
		for _, v := range opts.K8sReport.Violations {
			tags := []string{"security", "kubernetes", strings.ToLower(v.ResourceKind)}
			if v.MatchedCVE != "" {
				tags = append(tags, strings.ToLower(v.MatchedCVE))
			}

			ruleIdx := getOrCreateRule(v.RuleID, v.Title, v.Description, v.Remediation, v.Severity, v.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(v.Severity), v.CVSSScore)

			targetURI := v.FilePath
			if targetURI == "" {
				targetURI = opts.K8sPath
			}
			if targetURI == "" {
				targetURI = "manifests/k8s-manifest.yaml"
			}
			targetURI = filepath.ToSlash(targetURI)

			line := v.StartLine
			if line <= 0 {
				line = 1
			}

			resMsg := fmt.Sprintf("[%s/%s] %s: %s", v.ResourceKind, v.ResourceName, v.Title, v.Description)
			if v.Remediation != "" {
				resMsg = fmt.Sprintf("%s (Remediation: %s)", resMsg, v.Remediation)
			}

			results = append(results, SARIFResult{
				RuleID:    v.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       targetURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               v.ResourceName,
								Kind:               v.ResourceKind,
								FullyQualifiedName: fmt.Sprintf("%s/%s", v.Namespace, v.ResourceName),
							},
						},
					},
				},
			})
		}
	}

	// 2. Process Nix Flake Dependency CVE Matches
	if len(opts.FlakeMatches) > 0 {
		for _, m := range opts.FlakeMatches {
			tags := []string{"security", "nixos", "flake-lock", "dependency"}
			desc := fmt.Sprintf("Nix flake input '%s' (locked revision %s) matches vulnerability %s.",
				m.DependencyName, m.InstalledRev, m.AdvisoryID)

			ruleIdx := getOrCreateRule(m.AdvisoryID, m.Title, desc, m.Mitigation, m.Severity, m.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(m.Severity), m.CVSSScore)

			flakeURI := m.FilePath
			if flakeURI == "" {
				flakeURI = opts.FlakePath
			}
			if flakeURI == "" {
				flakeURI = "flake.lock"
			}
			flakeURI = filepath.ToSlash(flakeURI)

			line := m.StartLine
			if line <= 0 {
				line = 1
			}

			resMsg := fmt.Sprintf("Nix flake input '%s' (rev %s): %s [Mitigation: %s]",
				m.DependencyName, m.InstalledRev, m.Title, m.Mitigation)

			results = append(results, SARIFResult{
				RuleID:    m.AdvisoryID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       flakeURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               m.DependencyName,
								Kind:               "FlakeInput",
								FullyQualifiedName: fmt.Sprintf("%s/%s", m.NodeKey, m.DependencyName),
							},
						},
					},
				},
			})
		}
	}

	// 3. Process Bare-Metal eBPF Telemetry Findings
	if len(opts.ProbeEvents) > 0 {
		for _, ev := range opts.ProbeEvents {
			if ev.RiskScore < 4.0 && ev.Severity != "CRITICAL" && ev.Severity != "HIGH" {
				continue
			}
			ruleID := ev.EventType
			if len(ev.ThreatTags) > 0 {
				ruleID = ev.ThreatTags[0]
			}
			tags := []string{"security", "ebpf", "telemetry", string(ev.ProbeType), ev.NodeName}
			ruleIdx := getOrCreateRule(ruleID, ev.EventType, ev.Message, "Isolate suspicious node/pod and enforce network policy egress restrictions.", intel.Severity(ev.Severity), ev.RiskScore, tags)
			level := SeverityToSARIFLevel(ev.Severity, ev.RiskScore)

			locURI := fmt.Sprintf("nodes/%s/%s", ev.NodeName, strings.ToLower(string(ev.ProbeType)))
			resMsg := fmt.Sprintf("[%s/%s] %s: %s (PID: %d, Comm: %s)", ev.NodeName, ev.ProbeType, ev.EventType, ev.Message, ev.PID, ev.Comm)

			results = append(results, SARIFResult{
				RuleID:    ruleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   1,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               ev.Comm,
								Kind:               "KernelProcess",
								FullyQualifiedName: fmt.Sprintf("%s/%s", ev.NodeName, ev.Comm),
							},
						},
					},
				},
			})
		}
	}

	// 4. Process Rook Ceph Storage Cluster Integrity Violations
	if len(opts.StorageViolations) > 0 {
		for _, sv := range opts.StorageViolations {
			tags := []string{"security", "storage", "ceph", "rook", strings.ToLower(sv.ResourceKind)}
			if sv.MatchedCVE != "" {
				tags = append(tags, sv.MatchedCVE)
			}
			ruleIdx := getOrCreateRule(sv.RuleID, sv.Title, sv.Description, sv.Remediation, sv.Severity, sv.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(sv.Severity), sv.CVSSScore)

			locURI := sv.FilePath
			if locURI == "" {
				locURI = opts.StoragePath
			}
			if locURI == "" {
				locURI = fmt.Sprintf("storage/%s/%s", strings.ToLower(sv.ResourceKind), sv.ResourceName)
			}
			locURI = filepath.ToSlash(locURI)

			line := sv.StartLine
			if line <= 0 {
				line = 1
			}

			cveTag := ""
			if sv.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", sv.MatchedCVE)
			}
			resMsg := fmt.Sprintf("[%s/%s]%s %s: %s (Remediation: %s)", sv.ResourceKind, sv.ResourceName, cveTag, sv.Title, sv.Description, sv.Remediation)

			results = append(results, SARIFResult{
				RuleID:    sv.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               sv.ResourceName,
								Kind:               sv.ResourceKind,
								FullyQualifiedName: fmt.Sprintf("%s/%s", sv.ResourceKind, sv.ResourceName),
							},
						},
					},
				},
			})
		}
	}

	// 5. Process WireGuard Mesh Violations
	if len(opts.WireGuardViolations) > 0 {
		for _, wv := range opts.WireGuardViolations {
			tags := []string{"security", "wireguard", "mesh", "crypto", strings.ToLower(wv.InterfaceName)}
			if wv.MatchedCVE != "" {
				tags = append(tags, wv.MatchedCVE)
			}
			ruleIdx := getOrCreateRule(wv.RuleID, wv.Title, wv.Description, wv.Remediation, wv.Severity, wv.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(wv.Severity), wv.CVSSScore)

			locURI := wv.FilePath
			if locURI == "" {
				locURI = opts.WireGuardPath
			}
			if locURI == "" {
				locURI = fmt.Sprintf("wireguard/%s", wv.InterfaceName)
			}
			locURI = filepath.ToSlash(locURI)

			line := wv.StartLine
			if line <= 0 {
				line = 1
			}

			cveTag := ""
			if wv.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", wv.MatchedCVE)
			}
			peerTag := ""
			if wv.PeerPublicKey != "" {
				peerTag = fmt.Sprintf(" (Peer: %s)", wv.PeerPublicKey)
			}
			resMsg := fmt.Sprintf("[%s]%s%s %s: %s (Remediation: %s)", wv.InterfaceName, peerTag, cveTag, wv.Title, wv.Description, wv.Remediation)

			results = append(results, SARIFResult{
				RuleID:    wv.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               wv.InterfaceName,
								Kind:               "WireGuardInterface",
								FullyQualifiedName: fmt.Sprintf("wireguard/%s", wv.InterfaceName),
							},
						},
					},
				},
			})
		}
	}

	// 6. Process CIS Kubernetes Benchmark Violations
	if len(opts.CISViolations) > 0 {
		for _, cv := range opts.CISViolations {
			tags := []string{"security", "kubernetes", "cis-benchmark", string(cv.Component), cv.Section}
			if cv.MatchedCVE != "" {
				tags = append(tags, cv.MatchedCVE)
			}
			ruleIdx := getOrCreateRule(cv.RuleID, cv.Title, cv.Description, cv.Remediation, cv.Severity, cv.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(cv.Severity), cv.CVSSScore)

			locURI := cv.FilePath
			if locURI == "" {
				locURI = opts.CISPath
			}
			if locURI == "" {
				locURI = fmt.Sprintf("k8s/%s", cv.Component)
			}
			locURI = filepath.ToSlash(locURI)

			line := cv.StartLine
			if line <= 0 {
				line = 1
			}

			cveTag := ""
			if cv.MatchedCVE != "" {
				cveTag = fmt.Sprintf(" [%s]", cv.MatchedCVE)
			}
			resMsg := fmt.Sprintf("[%s Section %s]%s %s: Flag '%s' is '%s' (expected '%s')",
				cv.Component, cv.Section, cveTag, cv.Title, cv.FlagName, cv.ActualValue, cv.ExpectedValue)

			results = append(results, SARIFResult{
				RuleID:    cv.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               cv.RuleID,
								Kind:               "CISBenchmarkRule",
								FullyQualifiedName: fmt.Sprintf("cis/%s/%s", cv.Component, cv.RuleID),
							},
						},
					},
				},
			})
		}
	}

	// 7. Process Gateway API & EnvoyFilter Route Threat Radar Violations
	if len(opts.GatewayViolations) > 0 {
		for _, gv := range opts.GatewayViolations {
			tags := []string{"security", "kubernetes", "gateway-api", "envoy", strings.ToLower(gv.Category)}
			ruleIdx := getOrCreateRule(gv.RuleID, gv.Title, gv.Message, gv.Remediation, gv.Severity, gv.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(gv.Severity), gv.CVSSScore)

			locURI := gv.FilePath
			if locURI == "" {
				locURI = opts.GatewayPath
			}
			if locURI == "" {
				locURI = "gateway-routes.yaml"
			}
			locURI = filepath.ToSlash(locURI)

			line := gv.StartLine
			if line <= 0 {
				line = 1
			}

			cveSuffix := ""
			if gv.MatchedCVE != "" {
				cveSuffix = fmt.Sprintf(" [%s]", gv.MatchedCVE)
			}
			resMsg := fmt.Sprintf("[%s/%s] %s: %s%s (Remediation: %s)", gv.ResourceKind, gv.ResourceName, gv.Title, gv.Message, cveSuffix, gv.Remediation)

			results = append(results, SARIFResult{
				RuleID:    gv.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               gv.RuleID,
								Kind:               gv.ResourceKind,
								FullyQualifiedName: fmt.Sprintf("gateway/%s/%s/%s", gv.Namespace, gv.ResourceKind, gv.ResourceName),
							},
						},
					},
				},
			})
		}
	}

	// 8. Process Confidential Computing & Measured Boot Attestation Violations
	if len(opts.AttestViolations) > 0 {
		for _, av := range opts.AttestViolations {
			tags := []string{"security", "confidential-computing", "measured-boot", "tpm2", strings.ToLower(av.Category)}
			ruleIdx := getOrCreateRule(av.RuleID, av.Title, av.Message, av.Remediation, av.Severity, av.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(av.Severity), av.CVSSScore)

			locURI := av.FilePath
			if locURI == "" {
				locURI = opts.AttestPath
			}
			if locURI == "" {
				locURI = opts.AttestTelemetryPath
			}
			if locURI == "" {
				locURI = "nixos-attestation.json"
			}
			locURI = filepath.ToSlash(locURI)

			line := av.StartLine
			if line <= 0 {
				line = 1
			}

			cveSuffix := ""
			if av.MatchedCVE != "" {
				cveSuffix = fmt.Sprintf(" [%s]", av.MatchedCVE)
			}
			resMsg := fmt.Sprintf("[%s/%s] %s: %s%s (Remediation: %s)", av.Technology, av.Target, av.Title, av.Message, cveSuffix, av.Remediation)

			results = append(results, SARIFResult{
				RuleID:    av.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               av.RuleID,
								Kind:               "AttestationViolation",
								FullyQualifiedName: fmt.Sprintf("attest/%s/%s", av.Technology, av.Target),
							},
						},
					},
				},
			})
		}
	}

	// 9. Process Multi-Cluster Fleet Synchronization & OIDC Token Radar Violations
	if len(opts.FleetViolations) > 0 {
		for _, fv := range opts.FleetViolations {
			tags := []string{"security", "kubernetes", "fleet", "gitops", "oidc", strings.ToLower(string(fv.Category))}
			if fv.MatchedCVE != "" {
				tags = append(tags, fv.MatchedCVE)
			}
			ruleIdx := getOrCreateRule(fv.RuleID, fv.Title, fv.Message, fv.Remediation, fv.Severity, fv.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(fv.Severity), fv.CVSSScore)

			locURI := fv.FilePath
			if locURI == "" {
				locURI = opts.FleetPath
			}
			if locURI == "" {
				locURI = opts.FleetTelemetryPath
			}
			if locURI == "" {
				locURI = "fleet-sync.yaml"
			}
			locURI = filepath.ToSlash(locURI)

			line := fv.StartLine
			if line <= 0 {
				line = 1
			}

			cveSuffix := ""
			if fv.MatchedCVE != "" {
				cveSuffix = fmt.Sprintf(" [%s]", fv.MatchedCVE)
			}
			resMsg := fmt.Sprintf("[%s/%s] %s: %s%s (Remediation: %s)", fv.Category, fv.ResourceKind, fv.Title, fv.Message, cveSuffix, fv.Remediation)

			results = append(results, SARIFResult{
				RuleID:    fv.RuleID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       locURI,
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   line,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               fv.RuleID,
								Kind:               fv.ResourceKind,
								FullyQualifiedName: fmt.Sprintf("fleet/%s/%s/%s", fv.ClusterID, fv.ResourceKind, fv.ResourceName),
							},
						},
					},
				},
			})
		}
	}

	// 10. Process Standalone Feed Advisories (if no specific audit targets yielded findings)
	if (opts.K8sReport == nil || len(opts.K8sReport.Violations) == 0) && len(opts.FlakeMatches) == 0 && len(opts.ProbeEvents) == 0 && len(opts.StorageViolations) == 0 && len(opts.WireGuardViolations) == 0 && len(opts.CISViolations) == 0 && len(opts.GatewayViolations) == 0 && len(opts.AttestViolations) == 0 && len(opts.FleetViolations) == 0 && opts.Feed != nil {
		feedItems := opts.Feed.Items
		if opts.TargetFilter != "" {
			feedItems = opts.Feed.FilterByTarget(opts.TargetFilter)
		}

		for _, item := range feedItems {
			tags := []string{"security", item.Target, item.Component, "cve"}
			ruleIdx := getOrCreateRule(item.ID, item.Title, item.Description, item.Mitigation, item.Severity, item.CVSSScore, tags)
			level := SeverityToSARIFLevel(string(item.Severity), item.CVSSScore)

			resMsg := fmt.Sprintf("[%s/%s] %s: %s (Mitigation: %s)", item.Target, item.Component, item.Title, item.Description, item.Mitigation)

			results = append(results, SARIFResult{
				RuleID:    item.ID,
				RuleIndex: ruleIdx,
				Level:     level,
				Message:   SARIFMessage{Text: resMsg},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI:       "intel/cve-feed.json",
								URIBaseID: "%SRCROOT%",
							},
							Region: &Region{
								StartLine:   1,
								StartColumn: 1,
							},
						},
						LogicalLocations: []LogicalLocation{
							{
								Name:               item.ID,
								Kind:               "SecurityAdvisory",
								FullyQualifiedName: fmt.Sprintf("%s/%s", item.Target, item.Component),
							},
						},
					},
				},
			})
		}
	}

	sarif := &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: driver,
				},
				Results: results,
			},
		},
	}

	return sarif, nil
}

// FormatSARIF serializes a SARIFLog object into formatted JSON bytes.
func FormatSARIF(log *SARIFLog, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(log, "", "  ")
	}
	return json.Marshal(log)
}

// WriteSARIFToFile persists a SARIFLog document to disk with path traversal defense.
func WriteSARIFToFile(log *SARIFLog, destPath string, pretty bool) error {
	cleanPath := filepath.Clean(destPath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory for SARIF report: %w", err)
	}

	data, err := FormatSARIF(log, pretty)
	if err != nil {
		return fmt.Errorf("failed to serialize SARIF log: %w", err)
	}

	if err := os.WriteFile(cleanPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write SARIF report to %s: %w", cleanPath, err)
	}

	return nil
}
