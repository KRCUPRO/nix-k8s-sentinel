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
		ver = "0.6.0"
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

	// 4. Process Standalone Feed Advisories (if neither k8s nor flake nor probe was specified)
	if (opts.K8sReport == nil || len(opts.K8sReport.Violations) == 0) && len(opts.FlakeMatches) == 0 && len(opts.ProbeEvents) == 0 && opts.Feed != nil {
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
