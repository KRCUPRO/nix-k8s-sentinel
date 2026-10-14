package k8s

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const (
	// MaxManifestBytes sets a 10MB upper limit to prevent memory exhaustion attacks.
	MaxManifestBytes = 10 * 1024 * 1024
	// MaxDocumentsPerStream prevents algorithmic complexity attacks via document flooding.
	MaxDocumentsPerStream = 1000
)

// Violation represents a concrete security finding identified in a Kubernetes resource.
type Violation struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	ResourceKind string         `json:"resource_kind"`
	ResourceName string         `json:"resource_name"`
	Namespace    string         `json:"namespace"`
	Severity     intel.Severity `json:"severity"`
	CVSSScore    float64        `json:"cvss_score"`
	Description  string         `json:"description"`
	Remediation  string         `json:"remediation"`
	MatchedCVE   string         `json:"matched_cve,omitempty"`
	FilePath     string         `json:"file_path,omitempty"`
	StartLine    int            `json:"start_line,omitempty"`
}

// RawResource encapsulates parsed declarative metadata and block contents.
type RawResource struct {
	APIVersion  string            `json:"api_version"`
	Kind        string            `json:"kind"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`
	RawContent  string            `json:"raw_content"`
}

// ParseManifestDocuments splits a multi-document YAML stream into distinct RawResource items.
func ParseManifestDocuments(content string) ([]RawResource, error) {
	if len(content) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest payload exceeds maximum allowable size of %d bytes", MaxManifestBytes)
	}

	rawDocs := splitYamlDocuments(content)
	if len(rawDocs) > MaxDocumentsPerStream {
		return nil, fmt.Errorf("document count (%d) exceeds safety ceiling of %d", len(rawDocs), MaxDocumentsPerStream)
	}

	var resources []RawResource
	for _, doc := range rawDocs {
		trimmed := strings.TrimSpace(doc)
		if trimmed == "" {
			continue
		}

		res := parseSingleResource(trimmed)
		if res.Kind != "" {
			resources = append(resources, res)
		}
	}

	return resources, nil
}

// splitYamlDocuments splits streams on '---' boundaries while ignoring comments.
func splitYamlDocuments(content string) []string {
	var docs []string
	var current strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			if current.Len() > 0 {
				docs = append(docs, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}

	if current.Len() > 0 {
		docs = append(docs, current.String())
	}

	return docs
}

// parseSingleResource extracts Kubernetes metadata fields with line-based parsing.
func parseSingleResource(doc string) RawResource {
	res := RawResource{
		Annotations: make(map[string]string),
		Labels:      make(map[string]string),
		RawContent:  doc,
		Namespace:   "default",
	}

	scanner := bufio.NewScanner(strings.NewReader(doc))
	inMetadata := false
	inAnnotations := false
	inLabels := false
	metadataIndent := -1
	sectionIndent := -1
	currAnnKey := ""
	currAnnIndent := -1

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := countLeadingSpaces(line)

		// Root-level fields
		if indent == 0 {
			inMetadata = false
			inAnnotations = false
			inLabels = false
			currAnnKey = ""

			if strings.HasPrefix(trimmed, "apiVersion:") {
				res.APIVersion = cleanYamlValue(strings.TrimPrefix(trimmed, "apiVersion:"))
			} else if strings.HasPrefix(trimmed, "kind:") {
				res.Kind = cleanYamlValue(strings.TrimPrefix(trimmed, "kind:"))
			} else if strings.HasPrefix(trimmed, "metadata:") {
				inMetadata = true
				metadataIndent = indent
			}
			continue
		}

		// Inside metadata block
		if inMetadata && indent > metadataIndent {
			if inAnnotations {
				if indent > sectionIndent {
					if strings.Contains(trimmed, ":") && (currAnnKey == "" || indent <= currAnnIndent) {
						parts := strings.SplitN(trimmed, ":", 2)
						key := strings.TrimSpace(parts[0])
						val := cleanYamlValue(parts[1])
						currAnnKey = key
						currAnnIndent = indent
						if val == "|" || val == "|-" || val == ">" || val == ">-" {
							res.Annotations[key] = ""
						} else {
							res.Annotations[key] = val
						}
						continue
					} else if currAnnKey != "" && indent > currAnnIndent {
						// Multiline scalar continuation
						if res.Annotations[currAnnKey] != "" {
							res.Annotations[currAnnKey] += "\n"
						}
						res.Annotations[currAnnKey] += trimmed
						continue
					}
				} else if indent <= sectionIndent {
					inAnnotations = false
					currAnnKey = ""
				}
			}

			if inLabels {
				currAnnKey = ""
				if indent > sectionIndent && strings.Contains(trimmed, ":") {
					parts := strings.SplitN(trimmed, ":", 2)
					key := strings.TrimSpace(parts[0])
					val := cleanYamlValue(parts[1])
					res.Labels[key] = val
					continue
				} else if indent <= sectionIndent {
					inLabels = false
				}
			}

			if strings.HasPrefix(trimmed, "name:") {
				res.Name = cleanYamlValue(strings.TrimPrefix(trimmed, "name:"))
			} else if strings.HasPrefix(trimmed, "namespace:") {
				res.Namespace = cleanYamlValue(strings.TrimPrefix(trimmed, "namespace:"))
			} else if strings.HasPrefix(trimmed, "annotations:") {
				inAnnotations = true
				inLabels = false
				sectionIndent = indent
			} else if strings.HasPrefix(trimmed, "labels:") {
				inLabels = true
				inAnnotations = false
				sectionIndent = indent
			}
		}
	}

	return res
}

func countLeadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}

func cleanYamlValue(val string) string {
	v := strings.TrimSpace(val)
	v = strings.Trim(v, `"'`)
	return v
}
