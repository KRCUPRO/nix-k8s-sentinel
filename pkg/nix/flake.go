package nix

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// MaxLockfileSize limits lockfile size to 10 MB to prevent unbounded memory allocation.
const MaxLockfileSize = 10 * 1024 * 1024

// MaxTraversalDepth prevents stack/memory overflow on cyclic or deeply nested graphs.
const MaxTraversalDepth = 64

// FlakeLockedRef describes the pinned revision and source metadata of an input.
type FlakeLockedRef struct {
	Type         string `json:"type"`
	Owner        string `json:"owner,omitempty"`
	Repo         string `json:"repo,omitempty"`
	Rev          string `json:"rev,omitempty"`
	NarHash      string `json:"narHash,omitempty"`
	LastModified int64  `json:"lastModified,omitempty"`
	URL          string `json:"url,omitempty"`
	Ref          string `json:"ref,omitempty"`
}

// FlakeOriginalRef describes the original user-declared input specification.
type FlakeOriginalRef struct {
	Type  string `json:"type"`
	Owner string `json:"owner,omitempty"`
	Repo  string `json:"repo,omitempty"`
	Ref   string `json:"ref,omitempty"`
	URL   string `json:"url,omitempty"`
}

// FlakeNode represents an individual node in the flake.lock dependency graph.
type FlakeNode struct {
	Inputs   map[string]any    `json:"inputs,omitempty"`
	Locked   *FlakeLockedRef   `json:"locked,omitempty"`
	Original *FlakeOriginalRef `json:"original,omitempty"`
}

// FlakeLock represents a complete parsed flake.lock JSON document.
type FlakeLock struct {
	Version int                  `json:"version"`
	Root    string               `json:"root"`
	Nodes   map[string]FlakeNode `json:"nodes"`
}

// FlakeDependency models a resolved input dependency in the flake graph.
type FlakeDependency struct {
	Name      string         `json:"name"`
	NodeKey   string         `json:"node_key"`
	Locked    FlakeLockedRef `json:"locked"`
	Depth     int            `json:"depth"`
	InputPath []string       `json:"input_path"`
}

// NixSecurityAdvisory models a security vulnerability known to affect Nix packages/flakes.
type NixSecurityAdvisory struct {
	ID                string         `json:"id"`
	Package           string         `json:"package"`
	AffectedRevisions []string       `json:"affected_revisions,omitempty"`
	PatchedRevision   string         `json:"patched_revision,omitempty"`
	Severity          intel.Severity `json:"severity"`
	CVSSScore         float64        `json:"cvss_score"`
	Title             string         `json:"title"`
	Description       string         `json:"description"`
	Mitigation        string         `json:"mitigation"`
}

// FlakeVulnerabilityMatch represents a detected vulnerability in a flake dependency.
type FlakeVulnerabilityMatch struct {
	AdvisoryID     string         `json:"advisory_id"`
	DependencyName string         `json:"dependency_name"`
	NodeKey        string         `json:"node_key"`
	InstalledRev   string         `json:"installed_rev"`
	Severity       intel.Severity `json:"severity"`
	CVSSScore      float64        `json:"cvss_score"`
	Title          string         `json:"title"`
	Mitigation     string         `json:"mitigation"`
	FilePath       string         `json:"file_path,omitempty"`
	StartLine      int            `json:"start_line,omitempty"`
}

// ParseFlakeLock parses raw bytes into a validated FlakeLock structure.
func ParseFlakeLock(data []byte) (*FlakeLock, error) {
	if len(data) == 0 {
		return nil, errors.New("empty flake.lock content")
	}
	if len(data) > MaxLockfileSize {
		return nil, fmt.Errorf("flake.lock exceeds maximum allowed size (%d bytes)", MaxLockfileSize)
	}

	var lock FlakeLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse flake.lock JSON: %w", err)
	}

	if lock.Nodes == nil {
		return nil, errors.New("invalid flake.lock: missing nodes field")
	}
	if lock.Root == "" {
		lock.Root = "root"
	}

	return &lock, nil
}

// ParseFlakeLockFile reads and parses a flake.lock file from the filesystem.
func ParseFlakeLockFile(filePath string) (*FlakeLock, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to access flake.lock (%s): %w", filePath, err)
	}
	if info.Size() > MaxLockfileSize {
		return nil, fmt.Errorf("flake.lock file exceeds size limit (%d bytes)", MaxLockfileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read flake.lock (%s): %w", filePath, err)
	}

	return ParseFlakeLock(data)
}

func resolveInputTarget(target any) string {
	switch v := target.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if s, ok := v[len(v)-1].(string); ok {
				return s
			}
		}
	case []string:
		if len(v) > 0 {
			return v[len(v)-1]
		}
	}
	return ""
}

type queueItem struct {
	name      string
	nodeKey   string
	depth     int
	inputPath []string
}

// ResolveDependencies recursively walks the flake input graph starting from root.
func (fl *FlakeLock) ResolveDependencies(rootKey string) ([]FlakeDependency, error) {
	if rootKey == "" {
		rootKey = fl.Root
	}
	rootNode, ok := fl.Nodes[rootKey]
	if !ok {
		return nil, fmt.Errorf("root node '%s' not found in flake.lock nodes", rootKey)
	}

	var results []FlakeDependency
	visited := make(map[string]bool)
	queue := []queueItem{}

	for inputName, targetRaw := range rootNode.Inputs {
		targetKey := resolveInputTarget(targetRaw)
		if targetKey == "" {
			continue
		}
		queue = append(queue, queueItem{
			name:      inputName,
			nodeKey:   targetKey,
			depth:     1,
			inputPath: []string{inputName},
		})
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.depth > MaxTraversalDepth {
			continue
		}

		visitedKey := fmt.Sprintf("%s:%s", curr.name, curr.nodeKey)
		if visited[visitedKey] {
			continue
		}
		visited[visitedKey] = true

		targetNode, found := fl.Nodes[curr.nodeKey]
		if !found {
			continue
		}

		if targetNode.Locked != nil {
			results = append(results, FlakeDependency{
				Name:      curr.name,
				NodeKey:   curr.nodeKey,
				Locked:    *targetNode.Locked,
				Depth:     curr.depth,
				InputPath: curr.inputPath,
			})
		}

		for childName, childRaw := range targetNode.Inputs {
			childTargetKey := resolveInputTarget(childRaw)
			if childTargetKey == "" {
				continue
			}

			nextPath := make([]string, len(curr.inputPath)+1)
			copy(nextPath, curr.inputPath)
			nextPath[len(curr.inputPath)] = childName

			queue = append(queue, queueItem{
				name:      childName,
				nodeKey:   childTargetKey,
				depth:     curr.depth + 1,
				inputPath: nextPath,
			})
		}
	}

	return results, nil
}

// MapFlakeAdvisories audits resolved dependencies against a known list of Nix advisories.
func MapFlakeAdvisories(lock *FlakeLock, advisories []NixSecurityAdvisory) ([]FlakeVulnerabilityMatch, error) {
	deps, err := lock.ResolveDependencies(lock.Root)
	if err != nil {
		return nil, err
	}

	var matches []FlakeVulnerabilityMatch
	for _, dep := range deps {
		for _, adv := range advisories {
			if !matchesPackage(dep, adv.Package) {
				continue
			}

			if isRevisionAffected(dep.Locked.Rev, adv.AffectedRevisions) {
				matches = append(matches, FlakeVulnerabilityMatch{
					AdvisoryID:     adv.ID,
					DependencyName: dep.Name,
					NodeKey:        dep.NodeKey,
					InstalledRev:   dep.Locked.Rev,
					Severity:       adv.Severity,
					CVSSScore:      adv.CVSSScore,
					Title:          adv.Title,
					Mitigation:     adv.Mitigation,
				})
			}
		}
	}

	return matches, nil
}

// ScanFlakeAgainstFeed audits resolved dependencies against the general Threat Feed.
func ScanFlakeAgainstFeed(lock *FlakeLock, feed *intel.Feed) ([]FlakeVulnerabilityMatch, error) {
	if feed == nil {
		return nil, errors.New("threat feed cannot be nil")
	}

	deps, err := lock.ResolveDependencies(lock.Root)
	if err != nil {
		return nil, err
	}

	nixThreats := feed.FilterByTarget("nixos")
	var matches []FlakeVulnerabilityMatch

	for _, dep := range deps {
		for _, threat := range nixThreats {
			if matchesPackage(dep, threat.Component) {
				matches = append(matches, FlakeVulnerabilityMatch{
					AdvisoryID:     threat.ID,
					DependencyName: dep.Name,
					NodeKey:        dep.NodeKey,
					InstalledRev:   dep.Locked.Rev,
					Severity:       threat.Severity,
					CVSSScore:      threat.CVSSScore,
					Title:          threat.Title,
					Mitigation:     threat.Mitigation,
				})
			}
		}
	}

	return matches, nil
}

func matchesPackage(dep FlakeDependency, targetPackage string) bool {
	target := strings.ToLower(targetPackage)
	if strings.ToLower(dep.Name) == target {
		return true
	}
	if strings.ToLower(dep.NodeKey) == target {
		return true
	}
	if strings.ToLower(dep.Locked.Repo) == target {
		return true
	}
	return false
}

func isRevisionAffected(installedRev string, affectedRevisions []string) bool {
	if len(affectedRevisions) == 0 {
		return true
	}
	if installedRev == "" {
		return true
	}

	for _, aff := range affectedRevisions {
		if strings.EqualFold(installedRev, aff) {
			return true
		}
		if len(aff) >= 7 && len(installedRev) >= 7 {
			if strings.HasPrefix(strings.ToLower(installedRev), strings.ToLower(aff)) ||
				strings.HasPrefix(strings.ToLower(aff), strings.ToLower(installedRev)) {
				return true
			}
		}
	}
	return false
}
