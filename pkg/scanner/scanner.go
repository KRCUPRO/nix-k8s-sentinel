package scanner

import (
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// MatchResult represents a threat match found against infrastructure declarations.
type MatchResult struct {
	Threat      intel.ThreatItem `json:"threat"`
	MatchedFile string           `json:"matched_file"`
	Reason      string           `json:"reason"`
}

// Scanner scans configuration manifests against threat feeds.
type Scanner struct {
	Feed *intel.Feed
}

// New creates a new Scanner instance with the given feed.
func New(feed *intel.Feed) *Scanner {
	return &Scanner{Feed: feed}
}

// ScanNixConfig inspects NixOS configuration contents for known vulnerable packages.
func (s *Scanner) ScanNixConfig(filename string, content string) []MatchResult {
	var matches []MatchResult
	if s.Feed == nil {
		return matches
	}

	nixThreats := s.Feed.FilterByTarget("nixos")
	for _, threat := range nixThreats {
		if strings.Contains(content, threat.Component) {
			matches = append(matches, MatchResult{
				Threat:      threat,
				MatchedFile: filename,
				Reason:      "Component reference found in Nix declaration",
			})
		}
	}
	return matches
}

// ScanK8sManifest inspects Kubernetes manifests for vulnerable images or components.
func (s *Scanner) ScanK8sManifest(filename string, content string) []MatchResult {
	var matches []MatchResult
	if s.Feed == nil {
		return matches
	}

	k8sThreats := s.Feed.FilterByTarget("kubernetes")
	for _, threat := range k8sThreats {
		if strings.Contains(content, threat.Component) {
			matches = append(matches, MatchResult{
				Threat:      threat,
				MatchedFile: filename,
				Reason:      "Vulnerable component reference detected in K8s manifest",
			})
		}
	}
	return matches
}
