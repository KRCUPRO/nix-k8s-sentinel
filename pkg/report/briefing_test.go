package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/k8s"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/nix"
)

func sampleFeed() *intel.Feed {
	return &intel.Feed{
		Version:   "1.0.0",
		UpdatedAt: time.Date(2026, 10, 13, 20, 30, 0, 0, time.UTC),
		Items: []intel.ThreatItem{
			{
				ID:          "CVE-2026-21801",
				Title:       "Kubernetes Ingress-Nginx Path Traversal Vulnerability",
				Component:   "ingress-nginx",
				Target:      "kubernetes",
				Severity:    intel.SeverityHigh,
				CVSSScore:   8.4,
				Description: "Specially crafted request URI paths bypass URL rewriting rules.",
				Mitigation:  "Enforce strict URI normalization and upgrade ingress-nginx.",
				PublishedAt: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC),
			},
			{
				ID:          "CVE-2026-19402",
				Title:       "NixOS Flake Lock Input Evaluation Hijack",
				Component:   "nix",
				Target:      "nixos",
				Severity:    intel.SeverityMedium,
				CVSSScore:   6.1,
				Description: "Recursive flake evaluations in untrusted git inputs trigger fetches.",
				Mitigation:  "Enable pure-eval mode and lock input revisions explicitly.",
				PublishedAt: time.Date(2026, 10, 13, 11, 30, 0, 0, time.UTC),
			},
			{
				ID:          "CVE-2026-99999",
				Title:       "Critical Kernel Remote Code Execution",
				Component:   "linux-kernel",
				Target:      "nixos",
				Severity:    intel.SeverityCritical,
				CVSSScore:   9.8,
				Description: "Critical unauthenticated remote execution vulnerability.",
				Mitigation:  "Apply kernel patch 6.12.20 immediately.",
				PublishedAt: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
			},
			{
				ID:          "CVE-2026-11111",
				Title:       "Minor Documentation Information Disclosure",
				Component:   "docs",
				Target:      "kubernetes",
				Severity:    intel.SeverityLow,
				CVSSScore:   3.2,
				Description: "Minor doc discrepancy.",
				Mitigation:  "Update documentation bundle.",
				PublishedAt: time.Date(2026, 10, 13, 13, 0, 0, 0, time.UTC),
			},
		},
	}
}

func TestComputeTelemetry_FeedOnly(t *testing.T) {
	feed := sampleFeed()
	summary := ComputeTelemetry(feed, nil, nil)

	if summary.TotalThreats != 4 {
		t.Fatalf("expected 4 total threats, got %d", summary.TotalThreats)
	}
	if summary.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", summary.CriticalCount)
	}
	if summary.HighCount != 1 {
		t.Errorf("expected 1 high, got %d", summary.HighCount)
	}
	if summary.MediumCount != 1 {
		t.Errorf("expected 1 medium, got %d", summary.MediumCount)
	}
	if summary.LowCount != 1 {
		t.Errorf("expected 1 low, got %d", summary.LowCount)
	}
	if summary.MaxCVSS != 9.8 {
		t.Errorf("expected max CVSS 9.8, got %.1f", summary.MaxCVSS)
	}
	// Average: (8.4 + 6.1 + 9.8 + 3.2) / 4 = 27.5 / 4 = 6.875 -> rounded to 6.9
	if summary.AverageCVSS != 6.9 {
		t.Errorf("expected average CVSS 6.9, got %.1f", summary.AverageCVSS)
	}
	if summary.TargetDistribution["nixos"] != 2 {
		t.Errorf("expected 2 nixos targets, got %d", summary.TargetDistribution["nixos"])
	}
	if summary.TargetDistribution["kubernetes"] != 2 {
		t.Errorf("expected 2 kubernetes targets, got %d", summary.TargetDistribution["kubernetes"])
	}
}

func TestComputeTelemetry_EmptyFeed(t *testing.T) {
	summary := ComputeTelemetry(nil, nil, nil)
	if summary.TotalThreats != 0 {
		t.Errorf("expected 0 total threats, got %d", summary.TotalThreats)
	}
	if summary.MaxCVSS != 0.0 || summary.AverageCVSS != 0.0 {
		t.Errorf("expected zero scores for empty feed, got max=%.1f, avg=%.1f", summary.MaxCVSS, summary.AverageCVSS)
	}
}

func TestComputeTelemetry_WithK8sAndFlake(t *testing.T) {
	feed := sampleFeed()
	k8sReport := &k8s.ManifestAuditReport{
		TotalFiles:     2,
		TotalResources: 5,
		Violations: []k8s.Violation{
			{
				RuleID:       "K8S-ING-001",
				Severity:     "CRITICAL",
				Title:        "Custom Lua Snippet Injection",
				ResourceKind: "Ingress",
				ResourceName: "app-ingress",
				Namespace:    "production",
				MatchedCVE:   "CVE-2023-5044",
			},
		},
	}
	flakeMatches := []nix.FlakeVulnerabilityMatch{
		{
			DependencyName: "nixpkgs",
			NodeKey:        "nixpkgs",
			InstalledRev:   "abcdef123456",
			AdvisoryID:     "CVE-2026-19402",
			Severity:       intel.SeverityMedium,
			Title:          "NixOS Flake Lock Input Evaluation Hijack",
			Mitigation:     "Lock input revision explicitly.",
		},
	}

	summary := ComputeTelemetry(feed, k8sReport, flakeMatches)
	if summary.TotalViolations != 1 {
		t.Errorf("expected 1 violation, got %d", summary.TotalViolations)
	}
	if summary.TotalFlakeMatches != 1 {
		t.Errorf("expected 1 flake match, got %d", summary.TotalFlakeMatches)
	}
}

func TestGenerateBriefing_MarkdownFormatting(t *testing.T) {
	feed := sampleFeed()
	opts := BriefingOptions{
		Title:        "Custom Hourly Briefing Test",
		Version:      "0.4.0",
		HourlyWindow: time.Date(2026, 10, 13, 22, 0, 0, 0, time.UTC),
		Feed:         feed,
	}

	report, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("unexpected error generating briefing: %v", err)
	}

	content := report.Content
	if !strings.Contains(content, "# Custom Hourly Briefing Test") {
		t.Errorf("expected custom title in markdown")
	}
	if !strings.Contains(content, "2026-10-13 22:00 UTC") {
		t.Errorf("expected window in markdown")
	}
	if !strings.Contains(content, "CVSS Severity Tier") {
		t.Errorf("expected severity matrix table")
	}
	if !strings.Contains(content, "CVE-2026-21801") || !strings.Contains(content, "CVE-2026-99999") {
		t.Errorf("expected CVE items in advisories")
	}
	if !strings.Contains(content, "SecOps & SRE Operational Checklist") {
		t.Errorf("expected operational checklist")
	}
}

func TestWriteBriefingToFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel-briefing-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	feed := sampleFeed()
	opts := BriefingOptions{
		HourlyWindow: time.Date(2026, 10, 13, 22, 0, 0, 0, time.UTC),
		Feed:         feed,
	}

	report, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	filePath, err := WriteBriefingToFile(report, tempDir, "")
	if err != nil {
		t.Fatalf("failed to write briefing file: %v", err)
	}

	expectedName := "briefing-2026-10-13-2200.md"
	if filepath.Base(filePath) != expectedName {
		t.Errorf("expected file %s, got %s", expectedName, filepath.Base(filePath))
	}

	readData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	if string(readData) != report.Content {
		t.Errorf("content mismatch between report and written file")
	}
}

func TestWriteBriefingToFile_PathTraversalSafety(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel-traversal-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	opts := BriefingOptions{
		Feed: sampleFeed(),
	}
	report, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Attempt path traversal via custom filename
	traversalFilename := "../../evil-briefing.md"
	filePath, err := WriteBriefingToFile(report, tempDir, traversalFilename)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Should be stripped to base name inside tempDir
	if filepath.Dir(filePath) != tempDir {
		t.Errorf("expected file in %s, got dir %s", tempDir, filepath.Dir(filePath))
	}
	if filepath.Base(filePath) != "evil-briefing.md" {
		t.Errorf("expected stripped base name 'evil-briefing.md', got %s", filepath.Base(filePath))
	}
}

func TestWriteBriefingToFile_NilReport(t *testing.T) {
	_, err := WriteBriefingToFile(nil, "some/dir", "test.md")
	if err == nil {
		t.Fatalf("expected error on nil report, got nil")
	}
}
