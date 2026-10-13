package intel

import (
	"testing"
	"time"
)

func TestParseFeedAndFilter(t *testing.T) {
	raw := []byte(`{
		"version": "1.0",
		"updated_at": "2026-10-13T12:00:00Z",
		"items": [
			{
				"id": "CVE-2026-21801",
				"title": "Kubernetes Ingress Path Traversal",
				"component": "ingress-nginx",
				"target": "kubernetes",
				"severity": "HIGH",
				"cvss_score": 8.4,
				"description": "Path traversal in custom snippets",
				"mitigation": "Upgrade to ingress-nginx 1.11.0+",
				"published_at": "2026-10-13T10:00:00Z"
			},
			{
				"id": "CVE-2026-19402",
				"title": "NixOS Flake Lock Injection",
				"component": "nix",
				"target": "nixos",
				"severity": "MEDIUM",
				"cvss_score": 5.9,
				"description": "Unchecked flake inputs in recursive evaluations",
				"mitigation": "Enforce pure evaluation mode",
				"published_at": "2026-10-13T11:00:00Z"
			}
		]
	}`)

	feed, err := ParseFeed(raw)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(feed.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(feed.Items))
	}

	k8sItems := feed.FilterByTarget("kubernetes")
	if len(k8sItems) != 1 || k8sItems[0].ID != "CVE-2026-21801" {
		t.Errorf("expected 1 k8s item, got %+v", k8sItems)
	}

	nixosItems := feed.FilterByTarget("nixos")
	if len(nixosItems) != 1 || nixosItems[0].ID != "CVE-2026-19402" {
		t.Errorf("expected 1 nixos item, got %+v", nixosItems)
	}
}

func TestEmptyFeed(t *testing.T) {
	feed := &Feed{
		Version:   "1.0",
		UpdatedAt: time.Now(),
		Items:     nil,
	}

	res := feed.FilterByTarget("nixos")
	if len(res) != 0 {
		t.Errorf("expected 0 results for empty feed, got %d", len(res))
	}
}
