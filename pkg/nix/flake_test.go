package nix

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

const sampleFlakeLockJSON = `{
  "nodes": {
    "root": {
      "inputs": {
        "nixpkgs": "nixpkgs",
        "flake-utils": "flake-utils"
      }
    },
    "nixpkgs": {
      "locked": {
        "lastModified": 1712345678,
        "narHash": "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "05730f5dc1b072834b6ea08ca3ae6a09fca03e00",
        "type": "github"
      },
      "original": {
        "owner": "NixOS",
        "ref": "nixos-unstable",
        "repo": "nixpkgs",
        "type": "github"
      }
    },
    "flake-utils": {
      "inputs": {
        "systems": "systems"
      },
      "locked": {
        "lastModified": 1710000000,
        "narHash": "sha256-0000000000000000000000000000000000000000000=",
        "owner": "numtide",
        "repo": "flake-utils",
        "rev": "b1d9ab7cd6a3f6ac380b6dcab24824f33784a09f",
        "type": "github"
      },
      "original": {
        "owner": "numtide",
        "repo": "flake-utils",
        "type": "github"
      }
    },
    "systems": {
      "locked": {
        "lastModified": 1705000000,
        "narHash": "sha256-1111111111111111111111111111111111111111111=",
        "owner": "nix-systems",
        "repo": "default",
        "rev": "dae7110c1aa59640ce57530832376e37946b1c8b",
        "type": "github"
      },
      "original": {
        "owner": "nix-systems",
        "repo": "default",
        "type": "github"
      }
    }
  },
  "root": "root",
  "version": 7
}`

func TestParseFlakeLock_Valid(t *testing.T) {
	lock, err := ParseFlakeLock([]byte(sampleFlakeLockJSON))
	if err != nil {
		t.Fatalf("unexpected error parsing valid flake.lock: %v", err)
	}

	if lock.Version != 7 {
		t.Errorf("expected version 7, got %d", lock.Version)
	}
	if lock.Root != "root" {
		t.Errorf("expected root 'root', got %s", lock.Root)
	}
	if len(lock.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(lock.Nodes))
	}
}

func TestParseFlakeLock_InvalidJSON(t *testing.T) {
	_, err := ParseFlakeLock([]byte(`{ "invalid": `))
	if err == nil {
		t.Fatal("expected error parsing invalid JSON, got nil")
	}

	_, err = ParseFlakeLock([]byte{})
	if err == nil {
		t.Fatal("expected error parsing empty byte slice, got nil")
	}
}

func TestResolveDependencies_Transitive(t *testing.T) {
	lock, err := ParseFlakeLock([]byte(sampleFlakeLockJSON))
	if err != nil {
		t.Fatalf("failed to parse flake lock: %v", err)
	}

	deps, err := lock.ResolveDependencies("")
	if err != nil {
		t.Fatalf("unexpected error resolving dependencies: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 resolved dependencies (nixpkgs, flake-utils, systems), got %d", len(deps))
	}

	depMap := make(map[string]FlakeDependency)
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if _, ok := depMap["nixpkgs"]; !ok {
		t.Error("expected nixpkgs dependency to be resolved")
	}
	if _, ok := depMap["flake-utils"]; !ok {
		t.Error("expected flake-utils dependency to be resolved")
	}
	if sys, ok := depMap["systems"]; !ok {
		t.Error("expected systems transitive dependency to be resolved")
	} else if sys.Depth != 2 {
		t.Errorf("expected systems depth 2, got %d", sys.Depth)
	}
}

func TestResolveDependencies_CycleProtection(t *testing.T) {
	cyclicJSON := `{
		"nodes": {
			"root": { "inputs": { "nodeA": "nodeA" } },
			"nodeA": {
				"inputs": { "nodeB": "nodeB" },
				"locked": { "repo": "repoA", "rev": "aaa111" }
			},
			"nodeB": {
				"inputs": { "nodeA": "nodeA" },
				"locked": { "repo": "repoB", "rev": "bbb222" }
			}
		},
		"root": "root",
		"version": 7
	}`

	lock, err := ParseFlakeLock([]byte(cyclicJSON))
	if err != nil {
		t.Fatalf("failed to parse cyclic json: %v", err)
	}

	deps, err := lock.ResolveDependencies("")
	if err != nil {
		t.Fatalf("cycle resolution failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 resolved unique dependencies in cycle, got %d", len(deps))
	}
}

func TestMapFlakeAdvisories_Matches(t *testing.T) {
	lock, err := ParseFlakeLock([]byte(sampleFlakeLockJSON))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	advisories := []NixSecurityAdvisory{
		{
			ID:                "CVE-2026-9999",
			Package:           "nixpkgs",
			AffectedRevisions: []string{"05730f5dc1b072834b6ea08ca3ae6a09fca03e00"},
			PatchedRevision:   "05730f5dc1b072834b6ea08ca3ae6a09fca03e99",
			Severity:          intel.SeverityHigh,
			CVSSScore:         8.1,
			Title:             "Nixpkgs Vulnerable Channel Revision",
			Mitigation:        "Bump nixpkgs input to 24.11-stable",
		},
		{
			ID:                "CVE-2026-8888",
			Package:           "systems",
			AffectedRevisions: []string{"unrelated-hash-123"},
			Severity:          intel.SeverityLow,
			CVSSScore:         3.0,
			Title:             "Safe Advisory",
			Mitigation:        "No action needed",
		},
	}

	matches, err := MapFlakeAdvisories(lock, advisories)
	if err != nil {
		t.Fatalf("failed mapping advisories: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 vulnerability match, got %d", len(matches))
	}

	if matches[0].AdvisoryID != "CVE-2026-9999" {
		t.Errorf("expected match advisory ID CVE-2026-9999, got %s", matches[0].AdvisoryID)
	}
	if matches[0].Severity != intel.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", matches[0].Severity)
	}
}

func TestScanFlakeAgainstFeed(t *testing.T) {
	lock, err := ParseFlakeLock([]byte(sampleFlakeLockJSON))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	feedJSON := `{
		"version": "1.0.0",
		"items": [
			{
				"id": "CVE-2026-19402",
				"title": "NixOS Flake Lock Input Evaluation Hijack",
				"component": "nixpkgs",
				"target": "nixos",
				"severity": "MEDIUM",
				"cvss_score": 6.1,
				"description": "Recursive flake evaluations in untrusted git inputs can trigger unintentional remote binary cache fetches.",
				"mitigation": "Enable pure-eval mode and lock input revisions explicitly in flake.lock."
			},
			{
				"id": "CVE-2026-21801",
				"title": "Kubernetes Ingress-Nginx Path Traversal",
				"component": "ingress-nginx",
				"target": "kubernetes",
				"severity": "HIGH",
				"cvss_score": 8.4
			}
		]
	}`

	feed, err := intel.ParseFeed([]byte(feedJSON))
	if err != nil {
		t.Fatalf("failed to parse test feed: %v", err)
	}

	matches, err := ScanFlakeAgainstFeed(lock, feed)
	if err != nil {
		t.Fatalf("unexpected error scanning against feed: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match from feed, got %d", len(matches))
	}

	if matches[0].AdvisoryID != "CVE-2026-19402" {
		t.Errorf("expected CVE-2026-19402, got %s", matches[0].AdvisoryID)
	}
}

func TestParseFlakeLockFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "flake.lock")

	if err := os.WriteFile(filePath, []byte(sampleFlakeLockJSON), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	lock, err := ParseFlakeLockFile(filePath)
	if err != nil {
		t.Fatalf("failed to parse lock file: %v", err)
	}
	if lock.Version != 7 {
		t.Errorf("expected version 7, got %d", lock.Version)
	}

	// Non-existent file test
	_, err = ParseFlakeLockFile(filepath.Join(tmpDir, "does-not-exist.lock"))
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}
