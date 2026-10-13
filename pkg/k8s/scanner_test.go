package k8s

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestManifestScanner_ScanFileAndFeedCorrelation(t *testing.T) {
	manifestContent := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: edge-ingress
  namespace: app
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /$1
spec:
  rules:
  - http:
      paths:
      - path: /static/../../../internal
        pathType: Prefix
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-netpol
  namespace: app
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
`
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "cluster.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write temp manifest: %v", err)
	}

	feed := &intel.Feed{
		Version:   "1.0.0",
		UpdatedAt: time.Now(),
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-21801",
				Title:     "Ingress-Nginx Traversal",
				Component: "ingress-nginx",
				Target:    "kubernetes",
				Severity:  intel.SeverityHigh,
				CVSSScore: 8.4,
			},
		},
	}

	scanner := NewManifestScanner(feed)
	report, err := scanner.ScanFile(manifestPath)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if report.TotalFiles != 1 {
		t.Errorf("expected TotalFiles=1, got %d", report.TotalFiles)
	}
	if report.TotalResources != 2 {
		t.Errorf("expected TotalResources=2, got %d", report.TotalResources)
	}
	if len(report.Violations) == 0 {
		t.Fatalf("expected violations to be detected")
	}

	foundCVE := false
	for _, v := range report.Violations {
		if v.MatchedCVE == "CVE-2026-21801" {
			foundCVE = true
			break
		}
	}

	if !foundCVE {
		t.Errorf("expected CVE-2026-21801 correlation for Ingress vulnerability")
	}
}

func TestManifestScanner_ScanDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "ing.yaml")
	f2 := filepath.Join(tmpDir, "cni.yml")
	f3 := filepath.Join(tmpDir, "notes.txt") // non-yaml, must be ignored

	ingYaml := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ing
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
`
	cniYaml := `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-cni
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
`

	_ = os.WriteFile(f1, []byte(ingYaml), 0644)
	_ = os.WriteFile(f2, []byte(cniYaml), 0644)
	_ = os.WriteFile(f3, []byte("ignored"), 0644)

	scanner := NewManifestScanner(nil)
	report, err := scanner.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected directory scan error: %v", err)
	}

	if report.TotalFiles != 2 {
		t.Errorf("expected TotalFiles=2, got %d", report.TotalFiles)
	}
	if report.TotalResources != 2 {
		t.Errorf("expected TotalResources=2, got %d", report.TotalResources)
	}
}
