package scanner

import (
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

func TestScannerMatches(t *testing.T) {
	feed := &intel.Feed{
		Version:   "1.0",
		UpdatedAt: time.Now(),
		Items: []intel.ThreatItem{
			{
				ID:        "CVE-2026-0001",
				Component: "nginx",
				Target:    "kubernetes",
				Severity:  intel.SeverityHigh,
			},
			{
				ID:        "CVE-2026-0002",
				Component: "openssh",
				Target:    "nixos",
				Severity:  intel.SeverityCritical,
			},
		},
	}

	sc := New(feed)

	nixContent := `
	services.openssh.enable = true;
	networking.hostName = "myu-ken";
	`
	nixMatches := sc.ScanNixConfig("hosts/ken/configuration.nix", nixContent)
	if len(nixMatches) != 1 || nixMatches[0].Threat.ID != "CVE-2026-0002" {
		t.Fatalf("expected openssh threat match in Nix config, got %d matches", len(nixMatches))
	}

	k8sContent := `
	apiVersion: apps/v1
	kind: Deployment
	metadata:
	  name: ingress-controller
	spec:
	  template:
	    spec:
	      containers:
	      - name: nginx
	        image: k8s.gcr.io/ingress-nginx/controller:v1.9.0
	`
	k8sMatches := sc.ScanK8sManifest("deployments/ingress.yaml", k8sContent)
	if len(k8sMatches) != 1 || k8sMatches[0].Threat.ID != "CVE-2026-0001" {
		t.Fatalf("expected nginx threat match in K8s manifest, got %d matches", len(k8sMatches))
	}
}
