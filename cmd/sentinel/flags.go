package main

import (
	"flag"
	"fmt"
	"os"
)

// SentinelConfig encapsulates all CLI arguments, paths, and runtime flags.
type SentinelConfig struct {
	FeedPath          string
	ShowVersion       bool
	TargetFilter      string
	FlakePath         string
	K8sPath           string
	CephPath          string
	CephTelemetry     string
	WgPath            string
	WgTelemetry       string
	CISPath           string
	RemediationOut    string
	GwPath            string
	AttestPath        string
	AttestTelemetry   string
	FleetPath         string
	FleetTelemetry    string
	SpiffePath        string
	SvidTelemetry     string
	SpiffePolicyOut   string
	SbomPath          string
	AttestFile        string
	RuntimePath       string
	HsmPath           string
	HsmTelemetry      string
	BpfPath           string
	BpfTelemetry      string
	BpfSynthOut       string
	BpfService        string
	PqcPath           string
	PqcTelemetry      string
	PqcSynthOut       string
	CnsaStrict        bool
	SandboxPath       string
	SandboxTelemetry  string
	SandboxSynthOut   string
	QuarantineStrict  bool
	RemediatePath     string
	RemediateSynthOut string
	CanaryStrict      bool
	LSMPath           string
	LSMTelemetry      string
	LSMSynthOut       string
	LSMStrict         bool
	DRManifests       string
	DRTelemetry       string
	DRSynthOut        string
	DRRPOMax          int
	DRStrict          bool
	FastPathManifests string
	FastPathTelemetry string
	FastPathSynthOut  string
	FastPathStrict    bool
	EnclaveManifests  string
	EnclaveTelemetry  string
	EnclaveSynthOut   string
	EnclaveStrict     bool
	WebhookPath           string
	WebhookTelemetry      string
	WebhookSynthOut       string
	WebhookStrict         bool
	ImpermanencePath      string
	EphemeralRoot         bool
	ImpermanenceTelemetry string
	ImpermanenceSynthOut  string
	ImpermanenceStrict    bool
	BGPPath               string
	CiliumBGP             bool
	BGPTelemetry          string
	BGPSynthOut           string
	BGPStrict             bool
	StorePath             string
	BinaryCache           bool
	StoreTelemetry        string
	StoreSynthOut         string
	StoreStrict           bool
	LockdownPath          string
	SecureBoot            bool
	LockdownTelemetry     string
	LockdownSynthOut      string
	LockdownStrict        bool
	FlowPath              string
	CiliumFlow            bool
	FlowTelemetry         string
	FlowSynthOut          string
	FlowStrict            bool
	ClusterMeshPath          string
	GlobalServices           bool
	ClusterMeshTelemetryPath string
	ClusterMeshSynthOut      string
	ClusterMeshStrict        bool
	Briefing              bool
	BriefingDir       string
	BriefingFile      string
	PolicyOut         string
	PolicyEngine      string
	EnforceAction     string
	ProbeFlag         bool
	ProbeFixture      string
	ProbeNodes        string
	Format            string
	OutFile           string
}

// parseCLI parses command-line arguments and resolves aliases into a structured config.
func parseCLI() SentinelConfig {
	feedPath := flag.String("feed", "intel/cve-feed.json", "Path to threat intelligence feed JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	targetFilter := flag.String("target", "", "Filter feed by target ('nixos' or 'kubernetes')")
	flakePath := flag.String("flake", "", "Path to NixOS flake.lock to audit for known CVEs")
	k8sPath := flag.String("k8s", "", "Path to Kubernetes manifest file or directory to audit")
	cephPath := flag.String("ceph", "", "Path to Rook Ceph manifest file or directory to audit")
	storageShort := flag.String("storage", "", "Alias for --ceph")
	cephTelemetry := flag.String("ceph-telemetry", "", "Path to Ceph runtime health telemetry JSON to inspect")
	wgPath := flag.String("wg", "", "Path to NixOS WireGuard manifest file or directory to audit")
	wireguardLong := flag.String("wireguard", "", "Alias for --wg")
	wgTelemetry := flag.String("wg-telemetry", "", "Path to runtime WireGuard peer telemetry JSON to inspect")
	cisPath := flag.String("cis", "", "Path to NixOS module or Kubernetes YAML to audit against CIS Benchmark")
	benchShort := flag.String("bench", "", "Alias for --cis")
	kubeBenchLong := flag.String("kube-bench", "", "Alias for --cis")
	remediationOut := flag.String("remediation-out", "", "Output path to write synthesized NixOS CIS hardening remediation module")
	gwPath := flag.String("gateway", "", "Path to Kubernetes Gateway API or EnvoyFilter manifest file or directory to audit")
	gatewayShort := flag.String("gw", "", "Alias for --gateway")
	attestPath := flag.String("attest", "", "Path to NixOS measured boot configuration file or directory to audit")
	attestTelemetry := flag.String("attest-telemetry", "", "Path to node attestation telemetry JSON with TPM 2.0 PCR quotations")
	attestQuote := flag.String("attest-quote", "", "Alias for --attest-telemetry")
	fleetPath := flag.String("fleet", "", "Path to multi-cluster manifest file or directory to audit")
	gitopsShort := flag.String("gitops", "", "Alias for --fleet")
	fleetTelemetry := flag.String("fleet-telemetry", "", "Path to runtime fleet telemetry JSON with cluster and OIDC token states")
	spiffePath := flag.String("spiffe", "", "Path to SPIFFE/SPIRE manifest file or directory to audit")
	spireShort := flag.String("spire", "", "Alias for --spiffe")
	svidTelemetry := flag.String("svid-telemetry", "", "Path to runtime X.509 SVID telemetry JSON to inspect")
	spiffePolicyOut := flag.String("spiffe-policy-out", "", "Output path or directory to write synthesized Cilium zero-trust microsegmentation policies")
	sbomPath := flag.String("sbom", "", "Path to SPDX/CycloneDX SBOM manifest file or directory to audit")
	attestFile := flag.String("attestation", "", "Path to In-Toto Statement & SLSA Provenance JSON to verify")
	intotoShort := flag.String("intoto", "", "Alias for --attestation")
	runtimePath := flag.String("sbom-runtime", "", "Path to cluster runtime package state JSON for SBOM delta audit")
	deltaShort := flag.String("sbom-delta", "", "Alias for --sbom-runtime")
	hsmPath := flag.String("hsm", "", "Path to Kubernetes EncryptionConfiguration or NixOS HSM config to audit")
	kmsShort := flag.String("kms", "", "Alias for --hsm")
	hsmTelemetry := flag.String("hsm-telemetry", "", "Path to runtime HSM, PKCS#11, and KMS plugin telemetry JSON to inspect")
	nitroShort := flag.String("nitro", "", "Alias for --hsm-telemetry")
	bpfPath := flag.String("bpf", "", "Path to Kubernetes workload or NixOS manifest to audit for BPF/seccomp security")
	seccompShort := flag.String("seccomp", "", "Alias for --bpf")
	bpfTelemetry := flag.String("bpf-telemetry", "", "Path to runtime kernel BPF & syscall telemetry JSON to inspect")
	bpfSynthOut := flag.String("bpf-synth-out", "", "Output directory to export synthesized hardened Seccomp and eBPF LSM policies")
	bpfService := flag.String("bpf-service", "k8s-workload", "Target systemd service name for synthesized NixOS seccomp module")
	pqcPath := flag.String("pqc", "", "Path to Kubernetes control plane or NixOS crypto manifest file or directory to audit")
	cnsaShort := flag.String("cnsa", "", "Alias for --pqc")
	pqcTelemetry := flag.String("pqc-telemetry", "", "Path to runtime PQC TLS handshake telemetry JSON to inspect")
	pqcSynthOut := flag.String("pqc-synth-out", "", "Output directory to export synthesized hardened PQC and CNSA 2.0 policies")
	cnsaStrict := flag.Bool("cnsa-strict", false, "Enforce strict CNSA 2.0 2030/2033 cryptographic timeline compliance")
	sandboxPath := flag.String("sandbox", "", "Path to NixOS microvm or Kubernetes detonation manifest to audit")
	microvmShort := flag.String("microvm", "", "Alias for --sandbox")
	sandboxTelemetry := flag.String("sandbox-telemetry", "", "Path to runtime microVM detonation and honeypot telemetry JSON")
	honeypotShort := flag.String("honeypot", "", "Alias for --sandbox-telemetry")
	sandboxSynthOut := flag.String("sandbox-synth-out", "", "Output directory to export synthesized hardened MicroVM and honeypot manifests")
	quarantineStrict := flag.Bool("quarantine-strict", false, "Enforce immediate hard quarantine on any honeypot lure hit or anomaly")
	remediatePath := flag.String("remediate", "", "Path to manifest file or directory to audit for automated threat remediation")
	remediateShort := flag.String("auto-remediate", "", "Alias for --remediate")
	remediateSynthOut := flag.String("remediate-synth-out", "", "Output directory to export synthesized NixOS patches and GitOps Kustomize overlays")
	canaryStrict := flag.Bool("canary-strict", false, "Enforce strict zero-warning pre-flight canary test validation")
	lsmPath := flag.String("lsm", "", "Path to NixOS host config or Kubernetes manifest to audit for eBPF LSM & MAC")
	lsmShort := flag.String("lsm-mac", "", "Alias for --lsm")
	lsmTelemetry := flag.String("lsm-telemetry", "", "Path to runtime eBPF LSM denial telemetry JSON")
	lsmSynthOut := flag.String("lsm-synth-out", "", "Output directory to export synthesized hardened NixOS eBPF LSM modules, BPF C programs, and Kubernetes MAC policies")
	lsmStrict := flag.Bool("lsm-strict", false, "Enforce strict zero-warning eBPF LSM compliance")
	drManifests := flag.String("dr-manifests", "", "Path to CephFS / RBD volume replication and snapshot manifests or directory")
	drShort := flag.String("dr", "", "Alias for --dr-manifests")
	drTelemetry := flag.String("dr-telemetry", "", "Path to cross-region volume replication runtime telemetry JSON")
	drSynthOut := flag.String("dr-synth-out", "", "Output directory to write synthesized hardened CephFS snapshot schedule & replication manifests")
	drRPOMax := flag.Int("dr-rpo-max", 900, "Maximum allowable volume replication delta lag threshold in seconds (default 900s / 15m)")
	drStrict := flag.Bool("dr-strict", false, "Enforce strict zero-warning disaster recovery posture")
	fastpathManifests := flag.String("wg-fastpath", "", "Path to WireGuard fast-path manifest file or directory to audit")
	fastpathShort := flag.String("fastpath", "", "Alias for --wg-fastpath")
	fastpathTelemetry := flag.String("wg-fastpath-telemetry", "", "Path to runtime WireGuard crypto and fast-path telemetry JSON to inspect")
	fastpathSynthOut := flag.String("wg-fastpath-synth-out", "", "Output directory to write synthesized hardened NixOS fast-path modules, eBPF XDP programs, and K8s CRDs")
	fastpathStrict := flag.Bool("wg-fastpath-strict", false, "Enforce strict zero-drop and SIMD hardware acceleration thresholds")
	enclaveManifests := flag.String("wg-enclave", "", "Path to WireGuard confidential enclave peer manifests or directory")
	enclaveShort := flag.String("enclave", "", "Alias for --wg-enclave")
	enclaveTelemetry := flag.String("wg-enclave-telemetry", "", "Path to runtime enclave attestation telemetry JSON to inspect")
	enclaveSynthOut := flag.String("wg-enclave-synth-out", "", "Output directory to write synthesized hardened NixOS enclave modules, K8s CRDs, and gate scripts")
	enclaveStrict := flag.Bool("wg-enclave-strict", false, "Enforce strict zero-warning enclave peer attestation and measured boot compliance")
	webhookPath := flag.String("webhook", "", "Path to Kubernetes admission webhook manifests or directory to audit")
	webhookShort := flag.String("admission-webhook", "", "Alias for --webhook")
	webhookTelemetry := flag.String("webhook-telemetry", "", "Path to runtime admission webhook and CA rotation telemetry JSON to inspect")
	webhookSynthOut := flag.String("webhook-synth-out", "", "Output directory to write synthesized hardened WebhookConfiguration, cert-manager CA renewal, and PrometheusRule alert policies")
	webhookStrict := flag.Bool("webhook-strict", false, "Enforce strict zero-warning admission webhook and CA rotation compliance")
	impermanencePath := flag.String("impermanence", "", "Path to NixOS impermanence configuration file or directory to audit")
	ephemeralRootShort := flag.String("ephemeral-root", "", "Alias for --impermanence")
	impermanenceTelemetry := flag.String("impermanence-telemetry", "", "Path to runtime ephemeral storage and memory telemetry JSON to inspect")
	impermanenceSynthOut := flag.String("impermanence-synth-out", "", "Output directory to write synthesized hardened NixOS impermanence modules, wipe hooks, and Prometheus alerts")
	impermanenceStrict := flag.Bool("impermanence-strict", false, "Enforce strict zero-warning impermanence and ephemeral root compliance")
	bgpPath := flag.String("bgp", "", "Path to Cilium BGP manifest file or directory to audit")
	ciliumBGPShort := flag.String("cilium-bgp", "", "Alias for --bgp")
	bgpTelemetry := flag.String("bgp-telemetry", "", "Path to runtime BGP session and IPAM telemetry JSON to inspect")
	bgpSynthOut := flag.String("bgp-synth-out", "", "Output directory to write synthesized hardened Cilium BGP and NixOS modules")
	bgpStrict := flag.Bool("bgp-strict", false, "Enforce strict zero-warning BGP peering and dual-stack routing compliance")
	storePath := flag.String("nixstore", "", "Path to NixOS store configuration file or directory to audit")
	binaryCacheShort := flag.String("binary-cache", "", "Alias for --nixstore")
	storeTelemetry := flag.String("nixstore-telemetry", "", "Path to Nix daemon substitute verification telemetry JSON to inspect")
	storeSynthOut := flag.String("nixstore-synth-out", "", "Output directory to write synthesized hardened NixOS store modules, nix.conf, and Prometheus alert rules")
	storeStrict := flag.Bool("nixstore-strict", false, "Enforce strict zero-warning Nix store signature and binary cache compliance")
	lockdownPath := flag.String("lockdown", "", "Path to NixOS kernel lockdown configuration file or directory to audit")
	secureBootShort := flag.String("secure-boot", "", "Alias for --lockdown")
	lockdownTelemetry := flag.String("lockdown-telemetry", "", "Path to runtime kernel lockdown and UEFI DBX telemetry JSON to inspect")
	lockdownSynthOut := flag.String("lockdown-synth-out", "", "Output directory to write synthesized hardened NixOS lockdown modules, DBX sync service, and Prometheus alert rules")
	lockdownStrict := flag.Bool("lockdown-strict", false, "Enforce strict zero-warning kernel lockdown and UEFI DBX compliance")
	flowPath := flag.String("flow", "", "Path to CiliumNetworkPolicy manifests or NixOS flow profiler configs")
	ciliumFlowShort := flag.String("cilium-flow", "", "Alias for --flow")
	flowTelemetry := flag.String("flow-telemetry", "", "Path to runtime eBPF network flow and DNS telemetry JSON to inspect")
	flowSynthOut := flag.String("flow-synth-out", "", "Output directory to write synthesized hardened Cilium policies, NixOS flow modules, and Prometheus alert rules")
	flowStrict := flag.Bool("flow-strict", false, "Enforce strict zero-warning network flow and DNS exfiltration compliance")
	clusterMeshPath := flag.String("clustermesh", "", "Path to Cilium ClusterMesh manifest file or directory to audit")
	globalServicesShort := flag.String("global-services", "", "Alias for --clustermesh")
	clusterMeshTelemetry := flag.String("clustermesh-telemetry", "", "Path to runtime ClusterMesh peering telemetry JSON to inspect")
	clusterMeshSynthOut := flag.String("clustermesh-synth-out", "", "Output directory to write synthesized hardened ClusterMesh Helm values, policies, and alert rules")
	clusterMeshStrict := flag.Bool("clustermesh-strict", false, "Enforce strict zero-warning ClusterMesh and global service discovery compliance")
	briefing := flag.Bool("briefing", false, "Generate automated Markdown threat intelligence briefing")
	briefingDir := flag.String("briefing-dir", "intel/briefings", "Output directory for threat briefings")
	briefingFile := flag.String("briefing-file", "", "Custom filename for threat briefing markdown")
	policyOut := flag.String("policy-out", "", "Output directory to export synthesized Falco and OPA Gatekeeper security policies")
	policyEngine := flag.String("policy-engine", "all", "Policy engines to synthesize ('all', 'falco', 'gatekeeper')")
	enforceAction := flag.String("enforce-action", "deny", "OPA Gatekeeper enforcement action ('deny', 'dryrun', 'warn')")
	probeFlag := flag.Bool("probe", false, "Execute bare-metal eBPF kernel telemetry probe analysis")
	probeFixture := flag.String("probe-fixture", "fixtures/probe-telemetry.json", "Path to bare-metal probe events fixture JSON")
	probeNodes := flag.String("probe-nodes", "nixos-control-01,nixos-worker-01,nixos-worker-02", "Comma-separated list of bare-metal cluster node names")
	format := flag.String("format", "console", "Audit report output format ('console', 'json', 'sarif')")
	outFile := flag.String("output", "", "Output destination file for formatted report (defaults to stdout)")
	outShort := flag.String("o", "", "Shorthand for --output")
	flag.Parse()

	// Aliases resolution
	if *cephPath == "" && *storageShort != "" {
		*cephPath = *storageShort
	}
	if *wgPath == "" && *wireguardLong != "" {
		*wgPath = *wireguardLong
	}
	if *cisPath == "" && *benchShort != "" {
		*cisPath = *benchShort
	}
	if *cisPath == "" && *kubeBenchLong != "" {
		*cisPath = *kubeBenchLong
	}
	if *gwPath == "" && *gatewayShort != "" {
		*gwPath = *gatewayShort
	}
	if *attestTelemetry == "" && *attestQuote != "" {
		*attestTelemetry = *attestQuote
	}
	if *fleetPath == "" && *gitopsShort != "" {
		*fleetPath = *gitopsShort
	}
	if *spiffePath == "" && *spireShort != "" {
		*spiffePath = *spireShort
	}
	if *attestFile == "" && *intotoShort != "" {
		*attestFile = *intotoShort
	}
	if *runtimePath == "" && *deltaShort != "" {
		*runtimePath = *deltaShort
	}
	if *hsmPath == "" && *kmsShort != "" {
		*hsmPath = *kmsShort
	}
	if *hsmTelemetry == "" && *nitroShort != "" {
		*hsmTelemetry = *nitroShort
	}
	if *bpfPath == "" && *seccompShort != "" {
		*bpfPath = *seccompShort
	}
	if *pqcPath == "" && *cnsaShort != "" {
		*pqcPath = *cnsaShort
	}
	if *sandboxPath == "" && *microvmShort != "" {
		*sandboxPath = *microvmShort
	}
	if *sandboxTelemetry == "" && *honeypotShort != "" {
		*sandboxTelemetry = *honeypotShort
	}
	if *remediatePath == "" && *remediateShort != "" {
		*remediatePath = *remediateShort
	}
	if *lsmPath == "" && *lsmShort != "" {
		*lsmPath = *lsmShort
	}
	if *drManifests == "" && *drShort != "" {
		*drManifests = *drShort
	}
	if *fastpathManifests == "" && *fastpathShort != "" {
		*fastpathManifests = *fastpathShort
	}
	if *enclaveManifests == "" && *enclaveShort != "" {
		*enclaveManifests = *enclaveShort
	}
	if *webhookPath == "" && *webhookShort != "" {
		*webhookPath = *webhookShort
	}
	if *impermanencePath == "" && *ephemeralRootShort != "" {
		*impermanencePath = *ephemeralRootShort
	}
	if *bgpPath == "" && *ciliumBGPShort != "" {
		*bgpPath = *ciliumBGPShort
	}
	if *storePath == "" && *binaryCacheShort != "" {
		*storePath = *binaryCacheShort
	}
	if *lockdownPath == "" && *secureBootShort != "" {
		*lockdownPath = *secureBootShort
	}
	if *flowPath == "" && *ciliumFlowShort != "" {
		*flowPath = *ciliumFlowShort
	}
	if *clusterMeshPath == "" && *globalServicesShort != "" {
		*clusterMeshPath = *globalServicesShort
	}
	if *outFile == "" && *outShort != "" {
		*outFile = *outShort
	}

	if *showVersion {
		fmt.Printf("nix-k8s-sentinel v%s (Cloud-Native Threat Radar & Policy Synthesizer)\n", version)
		os.Exit(0)
	}

	return SentinelConfig{
		FeedPath:          *feedPath,
		ShowVersion:       *showVersion,
		TargetFilter:      *targetFilter,
		FlakePath:         *flakePath,
		K8sPath:           *k8sPath,
		CephPath:          *cephPath,
		CephTelemetry:     *cephTelemetry,
		WgPath:            *wgPath,
		WgTelemetry:       *wgTelemetry,
		CISPath:           *cisPath,
		RemediationOut:    *remediationOut,
		GwPath:            *gwPath,
		AttestPath:        *attestPath,
		AttestTelemetry:   *attestTelemetry,
		FleetPath:         *fleetPath,
		FleetTelemetry:    *fleetTelemetry,
		SpiffePath:        *spiffePath,
		SvidTelemetry:     *svidTelemetry,
		SpiffePolicyOut:   *spiffePolicyOut,
		SbomPath:          *sbomPath,
		AttestFile:        *attestFile,
		RuntimePath:       *runtimePath,
		HsmPath:           *hsmPath,
		HsmTelemetry:      *hsmTelemetry,
		BpfPath:           *bpfPath,
		BpfTelemetry:      *bpfTelemetry,
		BpfSynthOut:       *bpfSynthOut,
		BpfService:        *bpfService,
		PqcPath:           *pqcPath,
		PqcTelemetry:      *pqcTelemetry,
		PqcSynthOut:       *pqcSynthOut,
		CnsaStrict:        *cnsaStrict,
		SandboxPath:       *sandboxPath,
		SandboxTelemetry:  *sandboxTelemetry,
		SandboxSynthOut:   *sandboxSynthOut,
		QuarantineStrict:  *quarantineStrict,
		RemediatePath:     *remediatePath,
		RemediateSynthOut: *remediateSynthOut,
		CanaryStrict:      *canaryStrict,
		LSMPath:           *lsmPath,
		LSMTelemetry:      *lsmTelemetry,
		LSMSynthOut:       *lsmSynthOut,
		LSMStrict:         *lsmStrict,
		DRManifests:       *drManifests,
		DRTelemetry:       *drTelemetry,
		DRSynthOut:        *drSynthOut,
		DRRPOMax:          *drRPOMax,
		DRStrict:          *drStrict,
		FastPathManifests: *fastpathManifests,
		FastPathTelemetry: *fastpathTelemetry,
		FastPathSynthOut:  *fastpathSynthOut,
		FastPathStrict:    *fastpathStrict,
		EnclaveManifests:  *enclaveManifests,
		EnclaveTelemetry:  *enclaveTelemetry,
		EnclaveSynthOut:   *enclaveSynthOut,
		EnclaveStrict:     *enclaveStrict,
		WebhookPath:           *webhookPath,
		WebhookTelemetry:      *webhookTelemetry,
		WebhookSynthOut:       *webhookSynthOut,
		WebhookStrict:         *webhookStrict,
		ImpermanencePath:      *impermanencePath,
		EphemeralRoot:         *ephemeralRootShort != "",
		ImpermanenceTelemetry: *impermanenceTelemetry,
		ImpermanenceSynthOut:  *impermanenceSynthOut,
		ImpermanenceStrict:    *impermanenceStrict,
		BGPPath:               *bgpPath,
		CiliumBGP:             *ciliumBGPShort != "" || *bgpPath != "",
		BGPTelemetry:          *bgpTelemetry,
		BGPSynthOut:           *bgpSynthOut,
		BGPStrict:             *bgpStrict,
		StorePath:             *storePath,
		BinaryCache:           *binaryCacheShort != "" || *storePath != "",
		StoreTelemetry:        *storeTelemetry,
		StoreSynthOut:         *storeSynthOut,
		StoreStrict:           *storeStrict,
		LockdownPath:          *lockdownPath,
		SecureBoot:            *secureBootShort != "" || *lockdownPath != "",
		LockdownTelemetry:     *lockdownTelemetry,
		LockdownSynthOut:      *lockdownSynthOut,
		LockdownStrict:        *lockdownStrict,
		FlowPath:              *flowPath,
		CiliumFlow:            *ciliumFlowShort != "" || *flowPath != "",
		FlowTelemetry:         *flowTelemetry,
		FlowSynthOut:          *flowSynthOut,
		FlowStrict:            *flowStrict,
		ClusterMeshPath:          *clusterMeshPath,
		GlobalServices:           *globalServicesShort != "" || *clusterMeshPath != "",
		ClusterMeshTelemetryPath: *clusterMeshTelemetry,
		ClusterMeshSynthOut:      *clusterMeshSynthOut,
		ClusterMeshStrict:        *clusterMeshStrict,
		Briefing:              *briefing,
		BriefingDir:       *briefingDir,
		BriefingFile:      *briefingFile,
		PolicyOut:         *policyOut,
		PolicyEngine:      *policyEngine,
		EnforceAction:     *enforceAction,
		ProbeFlag:         *probeFlag,
		ProbeFixture:      *probeFixture,
		ProbeNodes:        *probeNodes,
		Format:            *format,
		OutFile:           *outFile,
	}
}

// HasAuditTargets reports whether any audit subsystem or synthesis target is requested.
func (c SentinelConfig) HasAuditTargets() bool {
	return c.FlakePath != "" || c.K8sPath != "" || c.PolicyOut != "" || c.ProbeFlag ||
		c.CephPath != "" || c.CephTelemetry != "" || c.WgPath != "" || c.WgTelemetry != "" ||
		c.CISPath != "" || c.GwPath != "" || c.AttestPath != "" || c.AttestTelemetry != "" ||
		c.FleetPath != "" || c.FleetTelemetry != "" || c.SpiffePath != "" || c.SvidTelemetry != "" ||
		c.SpiffePolicyOut != "" || c.SbomPath != "" || c.AttestFile != "" || c.RuntimePath != "" ||
		c.HsmPath != "" || c.HsmTelemetry != "" || c.BpfPath != "" || c.BpfTelemetry != "" ||
		c.BpfSynthOut != "" || c.PqcPath != "" || c.PqcTelemetry != "" || c.PqcSynthOut != "" ||
		c.SandboxPath != "" || c.SandboxTelemetry != "" || c.SandboxSynthOut != "" ||
		c.RemediatePath != "" || c.RemediateSynthOut != "" || c.LSMPath != "" || c.LSMTelemetry != "" ||
		c.LSMSynthOut != "" || c.DRManifests != "" || c.DRTelemetry != "" || c.DRSynthOut != "" ||
		c.FastPathManifests != "" || c.FastPathTelemetry != "" || c.FastPathSynthOut != "" ||
		c.EnclaveManifests != "" || c.EnclaveTelemetry != "" || c.EnclaveSynthOut != "" ||
		c.WebhookPath != "" || c.WebhookTelemetry != "" || c.WebhookSynthOut != "" ||
		c.ImpermanencePath != "" || c.ImpermanenceTelemetry != "" || c.ImpermanenceSynthOut != "" ||
		c.BGPPath != "" || c.BGPTelemetry != "" || c.BGPSynthOut != "" ||
		c.StorePath != "" || c.StoreTelemetry != "" || c.StoreSynthOut != "" ||
		c.LockdownPath != "" || c.LockdownTelemetry != "" || c.LockdownSynthOut != "" ||
		c.FlowPath != "" || c.FlowTelemetry != "" || c.FlowSynthOut != "" ||
		c.ClusterMeshPath != "" || c.ClusterMeshTelemetryPath != "" || c.ClusterMeshSynthOut != ""
}

