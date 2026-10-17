package remediate

import (
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// CanonicalRemediationRules defines the authoritative catalog of 12 declarative remediation rules.
var CanonicalRemediationRules = []RemediationRule{
	{
		ID:                   "REMEDIATE-AUTO-001",
		Target:               "nixos",
		Severity:             intel.SeverityMedium,
		CVSSScore:            6.1,
		Title:                "Unpinned Flake Input Dependency Declarative Lock Override",
		Description:          "Nix flake inputs without pure evaluation locks or with unpinned git references permit unintentional remote cache substitutes.",
		SuggestedRemediation: "Synthesize declarative flake.lock override enforcing pure evaluation and immutable narHash pinning.",
		MatchedCVE:           "CVE-2026-19402",
	},
	{
		ID:                   "REMEDIATE-AUTO-002",
		Target:               "kubernetes",
		Severity:             intel.SeverityHigh,
		CVSSScore:            7.8,
		Title:                "Unhardened Workload Container SecurityContext Kustomize Hardening",
		Description:          "Container workloads running without explicit securityContext parameters risk privilege escalation and host filesystem compromise.",
		SuggestedRemediation: "Synthesize Kustomize strategic merge patch enforcing runAsNonRoot: true, readOnlyRootFilesystem: true, and drop: ['ALL'] capabilities.",
		MatchedCVE:           "CVE-2026-20914",
	},
	{
		ID:                   "REMEDIATE-AUTO-003",
		Target:               "kubernetes",
		Severity:             intel.SeverityHigh,
		CVSSScore:            8.4,
		Title:                "Vulnerable Ingress Path Traversal & Snippet Injection Overlay",
		Description:          "Custom configuration snippets or unnormalized URI paths in Ingress manifests permit path traversal bypasses in ingress-nginx controllers.",
		SuggestedRemediation: "Synthesize Kustomize JSONPatch stripping raw configuration-snippet annotations and enforcing strict URI regex normalization.",
		MatchedCVE:           "CVE-2026-21801",
	},
	{
		ID:                   "REMEDIATE-AUTO-004",
		Target:               "kubernetes",
		Severity:             intel.SeverityHigh,
		CVSSScore:            7.5,
		Title:                "Permissive CNI Egress Default-Deny Microsegmentation Synthesis",
		Description:          "Workloads operating without egress network policies can establish unrestricted outbound connections to arbitrary 0.0.0.0/0 destinations.",
		SuggestedRemediation: "Synthesize declarative Cilium/Kubernetes NetworkPolicy overlay enforcing baseline default-deny egress microsegmentation.",
		MatchedCVE:           "CVE-2026-90412",
	},
	{
		ID:                   "REMEDIATE-AUTO-005",
		Target:               "nixos",
		Severity:             intel.SeverityMedium,
		CVSSScore:            5.5,
		Title:                "Ceph Distributed Storage In-Transit Wire Encryption & Peering Safety Patch",
		Description:          "Rook Ceph storage cluster operating without msgr2 cryptographic framing risks packet eavesdropping and BlueStore metadata desynchronization.",
		SuggestedRemediation: "Synthesize declarative CephCluster patch activating requireMsgr2: true and setting bluestore_default_buffered_write throttling.",
		MatchedCVE:           "CVE-2026-15509",
	},
	{
		ID:                   "REMEDIATE-AUTO-006",
		Target:               "nixos",
		Severity:             intel.SeverityHigh,
		CVSSScore:            8.5,
		Title:                "Plaintext WireGuard Private Key Migration to Encrypted Runtime Secret",
		Description:          "Embedding WireGuard private keys directly in declarative Nix expressions exposes cryptographic keys in the world-readable /nix/store.",
		SuggestedRemediation: "Synthesize NixOS configuration patch migrating privateKey strings to privateKeyFile paths under /run/secrets/wireguard/key.",
		MatchedCVE:           "CVE-2026-31048",
	},
	{
		ID:                   "REMEDIATE-AUTO-007",
		Target:               "nixos",
		Severity:             intel.SeverityMedium,
		CVSSScore:            6.8,
		Title:                "CIS Kubernetes Benchmark Control Plane Declarative Systemd Remediation",
		Description:          "Control plane components executing with default profiling or anonymous authentication violate CIS Kubernetes Benchmark standards.",
		SuggestedRemediation: "Synthesize drop-in NixOS systemd unit override hardening kube-apiserver with --profiling=false and --anonymous-auth=false.",
		MatchedCVE:           "CVE-2026-38102",
	},
	{
		ID:                   "REMEDIATE-AUTO-008",
		Target:               "kubernetes",
		Severity:             intel.SeverityHigh,
		CVSSScore:            8.2,
		Title:                "Missing SPIFFE/SPIRE Workload Attestation Mutual TLS Policy Synthesis",
		Description:          "Services communicating without cryptographically attested SPIFFE X.509 SVID identities permit identity spoofing across cluster namespaces.",
		SuggestedRemediation: "Synthesize CiliumNetworkPolicy enforcing mutual TLS authentication with verified io.spiffe.id selectors.",
		MatchedCVE:           "CVE-2026-67210",
	},
	{
		ID:                   "REMEDIATE-AUTO-009",
		Target:               "kubernetes",
		Severity:             intel.SeverityCritical,
		CVSSScore:            9.4,
		Title:                "Insecure KMS v2 Envelope Encryption & PKCS#11 Hardening Patch",
		Description:          "Kubernetes EncryptionConfiguration operating with KMS v1 APIs or plaintext identity providers permits etcd secrets exposure at rest.",
		SuggestedRemediation: "Synthesize hardened EncryptionConfiguration overlay enforcing KMS v2 unix domain socket IPC and 90-day KEK rotation.",
		MatchedCVE:           "CVE-2026-83190",
	},
	{
		ID:                   "REMEDIATE-AUTO-010",
		Target:               "kubernetes",
		Severity:             intel.SeverityCritical,
		CVSSScore:            9.8,
		Title:                "Unconfined Seccomp & Privileged BPF Syscall Restriction Overlay",
		Description:          "Workloads running without seccomp confinement or with unconfined profiles permit unprivileged raw socket floods and LSM bypasses.",
		SuggestedRemediation: "Synthesize Kustomize patch enforcing seccompProfile.type: RuntimeDefault and dropping CAP_NET_RAW capabilities.",
		MatchedCVE:           "CVE-2026-90412",
	},
	{
		ID:                   "REMEDIATE-AUTO-011",
		Target:               "kubernetes",
		Severity:             intel.SeverityHigh,
		CVSSScore:            8.8,
		Title:                "Classical TLS 1.2 Deprecation & Post-Quantum ML-KEM Hybrid TLS Overlay",
		Description:          "Cluster control plane endpoints accepting TLS 1.0/1.1 or classical RSA ciphers are vulnerable to Harvest-Now-Decrypt-Later attacks.",
		SuggestedRemediation: "Synthesize static pod configuration overlay enforcing TLS 1.3, hybrid X25519MLKEM768 key encapsulation, and CNSA 2.0 ciphers.",
		MatchedCVE:           "CVE-2026-94301",
	},
	{
		ID:                   "REMEDIATE-AUTO-012",
		Target:               "nixos",
		Severity:             intel.SeverityCritical,
		CVSSScore:            9.2,
		Title:                "Ephemeral MicroVM Network Egress Isolation & Decoy Honeypot Trap Patch",
		Description:          "MicroVM detonation sandboxes executing untrusted payloads without egress isolation allow C2 beaconing and honeypot evasion.",
		SuggestedRemediation: "Synthesize hardened NixOS microvm module enforcing unprivileged jailer UID/GID, read-only rootfs, and egress TAP redirection.",
		MatchedCVE:           "CVE-2026-97105",
	},
}

// GetRuleByID retrieves a canonical remediation rule by identifier.
func GetRuleByID(id string) (RemediationRule, bool) {
	cleanID := strings.ToUpper(strings.TrimSpace(id))
	for _, rule := range CanonicalRemediationRules {
		if rule.ID == cleanID {
			return rule, true
		}
	}
	return RemediationRule{}, false
}

// AllRules returns a copy of the canonical rule catalog.
func AllRules() []RemediationRule {
	res := make([]RemediationRule, len(CanonicalRemediationRules))
	copy(res, CanonicalRemediationRules)
	return res
}
