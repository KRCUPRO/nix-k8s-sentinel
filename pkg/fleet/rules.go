package fleet

import (
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// FleetRulesCatalog defines the authoritative security and drift ruleset for multi-cluster fleet ops and OIDC identity.
var FleetRulesCatalog = map[string]FleetRule{
	"FLEET-RBAC-001": {
		ID:          "FLEET-RBAC-001",
		Title:       "Wildcard Verb, Resource, or APIGroup in ClusterRole",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.3,
		Category:    CategoryRBAC,
		Description: "ClusterRole grants unrestricted wildcard '*' permissions across verbs, API groups, or resources, violating the principle of least privilege and risking total cluster compromise.",
		Remediation: "Explicitly enumerate required API groups, resources, and verbs. Avoid wildcard '*' specifications in cluster-scoped roles.",
	},
	"FLEET-RBAC-002": {
		ID:          "FLEET-RBAC-002",
		Title:       "Uncontained Privilege Escalation via Bind or Escalate Verbs",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.8,
		Category:    CategoryRBAC,
		Description: "Role or ClusterRole grants 'bind' or 'escalate' verbs on RBAC resources, allowing non-admin service accounts to grant themselves arbitrary higher privileges.",
		Remediation: "Restrict 'bind' and 'escalate' permissions exclusively to root cluster-admin operators. Audit RBAC role hierarchy.",
	},
	"FLEET-RBAC-003": {
		ID:          "FLEET-RBAC-003",
		Title:       "Cluster-Admin Bound to Broad Authenticated or Anonymous Subject Groups",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.8,
		Category:    CategoryRBAC,
		Description: "ClusterRoleBinding attaches high-privilege roles (like 'cluster-admin') to broad group subjects such as 'system:authenticated', 'system:unauthenticated', or 'system:anonymous'.",
		Remediation: "Remove broad group subjects from high-privilege role bindings. Scope bindings strictly to explicit users or isolated service accounts.",
	},
	"FLEET-RBAC-004": {
		ID:          "FLEET-RBAC-004",
		Title:       "Dangerous User or Group Impersonation Permissions",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.5,
		Category:    CategoryRBAC,
		Description: "Role or ClusterRole grants 'impersonate' verbs across users, groups, or service accounts without strict resourceNames filtering, allowing unauthorized identity masquerading.",
		Remediation: "Constrain 'impersonate' verb to explicit 'resourceNames' white-lists, or eliminate impersonation rights from tenant roles.",
	},
	"FLEET-RBAC-005": {
		ID:          "FLEET-RBAC-005",
		Title:       "Multi-Tenant Cross-Namespace Secret Access Without Partition Boundaries",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.2,
		Category:    CategoryRBAC,
		Description: "ClusterRole allows reading 'secrets' cluster-wide across all namespaces, breaking tenant isolation and risking cross-tenant credential exfiltration.",
		Remediation: "Use namespace-scoped RoleBindings for secret access. Never grant cluster-wide 'get', 'list', or 'watch' on secrets to tenant workloads.",
	},
	"FLEET-OIDC-001": {
		ID:          "FLEET-OIDC-001",
		Title:       "Insecure OIDC Token Signing Algorithm Permitting Forgery",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.6,
		Category:    CategoryOIDC,
		Description: "OIDC authenticator or federated token utilizes an insecure signing algorithm such as 'none' or symmetric HMAC ('HS256') instead of asymmetric public-key cryptography (RS256/ES256).",
		Remediation: "Enforce asymmetric algorithms (RS256, ES256, EdDSA) in OIDC identity provider configurations. Reject 'none' and symmetric HMAC algorithms.",
	},
	"FLEET-OIDC-002": {
		ID:          "FLEET-OIDC-002",
		Title:       "Excessive or Unexpiring OIDC Federated Token TTL",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.8,
		Category:    CategoryOIDC,
		Description: "Federated OIDC identity token specifies a lifespan (TTL) exceeding the 24-hour maximum threshold or lacks an expiration timestamp, risking replay and session hijacking attacks.",
		Remediation: "Enforce short-lived token lifetimes (ideally 1 to 8 hours, maximum 24 hours). Implement automated token rotation.",
	},
	"FLEET-OIDC-003": {
		ID:          "FLEET-OIDC-003",
		Title:       "Missing Audience or Issuer Claim Validation in Cluster OIDC Config",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.1,
		Category:    CategoryOIDC,
		Description: "OIDC configuration or federated token lacks mandatory audience ('aud') or issuer ('iss') claim restrictions, exposing the cluster to cross-service token substitution.",
		Remediation: "Specify dedicated, cluster-unique 'client_id' and 'audience' values in OIDC provider configs. Require verified 'iss' validation.",
	},
	"FLEET-OIDC-004": {
		ID:          "FLEET-OIDC-004",
		Title:       "Stale or Unrotated OIDC Signing Key in Federated Identity Pool",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.7,
		Category:    CategoryOIDC,
		Description: "OIDC federated identity keys have not been rotated within the 90-day threshold, increasing cryptographic exposure to key compromise.",
		Remediation: "Rotate OIDC signing keys on a regular cadence (at least every 60-90 days). Enable automated JWKS endpoint key discovery.",
	},
	"FLEET-GITOPS-001": {
		ID:          "FLEET-GITOPS-001",
		Title:       "GitOps Automated Self-Healing Disabled Permitting Silent Drift",
		Severity:    intel.SeverityHigh,
		CVSSScore:   7.5,
		Category:    CategoryGitOpsDrift,
		Description: "ArgoCD Application or Flux Kustomization lacks automated self-heal ('syncPolicy.automated.selfHeal: true'), allowing out-of-band cluster modifications to persist indefinitely.",
		Remediation: "Enable 'selfHeal: true' in ArgoCD syncPolicy or 'prune: true' in Flux Kustomizations to automatically correct configuration drift.",
	},
	"FLEET-GITOPS-002": {
		ID:          "FLEET-GITOPS-002",
		Title:       "Unpinned GitOps Source Revision Tracking Floating Branch",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.4,
		Category:    CategoryGitOpsDrift,
		Description: "GitOps Application tracks a mutable floating branch ('HEAD', 'main', 'master') without pinning to an immutable Git commit SHA or signed semantic tag, enabling supply-chain drift.",
		Remediation: "Pin 'targetRevision' to an immutable commit hash or cryptographically verified release tag. Avoid tracking mutable branches directly.",
	},
	"FLEET-GITOPS-003": {
		ID:          "FLEET-GITOPS-003",
		Title:       "Unauthenticated Git or OCI Repository Source",
		Severity:    intel.SeverityMedium,
		CVSSScore:   6.9,
		Category:    CategoryGitOpsDrift,
		Description: "GitOps repository source does not specify authentication secret references, relying on insecure public access or unverified endpoints for deployment manifests.",
		Remediation: "Bind GitRepository or Application sources to authenticated Kubernetes Secret credentials via 'secretRef'.",
	},
	"FLEET-GITOPS-004": {
		ID:          "FLEET-GITOPS-004",
		Title:       "Wildcard or Unrestricted Target Cluster Dispatch",
		Severity:    intel.SeverityCritical,
		CVSSScore:   9.1,
		Category:    CategoryGitOpsDrift,
		Description: "ArgoCD Application or ApplicationSet specifies wildcard target cluster ('server: *'), permitting workload deployment to arbitrary or untrusted cluster members.",
		Remediation: "Explicitly designate destination cluster URLs or names. Prohibit wildcard cluster targets in GitOps declarations.",
	},
	"FLEET-DRIFT-001": {
		ID:          "FLEET-DRIFT-001",
		Title:       "Multi-Cluster Fleet Desynchronization or Degraded Health Detected",
		Severity:    intel.SeverityHigh,
		CVSSScore:   8.0,
		Category:    CategoryMultiCluster,
		Description: "Runtime telemetry indicates out-of-sync or degraded cluster states across geographically distributed fleet members, creating divergent security postures.",
		Remediation: "Investigate cluster reconciliation stalls, resolve upstream GitOps sync errors, and restore cluster sync parity.",
	},
}

// LookupFleetRule retrieves a canonical FleetRule by ID or returns a fallback rule.
func LookupFleetRule(ruleID string) (FleetRule, bool) {
	rule, ok := FleetRulesCatalog[ruleID]
	return rule, ok
}
