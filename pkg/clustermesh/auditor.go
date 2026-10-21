package clustermesh

import (
	"fmt"
	"math"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// AuditMeshAssets performs an end-to-end evaluation of ClusterMesh configurations, global services, policies, and telemetry.
func AuditMeshAssets(
	configs []ClusterMeshConfig,
	services []GlobalServiceConfig,
	policies []MeshNetworkPolicyConfig,
	telemetry *ClusterMeshTelemetryReport,
	feed *intel.Feed,
) ([]MeshViolation, MeshSummary) {
	var violations []MeshViolation

	// 1. Audit ClusterMesh control plane and daemon configurations
	violations = append(violations, auditConfigs(configs)...)

	// 2. Audit Global Services & Multi-Cluster Services (MCS) exports
	violations = append(violations, auditServices(services, policies)...)

	// 3. Audit Network Policies for wildcard cluster selectors
	violations = append(violations, auditPolicies(policies)...)

	// 4. Audit runtime telemetry if present
	if telemetry != nil {
		violations = append(violations, auditTelemetry(telemetry)...)
	}

	// Calculate compliance score and summary metrics
	summary := computeSummary(configs, services, policies, telemetry, violations)

	return violations, summary
}

func auditConfigs(configs []ClusterMeshConfig) []MeshViolation {
	var violations []MeshViolation
	seenClusterIDs := make(map[int]string)

	for _, cfg := range configs {
		// MESH-RADAR-001: Unencrypted Cross-Cluster Tunnel
		if cfg.TunnelEncryption == EncryptionNone || cfg.TunnelEncryption == "" {
			rule := FindRuleByID("MESH-RADAR-001")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    cfg.ClusterName,
				Cluster:     cfg.ClusterName,
				Message:     fmt.Sprintf("Cluster '%s' uses unencrypted cross-cluster tunnel traffic (encryption=none)", cfg.ClusterName),
				LineNumber:  cfg.LineNumber,
				FilePath:    cfg.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}

		// MESH-RADAR-002: ClusterID Collision or Reserved Zero
		if cfg.ClusterID <= 0 || cfg.ClusterID > MaxAllowedClusterID {
			rule := FindRuleByID("MESH-RADAR-002")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    cfg.ClusterName,
				Cluster:     cfg.ClusterName,
				Message:     fmt.Sprintf("Cluster '%s' has invalid or reserved cluster-id: %d (valid range: 1..255)", cfg.ClusterName, cfg.ClusterID),
				LineNumber:  cfg.LineNumber,
				FilePath:    cfg.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		} else if existingCluster, found := seenClusterIDs[cfg.ClusterID]; found && existingCluster != cfg.ClusterName {
			rule := FindRuleByID("MESH-RADAR-002")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    cfg.ClusterName,
				Cluster:     cfg.ClusterName,
				Message:     fmt.Sprintf("ClusterID collision: cluster-id %d is used by both '%s' and '%s'", cfg.ClusterID, existingCluster, cfg.ClusterName),
				LineNumber:  cfg.LineNumber,
				FilePath:    cfg.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		} else if cfg.ClusterID > 0 {
			seenClusterIDs[cfg.ClusterID] = cfg.ClusterName
		}

		// MESH-RADAR-003: Insecure ClusterMesh Etcd TLS
		if !cfg.EtcdTLS || cfg.EtcdClientCert == "" {
			rule := FindRuleByID("MESH-RADAR-003")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    cfg.ClusterName,
				Cluster:     cfg.ClusterName,
				Message:     fmt.Sprintf("ClusterMesh control plane on cluster '%s' has insecure etcd TLS (tls=%v, clientCert='%s')", cfg.ClusterName, cfg.EtcdTLS, cfg.EtcdClientCert),
				LineNumber:  cfg.LineNumber,
				FilePath:    cfg.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}

		// MESH-RADAR-010: Unverified Remote Cluster CA Certificate
		if cfg.EtcdCACert == "" || strings.EqualFold(cfg.EtcdCACert, "none") {
			rule := FindRuleByID("MESH-RADAR-010")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    cfg.ClusterName,
				Cluster:     cfg.ClusterName,
				Message:     fmt.Sprintf("ClusterMesh on '%s' specifies empty or unverified CA certificate bundle", cfg.ClusterName),
				LineNumber:  cfg.LineNumber,
				FilePath:    cfg.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}
	}

	return violations
}

func auditServices(services []GlobalServiceConfig, policies []MeshNetworkPolicyConfig) []MeshViolation {
	var violations []MeshViolation
	seenServices := make(map[string]GlobalServiceConfig)

	sensitiveKeywords := []string{
		"vault", "database", "db", "etcd", "admin", "kube-system",
		"auth", "redis", "postgres", "mysql", "secret",
	}

	for _, svc := range services {
		key := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)

		// MESH-RADAR-004: ServiceExport Namespace Collision
		if prev, found := seenServices[key]; found {
			if prev.ClusterName != svc.ClusterName || prev.FilePath != svc.FilePath {
				rule := FindRuleByID("MESH-RADAR-004")
				violations = append(violations, MeshViolation{
					RuleID:      rule.ID,
					Name:        rule.Name,
					Severity:    rule.Severity,
					Resource:    key,
					Cluster:     svc.ClusterName,
					Message:     fmt.Sprintf("Global service name collision detected for '%s' across multiple manifests/clusters", key),
					LineNumber:  svc.LineNumber,
					FilePath:    svc.FilePath,
					Remediation: rule.Remediation,
					MatchedCVE:  rule.MatchedCVE,
					CVSSScore:   rule.CVSSScore,
				})
			}
		} else {
			seenServices[key] = svc
		}

		// MESH-RADAR-005: Unrestricted Global Service Exposure for sensitive workloads
		if svc.IsGlobal {
			lowerName := strings.ToLower(svc.Name)
			lowerNs := strings.ToLower(svc.Namespace)
			isSensitive := false
			for _, kw := range sensitiveKeywords {
				if strings.Contains(lowerName, kw) || strings.Contains(lowerNs, kw) {
					isSensitive = true
					break
				}
			}
			if isSensitive {
				rule := FindRuleByID("MESH-RADAR-005")
				violations = append(violations, MeshViolation{
					RuleID:      rule.ID,
					Name:        rule.Name,
					Severity:    rule.Severity,
					Resource:    key,
					Cluster:     svc.ClusterName,
					Message:     fmt.Sprintf("Sensitive service '%s' declared as global-service without strict tenant isolation", key),
					LineNumber:  svc.LineNumber,
					FilePath:    svc.FilePath,
					Remediation: rule.Remediation,
					MatchedCVE:  rule.MatchedCVE,
					CVSSScore:   rule.CVSSScore,
				})
			}
		}

		// MESH-RADAR-006: Missing Cross-Cluster Network Policy
		if svc.IsGlobal {
			hasPolicy := false
			for _, pol := range policies {
				if pol.IsClusterwide || pol.Namespace == svc.Namespace {
					hasPolicy = true
					break
				}
			}
			if !hasPolicy && len(policies) > 0 {
				rule := FindRuleByID("MESH-RADAR-006")
				violations = append(violations, MeshViolation{
					RuleID:      rule.ID,
					Name:        rule.Name,
					Severity:    rule.Severity,
					Resource:    key,
					Cluster:     svc.ClusterName,
					Message:     fmt.Sprintf("Global service '%s' lacks cross-cluster CiliumNetworkPolicy enforcement", key),
					LineNumber:  svc.LineNumber,
					FilePath:    svc.FilePath,
					Remediation: rule.Remediation,
					MatchedCVE:  rule.MatchedCVE,
					CVSSScore:   rule.CVSSScore,
				})
			}
		}

		// MESH-RADAR-009: Cross-Cluster Service Endpoint Saturation
		if svc.BackendCount > MaxGlobalServiceEndpoints {
			rule := FindRuleByID("MESH-RADAR-009")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    key,
				Cluster:     svc.ClusterName,
				Message:     fmt.Sprintf("Global service '%s' endpoint count (%d) exceeds BPF service table allocation ceiling (%d)", key, svc.BackendCount, MaxGlobalServiceEndpoints),
				LineNumber:  svc.LineNumber,
				FilePath:    svc.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}

		// MESH-RADAR-011: Non-Shared Service Routing Leak
		if !svc.IsShared && (svc.IsGlobal || svc.ServiceExport) {
			rule := FindRuleByID("MESH-RADAR-011")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    key,
				Cluster:     svc.ClusterName,
				Message:     fmt.Sprintf("Service '%s' has conflicting annotations: shared-service=false but global-service=true", key),
				LineNumber:  svc.LineNumber,
				FilePath:    svc.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}
	}

	return violations
}

func auditPolicies(policies []MeshNetworkPolicyConfig) []MeshViolation {
	var violations []MeshViolation

	for _, pol := range policies {
		// MESH-RADAR-007: Wildcard Remote Cluster Selector
		if pol.ClusterSelector == "*" || pol.ClusterSelector == "any" {
			rule := FindRuleByID("MESH-RADAR-007")
			violations = append(violations, MeshViolation{
				RuleID:      rule.ID,
				Name:        rule.Name,
				Severity:    rule.Severity,
				Resource:    pol.Name,
				Cluster:     "global",
				Message:     fmt.Sprintf("Network policy '%s' uses wildcard cluster selector ('*'), eliminating multi-cluster tenant boundaries", pol.Name),
				LineNumber:  pol.LineNumber,
				FilePath:    pol.FilePath,
				Remediation: rule.Remediation,
				MatchedCVE:  rule.MatchedCVE,
				CVSSScore:   rule.CVSSScore,
			})
		}
	}

	return violations
}

func auditTelemetry(telemetry *ClusterMeshTelemetryReport) []MeshViolation {
	var violations []MeshViolation

	// MESH-RADAR-008: ClusterMesh Sync Heartbeat Timeout
	if telemetry.SyncLatencyMs > MaxClusterMeshSyncLatencyMs || telemetry.EtcdSyncErrors > 0 || telemetry.SyncState == SyncStateDegraded {
		rule := FindRuleByID("MESH-RADAR-008")
		violations = append(violations, MeshViolation{
			RuleID:      rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			Resource:    telemetry.LocalClusterName,
			Cluster:     telemetry.LocalClusterName,
			Message:     fmt.Sprintf("ClusterMesh sync degraded on cluster '%s': latency=%.1fms (max %0.1fms), errors=%d, state=%s", telemetry.LocalClusterName, telemetry.SyncLatencyMs, MaxClusterMeshSyncLatencyMs, telemetry.EtcdSyncErrors, telemetry.SyncState),
			LineNumber:  1,
			FilePath:    "runtime/telemetry",
			Remediation: rule.Remediation,
			MatchedCVE:  rule.MatchedCVE,
			CVSSScore:   rule.CVSSScore,
		})
	}

	// MESH-RADAR-012: ClusterMesh Daemon Disconnected
	if len(telemetry.DisconnectedClusters) > 0 || telemetry.SyncState == SyncStateDisconnected || telemetry.SyncState == SyncStatePartitioned {
		rule := FindRuleByID("MESH-RADAR-012")
		violations = append(violations, MeshViolation{
			RuleID:      rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			Resource:    telemetry.LocalClusterName,
			Cluster:     telemetry.LocalClusterName,
			Message:     fmt.Sprintf("ClusterMesh disconnected: %d remote clusters unreachable (%s)", len(telemetry.DisconnectedClusters), strings.Join(telemetry.DisconnectedClusters, ", ")),
			LineNumber:  1,
			FilePath:    "runtime/telemetry",
			Remediation: rule.Remediation,
			MatchedCVE:  rule.MatchedCVE,
			CVSSScore:   rule.CVSSScore,
		})
	}

	return violations
}

func computeSummary(
	configs []ClusterMeshConfig,
	services []GlobalServiceConfig,
	policies []MeshNetworkPolicyConfig,
	telemetry *ClusterMeshTelemetryReport,
	violations []MeshViolation,
) MeshSummary {
	totalAudited := len(configs) + len(services) + len(policies)
	if telemetry != nil {
		totalAudited++
	}

	criticalCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	for _, v := range violations {
		switch v.Severity {
		case intel.SeverityCritical:
			criticalCount++
		case intel.SeverityHigh:
			highCount++
		case intel.SeverityMedium:
			medCount++
		default:
			lowCount++
		}
	}

	// Deterministic compliance score: starts at 100.0%, penalties applied per violation
	score := 100.0 - (float64(criticalCount) * 15.0) - (float64(highCount) * 8.0) - (float64(medCount) * 4.0) - (float64(lowCount) * 2.0)
	if score < 0.0 {
		score = 0.0
	}
	score = math.Round(score*10.0) / 10.0

	meshHealthy := criticalCount == 0 && highCount == 0 && (telemetry == nil || (telemetry.SyncState == SyncStateHealthy && len(telemetry.DisconnectedClusters) == 0))

	return MeshSummary{
		TotalAudited:    totalAudited,
		TotalViolations: len(violations),
		CriticalCount:   criticalCount,
		HighCount:       highCount,
		MediumCount:     medCount,
		LowCount:        lowCount,
		ComplianceScore: score,
		MeshHealthy:     meshHealthy,
	}
}
