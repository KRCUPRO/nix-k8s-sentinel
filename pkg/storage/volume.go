package storage

import (
	"fmt"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// auditStorageClassResource inspects StorageClass parameters and reclaim policies.
func auditStorageClassResource(name, content, filePath string, startLine int) []StorageViolation {
	var violations []StorageViolation
	lower := strings.ToLower(content)

	isCephProvisioner := strings.Contains(lower, "rook-ceph.rbd.csi.ceph.com") ||
		strings.Contains(lower, "rook-ceph.cephfs.csi.ceph.com") ||
		strings.Contains(lower, "ceph.com")

	if !isCephProvisioner {
		return violations
	}

	// 1. ROOK-CEPH-009: StorageClass Reclaim Policy Immediate Deletion
	isReclaimDelete := strings.Contains(lower, "reclaimpolicy: delete") ||
		strings.Contains(lower, "reclaimpolicy:delete")

	isDatabaseClass := strings.Contains(lower, "db") ||
		strings.Contains(lower, "database") ||
		strings.Contains(lower, "stateful") ||
		strings.Contains(lower, "postgres") ||
		strings.Contains(lower, "mysql") ||
		strings.Contains(lower, "etcd")

	if isReclaimDelete && isDatabaseClass {
		rule, _ := GetStorageRule(RuleRookStorageClassReclaim)
		violations = append(violations, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: "StorageClass",
			ResourceName: name,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  fmt.Sprintf("StorageClass '%s' for database/stateful workloads specifies 'reclaimPolicy: Delete', risking data loss if a PVC is deleted.", name),
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    findPatternLine(content, `(?i)reclaimPolicy:\s*Delete`, startLine),
		})
	}

	// 2. Encryption at rest parameter check for RBD storage class
	if strings.Contains(lower, "rook-ceph.rbd.csi.ceph.com") {
		hasParamEncryption := strings.Contains(lower, `encrypted: "true"`) ||
			strings.Contains(lower, "encrypted: true")
		if !hasParamEncryption {
			rule, _ := GetStorageRule(RuleRookAtRestEncryption)
			violations = append(violations, StorageViolation{
				RuleID:       rule.ID,
				Title:        rule.Title,
				ResourceKind: "StorageClass",
				ResourceName: name,
				Severity:     intel.SeverityMedium,
				CVSSScore:    6.2,
				Description:  fmt.Sprintf("StorageClass '%s' provisioner rook-ceph.rbd lacks 'encrypted: \"true\"' parameter for node-side dm-crypt encryption.", name),
				Remediation:  "Add 'parameters.encrypted: \"true\"' and configure a KMS encryption vault in the Ceph CSI cluster config.",
				FilePath:     filePath,
				StartLine:    startLine,
			})
		}
	}

	return violations
}

// auditPVCResource evaluates PVC access modes against storage backing constraints.
func auditPVCResource(name, namespace, content, filePath string, startLine int) []StorageViolation {
	var violations []StorageViolation
	lower := strings.ToLower(content)

	hasRWX := strings.Contains(lower, "readwritemany") || strings.Contains(lower, "- readwritemany")
	if !hasRWX {
		return violations
	}

	// ROOK-CEPH-008: RBD Block Volume Unsafe Multi-Attach (RWX)
	// Check if this PVC targets an RBD block pool or mentions rbd storage class
	isRBDStorage := strings.Contains(lower, "rook-ceph-block") ||
		strings.Contains(lower, "rbd") ||
		strings.Contains(lower, "ceph-block")

	isExplicitCephFS := strings.Contains(lower, "cephfs") ||
		strings.Contains(lower, "rook-cephfs")

	if isRBDStorage && !isExplicitCephFS {
		rule, _ := GetStorageRule(RuleRookPVCMultiAttach)
		violations = append(violations, StorageViolation{
			RuleID:       rule.ID,
			Title:        rule.Title,
			ResourceKind: "PersistentVolumeClaim",
			ResourceName: name,
			Namespace:    namespace,
			Severity:     rule.Severity,
			CVSSScore:    rule.CVSSScore,
			Description:  fmt.Sprintf("PersistentVolumeClaim '%s' specifies ReadWriteMany (RWX) on Ceph RBD block storage '%s'. Unlocked multi-node concurrent writes cause immediate ext4/xfs filesystem corruption.", name, extractStorageClassName(content)),
			Remediation:  rule.Remediation,
			FilePath:     filePath,
			StartLine:    findPatternLine(content, `(?i)ReadWriteMany`, startLine),
		})
	}

	return violations
}

func extractStorageClassName(content string) string {
	lower := strings.ToLower(content)
	idx := strings.Index(lower, "storageclassname:")
	if idx == -1 {
		return "default"
	}
	sub := content[idx+len("storageclassname:"):]
	if newline := strings.Index(sub, "\n"); newline != -1 {
		sub = sub[:newline]
	}
	return strings.TrimSpace(sub)
}
