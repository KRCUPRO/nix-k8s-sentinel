package attest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// TelemetryPayload models the incoming JSON structure containing node attestation reports.
type TelemetryPayload struct {
	Timestamp time.Time               `json:"timestamp"`
	Nodes     []NodeAttestationReport `json:"nodes"`
}

// AttestationVerifier inspects TPM 2.0 PCR quotations and remote attestation tokens.
type AttestationVerifier struct {
	feed *intel.Feed
}

// NewAttestationVerifier initializes a verifier with an optional threat intelligence feed.
func NewAttestationVerifier(feed *intel.Feed) *AttestationVerifier {
	return &AttestationVerifier{feed: feed}
}

// VerifyTelemetryFile loads and audits a JSON attestation telemetry file.
func (v *AttestationVerifier) VerifyTelemetryFile(filePath string) (*AttestationAuditReport, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat attestation telemetry file %s: %w", cleanPath, err)
	}

	if info.Size() > MaxAttestationBytes {
		return nil, fmt.Errorf("telemetry file %s exceeds maximum permitted size of %d bytes", cleanPath, MaxAttestationBytes)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation telemetry file %s: %w", cleanPath, err)
	}

	return v.VerifyTelemetryBytes(data, cleanPath)
}

// VerifyTelemetryBytes deserializes and verifies raw JSON attestation telemetry payload.
func (v *AttestationVerifier) VerifyTelemetryBytes(data []byte, sourcePath string) (*AttestationAuditReport, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty attestation telemetry data provided")
	}

	var payload TelemetryPayload
	if err := json.Unmarshal(data, &payload); err == nil && len(payload.Nodes) > 0 {
		// Parsed as TelemetryPayload with nodes
	} else {
		// Attempt single node parse
		var single NodeAttestationReport
		if errSingle := json.Unmarshal(data, &single); errSingle == nil && single.NodeName != "" {
			payload.Nodes = []NodeAttestationReport{single}
		} else if err != nil {
			return nil, fmt.Errorf("invalid attestation telemetry JSON format: %w", err)
		}
	}

	if len(payload.Nodes) == 0 {
		return nil, fmt.Errorf("no cluster nodes found in attestation telemetry")
	}

	report := &AttestationAuditReport{
		TelemetryPath: sourcePath,
		TotalNodes:    len(payload.Nodes),
		Violations:    make([]AttestationViolation, 0),
		EvaluatedNodes: make([]string, 0, len(payload.Nodes)),
	}

	totalChecks := 0
	passedChecks := 0
	nodesVerified := 0

	for i := range payload.Nodes {
		node := &payload.Nodes[i]
		report.EvaluatedNodes = append(report.EvaluatedNodes, node.NodeName)

		nodeViolations, checks, passed := v.auditNode(node, sourcePath)
		totalChecks += checks
		passedChecks += passed

		if len(nodeViolations) == 0 {
			node.Verified = true
			nodesVerified++
		} else {
			node.Verified = false
			report.Violations = append(report.Violations, nodeViolations...)
		}
	}

	score := 100.0
	if totalChecks > 0 {
		score = math.Round((float64(passedChecks)/float64(totalChecks))*1000) / 10
	}

	report.Summary = AttestationSummary{
		TotalChecks:     totalChecks,
		PassedChecks:    passedChecks,
		ComplianceScore: score,
		NodesAttested:   len(payload.Nodes),
		NodesVerified:   nodesVerified,
	}

	for _, viol := range report.Violations {
		switch viol.Severity {
		case intel.SeverityCritical:
			report.Summary.CriticalCount++
		case intel.SeverityHigh:
			report.Summary.HighCount++
		case intel.SeverityMedium:
			report.Summary.MediumCount++
		case intel.SeverityLow:
			report.Summary.LowCount++
		}
	}

	return report, nil
}

// auditNode performs rule-based verification on an individual node attestation report.
func (v *AttestationVerifier) auditNode(node *NodeAttestationReport, sourcePath string) ([]AttestationViolation, int, int) {
	var violations []AttestationViolation
	total := 0
	passed := 0

	now := time.Now().UTC()

	// 1. Token Validity & Expiration Check
	total++
	isExpired := node.TokenExpired
	if !node.AttestedAt.IsZero() && now.Sub(node.AttestedAt.UTC()) > 24*time.Hour {
		isExpired = true
	}
	if isExpired {
		rule := GetAttestationRule("ATTEST-BOOT-008")
		violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
			fmt.Sprintf("Attestation token for node '%s' has expired or exceeded maximum 24h validity window", node.NodeName)))
	} else {
		passed++
	}

	// 2. Debug Mode Check (Critical)
	total++
	if node.DebugMode {
		rule := GetAttestationRule("ATTEST-BOOT-005")
		violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
			fmt.Sprintf("Node '%s' is operating in unsealed debug mode; hypervisor can inspect enclave registers and memory", node.NodeName)))
	} else {
		passed++
	}

	// 3. Memory Encryption Enforcement
	total++
	if !node.MemoryEncryptionEnabled {
		ruleID := "ATTEST-BOOT-001"
		if node.Platform == PlatformIntelTDX {
			ruleID = "ATTEST-BOOT-002"
		}
		rule := GetAttestationRule(ruleID)
		violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
			fmt.Sprintf("Hardware memory encryption is inactive on confidential node '%s' (Platform: %s)", node.NodeName, node.Platform)))
	} else {
		passed++
	}

	// 4. Store Path Signature Integrity
	total++
	if node.StorePathSignature == "" {
		rule := GetAttestationRule("ATTEST-BOOT-006")
		violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
			fmt.Sprintf("Missing cryptographic signature for Nix store closure on node '%s'", node.NodeName)))
	} else if node.ExpectedStorePathSignature != "" && node.StorePathSignature != node.ExpectedStorePathSignature {
		rule := GetAttestationRule("ATTEST-BOOT-006")
		violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
			fmt.Sprintf("Nix store closure signature mismatch on node '%s' (observed: %s, expected: %s)",
				node.NodeName, node.StorePathSignature, node.ExpectedStorePathSignature)))
	} else {
		passed++
	}

	// 5. TCB Version Baseline Check
	if node.MinRequiredTCB != "" && node.TCBVersion != "" {
		total++
		if node.TCBVersion < node.MinRequiredTCB {
			rule := GetAttestationRule("ATTEST-BOOT-011")
			violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
				fmt.Sprintf("Node '%s' TCB version '%s' is below the minimum required baseline '%s'",
					node.NodeName, node.TCBVersion, node.MinRequiredTCB)))
		} else {
			passed++
		}
	}

	// 6. TPM 2.0 PCR Quotation Audits
	if len(node.Quotes) > 0 {
		for _, q := range node.Quotes {
			total++
			if !q.Valid || (q.ExpectedDigest != "" && q.ActualDigest != q.ExpectedDigest) {
				ruleID := "ATTEST-BOOT-003"
				switch q.Index {
				case 7:
					ruleID = "ATTEST-BOOT-003"
				case 8:
					ruleID = "ATTEST-BOOT-010"
				case 9:
					ruleID = "ATTEST-BOOT-012"
				case 11:
					ruleID = "ATTEST-BOOT-004"
				}
				rule := GetAttestationRule(ruleID)
				violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
					fmt.Sprintf("TPM PCR %d measurement mismatch on node '%s' [%s]: observed %s != expected %s",
						q.Index, node.NodeName, q.Description, q.ActualDigest, q.ExpectedDigest)))
			} else {
				passed++
			}
		}
	} else if len(node.PCRs) > 0 {
		// Validate known PCR map presence
		total++
		pcr11, has11 := node.PCRs[11]
		if !has11 || pcr11 == "" || strings.HasPrefix(pcr11, "00000000") {
			rule := GetAttestationRule("ATTEST-BOOT-004")
			violations = append(violations, v.createViolation(rule, node.NodeName, string(node.Platform), sourcePath,
				fmt.Sprintf("TPM PCR 11 (UKI/Nix closure) is empty or unmeasured on node '%s'", node.NodeName)))
		} else {
			passed++
		}
	}

	return violations, total, passed
}

func (v *AttestationVerifier) createViolation(rule AttestationRule, target, tech, sourcePath, message string) AttestationViolation {
	matchedCVE := ""
	if v.feed != nil {
		for _, item := range v.feed.Items {
			if strings.EqualFold(item.Component, "amd-sev") || strings.EqualFold(item.Component, "intel-tdx") || strings.EqualFold(item.Component, "tpm2") {
				matchedCVE = item.ID
				break
			}
		}
	}

	return AttestationViolation{
		RuleID:      rule.ID,
		Title:       rule.Title,
		Severity:    rule.Severity,
		CVSSScore:   rule.CVSSScore,
		Category:    rule.Category,
		Target:      target,
		Technology:  tech,
		FilePath:    sourcePath,
		StartLine:   1,
		Message:     message,
		Remediation: rule.Remediation,
		MatchedCVE:  matchedCVE,
	}
}
