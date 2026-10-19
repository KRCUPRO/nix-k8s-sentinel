package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/lockdown"
)

func TestLockdownSARIFExport(t *testing.T) {
	violations := []lockdown.LockdownViolation{
		{
			RuleID:      "LOCKDOWN-001",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.4,
			Title:       "Kernel Lockdown Mode Disabled",
			Description: "Linux kernel lockdown is disabled, permitting ring 0 modifications.",
			Remediation: "Set security.lockdown = \"confidentiality\" in NixOS configuration.",
			FilePath:    "configuration.nix",
			StartLine:   10,
			EndLine:     10,
			MatchedCVE:  "CVE-2026-92814",
		},
		{
			RuleID:      "LOCKDOWN-006",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.8,
			Title:       "Active Bootloader / Shim Binary Hash Revoked in DBX",
			Description: "Running bootloader matches forbidden SHA-256 in UEFI DBX.",
			Remediation: "Upgrade EFI bootloader and rebuild UKI.",
			FilePath:    "/boot/EFI/BOOT/shimx64.efi",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  "CVE-2023-40547",
		},
	}

	opts := ReportOptions{
		Version:            "0.29.0",
		LockdownViolations: violations,
		LockdownPath:       "configuration.nix",
	}

	sarifLog, err := BuildSARIFReport(opts)
	if err != nil {
		t.Fatalf("BuildSARIFReport failed: %v", err)
	}

	if len(sarifLog.Runs) == 0 {
		t.Fatalf("expected at least 1 run in SARIF log")
	}

	results := sarifLog.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(results))
	}

	ruleIDs := []string{results[0].RuleID, results[1].RuleID}
	found001 := false
	found006 := false
	for _, id := range ruleIDs {
		if id == "LOCKDOWN-001" {
			found001 = true
		}
		if id == "LOCKDOWN-006" {
			found006 = true
		}
	}
	if !found001 || !found006 {
		t.Errorf("expected both LOCKDOWN-001 and LOCKDOWN-006 in SARIF results, got %v", ruleIDs)
	}

	sarifBytes, err := FormatSARIF(sarifLog, true)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "CVE-2026-92814") {
		t.Errorf("SARIF export missing MatchedCVE CVE-2026-92814")
	}
}

func TestLockdownJSONExport(t *testing.T) {
	violations := []lockdown.LockdownViolation{
		{
			RuleID:      "LOCKDOWN-003",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.1,
			Title:       "Unsigned Kernel Module Loading Permitted",
			Description: "Arbitrary unsigned modules can execute in ring 0.",
			Remediation: "Set module.sig_enforce=1 and kernel.modules_disabled=1.",
			FilePath:    "configuration.nix",
			StartLine:   15,
			EndLine:     15,
		},
	}

	summary := &lockdown.LockdownSummary{
		TotalScanned:    1,
		ViolationCount:  1,
		CriticalCount:   1,
		ComplianceScore: 75.0,
	}

	telemetry := &lockdown.LockdownTelemetryReport{
		HostName:                 "worker-node-1",
		CollectedAt:              time.Now().UTC(),
		LiveLockdownMode:         lockdown.LockdownModeConfidentiality,
		ModuleSignatureEnforced:  true,
		SecureBootStatus:         lockdown.SecureBootEnabled,
		DBXVersion:               "2026-10",
		DBXTotalRevocations:      320,
		ActiveBootloaderRevoked:  false,
		UnsignedModuleLoadDenials: 0,
	}

	opts := ReportOptions{
		Version:            "0.29.0",
		LockdownViolations: violations,
		LockdownSummary:    summary,
		LockdownTelemetry:  telemetry,
		LockdownPath:       "configuration.nix",
	}

	jsonReport, err := BuildJSONReport(opts)
	if err != nil {
		t.Fatalf("BuildJSONReport failed: %v", err)
	}

	if jsonReport.ToolVersion != "0.29.0" {
		t.Errorf("expected tool version 0.29.0, got %s", jsonReport.ToolVersion)
	}
	if len(jsonReport.LockdownViolations) != 1 {
		t.Errorf("expected 1 lockdown violation, got %d", len(jsonReport.LockdownViolations))
	}
	if jsonReport.LockdownSummary.ComplianceScore != 75.0 {
		t.Errorf("expected compliance score 75.0, got %f", jsonReport.LockdownSummary.ComplianceScore)
	}
	if jsonReport.LockdownTelemetry.HostName != "worker-node-1" {
		t.Errorf("expected host worker-node-1, got %s", jsonReport.LockdownTelemetry.HostName)
	}

	jsonBytes, err := json.Marshal(jsonReport)
	if err != nil {
		t.Fatalf("failed to marshal JSON report: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "LOCKDOWN-003") {
		t.Errorf("JSON report missing LOCKDOWN-003 rule")
	}
}

func TestLockdownBriefingExport(t *testing.T) {
	violations := []lockdown.LockdownViolation{
		{
			RuleID:      "LOCKDOWN-004",
			Severity:    intel.SeverityCritical,
			CVSSScore:   9.3,
			Title:       "UEFI Secure Boot Disabled or in Insecure Setup Mode",
			Description: "Secure Boot is turned off in host firmware.",
			Remediation: "Enable Secure Boot in platform firmware.",
			FilePath:    "sysfs:/sys/firmware/efi/efivars/SecureBoot",
			StartLine:   1,
			EndLine:     1,
			MatchedCVE:  "CVE-2026-92814",
		},
	}

	summary := &lockdown.LockdownSummary{
		TotalScanned:    1,
		ViolationCount:  1,
		CriticalCount:   1,
		ComplianceScore: 75.0,
	}

	telemetry := &lockdown.LockdownTelemetryReport{
		HostName:                 "nixos-worker-01",
		CollectedAt:              time.Now().UTC(),
		LiveLockdownMode:         lockdown.LockdownModeNone,
		SecureBootStatus:         lockdown.SecureBootDisabled,
		SetupModeActive:          true,
		DBXVersion:               "2024-05",
		DBXAgeDays:               120,
		DBXTotalRevocations:      45,
		ActiveBootloaderRevoked:  false,
		UnsignedModuleLoadDenials: 3,
	}

	opts := BriefingOptions{
		Title:              "Test Lockdown Threat Briefing",
		Version:            "0.29.0",
		HourlyWindow:       time.Now().UTC(),
		LockdownViolations: violations,
		LockdownSummary:    summary,
		LockdownTelemetry:  telemetry,
	}

	briefing, err := GenerateBriefing(opts)
	if err != nil {
		t.Fatalf("GenerateBriefing failed: %v", err)
	}

	if !strings.Contains(briefing.Content, "## 🔒 Linux Kernel Lockdown & UEFI Secure Boot DBX Radar") {
		t.Errorf("briefing missing section 28 header")
	}
	if !strings.Contains(briefing.Content, "LOCKDOWN-004") {
		t.Errorf("briefing missing LOCKDOWN-004 violation")
	}
	if !strings.Contains(briefing.Content, "nixos-worker-01") {
		t.Errorf("briefing missing host name in telemetry table")
	}
	if !strings.Contains(briefing.Content, "Configure boot.kernelParams with lockdown=confidentiality") {
		t.Errorf("briefing missing updated SecOps checklist item")
	}
}
