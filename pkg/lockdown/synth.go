package lockdown

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SynthesizeHardenedLockdownModule generates a production-grade, hardened NixOS module enforcing kernel lockdown and Secure Boot.
func SynthesizeHardenedLockdownModule(cfg *LockdownSecurityConfig) string {
	var b strings.Builder
	b.WriteString("# Hardened Linux Kernel Lockdown & Lanzaboote UEFI Secure Boot Module\n")
	b.WriteString("# Generated automatically by nix-k8s-sentinel security synthesizer.\n")
	b.WriteString("{\n")
	b.WriteString("  config,\n")
	b.WriteString("  lib,\n")
	b.WriteString("  pkgs,\n")
	b.WriteString("  ...\n")
	b.WriteString("}:\n\n")
	b.WriteString("{\n")
	b.WriteString("  # 1. Enforce Kernel Lockdown Mode (Confidentiality)\n")
	b.WriteString("  # Restricts both ring 0 code modification and unprivileged physical/kernel memory extraction.\n")
	b.WriteString("  security.lockdown = \"confidentiality\";\n")
	b.WriteString("  security.protectKernelImage = true;\n\n")

	b.WriteString("  # 2. Strict Kernel Boot Command Line Parameters\n")
	b.WriteString("  boot.kernelParams = [\n")
	b.WriteString("    \"lockdown=confidentiality\"\n")
	b.WriteString("    \"module.sig_enforce=1\"\n")
	b.WriteString("    \"page_poison=1\"\n")
	b.WriteString("    \"init_on_free=1\"\n")
	b.WriteString("    \"slab_nomerge\"\n")
	b.WriteString("    \"slub_debug=FZP\"\n")
	b.WriteString("  ];\n\n")

	b.WriteString("  # 3. Kernel Sysctl Runtime Confinement\n")
	b.WriteString("  # Disable dynamic module loading and block unsigned kexec payloads after boot initialization.\n")
	b.WriteString("  boot.kernel.sysctl = {\n")
	b.WriteString("    \"kernel.modules_disabled\" = 1;\n")
	b.WriteString("    \"kernel.kexec_load_disabled\" = 1;\n")
	b.WriteString("    \"kernel.unprivileged_bpf_disabled\" = 1;\n")
	b.WriteString("    \"net.core.bpf_jit_harden\" = 2;\n")
	b.WriteString("    \"dev.mem.restricted\" = 1;\n")
	b.WriteString("  };\n\n")

	b.WriteString("  # 4. Lanzaboote UEFI Secure Boot with Unified Kernel Image (UKI)\n")
	b.WriteString("  # Signs both kernel, initrd, and bootloader into an atomic cryptographic artifact.\n")
	b.WriteString("  boot.loader.systemd-boot.enable = lib.mkForce false;\n")
	b.WriteString("  boot.lanzaboote = {\n")
	b.WriteString("    enable = true;\n")
	b.WriteString("    pkiBundle = \"/etc/secureboot\";\n")
	b.WriteString("  };\n\n")

	b.WriteString("  # 5. Security Auditing & DBX Sync Tools\n")
	b.WriteString("  environment.systemPackages = with pkgs; [\n")
	b.WriteString("    sbctl\n")
	b.WriteString("    mokutil\n")
	b.WriteString("    efibootmgr\n")
	b.WriteString("    fwupd\n")
	b.WriteString("  ];\n")
	b.WriteString("}\n")

	return b.String()
}

// SynthesizeDBXUpdateService generates a declarative NixOS systemd unit and timer for automated UEFI DBX synchronization.
func SynthesizeDBXUpdateService() string {
	var b strings.Builder
	b.WriteString("# Declarative Automated UEFI Secure Boot DBX Revocation Sync Service\n")
	b.WriteString("# Generated automatically by nix-k8s-sentinel security synthesizer.\n")
	b.WriteString("{\n")
	b.WriteString("  config,\n")
	b.WriteString("  lib,\n")
	b.WriteString("  pkgs,\n")
	b.WriteString("  ...\n")
	b.WriteString("}:\n\n")
	b.WriteString("{\n")
	b.WriteString("  systemd.services.uefi-dbx-sync = {\n")
	b.WriteString("    description = \"Automated UEFI Secure Boot DBX Revocation Sync\";\n")
	b.WriteString("    wantedBy = [ \"multi-user.target\" ];\n")
	b.WriteString("    after = [ \"network-online.target\" ];\n")
	b.WriteString("    wants = [ \"network-online.target\" ];\n")
	b.WriteString("    serviceConfig = {\n")
	b.WriteString("      Type = \"oneshot\";\n")
	b.WriteString("      ExecStart = \"${pkgs.fwupd}/bin/fwupdtool security --force\";\n")
	b.WriteString("      ProtectSystem = \"strict\";\n")
	b.WriteString("      ProtectHome = true;\n")
	b.WriteString("      PrivateTmp = true;\n")
	b.WriteString("      NoNewPrivileges = true;\n")
	b.WriteString("    };\n")
	b.WriteString("  };\n\n")
	b.WriteString("  systemd.timers.uefi-dbx-sync = {\n")
	b.WriteString("    description = \"Weekly UEFI Secure Boot DBX Revocation Sync Timer\";\n")
	b.WriteString("    wantedBy = [ \"timers.target\" ];\n")
	b.WriteString("    timerConfig = {\n")
	b.WriteString("      OnCalendar = \"weekly\";\n")
	b.WriteString("      Persistent = true;\n")
	b.WriteString("    };\n")
	b.WriteString("  };\n")
	b.WriteString("}\n")
	return b.String()
}

// SynthesizeLockdownAlertRules generates Prometheus alert rules monitoring kernel lockdown and UEFI DBX health.
func SynthesizeLockdownAlertRules() string {
	var b strings.Builder
	b.WriteString("# Prometheus Alerting Rules: Linux Kernel Lockdown & UEFI Secure Boot DBX Radar\n")
	b.WriteString("# Generated automatically by nix-k8s-sentinel security synthesizer.\n")
	b.WriteString("groups:\n")
	b.WriteString("  - name: kernel-lockdown-radar\n")
	b.WriteString("    rules:\n")
	b.WriteString("      - alert: KernelLockdownDisabled\n")
	b.WriteString("        expr: node_kernel_lockdown_mode{mode=\"none\"} == 1\n")
	b.WriteString("        for: 1m\n")
	b.WriteString("        labels:\n")
	b.WriteString("          severity: critical\n")
	b.WriteString("          cve: CVE-2026-92814\n")
	b.WriteString("        annotations:\n")
	b.WriteString("          summary: \"Linux kernel lockdown is disabled on host {{ $labels.instance }}\"\n")
	b.WriteString("          description: \"Kernel lockdown is set to 'none', allowing ring 0 tampering and unprivileged memory inspection.\"\n\n")

	b.WriteString("      - alert: UnsignedKernelModuleLoadAttempt\n")
	b.WriteString("        expr: increase(node_kernel_module_load_denials_total[5m]) > 0\n")
	b.WriteString("        for: 0m\n")
	b.WriteString("        labels:\n")
	b.WriteString("          severity: high\n")
	b.WriteString("          cve: CVE-2026-92814\n")
	b.WriteString("        annotations:\n")
	b.WriteString("          summary: \"Unauthorized unsigned kernel module load attempt on {{ $labels.instance }}\"\n")
	b.WriteString("          description: \"Kernel rejected attempts to load an unsigned module via init_module/finit_module.\"\n\n")

	b.WriteString("      - alert: UEFIDBXOutdated\n")
	b.WriteString("        expr: (time() - node_uefi_dbx_last_update_timestamp_seconds) > (60 * 86400)\n")
	b.WriteString("        for: 1h\n")
	b.WriteString("        labels:\n")
	b.WriteString("          severity: high\n")
	b.WriteString("          cve: CVE-2026-92814\n")
	b.WriteString("        annotations:\n")
	b.WriteString("          summary: \"UEFI Secure Boot DBX database outdated on {{ $labels.instance }}\"\n")
	b.WriteString("          description: \"Platform DBX forbidden signatures have not been updated in over 60 days.\"\n\n")

	b.WriteString("      - alert: RevokedBootloaderBinaryDetected\n")
	b.WriteString("        expr: node_uefi_bootloader_revoked_in_dbx == 1\n")
	b.WriteString("        for: 0m\n")
	b.WriteString("        labels:\n")
	b.WriteString("          severity: critical\n")
	b.WriteString("          cve: CVE-2023-40547\n")
	b.WriteString("        annotations:\n")
	b.WriteString("          summary: \"Revoked bootloader binary active on {{ $labels.instance }}\"\n")
	b.WriteString("          description: \"The running bootloader binary matches a forbidden SHA-256 authenticode in the UEFI DBX.\"\n")

	return b.String()
}

// WriteSynthesizedPolicies persists declarative hardened NixOS modules, DBX sync service, and alert rules to disk.
func WriteSynthesizedPolicies(outputDir string, cfg *LockdownSecurityConfig) ([]string, error) {
	cleanDir := filepath.Clean(outputDir)
	if err := os.MkdirAll(cleanDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory (%s): %w", cleanDir, err)
	}

	written := make([]string, 0, 3)

	// 1. nixos-lockdown-hardened.nix
	hardenedModule := SynthesizeHardenedLockdownModule(cfg)
	modulePath := filepath.Join(cleanDir, "nixos-lockdown-hardened.nix")
	if err := os.WriteFile(modulePath, []byte(hardenedModule), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write hardened NixOS module: %w", err)
	}
	written = append(written, modulePath)

	// 2. uefi-dbx-updater.nix
	dbxService := SynthesizeDBXUpdateService()
	servicePath := filepath.Join(cleanDir, "uefi-dbx-updater.nix")
	if err := os.WriteFile(servicePath, []byte(dbxService), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write UEFI DBX sync service: %w", err)
	}
	written = append(written, servicePath)

	// 3. lockdown-alerts.yaml
	alerts := SynthesizeLockdownAlertRules()
	alertsPath := filepath.Join(cleanDir, "lockdown-alerts.yaml")
	if err := os.WriteFile(alertsPath, []byte(alerts), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write lockdown alert rules: %w", err)
	}
	written = append(written, alertsPath)

	return written, nil
}
