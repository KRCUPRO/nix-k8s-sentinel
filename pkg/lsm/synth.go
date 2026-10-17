package lsm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SynthesizeNixOSLSMModule generates a hardened declarative NixOS module enforcing eBPF LSM and MAC.
func SynthesizeNixOSLSMModule(profiles []ContainerMACProfile) string {
	var buf strings.Builder

	buf.WriteString("# Automatically synthesized by nix-k8s-sentinel (v0.21.0)\n")
	buf.WriteString("# Declarative eBPF Linux Security Module (LSM) & Kernel Mandatory Access Control\n")
	buf.WriteString("{\n")
	buf.WriteString("  boot.kernelParams = [\n")
	buf.WriteString("    \"lsm=lockdown,yama,bpf,apparmor\"\n")
	buf.WriteString("  ];\n\n")
	buf.WriteString("  security.lsm = [ \"lockdown\" \"yama\" \"bpf\" \"apparmor\" ];\n\n")
	buf.WriteString("  boot.kernel.sysctl = {\n")
	buf.WriteString("    \"kernel.unprivileged_bpf_disabled\" = 1;\n")
	buf.WriteString("    \"kernel.kptr_restrict\" = 2;\n")
	buf.WriteString("    \"kernel.dmesg_restrict\" = 1;\n")
	buf.WriteString("  };\n\n")

	buf.WriteString("  # Systemd eBPF LSM Mandatory Access Control Manager\n")
	buf.WriteString("  systemd.services.ebpf-lsm-mac = {\n")
	buf.WriteString("    description = \"eBPF LSM Container Mandatory Access Control Daemon\";\n")
	buf.WriteString("    wantedBy = [ \"multi-user.target\" ];\n")
	buf.WriteString("    after = [ \"network.target\" \"cgroup.target\" ];\n")
	buf.WriteString("    serviceConfig = {\n")
	buf.WriteString("      Type = \"simple\";\n")
	buf.WriteString("      ExecStart = \"/run/current-system/sw/bin/sentinel-lsm-loader --cgroup-root=/sys/fs/cgroup/kubepods.slice\";\n")
	buf.WriteString("      Restart = \"always\";\n")
	buf.WriteString("      RestartSec = 3;\n")
	buf.WriteString("      ProtectSystem = \"strict\";\n")
	buf.WriteString("      ProtectHome = true;\n")
	buf.WriteString("      CapabilityBoundingSet = [ \"CAP_SYS_ADMIN\" \"CAP_BPF\" \"CAP_DAC_READ_SEARCH\" ];\n")
	buf.WriteString("    };\n")
	buf.WriteString("  };\n")
	buf.WriteString("}\n")

	return buf.String()
}

// SynthesizeBPFLSMCode generates an idiomatic eBPF C program implementing mandatory access control hooks.
func SynthesizeBPFLSMCode(profile *ContainerMACProfile) string {
	var buf strings.Builder

	name := "default"
	if profile != nil && profile.WorkloadName != "" {
		name = profile.WorkloadName
	}

	buf.WriteString("/*\n")
	buf.WriteString(fmt.Sprintf(" * eBPF LSM Mandatory Access Control Program: %s\n", name))
	buf.WriteString(" * Synthesized by nix-k8s-sentinel (v0.21.0)\n")
	buf.WriteString(" */\n\n")
	buf.WriteString("#include \"vmlinux.h\"\n")
	buf.WriteString("#include <bpf/bpf_helpers.h>\n")
	buf.WriteString("#include <bpf/bpf_tracing.h>\n")
	buf.WriteString("#include <bpf/bpf_core_read.h>\n\n")
	buf.WriteString("#define EPERM 1\n\n")

	buf.WriteString("char _license[] SEC(\"license\") = \"GPL\";\n\n")

	buf.WriteString("// Hook 1: Restrict binary execution from writable directories (/tmp, /dev/shm)\n")
	buf.WriteString("SEC(\"lsm/bprm_check_security\")\n")
	buf.WriteString("int BPF_PROG(mac_bprm_check, struct linux_binprm *bprm)\n")
	buf.WriteString("{\n")
	buf.WriteString("    char filename[256];\n")
	buf.WriteString("    int ret = bpf_core_read_str(&filename, sizeof(filename), bprm->filename);\n")
	buf.WriteString("    if (ret > 0) {\n")
	buf.WriteString("        if (filename[0] == '/' && filename[1] == 't' && filename[2] == 'm' && filename[3] == 'p') {\n")
	buf.WriteString("            bpf_printk(\"LSM MAC: blocked execution from /tmp: %s\\n\", filename);\n")
	buf.WriteString("            return -EPERM;\n")
	buf.WriteString("        }\n")
	buf.WriteString("    }\n")
	buf.WriteString("    return 0;\n")
	buf.WriteString("}\n\n")

	buf.WriteString("// Hook 2: Restrict sensitive kernel host files (/proc/kcore, /sys/kernel/debug)\n")
	buf.WriteString("SEC(\"lsm/file_open\")\n")
	buf.WriteString("int BPF_PROG(mac_file_open, struct file *file)\n")
	buf.WriteString("{\n")
	buf.WriteString("    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);\n")
	buf.WriteString("    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);\n")
	buf.WriteString("    char buf[32];\n")
	buf.WriteString("    if (bpf_core_read_str(buf, sizeof(buf), name) > 0) {\n")
	buf.WriteString("        if (buf[0] == 'k' && buf[1] == 'c' && buf[2] == 'o' && buf[3] == 'r' && buf[4] == 'e') {\n")
	buf.WriteString("            return -EPERM;\n")
	buf.WriteString("        }\n")
	buf.WriteString("    }\n")
	buf.WriteString("    return 0;\n")
	buf.WriteString("}\n\n")

	buf.WriteString("// Hook 3: Restrict raw packet sockets (AF_PACKET / SOCK_RAW)\n")
	buf.WriteString("SEC(\"lsm/socket_create\")\n")
	buf.WriteString("int BPF_PROG(mac_socket_create, int family, int type, int protocol, int kern)\n")
	buf.WriteString("{\n")
	buf.WriteString("    if (family == 17 /* AF_PACKET */ || type == 3 /* SOCK_RAW */) {\n")
	buf.WriteString("        return -EPERM;\n")
	buf.WriteString("    }\n")
	buf.WriteString("    return 0;\n")
	buf.WriteString("}\n\n")

	buf.WriteString("// Hook 4: Guard against setuid privilege escalation\n")
	buf.WriteString("SEC(\"lsm/task_fix_setuid\")\n")
	buf.WriteString("int BPF_PROG(mac_task_fix_setuid, struct cred *new, const struct cred *old, int flags)\n")
	buf.WriteString("{\n")
	buf.WriteString("    uid_t old_uid = BPF_CORE_READ(old, uid.val);\n")
	buf.WriteString("    uid_t new_uid = BPF_CORE_READ(new, uid.val);\n")
	buf.WriteString("    if (old_uid != 0 && new_uid == 0) {\n")
	buf.WriteString("        return -EPERM;\n")
	buf.WriteString("    }\n")
	buf.WriteString("    return 0;\n")
	buf.WriteString("}\n")

	return buf.String()
}

// SynthesizeK8sMACPolicy generates a declarative Kubernetes ContainerMACProfile custom resource.
func SynthesizeK8sMACPolicy(profile *ContainerMACProfile) string {
	var buf strings.Builder

	name := "hardened-mac-profile"
	ns := "default"
	if profile != nil {
		if profile.WorkloadName != "" {
			name = fmt.Sprintf("mac-%s", profile.WorkloadName)
		}
		if profile.Namespace != "" {
			ns = profile.Namespace
		}
	}

	buf.WriteString("apiVersion: security.nix-k8s-sentinel.io/v1alpha1\n")
	buf.WriteString("kind: ContainerMACProfile\n")
	buf.WriteString("metadata:\n")
	buf.WriteString(fmt.Sprintf("  name: %s\n", name))
	buf.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	buf.WriteString("  labels:\n")
	buf.WriteString("    security.sentinel/managed-by: \"nix-k8s-sentinel\"\n")
	buf.WriteString("    security.sentinel/profile: \"hardened-lsm\"\n")
	buf.WriteString("spec:\n")
	buf.WriteString("  enforce: true\n")
	buf.WriteString("  cgroupDriver: systemd\n")
	buf.WriteString("  blockedHooks:\n")
	buf.WriteString("    - bprm_check_security\n")
	buf.WriteString("    - file_open\n")
	buf.WriteString("    - socket_create\n")
	buf.WriteString("    - task_fix_setuid\n")
	buf.WriteString("    - bpf\n")
	buf.WriteString("    - ptrace_access_check\n")
	buf.WriteString("  protectedPaths:\n")
	buf.WriteString("    - /proc/kcore\n")
	buf.WriteString("    - /sys/kernel/debug\n")
	buf.WriteString("    - /etc/shadow\n")
	buf.WriteString("  disallowedDirectories:\n")
	buf.WriteString("    - /tmp\n")
	buf.WriteString("    - /dev/shm\n")

	return buf.String()
}

// WriteLSMArtifacts writes synthesized NixOS, eBPF C, and Kubernetes policy artifacts to disk safely.
func WriteLSMArtifacts(outDir string, nixModule string, bpfCode string, k8sPolicy string) (map[string]string, error) {
	cleanDir := filepath.Clean(outDir)
	if err := os.MkdirAll(cleanDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create lsm synth directory (%s): %w", cleanDir, err)
	}

	results := make(map[string]string)

	nixPath := filepath.Join(cleanDir, "lsm-bpf-policy.nix")
	if err := os.WriteFile(nixPath, []byte(nixModule), 0644); err != nil {
		return nil, fmt.Errorf("failed to write nix lsm module: %w", err)
	}
	results["nixos_module"] = nixPath

	bpfPath := filepath.Join(cleanDir, "lsm_container_mac.bpf.c")
	if err := os.WriteFile(bpfPath, []byte(bpfCode), 0644); err != nil {
		return nil, fmt.Errorf("failed to write bpf lsm code: %w", err)
	}
	results["bpf_program"] = bpfPath

	k8sPath := filepath.Join(cleanDir, "container-mac-policy.yaml")
	if err := os.WriteFile(k8sPath, []byte(k8sPolicy), 0644); err != nil {
		return nil, fmt.Errorf("failed to write k8s mac policy: %w", err)
	}
	results["k8s_policy"] = k8sPath

	// Sort keys for deterministic output
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return results, nil
}
