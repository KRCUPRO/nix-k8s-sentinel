/*
 * eBPF LSM Mandatory Access Control Program: vulnerable-privileged-daemon
 * Synthesized by nix-k8s-sentinel (v0.21.0)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

char _license[] SEC("license") = "GPL";

// Hook 1: Restrict binary execution from writable directories (/tmp, /dev/shm)
SEC("lsm/bprm_check_security")
int BPF_PROG(mac_bprm_check, struct linux_binprm *bprm)
{
    char filename[256];
    int ret = bpf_core_read_str(&filename, sizeof(filename), bprm->filename);
    if (ret > 0) {
        if (filename[0] == '/' && filename[1] == 't' && filename[2] == 'm' && filename[3] == 'p') {
            bpf_printk("LSM MAC: blocked execution from /tmp: %s\n", filename);
            return -EPERM;
        }
    }
    return 0;
}

// Hook 2: Restrict sensitive kernel host files (/proc/kcore, /sys/kernel/debug)
SEC("lsm/file_open")
int BPF_PROG(mac_file_open, struct file *file)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    char buf[32];
    if (bpf_core_read_str(buf, sizeof(buf), name) > 0) {
        if (buf[0] == 'k' && buf[1] == 'c' && buf[2] == 'o' && buf[3] == 'r' && buf[4] == 'e') {
            return -EPERM;
        }
    }
    return 0;
}

// Hook 3: Restrict raw packet sockets (AF_PACKET / SOCK_RAW)
SEC("lsm/socket_create")
int BPF_PROG(mac_socket_create, int family, int type, int protocol, int kern)
{
    if (family == 17 /* AF_PACKET */ || type == 3 /* SOCK_RAW */) {
        return -EPERM;
    }
    return 0;
}

// Hook 4: Guard against setuid privilege escalation
SEC("lsm/task_fix_setuid")
int BPF_PROG(mac_task_fix_setuid, struct cred *new, const struct cred *old, int flags)
{
    uid_t old_uid = BPF_CORE_READ(old, uid.val);
    uid_t new_uid = BPF_CORE_READ(new, uid.val);
    if (old_uid != 0 && new_uid == 0) {
        return -EPERM;
    }
    return 0;
}
