## 🛡️ Autonomous Security Remediation Pull Request

**Target Base:** `main` | **Head Branch:** `remediation/hardening-1792202705`

### Summary of Declarative Patches:

#### NixOS System Patches (3)

| Target Module | Option Path | Mitigated CVE | Description |
| :--- | :--- | :---: | :--- |
| `nixos-vulnerable.nix` | `networking.wireguard.interfaces.wg0.privateKeyFile` | `CVE-2026-31048` | Synthesize NixOS configuration patch migrating privateKey strings to privateKeyFile paths under /run/secrets/wireguard/key. |
| `nixos-vulnerable.nix` | `services.ceph.requireMsgr2` | `CVE-2026-15509` | Synthesize declarative CephCluster patch activating requireMsgr2: true and setting bluestore_default_buffered_write throttling. |
| `nixos-vulnerable.nix` | `microvm.vms.detonation.jailer.enable` | `CVE-2026-97105` | Synthesize hardened NixOS microvm module enforcing unprivileged jailer UID/GID, read-only rootfs, and egress TAP redirection. |

#### Kubernetes Kustomize Overlays (3)

| Target Resource | Patch Type | Mitigated CVE | Description |
| :--- | :---: | :---: | :--- |
| `default/deployment/workload` | `strategic-merge` | `CVE-2026-20914` | Synthesize Kustomize strategic merge patch enforcing runAsNonRoot: true, readOnlyRootFilesystem: true, and drop: ['ALL'] capabilities. |
| `default/ingress/ingress-route` | `json6902` | `CVE-2026-21801` | Synthesize Kustomize JSONPatch stripping raw configuration-snippet annotations and enforcing strict URI regex normalization. |
| `default/deployment/bpf-workload` | `strategic-merge` | `CVE-2026-90412` | Synthesize Kustomize patch enforcing seccompProfile.type: RuntimeDefault and dropping CAP_NET_RAW capabilities. |

