<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <strong>🇨🇳 简体中文</strong> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**面向 NixOS 与 Kubernetes 的声明式漏洞扫描器与实时威胁情报雷达**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ 概述

`nix-k8s-sentinel` 是一款专为裸金属 NixOS 集群与 Kubernetes 生产级基础设施打造的高性能声明式漏洞扫描器、自主威胁修复引擎及持续威胁情报同步系统。

与传统的在部署后被动检查临时容器镜像层的扫描工具不同，`nix-k8s-sentinel` 在工作负载被调度之前对底层的声明式定义进行静态与动态审计，并与实时标准化的 CVSS 威胁情报数据源进行深度关联，从而实现主动的主机级与集群级先验防御。

### 🎯 五大核心防御支柱

1. **裸金属与内核安全加固**: Linux 内核锁定（Lockdown）模式、UEFI DBX 吊销列表验证、eBPF LSM 强制访问控制（MAC）及硬件信任根可信度量引导。
2. **集群网络与服务网格防御**: eBPF 套接字流与香农熵 DNS 数据外发检测、双栈 Cilium BGP 对等互联、WireGuard 内核快速路径及 Gateway API 路由安全。
3. **密码学、机密计算与身份**: 后量子密码学（NSA CNSA 2.0）、SPIFFE/SPIRE 身份凭证、机密虚拟机（AMD SEV-SNP / Intel TDX）远程证明及 HSM/KMS v2 信封加密。
4. **供应链与不可变存储**: In-Toto SLSA Level 3 SBOM 真实性审计、Ed25519 Nix 存储签名强制及 NixOS 无状态不可变根（Impermanence）验证。
5. **动态准入与自主修复**: 故障闭环（Fail-Closed）准入 Webhook 审计、临时 MicroVM 蜜罐诱饵起爆检测及基于金丝雀预验证的 GitOps PR 自动合成。

---

## 🏛️ 核心能力

### 1. 🛡️ 内核安全与主机加固

- **Linux 内核锁定 (Lockdown) 与 UEFI 安全引导 DBX (`LOCKDOWN-001..012`)**
  - *审计范畴*: 内核锁定模式（`integrity`/`confidentiality`）、未签名内核模块（`module.sig_enforce`）、`/dev/mem` 物理内存访问及 Lanzaboote 声明。
  - *威胁缓解*: 拦截任意 ring-0 提权破坏（`CVE-2026-92814`）并检测匹配 UEFI DBX 已吊销哈希的引导加载程序（`CVE-2023-40547`）。
  - *策略合成*: 自动生成加固版 NixOS 锁定模块（`nixos-lockdown-hardened.nix`）、systemd 自动 DBX 更新服务及 Prometheus 告警规则（`--lockdown`）。
- **eBPF LSM 安全模块与内核强制访问控制 (MAC)**
  - *审计范畴*: 宿主机内核 LSM 参数（`security.lsm = ["bpf"]`）及容器安全上下文（`bprm_check_security`、`file_open`、`socket_create`）。
  - *威胁缓解*: 阻断绕过 seccomp 的特权容器逃逸（`CVE-2026-99103`）及非法的 BPF Map 操作。
  - *策略合成*: 声明式 NixOS LSM 策略、可验证的 eBPF C 语言程序及 Kubernetes `ContainerMACProfile` CRD（`--lsm`）。
- **动态内核运行时威胁分析器与系统调用 BPF 过滤器**
  - *审计范畴*: 声明式 seccomp 配置、无限制容器及高危管理类系统调用（`ptrace`、`process_vm_writev`、`kexec_load`）。
  - *威胁缓解*: 检测超速套接字风暴（> 250 个/秒）与 raw 套接字滥用（关联 `CVE-2026-90412`）。
  - *策略合成*: 最小权限 Kubernetes Seccomp 配置及 systemd 沙箱隔离增强配置（`--bpf`）。
- **CIS Kubernetes 基准与裸金属探针**
  - *审计范畴*: 控制平面 systemd 单元参数、Kubelet 标记及跨工作节点的内核套接字/系统调用遥测。
  - *策略合成*: NixOS 宿主机自动化修复补丁及多节点实时探针遥测分析（`--cis`、`--probe`）。

### 2. 🌐 集群网络与服务网格防御

- **全集群 eBPF 网络流与 DNS 数据外发分析器 (`FLOW-RADAR-001..012`)**
  - *审计范畴*: Kubernetes `CiliumNetworkPolicy` 清单、NixOS 主机流分析器及实时 eBPF 套接字连接 / DNS 查询遥测。
  - *威胁缓解*: 拦截未受限的 53 端口外部通信（`CVE-2026-10392`）、高香农熵 DNS 隧道（$H > 4.2$）、DGA 突发查询及套接字突增（> 500 次/秒）。
  - *策略合成*: 自动生成防御加固版 `CiliumNetworkPolicy`（带 FQDN 正则的 L7 DNS 代理）、NixOS 分析器模块及 Prometheus 告警（`--flow`）。
- **双栈 IPv6 与 Cilium BGP 路由对等雷达 (`BGP-RADAR-001..012`)**
  - *审计范畴*: Cilium BGP 对等策略、负载均衡 IP 池及 NixOS FRR BGP 主机配置。
  - *威胁缓解*: 捕获缺失的 TCP MD5 / RFC 2385 认证（`CVE-2026-70192`）、默认路由越权外泄及前缀震荡。
  - *策略合成*: 加固版 Cilium BGP 清单、NixOS FRR 模块及 BGP Prometheus 告警规则（`--bgp`）。
- **WireGuard eBPF 内核快速路径与加密性能 (`WG-FAST-001..012`)**
  - *审计范畴*: ChaCha20-Poly1305 SIMD 向量加速（AVX-512、ARM Neon）、原生 eBPF/XDP 挂载及 100GbE 覆盖网络。
  - *威胁缓解*: 检测标量软件回退、softIRQ 严重耗尽（> 70%）及环形缓冲区饱和（`CVE-2026-31049`）。
  - *策略合成*: 加固版 NixOS 快速路径模块及验证通过的 eBPF XDP C 语言流量控制程序（`--wg-fastpath`）。
- **Kubernetes Ingress、Gateway API 与 EnvoyFilter 路由威胁雷达**
  - *审计范畴*: `Gateway`、`HTTPRoute`、`GRPCRoute`、`ReferenceGrant` 及 Istio `EnvoyFilter` 声明。
  - *威胁缓解*: 防御 Snippet 注入（`CVE-2023-5044`）、跨命名空间路由劫持（`CVE-2026-44219`）、内联 Lua 脚本执行及路径穿越（`--gw`、`--k8s`）。

### 3. 🔐 密码学、机密计算与身份管理

- **后量子密码学 (PQC) 与 NSA CNSA 2.0 迁移审计**
  - *审计范畴*: 控制平面 TLS 标志、NixOS OpenSSL `oqsprovider` 激活及 GnuTLS 优先级策略。
  - *威胁缓解*: 全面抵御“先窃取后解密”（HNDL）量子计算破解风险（`CVE-2026-94301`）。
  - *策略合成*: 量子混合 ML-KEM/Kyber TLS 策略与 CNSA 2.0 阶段合规评估（`--pqc`）。
- **机密虚拟机与安全飞地 WireGuard 远程证明 (`WG-ENC-001..012`)**
  - *审计范畴*: AMD SEV-SNP VCEK 证书链、Intel TDX Quote 报告及度量引导 PCR 摘要。
  - *威胁缓解*: 将临时会话密钥与飞地报告深度绑定，直接拒绝未受信任或被篡改的通道（`CVE-2026-40291`）。
  - *策略合成*: 加固版 NixOS 飞地模块及握手前内核门禁校验脚本（`--wg-enclave`）。
- **零信任微隔离与 SPIFFE/SPIRE 工作负载身份证明**
  - *审计范畴*: RFC 标准 SPIFFE ID、Cilium 强制 mTLS 模式及短期 SVID 轮换窗口。
  - *威胁缓解*: 清除危险的通配符选择器（`k8s:ns:*`）并阻断证书不同步造成的通信中断（`CVE-2026-67210`）（`--spiffe-policy-out`）。
- **硬件安全模块 (HSM) 与 PKCS#11 信封加密**
  - *审计范畴*: Kubernetes etcd `EncryptionConfiguration`、KMS v2 插件及 AWS Nitro Enclaves（`CVE-2026-83190`）（`--hsm`）。
- **多集群舰队同步与 OIDC 令牌雷达**
  - *审计范畴*: 多租户 RBAC 权限越权、联合 OIDC 签名算法及 ArgoCD/Flux GitOps 状态漂移检测（`CVE-2026-60114`）（`--fleet`）。

### 4. 📦 声明式供应链与不可变存储

- **多租户 Nix 存储签名与二进制缓存隔离 (`NIX-STORE-001..012`)**
  - *审计范畴*: Nix 守护进程配置（`nix.settings.*`、`nix.conf`）、Ed25519 签名强制及实时替代物（Substitute）遥测。
  - *威胁缓解*: 拦截未签名替代物缓存投毒（`CVE-2026-81930`）、明文 HTTP 替代物及沙箱逃逸绕过。
  - *策略合成*: 加固版 NixOS 存储配置、`/etc/nix/nix.conf` 及 Prometheus 告警规则（`--nixstore`）。
- **NixOS 不可变根与持久化存储挥发性验证 (`IMP-ROOT-001..012`)**
  - *审计范畴*: NixOS Impermanence 配置（`environment.persistence`）及 Kubernetes `hostPath` 集群挂载。
  - *威胁缓解*: 强制基于内存的 `tmpfs` 根文件系统，拦截突破到临时存储的 hostPath 挂载（`CVE-2026-61842`）及未加密 Swap。
  - *策略合成*: 加固版持久化模块、重启自动清空 initrd 挂钩及存储余量监控（`--impermanence`）。
- **软件物料清单 (SBOM) 与 In-Toto SLSA Level 3 供应链证明**
  - *审计范畴*: SPDX v3.0、CycloneDX v1.6、Nix 闭包及 In-Toto 密码学证明校验。
  - *威胁缓解*: 及时发现制品篡改（`CVE-2026-71044`）及清单与集群运行时之间的依赖漂移（`--sbom`）。

### 5. 🤖 工作负载准入、灾难恢复与自主修复

- **Kubernetes 动态准入 Webhook 与 CA 轮换雷达 (`WH-RADAR-001..012`)**
  - *审计范畴*: `ValidatingWebhookConfiguration`、`MutatingWebhookConfiguration` 及 X.509 CA 证书有效期限。
  - *威胁缓解*: 阻断不安全的 `failurePolicy: Ignore` 旁路绕过（`CVE-2026-52194`）、超长超时（> 3秒）及集群启动死锁。
  - *策略合成*: 加固版 ValidatingWebhooks、cert-manager 自动证书资源及延迟告警（`--webhook`）。
- **CephFS 快照调度与跨区域卷复制灾备 (`CEPH-DR-001..012`)**
  - *审计范畴*: CephFS 快照排期、CSI 卷复制类及跨地域增量同步状态。
  - *威胁缓解*: 消除破坏恢复目标的 deletionPolicy `Delete` 及跨区域脑裂双主冲突（`CVE-2026-10140`）。
  - *策略合成*: 加固版 VolumeSnapshotClasses、加密同步链路及镜像守护进程高可用配置（`--dr`）。
- **临时 MicroVM 沙箱与蜜罐诱饵起爆分发**
  - *审计范畴*: Firecracker MicroVM 容器沙箱、jailer 限制参数及虚拟 Kubelet/etcd 诱饵。
  - *威胁缓解*: 隔离未经审计的恶意镜像并检测虚拟化 MMIO 逃逸行为（`CVE-2026-97105`）（`--sandbox-synth-out`）。
- **自主威胁修复与 GitOps PR 自动合成**
  - *工作机制*: 基于纯净 Nix Flake 估算与 `kubectl kustomize` dry-run 的安全金丝雀预验证（`pkg/remediate/canary.go`）。
  - *生成成果*: 100% 非破坏性原子级 PR（`remediation/*`）、Kustomize 合并补丁及 RFC 6902 JSONPatch（`CVE-2026-98402`）（`--remediate`）。

---

## 🚀 快速上手

### 环境准备
- 本地安装 Go 1.22+。

### 构建与运行
```bash
# 克隆仓库
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# 运行测试套件
go test ./...

# 实时威胁情报源检查
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# 对比已知漏洞库审计 NixOS flake.lock
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# 审计 Kubernetes 清单中的 Ingress 与 CNI 策略漏洞
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# 审计 Kubernetes CiliumNetworkPolicy 与 NixOS eBPF 流分析器
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# 调和运行时 eBPF 网络流遥测并自动合成安全策略
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# 审计 Linux 内核锁定与 Lanzaboote UEFI 安全引导 DBX 配置
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# 审计多租户 Nix 存储与二进制缓存隔离设置
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# 审计 NixOS 不可变持久化配置与集群 hostPath 挂载
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# 审计 Kubernetes 准入控制器配置 (ValidatingWebhookConfiguration)
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# 审计机密虚拟机 WireGuard 对等节点证明清单 (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# 审计 WireGuard eBPF 内核快速路径与加密吞吐量
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# 审计 Cilium BGP 对等策略与 NixOS FRR BGP 声明
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# 运行跨节点裸金属 eBPF 内核遥测审计
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# 导出 OASIS SARIF v2.1.0 报告对接 GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# 导出结构化高精 JSON 安全遥测审计报告
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# 自动生成每小时威胁情报摘要简报
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ 路线图与演进规划

详细的工程演进路线与后续里程碑计划，请参考 [ROADMAP.md](../../ROADMAP.md)。

---

## 🔒 安全策略

有关漏洞披露程序及安全设计原则，请参阅 [SECURITY.md](../../SECURITY.md)。
