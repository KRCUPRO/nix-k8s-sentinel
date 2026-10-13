<div align="center">

<p align="center">
  <a href="./README.md">🇺🇸 English</a> ·
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

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.3.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ 概述

`nix-k8s-sentinel` 是一款专为裸金属 NixOS 集群和 Kubernetes 基础设施设计的高性能声明式漏洞扫描与持续威胁情报同步引擎。

与传统的在部署后检查临时容器镜像层的扫描器不同，`nix-k8s-sentinel` 对底层声明式配置矩阵（NixOS Flakes、Kubernetes CNI 网络策略及 Ingress 控制器）进行静态与动态审计，并与实时标准化的 CVSS 威胁情报数据源进行比对，从而在工作负载被调度之前实现主动防御。

---

## 🏛️ 核心能力

- **🔍 声明式基础设施审计**: 对 NixOS Flake 输入锁与 Kubernetes 清单规范进行模式匹配与依赖追踪。
- **📡 标准化威胁情报摄取**: 结构化解析 CVSS v3.1 评分、组件映射及切实可行的修复建议。
- **🛡️ 主动防御策略合成**: 根据检测到的威胁特征自动生成 Falco 运行时检测规则与 OPA Gatekeeper 准入控制策略。
- **⚡ 零分配 Go 引擎**: 高并发单二进制文件，零外部运行时依赖。

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

# 查看实时威胁情报源
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# 审计 NixOS flake.lock 依赖中的已知安全漏洞


go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# 按目标基础设施过滤
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ 路线图与演进规划

关于后续 Flake 输入解析器演进及 eBPF 裸金属探针规划，请参阅 [ROADMAP.md](./ROADMAP.md)。

---

## 🔒 安全策略

有关漏洞披露流程及安全守则，请查阅 [SECURITY.md](./SECURITY.md)。
