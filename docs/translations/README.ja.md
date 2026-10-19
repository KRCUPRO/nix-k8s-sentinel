<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <strong>🇯🇵 日本語</strong> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**NixOS および Kubernetes のための宣言型脆弱性スキャナー & リアルタイム脅威インテリジェンスレーダー**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ 概要

`nix-k8s-sentinel` は、ベアメタル NixOS クラスターおよび Kubernetes 本番インフラストラクチャ向けに設計された、高性能な宣言型脆弱性スキャナー、自律型脅威修復エンジン、および継続的脅威インテリジェンス同期システムです。

デプロイ後にコンテナレイヤーを受動的にスキャンする従来のツールとは異なり、`nix-k8s-sentinel` はワークロードがスケジュールされる前に基盤となる宣言型インフラ定義を包括的に監査し、リアルタイムで正規化された CVSS 脅威フィードと照合して能動的な事前防御を実現します。

### 🎯 5つの主要防御の柱

1. **ベアメタル & カーネルセキュリティ強化**: Linux カーネルロックダウン、UEFI DBX 失効リスト検証、eBPF LSM 強制アクセス制御（MAC）、ハードウェア高信頼測定ブート。
2. **クラスターネットワーク & サービスメッシュ防御**: eBPF ソケットフロー & シャノンエントロピー DNS 漏洩プロファイラー、デュアルスタック Cilium BGP ピアリング、WireGuard 高速パス、Gateway API ルーティング保護。
3. **暗号化 & コンフィデンシャルコンピューティング**: 耐量子暗号（NSA CNSA 2.0）、SPIFFE/SPIRE ワークロード構成証明、コンフィデンシャル VM（AMD SEV-SNP / Intel TDX）リモート引用、HSM/KMS v2 エンベロープ暗号化。
4. **サプライチェーン & 不変ストレージ**: In-Toto SLSA Level 3 SBOM 来歴検証、Ed25519 Nix ストア署名強制、NixOS ステートレスルート & インパーマネンス揮発性検証。
5. **動的アドミッション & 自律修復**: Fail-Closed アドミッション Webhook、エフェメラル MicroVM デコイ起爆解析、カナリア事前検証に基づく GitOps PR 自動生成。

---

## 🏛️ 主要機能

### 1. 🛡️ カーネルセキュリティ & ホスト強化

- **Linux カーネルロックダウン & UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *監査項目*: カーネルロックダウンモード（`integrity`/`confidentiality`）、未署名モジュール（`module.sig_enforce`）、`/dev/mem` 直接アクセス、Lanzaboote 宣言。
  - *脅威緩和*: 任意の ring-0 侵害（`CVE-2026-92814`）および失効済み UEFI DBX ダイジェスト（`CVE-2023-40547`）の検知と遮断。
  - *ポリシー合成*: 強化型 NixOS ロックダウンモジュール（`nixos-lockdown-hardened.nix`）、自動 DBX 更新サービス、Prometheus アラートルール（`--lockdown`）。
- **eBPF LSM セキュリティモジュール & カーネル強制アクセス制御（MAC）**
  - *監査項目*: ホストカーネル LSM パラメータ（`security.lsm = ["bpf"]`）およびコンテナセキュリティコンテキスト（`bprm_check_security`、`file_open`、`socket_create`）。
  - *脅威緩和*: seccomp を回避する特権コンテナ脱獄（`CVE-2026-99103`）および不正な BPF マップ操作の遮断。
  - *ポリシー合成*: 宣言型 NixOS LSM モジュール、検証可能な eBPF C プログラム、Kubernetes `ContainerMACProfile` CRD（`--lsm`）。
- **動的カーネルランタイム脅威プロファイラー & システムコール BPF フィルター**
  - *監査項目*: 宣言型 seccomp プロファイル、無制限コンテナ、管理者システムコール（`ptrace`、`process_vm_writev`、`kexec_load`）。
  - *脅威緩和*: 秒間 250 を超える異常なソケット生成バーストおよび raw ソケット濫用の検知（`CVE-2026-90412`）。
  - *ポリシー合成*: 最小権限 Kubernetes Seccomp プロファイルおよび systemd サンドボックスモジュール（`--bpf`）。
- **CIS Kubernetes ベンチマーク & ベアメタルプローブ**
  - *監査項目*: コントロールプレーン systemd ユニットフラグ、Kubelet 設定、ワーカーノードのカーネルソケット/システムコール遠隔測定。
  - *ポリシー合成*: NixOS ホスト自動修復パッチおよび複数ノードのリアルタイムプローブ分析（`--cis`、`--probe`）。

### 2. 🌐 クラスターネットワーク & サービスメッシュ防御

- **クラスター規模 eBPF ネットワークフロー & DNS 漏洩プロファイラー (`FLOW-RADAR-001..012`)**
  - *監査項目*: Kubernetes `CiliumNetworkPolicy` マニフェスト、NixOS ホストフロープロファイラー、リアルタイム eBPF ソケット/DNS クエリ遠隔測定。
  - *脅威緩和*: 制限のない外部 53 ポート通信（`CVE-2026-10392`）、高シャノンエントロピー DNS トンネル（$H > 4.2$）、DGA バースト（15回/分超）、ソケット急増（秒間500超）の遮断。
  - *ポリシー合成*: 強化型 `CiliumNetworkPolicy`（FQDN 正規表現による L7 DNS プロキシ）、NixOS プロファイラーモジュール、Prometheus アラート（`--flow`）。
- **デュアルスタック IPv6 & Cilium BGP ピアリングレーダー (`BGP-RADAR-001..012`)**
  - *監査項目*: Cilium BGP ピアリングポリシー、ロードバランサー IP プール、NixOS FRR BGP 構成。
  - *脅威緩和*: TCP MD5 / RFC 2385 認証の欠落（`CVE-2026-70192`）、デフォルトルート漏洩、プレフィックスフラッピングの防止。
  - *ポリシー合成*: 強化型 Cilium BGP マニフェスト、NixOS FRR モジュール、BGP Prometheus アラートルール（`--bgp`）。
- **WireGuard eBPF カーネルファストパス & 暗号化パフォーマンス (`WG-FAST-001..012`)**
  - *監査項目*: ChaCha20-Poly1305 SIMD ベクトル加速（AVX-512、ARM Neon）、ネイティブ eBPF/XDP フック、100GbE オーバーレイ。
  - *脅威緩和*: スカラー暗号フォールバック、softIRQ 枯渇（70%超）、カーネルリングバッファ飽和（`CVE-2026-31049`）の検知。
  - *ポリシー合成*: 強化型 NixOS ファストパスモジュールおよび検証済み eBPF XDP C プログラム（`--wg-fastpath`）。
- **Kubernetes Ingress、Gateway API & EnvoyFilter ルート脅威レーダー**
  - *監査項目*: `Gateway`、`HTTPRoute`、`GRPCRoute`、`ReferenceGrant`、および Istio `EnvoyFilter` 宣言。
  - *脅威緩和*: スニペットインジェクション（`CVE-2023-5044`）、クロスネームスペースルート乗っ取り（`CVE-2026-44219`）、インライン Lua スクリプト注入、パストラバーサルの遮断（`--gw`、`--k8s`）。

### 3. 🔐 暗号化、コンフィデンシャルコンピューティング & ID 管理

- **耐量子暗号（PQC） & NSA CNSA 2.0 移行監査**
  - *監査項目*: コントロールプレーン TLS フラグ、NixOS OpenSSL `oqsprovider` 有効化、GnuTLS 優先度設定。
  - *脅威緩和*: 「今収穫し、後で解読する（HNDL）」量子暗号解読脅威（`CVE-2026-94301`）に対する事前防御。
  - *ポリシー合成*: 耐量子ハイブリッド ML-KEM/Kyber TLS 宣言および CNSA 2.0 準備状況評価（`--pqc`）。
- **コンフィデンシャル VM & セキュアエンクレーブ WireGuard 構成証明 (`WG-ENC-001..012`)**
  - *監査項目*: AMD SEV-SNP VCEK 証明書チェーン、Intel TDX Quote、ランタイム測定ブート PCR ダイジェスト。
  - *脅威緩和*: エフェメラルセッションキーとエンクレーブレポートの暗号学的バインド、未検証ピアトンネルの拒絶（`CVE-2026-40291`）。
  - *ポリシー合成*: 強化型 NixOS エンクレーブモジュールおよびハンドシェイク前カーネル検証ゲートスクリプト（`--wg-enclave`）。
- **ゼロトラストマイクロセグメンテーション & SPIFFE/SPIRE 構成証明**
  - *監査項目*: RFC 準拠 SPIFFE ID、Cilium 必須 mTLS（`authentication.mode: required`）、短寿命 SVID 有効期間。
  - *脅威緩和*: 危険なワイルドカードセレクタ（`k8s:ns:*`）および SVID 更新不一致による切断（`CVE-2026-67210`）の防止（`--spiffe-policy-out`）。
- **ハードウェアセキュリティモジュール（HSM） & PKCS#11 エンベロープ暗号化**
  - *監査項目*: Kubernetes etcd `EncryptionConfiguration`、KMS v2 プラグイン、AWS Nitro Enclaves（`CVE-2026-83190`）（`--hsm`）。
- **マルチクラスターフリート同期 & OIDC トークンレーダー**
  - *監査項目*: マルチテナント RBAC 権限、フェデレーション OIDC 署名アルゴリズム、ArgoCD/Flux GitOps ドリフト検知（`CVE-2026-60114`）（`--fleet`）。

### 4. 📦 宣言型サプライチェーン & 不変ストレージ

- **マルチテナント Nix ストア署名 & バイナリキャッシュ隔離 (`NIX-STORE-001..012`)**
  - *監査項目*: Nix デーモン構成（`nix.settings.*`、`nix.conf`）、Ed25519 署名強制、リアルタイム置換物（Substitute）遠隔測定。
  - *脅威緩和*: 未署名置換物によるキャッシュ汚染（`CVE-2026-81930`）、平文 HTTP、ビルドサンドボックス回避の遮断。
  - *ポリシー合成*: 強化型 NixOS ストアモジュール、`/etc/nix/nix.conf`、Prometheus アラートルール（`--nixstore`）。
- **NixOS 不変ルート & インパーマネンス揮発性ストレージ (`IMP-ROOT-001..012`)**
  - *監査項目*: NixOS インパーマネンス構成（`environment.persistence`）および Kubernetes `hostPath` クラスターマウント。
  - *脅威緩和*: RAM 上の `tmpfs` ルート強制、hostPath 経由のルートエスケープ（`CVE-2026-61842`）、非暗号化スワップの遮断。
  - *ポリシー合成*: 強化型インパーマネンスモジュール、再起動時初期化 initrd フック、空き容量アラートルール（`--impermanence`）。
- **ソフトウェア部品表（SBOM） & In-Toto SLSA Level 3 サプライチェーン構成証明**
  - *監査項目*: SPDX v3.0、CycloneDX v1.6、Nix ストアクロージャと暗号学的 In-Toto 声明書の照合。
  - *脅威緩和*: ビルド成果物の改ざん（`CVE-2026-71044`）および本番環境パッケージのバージョン乖離検知（`--sbom`）。

### 5. 🤖 ワークロードアドミッション、ディザスタリカバリ & 自律修復

- **Kubernetes 動的アドミッション Webhook & CA 更新レーダー (`WH-RADAR-001..012`)**
  - *監査項目*: `ValidatingWebhookConfiguration`、`MutatingWebhookConfiguration`、X.509 CA 証明書有効期限。
  - *脅威緩和*: セキュリティ回避設定 `failurePolicy: Ignore`（`CVE-2026-52194`）、過度なタイムアウト（3秒超）、クラスターデッドロックの防止。
  - *ポリシー合成*: 強化型 ValidatingWebhooks、cert-manager 自動 CA リソース、遅延アラート（`--webhook`）。
- **CephFS スナップショットスケジュール & 地域間ボリューム複製 DR (`CEPH-DR-001..012`)**
  - *監査項目*: CephFS スナップショットスケジュール、CSI ボリューム複製クラス、地域間差分同期状態。
  - *脅威緩和*: RPO を破壊する deletionPolicy `Delete`、スプリットブレイン二重 Primary 競合（`CVE-2026-10140`）の検知。
  - *ポリシー合成*: 強化型 VolumeSnapshotClasses、暗号化転送レプリケーション、ミラーデーモン監視（`--dr`）。
- **エフェメラル MicroVM サンドボックス & デコイ起爆解析**
  - *監査項目*: Firecracker MicroVM 隔離、jailer パラメータ、偽 Kubelet/etcd デコイハニーポット。
  - *脅威緩和*: 未検証コンテナの隔離隔離およびハイパーバイザー MMIO 脱獄（`CVE-2026-97105`）の検出（`--sandbox-synth-out`）。
- **自律型脅威修復 & GitOps プルリクエスト合成エンジン**
  - *動作原理*: 純粋な Nix Flake 評価および `kubectl kustomize` dry-run による事前カナリア安全性検証（`pkg/remediate/canary.go`）。
  - *出力成果物*: 非破壊的原子的 PR（`remediation/*`）、Kustomize 戦略的マージパッチ、RFC 6902 JSONPatches（`CVE-2026-98402`）（`--remediate`）。

---

## 🚀 クイックスタート

### 前提条件
- Go 1.22 以上がローカルにインストールされていること。

### ビルドおよび実行
```bash
# リポジトリのクローン
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# テストスイートの実行
go test ./...

# リアルタイム脅威フィードの検査
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# NixOS flake.lock に対する既知のセキュリティ勧告照合監査
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Kubernetes マニフェストの Ingress および CNI 違反監査
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Kubernetes CiliumNetworkPolicy および NixOS eBPF フロープロファイラー監査
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# 実行時 eBPF ソケットフロー調整および強化ポリシー自動合成
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Linux カーネルロックダウンおよび UEFI Secure Boot DBX 構成監査
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# マルチテナント Nix ストアおよびバイナリキャッシュ隔離設定監査
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# NixOS インパーマネンス構成およびホストパスストレージ監査
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Kubernetes アドミッション Webhook 監査 (ValidatingWebhookConfiguration)
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# コンフィデンシャル VM WireGuard 構成証明マニフェスト監査 (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# WireGuard eBPF ファストパスおよび暗号化スループット監査
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Cilium BGP ピアリングポリシーおよび NixOS FRR BGP 監査
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# ベアメタル eBPF カーネル遠隔測定複数ノードリアルタイム分析
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# GitHub Code Scanning 連携用 OASIS SARIF v2.1.0 出力
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# 構造化された高精度 JSON セキュリティ監査レポート出力
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# 1時間ごとの脅威インテリジェンスブリーフィング自動生成
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ ロードマップおよび開発計画

開発ロードマップおよび今後のリリース計画については、[ROADMAP.md](../../ROADMAP.md) をご参照ください。

---

## 🔒 セキュリティポリシー

脆弱性の報告手順およびセキュリティ設計の詳細については、[SECURITY.md](../../SECURITY.md) をご確認ください。
