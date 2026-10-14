<div align="center">

<p align="center">
  <a href="./README.md">🇺🇸 English</a> ·
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

**NixOS および Kubernetes のための宣言型脆弱性スキャナー & 脅威インテリジェンスレーダー**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.7.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ 概要

`nix-k8s-sentinel` は、ベアメタル NixOS クラスターおよび Kubernetes インフラストラクチャに特化して設計された、高性能な宣言型脆弱性スキャナーおよび継続的脅威インテリジェンス同期エンジンです。

デプロイ後に一時的なコンテナレイヤーを検査する従来のスキャナーとは異なり、`nix-k8s-sentinel` は宣言型構成定義（NixOS Flakes、Kubernetes CNI ポリシー、Ingress コントローラー）をリアルタイムの正規化された CVSS 脅威インテリジェンスフィードと照合し、ワークロードがスケジュールされる前に対策を実行できるようにします。

---

## 🏛️ 主要機能

- **🔍 宣言型インフラストラクチャ監査**: NixOS Flake 入力ロックおよび Kubernetes マニフェスト仕様のパターンマッチングと依存関係追跡。
- **🌐 Kubernetes Ingress & CNI セキュリティ検査**: スニペットインジェクション、URIパス走査、CORS/SSL設定不備、および0.0.0.0/0無制限送信・デフォルト拒否隔離の自動監査。
- **📊 1時間ごとの脅威インテリジェンスブリーフィング自動生成**: CVSSリスクテレメトリマトリックスと対策プレイブックを含むMarkdownレポートを `intel/briefings/` に自動出力。
- **📡 正規化された脅威インテリジェンスの収集**: CVSS v3.1 スコアリング、コンポーネントマッピング、実用的な修復アドバイザリの構造化収集。
- **🛡️ アクティブポリシー合成**: 検出された脅威シグネチャからの Falco ランタイム検知ルールおよび OPA Gatekeeper 制約ポリシーの自動生成。
- **⚡ ゼロアロケーション Go エンジン**: 外部ランタイム依存関係のない、高並行単一バイナリ。

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

# リアルタイム脅威フィードの確認
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# NixOS flake.lock を既知のセキュリティアドバイザリと照合監査
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Kubernetes マニフェストのセキュリティ監査
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml
go run cmd/sentinel/main.go --k8s=fixtures/

# 脅威インテリジェンスブリーフィングの自動生成
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# 対象インフラストラクチャによるフィルタリング
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ ロードマップと開発計画

今後の Flake 入力パーサー拡張や eBPF ベアメタルプローブのロードマップについては、[ROADMAP.md](./ROADMAP.md) をご参照ください。

---

## 🔒 セキュリティポリシー

脆弱性の報告手順および開示ガイドラインについては、[SECURITY.md](./SECURITY.md) をご確認ください。
