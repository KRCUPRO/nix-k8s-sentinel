<div align="center">

<p align="center">
  <a href="./README.md">🇺🇸 English</a> ·
  <strong>🇰🇷 한국어</strong> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**NixOS 및 Kubernetes를 위한 선언적 취약점 스캐너 & 실시간 위협 인텔리전스 레이더**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.2.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ 개요

`nix-k8s-sentinel`은 베어메탈 NixOS 클러스터 및 Kubernetes 인프라에 최적화된 고성능 선언적 취약점 스캐너이자 지속적 위협 인텔리전스 동기화 엔진입니다.

배포 후 컨테이너 레이어를 수동적으로 검사하는 기존 런타임 스캐너와 달리, `nix-k8s-sentinel`은 선언적 구성 명세(NixOS Flakes, Kubernetes CNI 정책, Ingress 컨트롤러)를 실시간 정규화된 CVSS 위협 피드와 대조하여 워크로드가 스케줄링되기 전에 사전 대응할 수 있도록 지원합니다.

---

## 🏛️ 핵심 역량

- **🔍 선언적 인프라 감사**: NixOS Flake 입력 락 및 Kubernetes 매니페스트 명세에 대한 패턴 매칭 및 의존성 추적.
- **📡 정규화된 위협 인텔리전스 수집**: CVSS v3.1 스코어링, 컴포넌트 매핑, 실행 가능한 보안 권고안의 구조화된 수집.
- **🛡️ 능동적 보안 정책 합성**: 탐지된 위협 시그니처로부터 Falco 런타임 감지 룰 및 OPA Gatekeeper 제약 조건 정책 자동 생성.
- **⚡ 제로 알로케이션 Go 엔진**: 외부 런타임 의존성 없는 고동시성 단일 바이너리.

---

## 🚀 빠른 시작

### 사전 요구 사항
- Go 1.22 이상 설치.

### 빌드 및 실행
```bash
# 저장소 복제
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# 테스트 스위트 실행
go test ./...

# 실시간 위협 피드 조회
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# NixOS flake.lock 보안 권고안 대조 감사
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# 대상 인프라별 필터링
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ 로드맵 및 개발 계획

향후 예정된 Flake 입력 파서 개선 및 eBPF 베어메탈 프로브 개발 일정은 [ROADMAP.md](./ROADMAP.md)를 참고해 주십시오.

---

## 🔒 보안 정책

취약점 제보 절차 및 보안 관련 세부 원칙은 [SECURITY.md](./SECURITY.md)를 확인해 주시기 바랍니다.
