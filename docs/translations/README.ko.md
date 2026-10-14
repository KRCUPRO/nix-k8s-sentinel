<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
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

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.7.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ 개요

`nix-k8s-sentinel`은 베어메탈 NixOS 클러스터 및 Kubernetes 인프라에 최적화된 고성능 선언적 취약점 스캐너이자 지속적 위협 인텔리전스 동기화 엔진입니다.

배포 후 컨테이너 레이어를 수동적으로 검사하는 기존 런타임 스캐너와 달리, `nix-k8s-sentinel`은 선언적 구성 명세(NixOS Flakes, Kubernetes CNI 정책, Ingress 컨트롤러)를 실시간 정규화된 CVSS 위협 피드와 대조하여 워크로드가 스케줄링되기 전에 사전 대응할 수 있도록 지원합니다.

---

## 🏛️ 핵심 역량

- **🔍 선언적 인프라 감사**: NixOS Flake 입력 락, Kubernetes 매니페스트 명세, CNI 네트워크 정책에 대한 패턴 매칭 및 의존성 추적.
- **🌐 Kubernetes Ingress 보안 검증**: 커스텀 스니펫 인젝션(CVE-2023-5044 / CVE-2026-21801), URI rewrite 캡처 그룹 불일치, 경로 탐색(`../`), 평문 HTTP 비인가 허용, 와일드카드 CORS 자격증명 노출 자동 탐지.
- **🔌 CNI 네트워크 정책 검증**: 표준 Kubernetes NetworkPolicy, Calico GlobalNetworkPolicy, CiliumNetworkPolicy 전수 감사. 기본 거부(Default-Deny) 제로 트러스트 격리, 0.0.0.0/0 무제한 외부 송신 데이터 유출, 민감 인프라 포트(etcd, kubelet) 노출, L7 와일드카드 우회 차단.
- **🔬 베어메탈 eBPF 텔레메트리 프로브**: 다중 노드 베어메탈 클러스터 전반에서 커널 수준 소켓(`connect`), 시스템 콜(`execve`, `ptrace`, `bpf`), 스토리지 무결성 감시 및 이상 징후 자동 탐지.
- **📊 시간별 위협 인텔리전스 브리핑 자동 생성**: `intel/briefings/`에 실시간 CVSS 위험 텔레메트리 매트릭스와 상세 권고안 마크다운 리포트를 자동 합성하여 감사 추적 및 SecOps 대시보드 제공.
- **📡 정규화된 위협 인텔리전스 수집**: CVSS v3.1 스코어링, 컴포넌트 매핑, 실행 가능한 보안 권고안의 구조화된 수집.
- **🛡️ 능동적 보안 정책 합성**: 탐지된 위협 시그니처로부터 Falco 런타임 감지 룰 및 OPA Gatekeeper 제약 조건 정책 자동 생성.
- **📑 SARIF v2.1.0 및 JSON 보안 감사 보고서**: GitHub Security Code Scanning 완벽 연동을 위한 OASIS SARIF v2.1.0 규격 네이티브 출력 및 엔터프라이즈 CI/CD 파이프라인용 구조화 JSON 텔레메트리 내보내기 지원.
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

# Kubernetes 매니페스트 파일 및 디렉토리 보안 감사
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml
go run cmd/sentinel/main.go --k8s=fixtures/

# 베어메탈 eBPF 커널 텔레메트리 다중 노드 실시간 분석 실행
go run cmd/sentinel/main.go --probe
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif
go run cmd/sentinel/main.go --probe --format=json

# GitHub Code Scanning 연동용 OASIS SARIF v2.1.0 리포트 내보내기
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# 구조화된 고정밀 JSON 보안 텔레메트리 리포트 내보내기
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# 시간별 위협 인텔리전스 브리핑 마크다운 자동 생성
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# Falco 런타임 탐지 룰 및 OPA Gatekeeper 어드미션 제약 자동 합성
go run cmd/sentinel/main.go --policy-out=policies/generated
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml --policy-out=policies/generated --enforce-action=deny

# 대상 인프라별 필터링
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ 로드맵 및 개발 계획

향후 예정된 Flake 입력 파서 개선 및 eBPF 베어메탈 프로브 개발 일정은 [ROADMAP.md](../../ROADMAP.md)를 참고해 주십시오.

---

## 🔒 보안 정책

취약점 제보 절차 및 보안 관련 세부 원칙은 [SECURITY.md](../../SECURITY.md)를 확인해 주시기 바랍니다.
