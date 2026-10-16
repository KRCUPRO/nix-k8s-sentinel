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
[![Version](https://img.shields.io/badge/Release-v0.19.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ 개요

`nix-k8s-sentinel`은 베어메탈 NixOS 클러스터 및 Kubernetes 인프라에 최적화된 고성능 선언적 취약점 스캐너이자 지속적 위협 인텔리전스 동기화 엔진입니다.

배포 후 컨테이너 레이어를 수동적으로 검사하는 기존 런타임 스캐너와 달리, `nix-k8s-sentinel`은 선언적 구성 명세(NixOS Flakes, Kubernetes CNI 정책, Ingress 컨트롤러, Gateway API, Rook Ceph, WireGuard, CIS 벤치마크, 기밀 컴퓨팅, 멀티 클러스터 GitOps 플릿, SPIFFE/SPIRE 제로 트러스트 마이크로세그멘테이션, 소프트웨어 자재명세서 및 In-Toto SLSA Level 3 공급망 증명, 하드웨어 보안 모듈 봉투 암호화, 동적 커널 위협 프로파일링, 시스템 콜 BPF 필터, 양자 내성 암호(PQC) 및 NSA CNSA 2.0 TLS 감사 엔진, 에페메럴 마이크로VM 샌드박스 및 허니팟 디토네이션 디스패치)를 실시간 정규화된 CVSS 위협 피드와 대조하여 워크로드가 스케줄링되기 전에 사전 대응할 수 있도록 지원합니다.

---

## 🏛️ 핵심 역량

- **🔍 선언적 인프라 감사**: NixOS Flake 입력 락, Kubernetes 매니페스트 명세, CNI 네트워크 정책에 대한 패턴 매칭 및 의존성 추적.
- **🔬 에페메럴 마이크로VM 샌드박스 & 허니팟 디토네이션 디스패치 엔진**: 클러스터 배포 전 미검증 컨테이너 이미지, OCI 아티팩트 및 바이너리를 격리 분석하기 위해 NixOS 및 Kubernetes 상에서 에페메럴 Firecracker 마이크로VM을 동적 오케스트레이션하는 클라우드 네이티브 보안 엔진. NixOS microvm 모듈(`microvm.vms.<name>`), 하이퍼바이저 설정, jailer chroot 격리 매개변수 및 Kubernetes `DetonationJob` CRD 매니페스트 스트리밍 파싱. 런타임 실행 텔레메트리, 커널 프로브 및 디코이 허니팟 유인체 접촉(가짜 Kubelet 포트 10250, 가짜 etcd 포트 2379/2380, 카나리 토큰) 분석, 컨테이너 격리 쿼런틴(Quarantine) 제어, 게스트 내 리버스 쉘 비커닝, 권한 상승 시스템 콜, virtio MMIO 하이퍼바이저 탈출 이상 징후, 안티 샌드박스 지연 회피 탐지 및 강화된 마이크로VM 모듈/허니팟 유인체 선언적 합성(`--sandbox-synth-out`, CVE-2026-97105).
- **⚛️ 양자 내성 암호(PQC) & NSA CNSA 2.0 TLS 감사 엔진**: Kubernetes 컨트롤 플레인 컴포넌트(kube-apiserver, etcd, kubelet)와 NixOS 호스트 암호화 구성을 위한 엔터프라이즈 PQC 보안 감사 엔진. TLS 1.3 미만 취약 프로토콜, 하이브리드 포스트 퀀텀 키 캡슐화(NIST FIPS 203 ML-KEM-768/1024) 누락으로 인한 수확 후 복호화(Harvest-Now-Decrypt-Later) 위협(CVE-2026-94301), 취약 고전 암호(CBC/3DES/정적 RSA), 256비트 미만 대칭키, 고전 전용 인증서 서명 차단. NixOS OpenSSL `oqsprovider` 활성화 및 GnuTLS 우선순위 정책 감사, NSA CNSA 2.0 전환 일정(2025/2030/2033) 추적 및 양자 내성 강화 모듈 선언적 합성(`--pqc-synth-out`).
- **🛡️ 동적 커널 런타임 위협 프로파일러 & 시스템 콜 BPF 필터**: Kubernetes 클러스터 전반에서 선언적 seccomp 프로필, NixOS 호스트 커널 매개변수 및 런타임 eBPF 텔레메트리를 분석하는 심층 커널 보안 감사 엔진. 무격리 컨테이너 seccomp 프로필(`type: Unconfined`), 위험 관리자 시스템 콜(`ptrace`, `process_vm_writev`, `kexec_load`), NixOS 호스트 eBPF LSM 모듈 누락(`security.lsm = [ ... "bpf" ... ]`), 호스트 네임스페이스 공유(`hostPID`/`hostIPC`), 비인가 BPF 접근 차단. 런타임 소켓 생성 버스트(초당 250개 초과), raw 소켓 할당(`SOCK_RAW`, `AF_PACKET`) 탐지 및 강화된 Kubernetes Seccomp 프로필, 드롭인 NixOS systemd 샌드박싱 모듈, 선언적 eBPF LSM 정책 매니페스트 자동 합성(CVE-2026-90412).
- **🔐 하드웨어 보안 모듈(HSM) & PKCS#11 봉투 암호화 파이프라인**: Kubernetes etcd 저장 데이터 암호화, KMS v2 플러그인, PKCS#11 토큰 및 AWS Nitro Enclaves를 위한 엔터프라이즈급 암호화 보안 감사 엔진. `apiserver.config.k8s.io/v1` EncryptionConfiguration 매니페스트, RFC 7512 PKCS#11 URI 및 NixOS 호스트 모듈(`services.p11-kit`, `hardware.nitro-enclaves`) 스트리밍 파싱. 런타임 KMS 플러그인 상태 점검, 90일 초과 미회전 마스터 키(KEK) 탐지, 매니페스트 내 평문 PIN 노출 차단 및 Nitro Enclave 세션 누수/비봉인 증명 공격 방어(CVE-2026-83190).
- **📦 소프트웨어 자재명세서(SBOM) & In-Toto 공급망 증명**: SPDX v3.0, SPDX v2.3, CycloneDX v1.6, Nix 스토어 클로저 통합 수집. In-Toto 성명서(`_type: https://in-toto.io/Statement/v1`) 암호학적 서명 검증, 빌드 산출물 SHA256 다이제스트 변조 감지(CVE-2026-71044), SLSA Level 3 밀폐(Hermetic) 샌드박스 및 불변 의존성 강제, 선언적 SBOM과 런타임 클러스터 패키지 간 버전 드리프트 및 미인가 섀도우 바이너리 주입 자동 조정(`--sbom`, `--attestation`, `--sbom-runtime`).
- **🔒 제로 트러스트 마이크로세그멘테이션 & SPIFFE/SPIRE 워크로드 증명**: SPIFFE/SPIRE 워크로드 아이덴티티 및 Cilium eBPF 네트워크 마이크로세그멘테이션을 위한 네이티브 보안 감사 엔진. 신뢰 도메인 허용 목록 기반 RFC 규격 SPIFFE ID 검증, Cilium mTLS 강제 모드(`authentication.mode: required`) 검증, 취약 암호화 키(RSA-1024/2048) 탐지, 위험 와일드카드 셀렉터(`k8s:ns:*`) 차단, 만료 임박(< 15분) SVID 불일치로 인한 워크로드 단절 방지(CVE-2026-67210) 및 제로 트러스트 `CiliumNetworkPolicy` 자동 합성(`--spiffe-policy-out`).
- **🛰️ 멀티 클러스터 플릿 동기화 & OIDC 토큰 레이더**: 지리적으로 분산된 다중 Kubernetes 클러스터 전반의 RBAC 와일드카드(`*`), `bind`/`escalate` 권한 상승, `system:authenticated` 광범위 바인딩 및 비인가 시크릿 접근 차단. 취약한 OIDC 알고리즘(`none`, `HS256`) 및 24시간 초과 토큰 탐지. ArgoCD/Flux GitOps 선언의 자동 자가 치유(`selfHeal`, `prune`), 부동 브랜치, 와일드카드 대상 클러스터 감사 및 실시간 동기화 드리프트 포렌식 탐지(CVE-2026-60114).
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

# SPIFFE/SPIRE 워크로드 등록 매니페스트 및 Cilium 마이크로세그멘테이션 감사
go run cmd/sentinel/main.go --spiffe=fixtures/spiffe-manifests.yaml

# 런타임 SVID 텔레메트리 조정 및 경량화된 CiliumNetworkPolicy 자동 합성
go run cmd/sentinel/main.go --spiffe=fixtures/spiffe-manifests.yaml --svid-telemetry=fixtures/spiffe-telemetry.json --spiffe-policy-out=policies/generated/cilium-spiffe-policies.yaml --format=sarif --output=spiffe-results.sarif

# Kubernetes EncryptionConfiguration 및 NixOS 하드웨어 보안 모듈(HSM) 감사
go run cmd/sentinel/main.go --hsm=fixtures/k8s-encryption-config.yaml
go run cmd/sentinel/main.go --hsm=fixtures/nixos-hsm.nix

# 런타임 HSM, PKCS#11 및 KMS v2 플러그인 텔레메트리 실시간 조정 및 SARIF 출력
go run cmd/sentinel/main.go --hsm=fixtures/k8s-encryption-config.yaml --hsm-telemetry=fixtures/hsm-telemetry.json --format=sarif --output=hsm-results.sarif

# Kubernetes 컨트롤 플레인 및 NixOS OpenSSL/GnuTLS 양자 내성 암호(PQC) 감사
go run cmd/sentinel/main.go --pqc=fixtures/k8s-pqc-vulnerable.yaml
go run cmd/sentinel/main.go --pqc=fixtures/nixos-pqc.nix

# 런타임 TLS 악수 텔레메트리 조정 및 NSA CNSA 2.0 규격 준수 평가
go run cmd/sentinel/main.go --pqc=fixtures/k8s-pqc-vulnerable.yaml --pqc-telemetry=fixtures/pqc-telemetry.json --format=sarif --output=pqc-results.sarif

# 강화된 NixOS 및 Kubernetes PQC 구성 정책 자동 합성
go run cmd/sentinel/main.go --pqc-synth-out=policies/generated/pqc

# NixOS 마이크로VM 선언 명세 및 Kubernetes DetonationJob 매니페스트 감사
go run cmd/sentinel/main.go --sandbox=fixtures/nixos-microvm-vulnerable.nix
go run cmd/sentinel/main.go --sandbox=fixtures/k8s-detonation-job.yaml

# 런타임 마이크로VM 디토네이션 텔레메트리, 허니팟 유인체 접촉 및 쿼런틴 상태 조정
go run cmd/sentinel/main.go --sandbox=fixtures/nixos-microvm-vulnerable.nix --sandbox-telemetry=fixtures/sandbox-telemetry.json --format=sarif --output=sandbox-results.sarif

# 강화된 NixOS 마이크로VM, DetonationJob 및 허니팟 유인체 자동 합성
go run cmd/sentinel/main.go --sandbox-synth-out=policies/generated/sandbox

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
