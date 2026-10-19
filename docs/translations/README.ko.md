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
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ 개요

`nix-k8s-sentinel`은 베어메탈 NixOS 클러스터 및 Kubernetes 프로덕션 인프라에 최적화된 고성능 선언적 취약점 스캐너이자 자율 위협 해결 엔진, 지속적 위협 인텔리전스 동기화 시스템입니다.

배포 후 컨테이너 레이어를 수동적으로 검사하는 기존 런타임 스캐너와 달리, `nix-k8s-sentinel`은 워크로드가 스케줄링되기 전에 선언적 인프라 정의를 전수 감사하고 실시간 정규화된 CVSS 위협 피드와 대조하여 능동적 선제 방어를 수행합니다.

### 🎯 5대 핵심 방어 기둥

1. **베어메탈 & 커널 보안 강화**: 리눅스 커널 록다운 모드, UEFI DBX 폐기 목록 검증, eBPF LSM 강제적 접근 제어(MAC), 하드웨어 신뢰점 측정 부트.
2. **클러스터 네트워킹 & 서비스 메시 방어**: eBPF 소켓 플로우 & 섀넌 엔트로피 기반 DNS 유출 감시, 듀얼스택 Cilium BGP 피어링, WireGuard 커널 패스트패스, Gateway API 라우팅 보안.
3. **암호화 & 기밀 컴퓨팅**: 양자 내성 암호(NSA CNSA 2.0), SPIFFE/SPIRE 워크로드 증명, 기밀 VM(AMD SEV-SNP / Intel TDX) 원격 증명, HSM/KMS v2 봉투 암호화.
4. **공급망 보안 & 불변 스토리지**: In-Toto SLSA Level 3 SBOM 증명 검증, Ed25519 Nix 스토어 전자서명 강제, NixOS 불변 루트 & 임퍼머넌스 휘발성 검증.
5. **동적 어드미션 & 자율 패치 합성**: Fail-Closed 어드미션 웹훅 감사, 에페메럴 MicroVM 허니팟 디토네이션, 카나리 사전 검증 기반 GitOps PR 자동 합성.

---

## 🏛️ 핵심 역량

### 1. 🛡️ 커널 보안 & 호스트 강화

- **리눅스 커널 록다운(Lockdown) & UEFI 시큐어 부트 DBX (`LOCKDOWN-001..012`)**
  - *감사 대상*: 커널 록다운 모드(`integrity`/`confidentiality`), 미서명 커널 모듈 적재(`module.sig_enforce`), `/dev/mem` 메모리 직접 접근, Lanzaboote 선언.
  - *위협 완화*: 임의 ring-0 장악(`CVE-2026-92814`) 차단 및 폐기된 UEFI DBX 해시 일치 부트로더(`CVE-2023-40547`) 탐지.
  - *정책 합성*: 강화된 NixOS 록다운 모듈(`nixos-lockdown-hardened.nix`), systemd 자동 DBX 업데이트 서비스, Prometheus 경보 룰(`--lockdown`).
- **eBPF LSM 보안 모듈 & 커널 강제적 접근 제어(MAC)**
  - *감사 대상*: 호스트 커널 LSM 매개변수(`security.lsm = ["bpf"]`) 및 컨테이너 보안 컨텍스트(`bprm_check_security`, `file_open`, `socket_create`).
  - *위협 완화*: seccomp를 우회하는 특권 컨테이너 탈출(`CVE-2026-99103`) 및 비인가 BPF 맵 조작 차단.
  - *정책 합성*: 선언적 NixOS LSM 모듈, 검증 가능한 eBPF C 프로그램, Kubernetes `ContainerMACProfile` CRD(`--lsm`).
- **동적 커널 런타임 위협 프로파일러 & 시스템 콜 BPF 필터**
  - *감사 대상*: 선언적 seccomp 프로필, 무격리 컨테이너, 관리자 시스템 콜(`ptrace`, `process_vm_writev`, `kexec_load`).
  - *위협 완화*: 초당 250개 초과 비정상 소켓 폭주 및 raw 소켓 생성 탐지(`CVE-2026-90412`).
  - *정책 합성*: 최소 권한 Kubernetes Seccomp 프로필 및 systemd 샌드박싱 모듈(`--bpf`).
- **CIS Kubernetes 벤치마크 & 베어메탈 프로브**
  - *감사 대상*: 컨트롤 플레인 systemd 유닛 플래그, Kubelet 설정, 워커 노드 커널 소켓/시스템 콜 텔레메트리.
  - *정책 합성*: NixOS 호스트 자동 조치 패치 및 다중 노드 실시간 프로브 분석(`--cis`, `--probe`).

### 2. 🌐 클러스터 네트워킹 & 서비스 메시 방어

- **클러스터 eBPF 네트워크 플로우 & DNS 유출 이상 프로파일러 (`FLOW-RADAR-001..012`)**
  - *감사 대상*: Kubernetes `CiliumNetworkPolicy` 매니페스트, NixOS 호스트 플로우 프로파일러, 실시간 eBPF 소켓/DNS 질의 텔레메트리.
  - *위협 완화*: 외부 53 포트 무제한 송신(`CVE-2026-10392`), 고엔트로피 DNS 터널링($H > 4.2$), DGA 버스트(분당 15회 초과), 소켓 스파이크(초당 500회 초과) 차단.
  - *정책 합성*: 강화된 `CiliumNetworkPolicy`(L7 DNS 프록시 및 FQDN 정규식 제약), NixOS 프로파일러 모듈, Prometheus 경보 룰(`--flow`).
- **듀얼스택 IPv6 & Cilium BGP 피어링 레이더 (`BGP-RADAR-001..012`)**
  - *감사 대상*: Cilium BGP 피어링 정책, 로드 밸런서 IP 풀, NixOS FRR BGP 호스트 구성.
  - *위협 완화*: TCP MD5 / RFC 2385 인증 누락(`CVE-2026-70192`), 기본 라우트 유출, 프리픽스 변동 차단.
  - *정책 합성*: 강화된 Cilium BGP 매니페스트, NixOS FRR 모듈, BGP Prometheus 경보 룰(`--bgp`).
- **WireGuard eBPF 커널 패스트패스 & 암호화 성능 (`WG-FAST-001..012`)**
  - *감사 대상*: ChaCha20-Poly1305 SIMD 벡터 가속(AVX-512, ARM Neon), 네이티브 eBPF/XDP 드라이버 바인딩, 100GbE 오버레이.
  - *위협 완화*: 스칼라 암호화 폴백, softIRQ 고갈(70% 초과), 커널 링 버퍼 포화(`CVE-2026-31049`) 정밀 탐지.
  - *정책 합성*: 강화된 NixOS 패스트패스 모듈 및 검증된 eBPF XDP C 프로그램(`--wg-fastpath`).
- **Kubernetes Ingress, Gateway API & EnvoyFilter 라우트 위협 레이더**
  - *감사 대상*: `Gateway`, `HTTPRoute`, `GRPCRoute`, `ReferenceGrant`, Istio `EnvoyFilter` 매니페스트.
  - *위협 완화*: 스니펫 인젝션(`CVE-2023-5044`), 교차 네임스페이스 라우트 하이재킹(`CVE-2026-44219`), 인라인 Lua 스크립트 인젝션, 경로 탐색 차단(`--gw`, `--k8s`).

### 3. 🔐 암호화, 기밀 컴퓨팅 & 신원 관리

- **양자 내성 암호(PQC) & NSA CNSA 2.0 전환**
  - *감사 대상*: 컨트롤 플레인 TLS 매개변수, NixOS OpenSSL `oqsprovider` 활성화, GnuTLS 우선순위 정책.
  - *위협 완화*: 수확 후 복호화(HNDL) 양자 암호 해독 위협(`CVE-2026-94301`) 차단.
  - *정책 합성*: 양자 하이브리드 ML-KEM/Kyber TLS 정책 및 CNSA 2.0 전환 로드맵 평가(`--pqc`).
- **기밀 VM & 보안 엔클레이브 WireGuard 원격 증명 (`WG-ENC-001..012`)**
  - *감사 대상*: AMD SEV-SNP VCEK 인증서 체인, Intel TDX Quote, 런타임 측정 부트 PCR 다이제스트.
  - *위협 완화*: 에페메럴 세션 키와 엔클레이브 보고서 간 바인딩 검증, 미검증/변조 피어 터널 차단(`CVE-2026-40291`).
  - *정책 합성*: 강화된 NixOS 엔클레이브 모듈 및 핸드셰이크 이전 커널 증명 게이트키퍼 스크립트(`--wg-enclave`).
- **제로 트러스트 마이크로세그멘테이션 & SPIFFE/SPIRE 워크로드 증명**
  - *감사 대상*: RFC 규격 SPIFFE ID, Cilium mTLS 강제 모드(`authentication.mode: required`), 단기 SVID 갱신 주기.
  - *위협 완화*: 위험 와일드카드 셀렉터(`k8s:ns:*`) 차단 및 SVID 만료 불일치 단절 방지(`CVE-2026-67210`)(`--spiffe-policy-out`).
- **하드웨어 보안 모듈(HSM) & PKCS#11 봉투 암호화**
  - *감사 대상*: Kubernetes etcd `EncryptionConfiguration`, KMS v2 플러그인, AWS Nitro Enclaves(`CVE-2026-83190`)(`--hsm`).
- **멀티 클러스터 플릿 동기화 & OIDC 토큰 레이더**
  - *감사 대상*: 멀티 테넌트 RBAC 권한, 연합 OIDC 서명 알고리즘, ArgoCD/Flux GitOps 드리프트 탐지(`CVE-2026-60114`)(`--fleet`).

### 4. 📦 선언적 공급망 & 불변 스토리지

- **멀티 테넌트 Nix 스토어 전자서명 & 바이너리 캐시 격리 (`NIX-STORE-001..012`)**
  - *감사 대상*: Nix 데몬 설정(`nix.settings.*`, `nix.conf`), Ed25519 서명 강제, 런타임 대체물(Substitute) 텔레메트리.
  - *위협 완화*: 미서명 대체물 캐시 오염(`CVE-2026-81930`), 평문 HTTP 대체물, 빌드 샌드박스 우회 차단.
  - *정책 합성*: 강화된 NixOS 스토어 모듈, `/etc/nix/nix.conf`, Prometheus 경보 룰(`--nixstore`).
- **NixOS 불변 루트 & 임퍼머넌스(Impermanence) 스토리지 휘발성 (`IMP-ROOT-001..012`)**
  - *감사 대상*: NixOS 임퍼머넌스 구성(`environment.persistence`) 및 Kubernetes `hostPath` 마운트.
  - *위협 완화*: RAM 기반 `tmpfs` 루트 강제, 휘발성 슬라이스로 탈출하는 hostPath 마운트(`CVE-2026-61842`) 차단, 비암호화 스왑 방어.
  - *정책 합성*: 강화된 임퍼머넌스 모듈, 재부팅 시 초기화 initrd 훅, 여유 스토리지 경보 룰(`--impermanence`).
- **소프트웨어 자재명세서(SBOM) & In-Toto SLSA Level 3 공급망 증명**
  - *감사 대상*: SPDX v3.0, CycloneDX v1.6, Nix 스토어 클로저 및 In-Toto 암호학적 서명 검증.
  - *위협 완화*: 산출물 변조(`CVE-2026-71044`) 및 선언적 명세 대비 클러스터 런타임 패키지 드리프트 포렌식 탐지(`--sbom`).

### 5. 🤖 워크로드 어드미션, 재해 복구 & 자율 위협 해결

- **Kubernetes 동적 어드미션 웹훅 & CA 교체 레이더 (`WH-RADAR-001..012`)**
  - *감사 대상*: `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`, X.509 CA 번들 인증서 만료.
  - *위협 완화*: 보안 우회 취약점 `failurePolicy: Ignore`(`CVE-2026-52194`), 과도한 타임아웃(3초 초과), 클러스터 부팅 교착 차단.
  - *정책 합성*: 강화된 ValidatingWebhooks, cert-manager 자동 CA 리소스, 지연 시간 경보 룰(`--webhook`).
- **CephFS 스냅샷 스케줄링 & 크로스 리전 볼륨 복제 재해 복구 (`CEPH-DR-001..012`)**
  - *감사 대상*: CephFS 스냅샷 스케줄, CSI 볼륨 복제 클래스, 리전 간 델타 동기화 상태.
  - *위협 완화*: RPO 파괴 deletionPolicy `Delete`, 스플릿 브레인 이중 Primary 선언(`CVE-2026-10140`) 탐지.
  - *정책 합성*: 강화된 VolumeSnapshotClasses, 암호화 복제 전송, 미러 데몬 안티 어피니티 보장(`--dr`).
- **에페메럴 마이크로VM 샌드박스 & 허니팟 디토네이션 디스패치**
  - *감사 대상*: Firecracker 마이크로VM 격리, jailer 매개변수, 가짜 Kubelet/etcd 디코이 유인체.
  - *위협 완화*: 미검증 컨테이너 격리 쿼런틴 및 하이퍼바이저 MMIO 탈출(`CVE-2026-97105`) 탐지(`--sandbox-synth-out`).
- **자율 위협 해결 & GitOps 풀 리퀘스트 합성 엔진**
  - *동작 원리*: 순수 Nix Flake 평가 및 `kubectl kustomize` dry-run 기반 사전 카나리 검증(`pkg/remediate/canary.go`).
  - *산출물*: 비파괴적 원자적 PR(`remediation/*`), Kustomize 전략적 머지 패치, RFC 6902 JSONPatches(`CVE-2026-98402`)(`--remediate`).

---

## 🚀 빠른 시작 가이드

### 사전 요구 사항
- Go 1.22+ 로컬 설치 완료.

### 빌드 및 실행
```bash
# 저장소 복제
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# 테스트 스위트 실행
go test ./...

# 실시간 위협 피드 확인
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# NixOS flake.lock 보안 권고 대조 감사
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Kubernetes 매니페스트 Ingress 및 CNI 정책 감사
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Kubernetes CiliumNetworkPolicy 및 NixOS eBPF 플로우 프로파일러 감사
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# 런타임 eBPF 소켓 플로우 조정 및 강화 정책 자동 합성
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# 리눅스 커널 록다운 & Lanzaboote UEFI 시큐어 부트 DBX 설정 감사
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# 멀티 테넌트 Nix 스토어 & 바이너리 캐시 격리 설정 감사
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# NixOS 임퍼머넌스 구성 및 클러스터 스토리지 hostPath 마운트 감사
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Kubernetes 동적 어드미션 웹훅 매니페스트 감사
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# 기밀 VM WireGuard 피어 원격 증명 매니페스트 감사 (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# WireGuard eBPF 커널 패스트패스 & 암호화 성능 설정 감사
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Cilium BGP 피어링 정책 및 NixOS FRR BGP 매니페스트 감사
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# 베어메탈 eBPF 커널 텔레메트리 다중 노드 실시간 분석 실행
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# GitHub Code Scanning 연동용 OASIS SARIF v2.1.0 리포트 내보내기
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# 구조화된 고정밀 JSON 보안 텔레메트리 리포트 내보내기
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# 시간별 위협 인텔리전스 브리핑 마크다운 자동 생성
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ 로드맵 및 지속적 진화

엔지니어링 로드맵 및 향후 릴리스 계획은 [ROADMAP.md](../../ROADMAP.md)를 참고해 주십시오.

---

## 🔒 보안 정책

취약점 제보 절차 및 보안 불변식 가이드는 [SECURITY.md](../../SECURITY.md)를 확인해 주십시오.
