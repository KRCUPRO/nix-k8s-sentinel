<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <strong>🇧🇷 Português</strong> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Scanner declarativo de vulnerabilidades e radar de inteligência contra ameaças em tempo real para NixOS & Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Visão Geral

O `nix-k8s-sentinel` é um mecanismo declarativo de auditoria de vulnerabilidades, remediação autônoma e sincronização contínua de inteligência contra ameaças, projetado especificamente para clusters bare-metal NixOS e infraestruturas de produção Kubernetes.

Diferente de scanners tradicionais que inspecionam passivamente camadas efêmeras de contêineres após a implantação, o `nix-k8s-sentinel` audita as definições declarativas subjacentes antes do agendamento das cargas de trabalho, correlacionando manifestos e telemetria do kernel com feeds de ameaças CVSS normalizados em tempo real.

### 🎯 Cinco Pilares Fundamentais de Defesa

1. **Fortalecimento Bare-Metal & Kernel**: Bloqueio de Kernel Linux (Lockdown), verificação de revogação UEFI DBX, controle de acesso obrigatório (MAC) com eBPF LSM e inicialização aferida com raiz de confiança em hardware.
2. **Rede de Cluster & Defesa de Service Mesh**: Detecção de exfiltração DNS e fluxos de sockets eBPF por entropia de Shannon, emparelhamento Cilium BGP dual-stack, fast-path de kernel WireGuard e segurança de rotas Gateway API.
3. **Criptografia & Computação Confidencial**: Criptografia pós-quântica (NSA CNSA 2.0), atestação de workloads SPIFFE/SPIRE, atestação remota de VMs confidenciais (AMD SEV-SNP / Intel TDX) e criptografia de envelope HSM/KMS v2.
4. **Cadeia de Suprimentos Declarativa & Armazenamento Imutável**: Atestação de procedência SBOM In-Toto SLSA Nível 3, verificação de assinaturas Ed25519 para o Nix store e validação de raiz sem estado (Impermanence) no NixOS.
5. **Admissão Dinâmica & Remediação Autônoma**: Webhooks de admissão fail-closed, detonação de iscas honeypot em MicroVMs efêmeras e síntese automatizada de PRs GitOps com validação canary.

---

## 🏛️ Recursos Principais

### 1. 🛡️ Segurança do Kernel & Fortalecimento do Host

- **Bloqueio do Kernel Linux (Lockdown) e UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *Auditorias*: Modos de bloqueio (`integrity`/`confidentiality`), módulos não assinados (`module.sig_enforce`), acesso a `/dev/mem` e declarações Lanzaboote.
  - *Mitigações*: Previne escalonamento arbitrário para ring-0 (`CVE-2026-92814`) e bloqueia carregadores revogados da base UEFI DBX (`CVE-2023-40547`).
  - *Síntese*: Módulos NixOS fortalecidos (`nixos-lockdown-hardened.nix`), serviços systemd de atualização de DBX e alertas Prometheus (`--lockdown`).
- **Módulo de Segurança eBPF LSM e Controle de Acesso Obrigatório (MAC)**
  - *Auditorias*: Parâmetros LSM do kernel (`security.lsm = ["bpf"]`) e contextos de segurança de contêineres (`bprm_check_security`, `file_open`, `socket_create`).
  - *Mitigações*: Bloqueia evasões de contêineres privilegiados contornando seccomp (`CVE-2026-99103`) e manipulações ilícitas de tabelas BPF.
  - *Síntese*: Módulos NixOS declarativos, programas C eBPF verificáveis e CRDs Kubernetes `ContainerMACProfile` (`--lsm`).
- **Perfilador Dinâmico de Ameaças do Kernel e Filtro BPF de Syscalls**
  - *Auditorias*: Perfis seccomp declarativos, contêineres irrestritos e chamadas de sistema administrativas críticas (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *Mitigações*: Detecta tempestades de criação de sockets (> 250 sockets/s) e alocação de raw sockets associadas à `CVE-2026-90412`.
  - *Síntese*: Perfis Seccomp de menor privilégio e módulos de isolamento systemd para NixOS (`--bpf`).
- **Benchmark CIS Kubernetes e Sondas Bare-Metal**
  - *Auditorias*: Parâmetros de unidades systemd do plano de controle, opções do Kubelet e telemetria de sockets/syscalls nos nós de trabalho.
  - *Síntese*: Patches automatizados de remediação para hosts NixOS e agregação de sondas em múltiplos nós (`--cis`, `--probe`).

### 2. 🌐 Rede de Cluster & Defesa de Service Mesh

- **Perfilador de Fluxo de Rede eBPF e Radar de Exfiltração DNS (`FLOW-RADAR-001..012`)**
  - *Auditorias*: Manifestos `CiliumNetworkPolicy`, perfiladores de host NixOS e telemetria eBPF de conexões de socket e consultas DNS.
  - *Mitigações*: Intercepta tráfego de saída irrestrito na porta 53 (`CVE-2026-10392`), túneis DNS com alta entropia de Shannon ($H > 4.2$), picos de DGA e anomalias de conexões (> 500 conexões/s).
  - *Síntese*: Recursos `CiliumNetworkPolicy` blindados (proxy DNS L7 com regex FQDN) e alertas Prometheus (`--flow`).
- **Radar de Peering BGP Cilium e IPv6 Dual-Stack (`BGP-RADAR-001..012`)**
  - *Auditorias*: Políticas de emparelhamento Cilium BGP, pools de IP de LoadBalancer e configurações NixOS FRR BGP.
  - *Mitigações*: Identifica ausência de autenticação TCP MD5 / RFC 2385 (`CVE-2026-70192`), vazamento de exportação de rotas e oscilação de prefixos.
  - *Síntese*: Manifestos Cilium BGP fortalecidos, módulos NixOS FRR e regras de alerta Prometheus (`--bgp`).
- **Fast-Path WireGuard no Kernel com eBPF e Aceleração Criptográfica (`WG-FAST-001..012`)**
  - *Auditorias*: Aceleração vetorial SIMD ChaCha20-Poly1305 (AVX-512, ARM Neon), hooks nativos eBPF/XDP e redes overlay 100GbE.
  - *Mitigações*: Detecta regressão para rotinas criptográficas escalares, saturação de softIRQ (> 70%) e estouro de filas de buffer (`CVE-2026-31049`).
  - *Síntese*: Módulos NixOS fast-path reforçados e programas C eBPF XDP verificados (`--wg-fastpath`).
- **Radar de Ameaças para Kubernetes Ingress, Gateway API e EnvoyFilter**
  - *Auditorias*: Recursos `Gateway`, `HTTPRoute`, `GRPCRoute`, `ReferenceGrant` e regras Istio `EnvoyFilter`.
  - *Mitigações*: Bloqueia injeção de snippets (`CVE-2023-5044`), sequestro de rotas entre namespaces (`CVE-2026-44219`), scripts arbitrários Lua e ataques de path traversal (`--gw`, `--k8s`).

### 3. 🔐 Criptografia, Computação Confidencial & Gestão de Identidades

- **Criptografia Pós-Quântica (PQC) e Transição NSA CNSA 2.0**
  - *Auditorias*: Parâmetros TLS do plano de controle, ativação do provedor OpenSSL `oqsprovider` no NixOS e prioridades GnuTLS.
  - *Mitigações*: Protege contra ataques de descriptografia retroativa (Harvest Now, Decrypt Later - HNDL) (`CVE-2026-94301`).
  - *Síntese*: Declarações TLS híbridas ML-KEM/Kyber e conformidade com os marcos do padrão CNSA 2.0 (`--pqc`).
- **Atestação de Máquinas Virtuais Confidenciais para WireGuard (`WG-ENC-001..012`)**
  - *Auditorias*: Cadeias de certificados AMD SEV-SNP VCEK, cotações Intel TDX e digests de inicialização aferida via PCRs.
  - *Mitigações*: Vincula chaves de sessão efêmeras a relatórios de enclave, rejeitando túneis adulterados ou não verificados (`CVE-2026-40291`).
  - *Síntese*: Módulos NixOS reforçados e scripts de validação pré-handshake (`--wg-enclave`).
- **Microssegmentação Zero-Trust e Atestação SPIFFE/SPIRE**
  - *Auditorias*: IDs SPIFFE em conformidade com as RFCs, modo mTLS obrigatório no Cilium e janelas de validade dos SVIDs.
  - *Mitigações*: Elimina seletores coringa perigosos (`k8s:ns:*`) e previne indisponibilidades por dessincronização de certificados (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **Módulos de Segurança em Hardware (HSM) e Criptografia de Envelope PKCS#11**
  - *Auditorias*: Arquivos `EncryptionConfiguration` do etcd, plugins KMS v2 e AWS Nitro Enclaves (`CVE-2026-83190`) (`--hsm`).
- **Sincronização de Frotas Multi-Cluster e Radar de Tokens OIDC**
  - *Auditorias*: Permissões RBAC multi-inquilino, algoritmos de assinatura OIDC federados e desvios de GitOps no ArgoCD/Flux (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 Cadeia de Suprimentos Declarativa & Armazenamento Imutável

- **Isolamento do Nix Store Multi-Inquilino e Segurança de Cache Binário (`NIX-STORE-001..012`)**
  - *Auditorias*: Parâmetros do daemon Nix (`nix.settings.*`, `nix.conf`), validação de assinaturas Ed25519 e telemetria de substituters.
  - *Mitigações*: Impede envenenamento de cache por substitutos não assinados (`CVE-2026-81930`), transmissões HTTP abertas e evasões de sandbox.
  - *Síntese*: Módulos NixOS fortalecidos, modelos `/etc/nix/nix.conf` e alertas Prometheus (`--nixstore`).
- **Raiz Imutável NixOS e Armazenamento Efêmero Impermanence (`IMP-ROOT-001..012`)**
  - *Auditorias*: Declarações de persistência (`environment.persistence`) e montagens `hostPath` no cluster.
  - *Mitigações*: Impõe raiz em memória `tmpfs`, detecta vazamentos de dados via hostPath (`CVE-2026-61842`) e bloqueia swap não criptografado.
  - *Síntese*: Módulos de impermanência reforçados, hooks de limpeza initrd na inicialização e monitoramento de disco (`--impermanence`).
- **Lista de Materiais de Software (SBOM) e Atestação In-Toto SLSA Nível 3**
  - *Auditorias*: Documentos SPDX v3.0 e CycloneDX v1.6 cruzados com fechamentos Nix e atestações criptográficas In-Toto.
  - *Mitigações*: Detecta adulteração de artefatos (`CVE-2026-71044`) e identifica divergências de versões em produção (`--sbom`).

### 5. 🤖 Admissão de Cargas, Recuperação de Desastres & Remediação Autônoma

- **Radar de Webhooks de Admissão Dinâmica e Rotação de CAs (`WH-RADAR-001..012`)**
  - *Auditorias*: Manifestos `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration` e validade dos certificados X.509 de CA.
  - *Mitigações*: Elimina configurações permissivas `failurePolicy: Ignore` (`CVE-2026-52194`), atrasos excessivos (> 3s) e bloqueios na inicialização.
  - *Síntese*: Webhooks resilientes a falhas, recursos automatizados de cert-manager e monitoramento de latência (`--webhook`).
- **Agendamento de Snapshots CephFS e Recuperação de Desastres Geo-Replicada (`CEPH-DR-001..012`)**
  - *Auditorias*: Cronogramas de snapshots CephFS, classes de replicação de volumes CSI e sincronização delta entre regiões.
  - *Mitigações*: Bloqueia políticas de exclusão destrutivas para o RPO (`deletionPolicy: Delete`) e cenários de inconsistência split-brain (`CVE-2026-10140`).
  - *Síntese*: Classes de snapshot reforçadas, replicação criptografada e regras de anti-afinidade para daemons de espelhamento (`--dr`).
- **Sandbox Efêmero em MicroVM e Detonação de Iscas Honeypot**
  - *Auditorias*: Isolamento de MicroVMs Firecracker, parâmetros de jailer e alvos fictícios simulando Kubelet/etcd.
  - *Mitigações*: Coloca contêineres suspeitos em quarentena e detecta tentativas de fuga de hipervisor via MMIO (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **Remediação Autônoma e Gerador de Pull Requests GitOps**
  - *Mecanismo*: Validação prévia com canários (`pkg/remediate/canary.go`), avaliação pura em Nix Flake e testes dry-run com `kubectl kustomize`.
  - *Entregas*: PRs atômicos sem impacto (`remediation/*`), patches estratégicos Kustomize e RFC 6902 JSONPatches (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 Início Rápido

### Pré-requisitos
- Instalação local do Go 1.22+.

### Compilação e Execução
```bash
# Clonar o repositório
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Executar a suíte de testes
go test ./...

# Inspecionar o feed de inteligência contra ameaças em tempo real
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Auditar o flake.lock contra avisos de vulnerabilidades
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Auditar manifestos Kubernetes quanto a vulnerabilidades Ingress e CNI
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Auditar políticas CiliumNetworkPolicy e perfiladores eBPF no NixOS
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# Reconciliar telemetria eBPF e sintetizar políticas blindadas
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Auditar o bloqueio do kernel Linux e a base UEFI Secure Boot DBX
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# Auditar o isolamento do Nix store e caches binários
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# Auditar a raiz imutável NixOS e pontos de montagem hostPath
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Auditar webhooks de admissão dinâmica do Kubernetes
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# Auditar a atestação de nós WireGuard em VMs confidenciais (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# Auditar o fast-path WireGuard eBPF e a aceleração criptográfica
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Auditar políticas de emparelhamento Cilium BGP e declarações FRR
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# Executar análise de telemetria eBPF bare-metal em todo o cluster
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# Exportar resultados no formato OASIS SARIF v2.1.0 para o GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Gerar relatório abrangente de auditoria em formato JSON
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Gerar briefing automatizado de segurança de hora em hora
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ Roteiro e Evolução Contínua

Consulte [ROADMAP.md](../../ROADMAP.md) para acompanhar o roteiro de desenvolvimento ativo e os próximos marcos.

---

## 🔒 Política de Segurança

Para reportar vulnerabilidades e conhecer nossas diretrizes de segurança, consulte [SECURITY.md](../../SECURITY.md).
