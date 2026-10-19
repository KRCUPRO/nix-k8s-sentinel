<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <strong>🇪🇸 Español</strong><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Escáner de vulnerabilidades declarativo y radar de inteligencia de amenazas en tiempo real para NixOS y Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Descripción General

`nix-k8s-sentinel` es un motor de escaneo declarativo de vulnerabilidades de alto rendimiento, remediación autónoma y sincronización continua de inteligencia de amenazas, diseñado específicamente para clústeres bare-metal NixOS e infraestructura de producción Kubernetes.

A diferencia de los escáneres tradicionales que inspeccionan capas efímeras de contenedores tras el despliegue, `nix-k8s-sentinel` audita las definiciones declarativas subyacentes antes de que las cargas de trabajo sean programadas, correlacionando manifiestos y telemetría del kernel con fuentes normalizadas de inteligencia CVSS en tiempo real.

### 🎯 Cinco Pilares de Defensa

1. **Endurecimiento Bare-Metal y Kernel**: Bloqueo del kernel Linux (Lockdown), verificación de revocación UEFI DBX, control de acceso obligatorio (MAC) con eBPF LSM y arranque medido con raíz de confianza de hardware.
2. **Redes de Clúster y Malla de Servicios**: Detección de exfiltración DNS y flujos eBPF mediante entropía de Shannon, peering Cilium BGP de doble pila, fast-path en kernel de WireGuard y seguridad en Gateway API.
3. **Criptografía y Computación Confidencial**: Criptografía poscuántica (NSA CNSA 2.0), atestación de cargas SPIFFE/SPIRE, cotizaciones remotas en VM confidenciales (AMD SEV-SNP / Intel TDX) y cifrado de sobre HSM/KMS v2.
4. **Cadena de Suministro y Almacenamiento Inmutable**: Verificación de procedencia SBOM In-Toto SLSA Nivel 3, firmas Ed25519 en Nix store y validación de raíz sin estado NixOS con impermanencia.
5. **Admisión Dinámica y Remediación Autónoma**: Webhooks de admisión con política de fallo cerrado, detonación de señuelos en MicroVM efímeras y síntesis automatizada de PRs GitOps con validación canary.

---

## 🏛️ Capacidades Principales

### 1. 🛡️ Seguridad del Kernel y Endurecimiento del Host

- **Bloqueo del Kernel Linux (Lockdown) y UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *Auditoría*: Modos de bloqueo (`integrity`/`confidentiality`), módulos no firmados (`module.sig_enforce`), acceso a `/dev/mem` y declaraciones Lanzaboote.
  - *Mitigación*: Previene compromisos arbitrarios de ring-0 (`CVE-2026-92814`) y cargadores revocados en la base DBX (`CVE-2023-40547`).
  - *Síntesis*: Módulos NixOS reforzados (`nixos-lockdown-hardened.nix`), servicios systemd de actualización DBX y alertas Prometheus (`--lockdown`).
- **Módulo de Seguridad eBPF LSM y Control de Acceso Obligatorio (MAC)**
  - *Auditoría*: Parámetros LSM del kernel (`security.lsm = ["bpf"]`) y contextos de seguridad (`bprm_check_security`, `file_open`, `socket_create`).
  - *Mitigación*: Bloquea escapes de contenedores privilegiados que eluden seccomp (`CVE-2026-99103`) y accesos indebidos a mapas BPF.
  - *Síntesis*: Módulos NixOS declarativos, programas C eBPF verificables y CRDs `ContainerMACProfile` (`--lsm`).
- **Perfilador Dinámico de Amenazas de Kernel y Filtro BPF de Syscalls**
  - *Auditoría*: Perfiles seccomp, contenedores sin confinamiento y llamadas de sistema administrativas (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *Mitigación*: Alerta sobre tormentas anormales de sockets (> 250 sockets/s) y creación de raw sockets asociados a `CVE-2026-90412`.
  - *Síntesis*: Perfiles Kubernetes Seccomp de mínimo privilegio y módulos de aislamiento systemd (`--bpf`).
- **CIS Kubernetes Benchmark y Sondas Bare-Metal**
  - *Auditoría*: Parámetros de unidades systemd del plano de control, opciones de Kubelet y eventos de kernel en nodos de trabajo.
  - *Síntesis*: Parches de remediación automatizados para NixOS y análisis de telemetría de sondas multinodo (`--cis`, `--probe`).

### 2. 🌐 Redes de Clúster y Defensa de Malla de Servicios

- **Perfilador de Flujos de Red eBPF y Exfiltración DNS (`FLOW-RADAR-001..012`)**
  - *Auditoría*: Manifiestos `CiliumNetworkPolicy`, perfiladores en NixOS y telemetría eBPF de sockets/consultas DNS.
  - *Mitigación*: Intercepta tráfico no restringido en puerto 53 (`CVE-2026-10392`), túneles DNS con alta entropía de Shannon ($H > 4.2$), ráfagas DGA y picos de conexión (> 500 conn/s).
  - *Síntesis*: Manifiestos `CiliumNetworkPolicy` reforzados (proxy DNS L7 con expresiones regulares FQDN) y alertas Prometheus (`--flow`).
- **Radar de Peering BGP de Cilium e IPv6 de Doble Pila (`BGP-RADAR-001..012`)**
  - *Auditoría*: Políticas de peering BGP en Cilium, pools de IP y configuración BGP en NixOS FRR.
  - *Mitigación*: Detecta ausencia de autenticación TCP MD5 / RFC 2385 (`CVE-2026-70192`), filtrado deficiente de rutas y fluctuación de prefijos.
  - *Síntesis*: Manifiestos Cilium BGP reforzados, módulos NixOS FRR y reglas de alerta BGP (`--bgp`).
- **Fast-Path en Kernel WireGuard con eBPF y Aceleración Criptográfica (`WG-FAST-001..012`)**
  - *Auditoría*: Aceleración vectorial SIMD ChaCha20-Poly1305 (AVX-512, ARM Neon), enlaces nativos eBPF/XDP y redes 100GbE.
  - *Mitigación*: Detecta degradación a criptografía escalar, agotamiento de softIRQ (> 70%) y saturación de búferes (`CVE-2026-31049`).
  - *Síntesis*: Módulos NixOS fast-path y programas C para eBPF XDP verificados (`--wg-fastpath`).
- **Radar de Amenazas en Kubernetes Ingress, Gateway API y EnvoyFilter**
  - *Auditoría*: Recursos `Gateway`, `HTTPRoute`, `GRPCRoute`, `ReferenceGrant` y filtros de Istio `EnvoyFilter`.
  - *Mitigación*: Bloquea inyecciones de snippets (`CVE-2023-5044`), secuestro de rutas entre namespaces (`CVE-2026-44219`), scripts Lua inseguros y traversals (`--gw`, `--k8s`).

### 3. 🔐 Criptografía, Computación Confidencial e Identidad

- **Criptografía Poscuántica (PQC) y Transición a NSA CNSA 2.0**
  - *Auditoría*: Flags TLS del plano de control, activación de OpenSSL `oqsprovider` en NixOS y políticas de GnuTLS.
  - *Mitigación*: Protege contra ataques de recolección ahora y descifrado futuro (HNDL) (`CVE-2026-94301`).
  - *Síntesis*: Configuraciones TLS híbridas ML-KEM/Kyber y evaluación de hitos CNSA 2.0 (`--pqc`).
- **Atestación de WireGuard en Máquinas Virtuales Confidenciales (`WG-ENC-001..012`)**
  - *Auditoría*: Cadenas de certificados AMD SEV-SNP VCEK, cotizaciones Intel TDX y registros PCR de arranque medido.
  - *Mitigación*: Vincula claves de sesión efímeras con informes de enclave, rechazando túneles manipulados (`CVE-2026-40291`).
  - *Síntesis*: Módulos NixOS reforzados y scripts de control previos al handshake (`--wg-enclave`).
- **Microsegmentación Zero-Trust y Atestación SPIFFE/SPIRE**
  - *Auditoría*: IDs SPIFFE conformes a RFC, modo mTLS obligatorio en Cilium y ventanas de renovación de SVIDs.
  - *Mitigación*: Elimina selectores comodín (`k8s:ns:*`) y previene desconexiones por desincronización de certificados (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **Módulo de Seguridad de Hardware (HSM) y Cifrado de Sobre PKCS#11**
  - *Auditoría*: `EncryptionConfiguration` de etcd, plugins KMS v2 y AWS Nitro Enclaves (`CVE-2026-83190`) (`--hsm`).
- **Sincronización de Flotas Multiclúster y Radar de Tokens OIDC**
  - *Auditoría*: Permisos RBAC multitenant, algoritmos de firma OIDC y derivas de estado en GitOps con ArgoCD/Flux (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 Cadena de Suministro Declarativa y Almacenamiento Inmutable

- **Aislamiento de Almacén Nix Multitenant y Caché Binaria (`NIX-STORE-001..012`)**
  - *Auditoría*: Configuración de Nix (`nix.settings.*`, `nix.conf`), firmas Ed25519 y telemetría de sustitutos en vivo.
  - *Mitigación*: Evita envenenamiento de caché por sustitutos sin firmar (`CVE-2026-81930`), sustitutos HTTP y elusiones de sandbox.
  - *Síntesis*: Módulos NixOS reforzados, `/etc/nix/nix.conf` y reglas de alerta Prometheus (`--nixstore`).
- **Raíz Inmutable en NixOS y Almacenamiento Efímero Impermanence (`IMP-ROOT-001..012`)**
  - *Auditoría*: Declaraciones de impermanencia (`environment.persistence`) y montajes `hostPath` en Kubernetes.
  - *Mitigación*: Exige raíz en `tmpfs` respaldada por RAM, detecta escapes de hostPath (`CVE-2026-61842`) y bloquea swap sin cifrar.
  - *Síntesis*: Módulos de impermanencia reforzados, ganchos initrd de limpieza al reiniciar y alertas de almacenamiento (`--impermanence`).
- **Lista de Materiales de Software (SBOM) y Atestación In-Toto SLSA Nivel 3**
  - *Auditoría*: Documentos SPDX v3.0, CycloneDX v1.6 y clausuras de Nix frente a declaraciones criptográficas In-Toto.
  - *Mitigación*: Detecta alteración de artefactos (`CVE-2026-71044`) y desvíos entre declaraciones y paquetes en ejecución (`--sbom`).

### 5. 🤖 Admisión de Cargas de Trabajo, Recuperación ante Desastres y Remediación Autónoma

- **Radar de Webhooks de Admisión Dinámica y Rotación de CA (`WH-RADAR-001..012`)**
  - *Auditoría*: Manifiestos `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration` y expiración de certificados X.509.
  - *Mitigación*: Evita omisiones con `failurePolicy: Ignore` (`CVE-2026-52194`), tiempos de espera excesivos (> 3s) y bloqueos de arranque.
  - *Síntesis*: Webhooks reforzados, recursos automatizados de cert-manager y alertas de latencia (`--webhook`).
- **Programación de Snapshots en CephFS y Replicación DR entre Regiones (`CEPH-DR-001..012`)**
  - *Auditoría*: Horarios de snapshots CephFS, clases de replicación de volúmenes CSI y sincronización delta entre regiones.
  - *Mitigación*: Bloquea políticas que comprometen el RPO (`deletionPolicy: Delete`) y conflictos split-brain (`CVE-2026-10140`).
  - *Síntesis*: Clases reforzadas, transporte cifrado y alta disponibilidad en demonios de replicación (`--dr`).
- **Sandbox Efímero en MicroVM y Detonación de Señuelos Honeypot**
  - *Auditoría*: Confinamiento de microVMs Firecracker, parámetros de jailer y señuelos simulados de Kubelet/etcd.
  - *Mitigación*: Pone en cuarentena imágenes sospechosas y detecta escapes MMIO del hipervisor (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **Remediación Autónoma de Amenazas y Síntesis de Pull Requests GitOps**
  - *Mecanismo*: Validación previa con canaries (`pkg/remediate/canary.go`), evaluación pura de flakes y simulaciones con `kubectl kustomize`.
  - *Resultado*: PRs atómicos no disruptivos (`remediation/*`), parches de fusión de Kustomize y parches RFC 6902 (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 Inicio Rápido

### Requisitos Previos
- Go 1.22+ instalado localmente.

### Compilación y Ejecución
```bash
# Clonar el repositorio
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Ejecutar la suite de pruebas
go test ./...

# Inspeccionar el feed de amenazas en tiempo real
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Auditar NixOS flake.lock frente a avisos de seguridad
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Auditar manifiestos de Kubernetes en busca de infracciones de Ingress y CNI
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Auditar CiliumNetworkPolicy y perfiladores eBPF en NixOS
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# Conciliar flujos de sockets eBPF y generar políticas de red reforzadas
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Auditar bloqueo del kernel Linux y Secure Boot DBX
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# Auditar aislamiento de almacén Nix multitenant y caché binaria
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# Auditar configuración de impermanencia en NixOS y montajes hostPath
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Auditar webhooks de admisión en Kubernetes (ValidatingWebhookConfiguration)
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# Auditar atestación de pares WireGuard en VM confidenciales (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# Auditar fast-path de WireGuard con eBPF y rendimiento criptográfico
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Auditar políticas de peering Cilium BGP y manifiestos NixOS FRR BGP
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# Ejecutar auditoría de telemetría de kernel eBPF bare-metal en clúster
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# Exportar hallazgos a formato OASIS SARIF v2.1.0 para GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Exportar informe estructurado de telemetría en JSON
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Generar informe de inteligencia de amenazas automatizado en Markdown
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ Hoja de Ruta y Evolución Continua

Consulte [ROADMAP.md](../../ROADMAP.md) para conocer la hoja de ruta activa y las próximas versiones programadas.

---

## 🔒 Política de Seguridad

Para conocer los procedimientos de notificación de vulnerabilidades y pautas de divulgación, consulte [SECURITY.md](../../SECURITY.md).
