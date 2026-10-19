<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <strong>🇷🇺 Русский</strong> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Декларативный сканер уязвимостей и радар данных об угрозах в реальном времени для NixOS и Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Обзор

`nix-k8s-sentinel` — это высокопроизводительный движок декларативного аудита уязвимостей, автономного устранения инцидентов и непрерывной синхронизации данных об угрозах, разработанный специально для bare-metal кластеров NixOS и промышленных сред Kubernetes.

В отличие от традиционных сканеров, пассивно инспектирующих эфемерные слои контейнеров уже после развертывания, `nix-k8s-sentinel` проверяет базовые декларативные манифесты еще до планирования рабочих нагрузок, сопоставляя конфигурации и телеметрию ядра с нормализованными фидами угроз CVSS в режиме реального времени.

### 🎯 Пять основных столпов защиты

1. **Укрепление Bare-Metal и Ядра**: Блокировка ядра Linux (Lockdown), проверка отзыва UEFI DBX, мандатный контроль доступа (MAC) с помощью eBPF LSM и доверенная загрузка с аппаратным корнем доверия (Root of Trust).
2. **Кластерная Сеть и Защита Service Mesh**: Обнаружение эксфильтрации DNS и сокет-потоков eBPF по энтропии Шеннона, BGP-пиринг Cilium Dual-Stack, ускоренный ядерный fast-path WireGuard и безопасность маршрутизации Gateway API.
3. **Криптография и Конфиденциальные Вычисления**: Постквантовая криптография (NSA CNSA 2.0), аттестация рабочих нагрузок SPIFFE/SPIRE, удаленная аттестация конфиденциальных виртуальных машин (AMD SEV-SNP / Intel TDX) и конвертное шифрование HSM/KMS v2.
4. **Декларативная Цепочка Поставок и Неизменяемое Хранилище**: Аттестация происхождения SBOM In-Toto SLSA Level 3, верификация подписей Ed25519 для Nix-хранилища и проверка корня без сохранения состояния (Impermanence) на NixOS.
5. **Динамический Допуск и Автономное Устранение**: Вебхуки допуска с блокировкой при сбое (Fail-Closed), запуск приманок-ловушек в эфемерных MicroVM и автоматический синтез GitOps-PR с канареечной валидацией.

---

## 🏛️ Основные возможности

### 1. 🛡️ Безопасность Ядра и Укрепление Хоста

- **Блокировка ядра Linux (Lockdown) и база UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *Аудит*: Режимы блокировки (`integrity`/`confidentiality`), неподписанные модули ядра (`module.sig_enforce`), доступ к `/dev/mem` и конфигурации Lanzaboote.
  - *Защита*: Предотвращает эскалацию привилегий в ring-0 (`CVE-2026-92814`) и блокирует скомпрометированные загрузчики из базы данных UEFI DBX (`CVE-2023-40547`).
  - *Синтез*: Укрепленные модули NixOS (`nixos-lockdown-hardened.nix`), службы обновления DBX для systemd и алерты Prometheus (`--lockdown`).
- **Модуль безопасности eBPF LSM и мандатный контроль доступа (MAC)**
  - *Аудит*: Параметры LSM ядра (`security.lsm = ["bpf"]`) и контексты безопасности контейнеров (`bprm_check_security`, `file_open`, `socket_create`).
  - *Защита*: Пресекает побеги из привилегированных контейнеров в обход seccomp (`CVE-2026-99103`) и несанкционированную модификацию BPF-карт.
  - *Синтез*: Декларативные модули NixOS, верифицируемые C-программы eBPF и CRD Kubernetes `ContainerMACProfile` (`--lsm`).
- **Динамический профилировщик угроз ядра и BPF-фильтр системных вызовов**
  - *Аудит*: Декларативные профили seccomp, неограниченные контейнеры и критические административные системные вызовы (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *Защита*: Обнаруживает штормы создания сокетов (> 250 сокетов/с) и аллокацию raw-сокетов, связанную с `CVE-2026-90412`.
  - *Синтез*: Профили Seccomp минимальных привилегий и модули изоляции systemd для NixOS (`--bpf`).
- **Бенчмарк CIS Kubernetes и Bare-Metal зонды**
  - *Аудит*: Параметры systemd-сервисов плоскости управления, параметры Kubelet и телеметрия сокетов/системных вызовов рабочих узлов.
  - *Синтез*: Автоматические патчи устранения несоответствий для хостов NixOS и межсерверная агрегация данных зондов (`--cis`, `--probe`).

### 2. 🌐 Кластерная Сеть и Защита Service Mesh

- **Профилировщик сетевых потоков eBPF и эксфильтрации DNS (`FLOW-RADAR-001..012`)**
  - *Аудит*: Манифесты `CiliumNetworkPolicy`, хостовые профилировщики NixOS и eBPF-телеметрия сокет-соединений и DNS-запросов.
  - *Защита*: Перехватывает неограниченный исходящий трафик через порт 53 (`CVE-2026-10392`), выявляет DNS-туннелирование с высокой энтропией Шеннона ($H > 4.2$), DGA-всплески и аномальные пики подключений (> 500 соед./с).
  - *Синтез*: Защищенные ресурсы `CiliumNetworkPolicy` (L7 DNS-проксирование с регулярными выражениями FQDN) и правила алертов Prometheus (`--flow`).
- **Радар BGP-пиринга Cilium и Dual-Stack IPv6 (`BGP-RADAR-001..012`)**
  - *Аудит*: Политики BGP-пиринга Cilium, пулы IP-адресов балансировщиков нагрузки и BGP-конфигурации FRR в NixOS.
  - *Защита*: Идентифицирует отсутствие аутентификации TCP MD5 / RFC 2385 (`CVE-2026-70192`), утечки экспорта маршрутов и флаппинг префиксов.
  - *Синтез*: Укрепленные манифесты Cilium BGP, модули NixOS FRR и метрики Prometheus (`--bgp`).
- **Fast-Path WireGuard в пространстве ядра с eBPF и аппаратным крипто-ускорением (`WG-FAST-001..012`)**
  - *Аудит*: SIMD-векторизация ChaCha20-Poly1305 (AVX-512, ARM Neon), нативные хуки eBPF/XDP и 100GbE оверлейные сети.
  - *Защита*: Фиксирует деградацию до скалярных криптовычислений, перегрузку SoftIRQ (> 70%) и переполнение очередей буфера (`CVE-2026-31049`).
  - *Синтез*: Оптимизированные модули fast-path для NixOS и проверенные C-программы eBPF XDP (`--wg-fastpath`).
- **Радар угроз для Kubernetes Ingress, Gateway API и EnvoyFilter**
  - *Аудит*: Ресурсы `Gateway`, `HTTPRoute`, `GRPCRoute`, `ReferenceGrant` и правила Istio `EnvoyFilter`.
  - *Защита*: Блокирует внедрение сниппетов (`CVE-2023-5044`), межпространственный перехват маршрутов (`CVE-2026-44219`), инъекции произвольных скриптов Lua и обход путей (path traversal) (`--gw`, `--k8s`).

### 3. 🔐 Криптография, Конфиденциальные Вычисления и Управление Доступом

- **Постквантовая криптография (PQC) и миграция NSA CNSA 2.0**
  - *Аудит*: Параметры TLS плоскости управления, активация провайдера `oqsprovider` для OpenSSL в NixOS и приоритеты GnuTLS.
  - *Защита*: Защищает от атак с отложенной расшифровкой (Harvest Now, Decrypt Later - HNDL) (`CVE-2026-94301`).
  - *Синтез*: Декларации гибридного TLS ML-KEM/Kyber и соответствие контрольным этапам стандарта CNSA 2.0 (`--pqc`).
- **Аттестация конфиденциальных виртуальных машин для WireGuard (`WG-ENC-001..012`)**
  - *Аудит*: Цепочки сертификатов AMD SEV-SNP VCEK, отчеты аттестации Intel TDX и хэши PCR доверенной загрузки.
  - *Защита*: Привязывает сессионные ключи к отчетам анклавов, разрывая соединения с модифицированными или неподтвержденными узлами (`CVE-2026-40291`).
  - *Синтез*: Укрепленные конфигурации NixOS и скрипты пре-хэндшейк верификации (`--wg-enclave`).
- **Микросегментация Zero-Trust и аттестация SPIFFE/SPIRE**
  - *Аудит*: Соответствие формату RFC идентификаторов SPIFFE, обязательный режим mTLS в Cilium и сроки действия SVID.
  - *Защита*: Устраняет опасные подстановочные селекторы (`k8s:ns:*`) и предотвращает сбои из-за десинхронизации сертификатов (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **Аппаратные модули безопасности (HSM) и конвертное шифрование PKCS#11**
  - *Аудит*: Конфигурации `EncryptionConfiguration` для etcd, плагины KMS v2 и анклавы AWS Nitro (`CVE-2026-83190`) (`--hsm`).
- **Мультикластерная синхронизация флота и аудит OIDC-токенов**
  - *Аудит*: Мультитенантные привилегии RBAC, федеративные алгоритмы подписи токенов OIDC и расхождения конфигураций GitOps в ArgoCD/Flux (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 Декларативная Цепочка Поставок и Неизменяемое Хранилище

- **Изоляция мультиарендного Nix-хранилища и безопасность бинарного кэша (`NIX-STORE-001..012`)**
  - *Аудит*: Параметры демона Nix (`nix.settings.*`, `nix.conf`), валидация подписей Ed25519 и телеметрия подстановочных серверов (substituters).
  - *Защита*: Предотвращает отравление кэша неподписанными пакетами (`CVE-2026-81930`), открытые HTTP-потоки и побеги из сборочной песочницы.
  - *Синтез*: Укрепленные модули NixOS, шаблоны конфигураций `/etc/nix/nix.conf` и алерты Prometheus (`--nixstore`).
- **Неизменяемый корень NixOS и эфемерное хранилище Impermanence (`IMP-ROOT-001..012`)**
  - *Аудит*: Декларации персистентности (`environment.persistence`) и кластерные монтирования `hostPath`.
  - *Защита*: Принудительно разворачивает корневой раздел в `tmpfs` в оперативной памяти, выявляет утечки данных через hostPath (`CVE-2026-61842`) и блокирует незашифрованный swap.
  - *Синтез*: Усиленные конфигурации Impermanence, хуки очистки initrd при перезагрузке и мониторинг емкости диска (`--impermanence`).
- **Спецификация программных компонентов (SBOM) и аттестация In-Toto SLSA Level 3**
  - *Аудит*: Документы SPDX v3.0 и CycloneDX v1.6 в сопоставлении с замыканиями Nix и криптографическими подтверждениями In-Toto.
  - *Защита*: Выявляет несанкционированную подмену артефактов (`CVE-2026-71044`) и версионные расхождения в продакшене (`--sbom`).

### 5. 🤖 Допуск Нагрузок, Аварийное Восстановление и Автономное Устранение

- **Радар динамических вебхуков допуска и ротация удостоверяющих центров (`WH-RADAR-001..012`)**
  - *Аудит*: Манифесты `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration` и сроки действия сертификатов CA X.509.
  - *Защита*: Исключает опасные конфигурации пропуска проверок `failurePolicy: Ignore` (`CVE-2026-52194`), чрезмерные задержки (> 3с) и взаимные блокировки при старте.
  - *Синтез*: Отказоустойчивые вебхуки, автоматизированные манифесты cert-manager и мониторинг задержек (`--webhook`).
- **Планирование снимков CephFS и межрегиональное аварийное восстановление (`CEPH-DR-001..012`)**
  - *Аудит*: Расписания снапшотов CephFS, классы репликации томов CSI и межрегиональная дельта-синхронизация.
  - *Защита*: Блокирует деструктивные политики удаления (`deletionPolicy: Delete`), нарушающие целевые показатели RPO, и состояния рассинхронизации Split-Brain (`CVE-2026-10140`).
  - *Синтез*: Надежные классы снимков, зашифрованная репликация и правила антиаффинитета демонов-зеркал (`--dr`).
- **Эфемерная песочница MicroVM и запуск детонационных ловушек (Honeypot)**
  - *Аудит*: Изоляция MicroVM Firecracker, параметры jailer и эмулированные ложные цели Kubelet/etcd.
  - *Защита*: Помещает подозрительные контейнеры в карантин и детектирует попытки побега из гипервизора через MMIO (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **Автономное устранение угроз и генератор GitOps Pull Request**
  - *Механизм*: Предварительная канареечная валидация (`pkg/remediate/canary.go`), чистая оценка Nix Flake и тестовые прогоны через `kubectl kustomize`.
  - *Результаты*: Атомарные безопасные PR (`remediation/*`), стратегические патчи Kustomize и RFC 6902 JSONPatches (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 Быстрый старт

### Требования
- Локально установленный Go 1.22+.

### Сборка и Запуск
```bash
# Клонирование репозитория
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Запуск тестов
go test ./...

# Проверка активного фида угроз
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Проверка зависимостей flake.lock на наличие бюллетеней безопасности
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Проверка манифестов Kubernetes на уязвимости Ingress и CNI
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# Аудит политик CiliumNetworkPolicy и eBPF-профилировщиков NixOS
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# Сопоставление телеметрии eBPF и синтез укрепленных политик
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# Аудит блокировки ядра Linux и базы UEFI Secure Boot DBX
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# Аудит изоляции Nix-хранилища и бинарных кэшей
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# Аудит неизменяемого корня NixOS и точек монтирования hostPath
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# Аудит динамических вебхуков допуска Kubernetes
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# Аудит аттестации пиров WireGuard на конфиденциальных ВМ (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# Аудит fast-path WireGuard eBPF и криптографического ускорения
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# Аудит политик BGP-пиринга Cilium и конфигураций FRR
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# Выполнение bare-metal телеметрического анализа eBPF по всему кластеру
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# Экспорт результатов в формате OASIS SARIF v2.1.0 для GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# Генерация полного отчета об аудите в формате JSON
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# Формирование автоматического ежечасного брифинга по безопасности
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ План развития

Подробный план развития проекта и запланированные этапы представлены в [ROADMAP.md](../../ROADMAP.md).

---

## 🔒 Политика безопасности

Для сообщений об обнаруженных уязвимостях и ознакомления с нашими принципами безопасности см. [SECURITY.md](../../SECURITY.md).
