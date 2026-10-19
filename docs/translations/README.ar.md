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
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <strong>🇸🇦 العربية</strong>
</p>

# 🛡️ nix-k8s-sentinel

**ماسح الثغرات الأمنية التعريفي ورادار معلومات التهديدات المباشرة لأنظمة NixOS وKubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.30.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ نظرة عامة

يُعد `nix-k8s-sentinel` محركاً متقدماً للتدقيق التعريفي في الثغرات الأمنية والمعالجة الذاتية التلقائية ومزامنة معلومات التهديدات المستمرة، والمصمم خصيصاً لمجموعات خوادم NixOS الفيزيائية (Bare-Metal) وبيئات إنتاج Kubernetes.

على عكس أدوات الفحص التقليدية التي تكتفي بالتدقيق السلبي للطبقات المؤقتة للحاويات بعد النشر، يقوم `nix-k8s-sentinel` بمراجعة التعريفات التصريحية الأساسية قبل جدولة أعباء العمل، مع ربط البيانات التعريفية والقياس عن بُعد للنواة بموجزات التهديدات القياسية (CVSS) في الوقت الفعلي.

### 🎯 ركائز الدفاع الخمس الأساسية

1. **تحصين الخوادم الفيزيائية ونواة النظام**: تأمين نواة Linux (Lockdown)، التحقق من إلغاء شهادات UEFI DBX، التحكم الإلزامي في الوصول (MAC) باستخدام eBPF LSM، والإقلاع المقاس مع جذر الثقة في العتاد (Hardware Root of Trust).
2. **شبكات المجموعات وحماية شبكة الخدمات (Service Mesh)**: الكشف عن تسريب DNS وتدفقات مآخذ eBPF عبر إنتروبيا شانون، واقتران Cilium BGP ثنائي الحزمة (Dual-Stack)، والمسار السريع لنواة WireGuard، وأمان مسارات Gateway API.
3. **التشفير والحوسبة السرية وإدارة الهوية**: التشفير المقاوم للحوسبة الكمومية (NSA CNSA 2.0)، وتوثيق أعباء العمل عبر SPIFFE/SPIRE، وتوثيق الأجهزة الافتراضية السرية عن بُعد (AMD SEV-SNP / Intel TDX)، وتشفير الأظرف عبر HSM/KMS v2.
4. **سلسلة التوريد التعريفية والتخزين غير القابل للتغيير**: توثيق منشأ البرمجيات (SBOM) بمستوى In-Toto SLSA Level 3، والتحقق من توقيعات Ed25519 لمخزن Nix، وتأكيد الجذر عديم الحالة (Impermanence) في NixOS.
5. **القبول الديناميكي والمعالجة التلقائية**: خطافات قبول الإغلاق عند الفشل (Fail-Closed Webhooks)، وتفجير الأفخاخ الاستدراجية (Honeypot) في بيئات MicroVM المعزولة، وتوليد طلبات السحب (GitOps PR) تلقائياً مع التحقق عبر الإصدارات التجريبية (Canary).

---

## 🏛️ القدرات الأساسية

### 1. 🛡️ أمان نواة النظام وتحصين المضيف

- **تأمين نواة Linux وقاعدة بيانات UEFI Secure Boot DBX (`LOCKDOWN-001..012`)**
  - *التدقيق*: أوضاع التأمين (`integrity`/`confidentiality`)، وحدات النواة غير الموقعة (`module.sig_enforce`)، الوصول إلى `/dev/mem`، وتعريفات Lanzaboote.
  - *المعالجة والتخفيف*: يمنع التصعيد العشوائي لامتيازات ring-0 (`CVE-2026-92814`) ويحظر محملات الإقلاع الملغاة في قاعدة بيانات UEFI DBX (`CVE-2023-40547`).
  - *التوليد والتركيب*: وحدات NixOS المحصنة (`nixos-lockdown-hardened.nix`)، وخدمات تحديث DBX عبر systemd، وتنبيهات Prometheus (`--lockdown`).
- **وحدة أمان eBPF LSM والتحكم الإلزامي في الوصول (MAC)**
  - *التدقيق*: معلمات LSM في النواة (`security.lsm = ["bpf"]`) وسياقات أمان الحاويات (`bprm_check_security`, `file_open`, `socket_create`).
  - *المعالجة والتخفيف*: يمنع هروب الحاويات ذات الامتيازات العالية عبر تجاوز seccomp (`CVE-2026-99103`) والتلاعب غير المصرح به بجداول BPF.
  - *التوليد والتركيب*: وحدات NixOS التعريفية، وبرامج C لـ eBPF قابلة للتحقق، وتعاريف موارد Kubernetes المخصصة `ContainerMACProfile` (`--lsm`).
- **محلل تهديدات النواة الديناميكي وتصفية استدعاءات النظام عبر BPF**
  - *التدقيق*: ملفات تعريف seccomp التصريحية، والحاويات غير المقيدة، واستدعاءات النظام الإدارية الحساسة (`ptrace`, `process_vm_writev`, `kexec_load`).
  - *المعالجة والتخفيف*: يكتشف عواصف إنشاء المآخذ (> 250 مأخذ/ث) وتخصيص raw sockets المرتبط بالثغرة `CVE-2026-90412`.
  - *التوليد والتركيب*: ملفات تعريف Seccomp بالحد الأدنى من الصلاحيات ووحدات عزل systemd لنظام NixOS (`--bpf`).
- **مقياس CIS Kubernetes ومجسات الخوادم الفيزيائية**
  - *التدقيق*: معلمات وحدات systemd لطبقة التحكم، وخيارات Kubelet، وقياس استدعاءات ومآخذ عقد التشغيل عن بُعد.
  - *التوليد والتركيب*: تصحيحات المعالجة الآلية لمضيفي NixOS ومزامنة المجسات عبر العقد المتعددة (`--cis`, `--probe`).

### 2. 🌐 شبكات المجموعات وحماية شبكة الخدمات

- **محلل تدفقات شبكة eBPF ورادار استنزاف DNS (`FLOW-RADAR-001..012`)**
  - *التدقيق*: ملفات `CiliumNetworkPolicy`، ومحللات مضيف NixOS، وقياسات eBPF لاتصالات المآخذ واستعلامات DNS.
  - *المعالجة والتخفيف*: يعترض حركة المرور الصادرة غير المقيدة عبر المنفذ 53 (`CVE-2026-10392`)، وأنفاق DNS ذات إنتروبيا شانون العالية ($H > 4.2$)، ونشاط خوارزميات DGA، والارتفاعات المفاجئة في الاتصالات (> 500 اتصال/ث).
  - *التوليد والتركيب*: سياسات `CiliumNetworkPolicy` مشددة (وكيل DNS للطبقة L7 مع تعبيرات نمطية لـ FQDN) وقواعد تنبيه Prometheus (`--flow`).
- **رادار اقتران Cilium BGP وشبكات IPv6 المزدوجة (`BGP-RADAR-001..012`)**
  - *التدقيق*: سياسات اقتران Cilium BGP، وتجمعات عناوين IP لموازنة الحمل، وتكوينات NixOS FRR BGP.
  - *المعالجة والتخفيف*: يكشف غياب المصادقة عبر TCP MD5 / RFC 2385 (`CVE-2026-70192`)، وتسريبات تصدير المسارات، وتذبذب البادئات.
  - *التوليد والتركيب*: ملفات Cilium BGP المحصنة، ووحدات NixOS FRR، وقواعد تنبيهات Prometheus (`--bgp`).
- **المسار السريع لنواة WireGuard مع eBPF والتسريع التشفيري (`WG-FAST-001..012`)**
  - *التدقيق*: التسريع الشعاعي عبر تعليمات SIMD لـ ChaCha20-Poly1305 (مثل AVX-512 و ARM Neon)، وخطافات eBPF/XDP الأصلية، وشبكات 100GbE التراكبية.
  - *المعالجة والتخفيف*: يرصد التراجع إلى التشفير القياسي، وتشبع مقاطعات SoftIRQ (> 70%)، وفيضان قوائم الانتظار في الذاكرة المؤقتة (`CVE-2026-31049`).
  - *التوليد والتركيب*: وحدات المسار السريع المحصنة لنظام NixOS وبرامج eBPF XDP المعتمدة بلغة C (`--wg-fastpath`).
- **رادار تهديدات Kubernetes Ingress و Gateway API و EnvoyFilter**
  - *التدقيق*: موارد `Gateway` و `HTTPRoute` و `GRPCRoute` و `ReferenceGrant` وقواعد Istio `EnvoyFilter`.
  - *المعالجة والتخفيف*: يحظر حقن القصاصات البرمجية (`CVE-2023-5044`)، واختطاف المسارات بين مساحات الأسماء (`CVE-2026-44219`)، ونصوص Lua العشوائية، وهجمات تجاوز المسارات (`--gw`, `--k8s`).

### 3. 🔐 التشفير، الحوسبة السرية وإدارة الهوية

- **التشفير ما بعد الكمومي (PQC) والتحول لمعايير NSA CNSA 2.0**
  - *التدقيق*: معلمات TLS لطبقة التحكم، وتفعيل موفر `oqsprovider` في OpenSSL لنظام NixOS، وأولويات GnuTLS.
  - *المعالجة والتخفيف*: الحماية من هجمات فك التشفير اللاحق (Harvest Now, Decrypt Later - HNDL) (`CVE-2026-94301`).
  - *التوليد والتركيب*: تعريفات بروتوكول TLS الهجين ML-KEM/Kyber والامتثال لمراحل معيار CNSA 2.0 (`--pqc`).
- **توثيق الأجهزة الافتراضية السرية لأنفاق WireGuard (`WG-ENC-001..012`)**
  - *التدقيق*: سلاسل شهادات AMD SEV-SNP VCEK، وشهادات إثبات Intel TDX، ومطابقات PCR للإقلاع المقاس.
  - *المعالجة والتخفيف*: ربط مفاتيح الجلسات المؤقتة بتقارير الحجرات الآمنة، ورفض الأنفاق المعدلة أو غير الموثقة (`CVE-2026-40291`).
  - *التوليد والتركيب*: وحدات NixOS المعززة ونصوص التحقق البرمجية قبل بدء المصافحة (`--wg-enclave`).
- **التقسيم الدقيق بنموذج الثقة المعدومة وتوثيق SPIFFE/SPIRE**
  - *التدقيق*: معرفات SPIFFE المتوافقة مع معايير RFC، ووضع mTLS الإلزامي في Cilium، ونوافذ صلاحية وثائق SVID.
  - *المعالجة والتخفيف*: إزالة محددات البطاقات المعممة الخطرة (`k8s:ns:*`) ومنع انقطاع الخدمات الناجم عن فقدان تزامن الشهادات (`CVE-2026-67210`) (`--spiffe-policy-out`).
- **وحدات أمان العتاد (HSM) وتشفير الأظرف عبر PKCS#11**
  - *التدقيق*: ملفات `EncryptionConfiguration` لبيانات etcd، ومكونات KMS v2 الإضافية، وحجرات AWS Nitro (`CVE-2026-83190`) (`--hsm`).
- **مزامنة أساطيل المجموعات المتعددة ورادار رموز OIDC**
  - *التدقيق*: أذونات التحكم في الوصول (RBAC) متعدد المستأجرين، وخوارزميات توقيع OIDC الاتحادية، وانحرافات GitOps في ArgoCD/Flux (`CVE-2026-60114`) (`--fleet`).

### 4. 📦 سلسلة التوريد التعريفية والتخزين غير القابل للتغيير

- **عزل مخزن Nix متعدد المستأجرين وأمان الذاكرة المؤقتة الثنائية (`NIX-STORE-001..012`)**
  - *التدقيق*: معلمات خدمة Nix (`nix.settings.*`, `nix.conf`)، والتحقق من توقيعات Ed25519، وبيانات خوادم البدائل (substituters).
  - *المعالجة والتخفيف*: يمنع تسميم الذاكرة المؤقتة ببدائل غير موقعة (`CVE-2026-81930`)، وحركات مرور HTTP غير المشفرة، وهروب بيئة العزل.
  - *التوليد والتركيب*: وحدات NixOS المحصنة، وقوالب إعدادات `/etc/nix/nix.conf`، وتنبيهات Prometheus (`--nixstore`).
- **الجذر غير القابل للتغيير في NixOS والتخزين المؤقت (Impermanence) (`IMP-ROOT-001..012`)**
  - *التدقيق*: تعريفات استمرارية البيانات (`environment.persistence`) وعمليات ربط `hostPath` على المجموعة.
  - *المعالجة والتخفيف*: يفرض جذراً مستنداً إلى `tmpfs` في الذاكرة العشوائية، ويكشف تسريبات hostPath إلى نظام الملفات المؤقت (`CVE-2026-61842`)، ويمنع استخدام مساحة التبديل (swap) غير المشفرة.
  - *التوليد والتركيب*: وحدات Impermanence المحصنة، وخطافات تنظيف initrd عند الإقلاع، ومراقبة مساحات التخزين (`--impermanence`).
- **قوائم مكونات البرمجيات (SBOM) وتوثيق In-Toto SLSA Level 3**
  - *التدقيق*: وثائق SPDX v3.0 و CycloneDX v1.6 ومطابقتها مع حزم Nix والشهادات المشفرة لـ In-Toto.
  - *المعالجة والتخفيف*: يكشف التلاعب في مخرجات البناء البرمجية (`CVE-2026-71044`) وانحرافات الإصدارات في الإنتاج (`--sbom`).

### 5. 🤖 قبول أعباء العمل والتعافي من الكوارث والمعالجة التلقائية

- **رادار خطافات القبول الديناميكية وتدوير مراجع الشهادات (`WH-RADAR-001..012`)**
  - *التدقيق*: ملفات `ValidatingWebhookConfiguration` و `MutatingWebhookConfiguration` وتواريخ صلاحية شهادات X.509 CA.
  - *المعالجة والتخفيف*: يزيل إعدادات التجاوز الخطرة `failurePolicy: Ignore` (`CVE-2026-52194`)، والمهلات المفرطة (> 3 ثوانٍ)، وتجمد بدء التشغيل.
  - *التوليد والتركيب*: خطافات ويب آمنة ومقاومة للأعطال، وموارد cert-manager المؤتمتة، ومراقبة زمن الاستجابة (`--webhook`).
- **جدولة اللقطات الفورية لـ CephFS والتعافي من الكوارث عبر المناطق الجغرافية (`CEPH-DR-001..012`)**
  - *التدقيق*: جداول اللقطات لـ CephFS، وفئات تكرار أحجام التخزين CSI، والمزامنة التفاضلية بين المناطق.
  - *المعالجة والتخفيف*: يمنع سياسات الحذف المدمرة لأهداف نقطة الاسترداد RPO (`deletionPolicy: Delete`) وحالات انقسام الدماغ (Split-Brain) (`CVE-2026-10140`).
  - *التوليد والتركيب*: فئات اللقطات المحصنة، والتكرار المشفر، وقواعد مكافحة التآلف لشياطين النسخ المتطابق (`--dr`).
- **بيئة MicroVM المعزولة المؤقتة وتفجير الأفخاخ الاستدراجية (Honeypot)**
  - *التدقيق*: عزل Firecracker MicroVMs، ومعلمات السجان (jailer)، والأهداف الوهمية المحاكية لـ Kubelet و etcd.
  - *المعالجة والتخفيف*: يعزل الحاويات المشبوهة ويكتشف محاولات الهروب من المراقِب (Hypervisor) عبر MMIO (`CVE-2026-97105`) (`--sandbox-synth-out`).
- **المعالجة الذاتية التلقائية ومولد طلبات السحب (GitOps PR)**
  - *آلية العمل*: التحقق المسبق عبر عينات كناري (`pkg/remediate/canary.go`)، والتقييم النقي لـ Nix Flake، واختبارات التشغيل الجاف عبر `kubectl kustomize`.
  - *المخرجات*: طلبات سحب ذرية غير مدمرة (`remediation/*`)، وتصحيحات Kustomize الاستراتيجية، وتصحيحات RFC 6902 JSONPatches (`CVE-2026-98402`) (`--remediate`).

---

## 🚀 البدء السريع

### المتطلبات الأساسية
- تثبيت محلي للغة Go بإصدار 1.22 فما فوق.

### البناء والتشغيل
```bash
# استنساخ المستودع
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# تشغيل حزمة الاختبارات
go test ./...

# فحص موجز التهديدات المباشر
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# تدقيق ملف flake.lock لاكتشاف الثغرات الأمنية
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# فحص ملفات Kubernetes لاكتشاف ثغرات Ingress و CNI
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# تدقيق سياسات CiliumNetworkPolicy ومحللات تدفقات eBPF
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml

# مطابقة قياسات eBPF وتوليد السياسات المحصنة
go run cmd/sentinel/main.go --flow=fixtures/cilium-flow-vulnerable.yaml --flow-telemetry=fixtures/flow-telemetry.json --flow-synth-out=policies/generated/flow --format=sarif --output=flow-results.sarif

# تدقيق تأمين نواة Linux وقاعدة بيانات UEFI Secure Boot DBX
go run cmd/sentinel/main.go --lockdown=fixtures/nixos-lockdown-vulnerable.nix --lockdown-telemetry=fixtures/lockdown-telemetry.json --lockdown-synth-out=policies/generated/lockdown

# تدقيق عزل مخزن Nix والذاكرة المؤقتة الثنائية
go run cmd/sentinel/main.go --nixstore=fixtures/nixos-store-vulnerable.nix --nixstore-telemetry=fixtures/nixstore-telemetry.json --nixstore-synth-out=policies/generated/nixstore

# تدقيق جذر NixOS غير القابل للتغيير ومسارات hostPath
go run cmd/sentinel/main.go --impermanence=fixtures/nixos-impermanence-vulnerable.nix --impermanence-telemetry=fixtures/impermanence-telemetry.json --impermanence-synth-out=policies/generated/impermanence

# تدقيق خطافات القبول الديناميكية في Kubernetes
go run cmd/sentinel/main.go --webhook=fixtures/k8s-admission-webhook-vulnerable.yaml --webhook-telemetry=fixtures/webhook-telemetry.json --webhook-synth-out=policies/generated/webhook

# تدقيق توثيق عقد WireGuard في الأجهزة الافتراضية السرية (SEV-SNP / TDX)
go run cmd/sentinel/main.go --wg-enclave=fixtures/nixos-wg-enclave-vulnerable.nix --wg-enclave-telemetry=fixtures/wg-enclave-telemetry.json --wg-enclave-synth-out=policies/generated/enclave

# تدقيق المسار السريع لـ WireGuard وتسريع العمليات التشفيرية
go run cmd/sentinel/main.go --wg-fastpath=fixtures/nixos-wg-fastpath-vulnerable.nix --wg-fastpath-telemetry=fixtures/wg-fastpath-telemetry.json --wg-fastpath-synth-out=policies/generated/fastpath

# تدقيق سياسات اقتران Cilium BGP وتكوينات FRR
go run cmd/sentinel/main.go --bgp=fixtures/cilium-bgp-vulnerable.yaml --bgp-telemetry=fixtures/bgp-telemetry.json --bgp-synth-out=policies/generated/bgp

# تشغيل فحص القياسات عن بُعد بتقنية eBPF على مستوى المجموعة بالكامل
go run cmd/sentinel/main.go --probe --format=sarif --output=probe-results.sarif

# تصدير النتائج بصيغة OASIS SARIF v2.1.0 لمنصة GitHub Code Scanning
go run cmd/sentinel/main.go --k8s=fixtures/ --format=sarif --output=results.sarif

# إنشاء تقرير تدقيق شامل بصيغة JSON
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/ --format=json

# توليد موجز أمني آلي كل ساعة
go run cmd/sentinel/main.go --briefing
```

---

## 🗺️ خارطة الطريق والتطوير المستمر

للاطلاع على خارطة الطريق النشطة والمحطات القادمة، يرجى مراجعة [ROADMAP.md](../../ROADMAP.md).

---

## 🔒 سياسة الأمان

للإبلاغ عن الثغرات الأمنية ومراجعة إرشادات الأمان المعتمدة لدينا، يرجى مراجعة [SECURITY.md](../../SECURITY.md).
