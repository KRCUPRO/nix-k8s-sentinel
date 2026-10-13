<div align="center">

<p align="center">
  <a href="./README.md">🇺🇸 English</a> ·
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

**فاحص تصريحي للثغرات الأمنية ورادار استخبارات التهديدات اللحظية لأنظمة NixOS وKubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.3.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ نظرة عامة

يُعد `nix-k8s-sentinel` محركاً عالي الأداء للفحص التصريحي للثغرات الأمنية ومزامنة استخبارات التهديدات المستمرة، والمصمم خصيصاً لمجموعات خوادم NixOS الفيزيائية (Bare-Metal) وبيئات Kubernetes السحابية.

على عكس فاحصات الحاويات التقليدية التي تفحص الطبقات المؤقتة بعد النشر، يقوم `nix-k8s-sentinel` بالتدقيق المباشر في مصفوفات الإعدادات التصريحية (ملفات NixOS Flake المقفولة، وسياسات شبكات CNI، ومتحكمات Ingress) ومقارنتها بمصادر تهديدات CVSS المعيارية في الوقت الفعلي، مما يتيح المعالجة التلقائية قبل جدولة أحمال العمل.

---

## 🏛️ القدرات الأساسية

- **🔍 تدقيق البنية التحتية التصريحية**: مطابقة الأنماط وتتبع التبعيات لمدخلات NixOS Flake ومخططات Kubernetes.
- **📡 استيعاب التهديدات المعياري**: معالجة مهيكلة لتقييمات CVSS v3.1، وتعيين المكونات، وتقديم إرشادات المعالجة القابلة للتطبيق.
- **🛡️ التوليف النشط للسياسات الأمنية**: توليد تلقائي لقواعد Falco أثناء التشغيل وسياسات قيود OPA Gatekeeper بناءً على بصمات التهديدات المكتشفة.
- **⚡ محرك Go بدون تخصيصات ذاكرة إضافية**: ملف تنفيذي مستقل عالي التزامن وبدون أي تبعيات تشغيلية خارجية.

---

## 🚀 البدء السريع

### المتطلبات الأساسية
- تثبيت Go 1.22+ محلياً.

### البناء والتشغيل
```bash
# استنساخ المستودع
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# تشغيل حزمة الاختبارات
go test ./...

# فحص موجز التهديدات اللحظي
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# تدقيق ملف NixOS flake.lock مقابل التحذيرات الأمنية المعروفة


go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml

# التصفية حسب البنية التحتية المستهدفة
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ خارطة الطريق والتطوير المستمر

يرجى مراجعة [ROADMAP.md](./ROADMAP.md) للاطلاع على خطة التطوير الحالية ومحللات مدخلات Flake المستقبلية ومجسات eBPF للخوادم الفيزيائية.

---

## 🔒 سياسة الأمان

للتعرف على إجراءات الإبلاغ عن الثغرات الأمنية وإرشادات الإفصاح المسؤول، يُرجى الرجوع إلى [SECURITY.md](./SECURITY.md).
