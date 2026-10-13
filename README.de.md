<div align="center">

<p align="center">
  <a href="./README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <a href="./README.fr.md">🇫🇷 Français</a> ·
  <strong>🇩🇪 Deutsch</strong> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Deklarativer Schwachstellen-Scanner & Echtzeit-Bedrohungsanalyse für NixOS und Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.2.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Übersicht

`nix-k8s-sentinel` ist eine hochperformante Engine für deklarative Schwachstellenanalysen und kontinuierliche Bedrohungssynchronisation, die speziell für Bare-Metal-NixOS-Cluster und Kubernetes-Infrastrukturen entwickelt wurde.

Im Gegensatz zu herkömmlichen Container-Scannern, die ephemere Schichten erst nach dem Deployment prüfen, auditiert `nix-k8s-sentinel` deklarative Konfigurationsmatrizen (NixOS Flakes, Kubernetes CNI-Netzwerkrichtlinien und Ingress-Controller) gegen normalisierte CVSS-Echtzeit-Feeds, um automatische Gegenmaßnahmen bereits vor dem Workload-Scheduling einzuleiten.

---

## 🏛️ Kernfunktionen

- **🔍 Deklarative Infrastruktur-Audits**: Mustererkennung und Abhängigkeitsanalyse für NixOS Flake-Locks und Kubernetes-Manifeste.
- **📡 Normalisierte Bedrohungsdaten-Erfassung**: Strukturierte Verarbeitung von CVSS v3.1-Bewertungen, Komponentenzuordnungen und praxisnahen Behebungshinweisen.
- **🛡️ Aktive Richtliniensynthese**: Automatische Generierung von Falco-Laufzeiterkennungsregeln und OPA Gatekeeper-Zulassungsbeschränkungen anhand erkannter Bedrohungssignaturen.
- **⚡ Zero-Allocation Go-Engine**: Hochgradig nebenläufige Standalone-Binärdatei ohne externe Laufzeitabhängigkeiten.

---

## 🚀 Schnellstart

### Voraussetzungen
- Lokal installiertes Go 1.22+.

### Erstellen und Ausführen
```bash
# Repository klonen
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Testsuite ausführen
go test ./...

# Echtzeit-Bedrohungsfeed einsehen
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# NixOS flake.lock gegen bekannte Sicherheitswarnungen auditieren
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Nach Zielinfrastruktur filtern
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ Roadmap und Weiterentwicklung

Informationen zur aktiven Entwicklungs-Roadmap, künftigen Flake-Input-Parsern und Bare-Metal-eBPF-Sonden finden Sie in [ROADMAP.md](./ROADMAP.md).

---

## 🔒 Sicherheitsrichtlinie

Hinweise zur Meldung von Sicherheitslücken und Veröffentlichungsrichtlinien entnehmen Sie bitte [SECURITY.md](./SECURITY.md).
