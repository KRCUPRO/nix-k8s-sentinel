<div align="center">

<p align="center">
  <a href="./README.md">🇺🇸 English</a> ·
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

**Декларативный сканер уязвимостей и радар киберугроз реального времени для NixOS и Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.5.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Обзор

`nix-k8s-sentinel` — это высокопроизводительный движок декларативного аудита уязвимостей и непрерывной синхронизации данных о киберугрозах, разработанный специально для bare-metal кластеров NixOS и инфраструктуры Kubernetes.

В отличие от традиционных сканеров контейнеров, проверяющих эфемерные слои уже после развертывания, `nix-k8s-sentinel` сопоставляет декларативные конфигурации (файлы `flake.lock` в NixOS, сетевые политики CNI и контроллеры Ingress) с нормализованными фидами уязвимостей CVSS в режиме реального времени, обеспечивая автоматическое устранение угроз до запуска рабочих нагрузок.

---

## 🏛️ Ключевые возможности

- **🔍 Декларативный аудит инфраструктуры**: Сопоставление шаблонов и отслеживание зависимостей в NixOS Flake lock и манифестах Kubernetes.
- **🌐 Аудит безопасности Kubernetes Ingress и политик CNI**: Автоматическое обнаружение инъекций сниппетов, обхода путей URI, небезопасных конфигураций CORS/SSL и утечек данных 0.0.0.0/0.
- **📊 Автоматические ежечасные сводки угроз**: Формирование структурированных отчетов Markdown с матрицами риска CVSS и рекомендациями в `intel/briefings/`.
- **📡 Нормализованный сбор данных об угрозах**: Структурированная обработка оценок CVSS v3.1, сопоставление компонентов и практические рекомендации по устранению.
- **🛡️ Активный синтез политик безопасности**: Автоматическая генерация правил времени выполнения для Falco и политик OPA Gatekeeper на основе обнаруженных сигнатур.
- **⚡ Движок Go с нулевым выделением памяти**: Высококонкурентный автономный бинарный файл без внешних зависимостей.

---

## 🚀 Быстрый старт

### Требования
- Установленный локально Go 1.22+.

### Сборка и запуск
```bash
# Клонирование репозитория
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Запуск набора тестов
go test ./...

# Просмотр ленты угроз в реальном времени
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Аудит NixOS flake.lock на известные бюллетени безопасности
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Аудит манифестов Kubernetes на нарушение политик безопасности
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml
go run cmd/sentinel/main.go --k8s=fixtures/

# Генерация ежечасной сводки киберугроз
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# Фильтрация по целевой инфраструктуре
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ План развития

Актуальный план разработки, планы по парсерам входных данных Flake и зондам eBPF для bare-metal представлены в [ROADMAP.md](./ROADMAP.md).

---

## 🔒 Политика безопасности

Процедуры сообщения об уязвимостях и рекомендации по раскрытию информации приведены в [SECURITY.md](./SECURITY.md).
