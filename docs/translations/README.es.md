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

**Escáner declarativo de vulnerabilidades e inteligencia de amenazas en tiempo real para NixOS y Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.7.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Descripción general

`nix-k8s-sentinel` es un motor de alto rendimiento para el análisis declarativo de vulnerabilidades y la sincronización continua de inteligencia de amenazas, diseñado específicamente para clústeres bare-metal con NixOS e infraestructuras Kubernetes.

A diferencia de los escáneres de contenedores tradicionales que inspeccionan capas efímeras tras el despliegue, `nix-k8s-sentinel` audita matrices de configuración declarativas (bloqueos de NixOS Flakes, políticas de red CNI e Ingress de Kubernetes) frente a fuentes normalizadas de amenazas CVSS en tiempo real, permitiendo una mitigación automatizada antes de que las cargas de trabajo sean programadas.

---

## 🏛️ Capacidades principales

- **🔍 Auditoría declarativa de infraestructura**: Coincidencia de patrones y seguimiento de dependencias en archivos `flake.lock` de NixOS y manifiestos de Kubernetes.
- **🌐 Seguridad de Kubernetes Ingress y Políticas CNI**: Detección automatizada de inyecciones de snippets, saltos de directorio URI, fallos CORS/SSL y fugas de datos 0.0.0.0/0.
- **📊 Informes horarios automatizados de inteligencia de amenazas**: Generación de matrices de telemetría de riesgo CVSS y manuales de mitigación en Markdown bajo `intel/briefings/`.
- **📡 Ingesta normalizada de amenazas**: Ingesta estructurada de puntuaciones CVSS v3.1, asignación de componentes y avisos de remediación aplicables.
- **🛡️ Síntesis activa de políticas**: Generación automática de reglas de detección en tiempo de ejecución para Falco y políticas de admisión para OPA Gatekeeper a partir de firmas detectadas.
- **⚡ Motor Go de cero asignaciones**: Binario independiente de alta concurrencia sin dependencias externas en tiempo de ejecución.

---

## 🚀 Inicio rápido

### Requisitos previos
- Go 1.22+ instalado localmente.

### Compilación y ejecución
```bash
# Clonar el repositorio
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Ejecutar suite de pruebas
go test ./...

# Inspeccionar fuentes de amenazas en tiempo real
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Auditar NixOS flake.lock frente a avisos de seguridad conocidos
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Auditar manifiestos de Kubernetes
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml
go run cmd/sentinel/main.go --k8s=fixtures/

# Generar informe horario de inteligencia de amenazas
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# Filtrar por infraestructura objetivo
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ Hoja de ruta y evolución continua

Consulte [ROADMAP.md](../../ROADMAP.md) para conocer la hoja de ruta de desarrollo activa, los próximos analizadores de entradas Flake y las sondas eBPF para servidores bare-metal.

---

## 🔒 Política de seguridad

Para conocer los procedimientos de notificación de vulnerabilidades y las directrices de divulgación, consulte [SECURITY.md](../../SECURITY.md).
