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
  <strong>🇧🇷 Português</strong> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Scanner declarativo de vulnerabilidades e radar de inteligência de ameaças em tempo real para NixOS e Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.4.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](./SECURITY.md)

</div>

---

## ⚡ Visão geral

O `nix-k8s-sentinel` é um mecanismo de alto desempenho para auditoria declarativa de vulnerabilidades e sincronização contínua de inteligência de ameaças, projetado especificamente para clusters bare-metal NixOS e infraestruturas Kubernetes.

Diferente dos scanners de contêineres convencionais que inspecionam camadas efêmeras após a implantação, o `nix-k8s-sentinel` audita matrizes declarativas de configuração (bloqueios do NixOS Flakes, políticas de rede CNI e controladores Ingress) em relação a feeds normalizados de ameaças CVSS em tempo real, permitindo a mitigação automatizada antes do agendamento das cargas de trabalho.

---

## 🏛️ Recursos principais

- **🔍 Auditoria declarativa de infraestrutura**: Correspondência de padrões e rastreamento de dependências para entradas NixOS Flake e manifestos Kubernetes.
- **🌐 Segurança de Kubernetes Ingress e Políticas CNI**: Detecção automatizada de injeções de snippets, desvios de diretório URI, falhas CORS/SSL e vazamentos de dados 0.0.0.0/0.
- **📊 Relatórios horários automatizados de inteligência de ameaças**: Síntese de matrizes de risco CVSS e manuais de mitigação em Markdown sob `intel/briefings/`.
- **📡 Ingestão normalizada de ameaças**: Ingestão estruturada de pontuações CVSS v3.1, mapeamento de componentes e recomendações práticas de remediação.
- **🛡️ Síntese ativa de políticas de segurança**: Geração automatizada de regras em tempo de execução para Falco e políticas de admissão para OPA Gatekeeper a partir de assinaturas detectadas.
- **⚡ Motor Go com zero alocações**: Binário autônomo de alta concorrência sem dependências externas de tempo de execução.

---

## 🚀 Início rápido

### Pré-requisitos
- Go 1.22+ instalado localmente.

### Compilação e execução
```bash
# Clonar o repositório
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Executar a suíte de testes
go test ./...

# Inspecionar feed de ameaças em tempo real
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Auditar NixOS flake.lock em relação a avisos conhecidos de segurança
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Auditar manifestos do Kubernetes
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml
go run cmd/sentinel/main.go --k8s=fixtures/

# Gerar relatório horário de inteligência de ameaças
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# Filtrar por infraestrutura de destino
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ Roteiro e evolução contínua

Consulte [ROADMAP.md](./ROADMAP.md) para acompanhar o roteiro ativo de desenvolvimento, os próximos analisadores de entradas Flake e as sondas eBPF para servidores bare-metal.

---

## 🔒 Política de segurança

Para procedimentos de divulgação responsável e reporte de vulnerabilidades, consulte [SECURITY.md](./SECURITY.md).
