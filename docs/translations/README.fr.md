<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> ·
  <a href="./README.ko.md">🇰🇷 한국어</a> ·
  <a href="./README.ja.md">🇯🇵 日本語</a> ·
  <a href="./README.zh.md">🇨🇳 简体中文</a> ·
  <a href="./README.es.md">🇪🇸 Español</a><br />
  <strong>🇫🇷 Français</strong> ·
  <a href="./README.de.md">🇩🇪 Deutsch</a> ·
  <a href="./README.ru.md">🇷🇺 Русский</a> ·
  <a href="./README.pt.md">🇧🇷 Português</a> ·
  <a href="./README.ar.md">🇸🇦 العربية</a>
</p>

# 🛡️ nix-k8s-sentinel

**Scanner déclaratif de vulnérabilités et radar de cybermenaces en temps réel pour NixOS & Kubernetes**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/KRCUPRO/nix-k8s-sentinel)](https://goreportcard.com/report/github.com/KRCUPRO/nix-k8s-sentinel)
[![Version](https://img.shields.io/badge/Release-v0.7.0-emerald.svg)](https://github.com/KRCUPRO/nix-k8s-sentinel/releases)
[![Architecture](https://img.shields.io/badge/Architecture-Bare--Metal_NixOS_+_K8s-8b5cf6.svg)](#-architecture-overview)
[![Security](https://img.shields.io/badge/Security-Declarative_Audit-38bdf8.svg)](../../SECURITY.md)

</div>

---

## ⚡ Présentation

`nix-k8s-sentinel` est un moteur haute performance d'audit déclaratif des vulnérabilités et de synchronisation continue des cybermenaces, spécialement conçu pour les clusters bare-metal NixOS et les infrastructures Kubernetes.

Contrairement aux scanners de conteneurs traditionnels qui inspectent les couches éphémères après le déploiement, `nix-k8s-sentinel` audite les matrices de configuration déclaratives (fichiers `flake.lock` NixOS, politiques réseau CNI et contrôleurs Ingress) par rapport à des flux de menaces CVSS normalisés en temps réel, permettant une remédiation automatisée avant même la planification des charges de travail.

---

## 🏛️ Fonctionnalités clés

- **🔍 Audit déclaratif de l'infrastructure**: Correspondance de motifs et traçabilité des dépendances pour les entrées NixOS Flake et les manifestes Kubernetes.
- **🌐 Sécurité Kubernetes Ingress et Politiques CNI**: Détection automatisée des injections de snippets, traversées de répertoires URI, mauvaises configurations CORS/SSL et fuites de données 0.0.0.0/0.
- **📊 Rapports horaires automatisés de cybermenaces**: Synthèse de matrices de télémétrie des risques CVSS et guides de remédiation en Markdown sous `intel/briefings/`.
- **📡 Ingestion normalisée des menaces**: Traitement structuré des scores CVSS v3.1, cartographie des composants et avis de remédiation directement applicables.
- **🛡️ Synthèse active de politiques de sécurité**: Génération automatisée de règles de détection au runtime pour Falco et de contraintes d'admission OPA Gatekeeper.
- **⚡ Moteur Go à allocation zéro**: Binaire autonome hautement concurrentiel, sans aucune dépendance d'exécution externe.

---

## 🚀 Démarrage rapide

### Prérequis
- Go 1.22+ installé localement.

### Compilation et exécution
```bash
# Cloner le dépôt
git clone https://github.com/KRCUPRO/nix-k8s-sentinel.git
cd nix-k8s-sentinel

# Exécuter la suite de tests
go test ./...

# Inspecter le flux de menaces en temps réel
go run cmd/sentinel/main.go --feed=intel/cve-feed.json

# Auditer un fichier NixOS flake.lock par rapport aux avis de sécurité connus
go run cmd/sentinel/main.go --flake=fixtures/flake.lock

# Auditer les manifestes Kubernetes
go run cmd/sentinel/main.go --k8s=fixtures/k8s-ingress-vulnerable.yaml
go run cmd/sentinel/main.go --k8s=fixtures/

# Générer le rapport horaire d'intelligence des cybermenaces
go run cmd/sentinel/main.go --briefing
go run cmd/sentinel/main.go --flake=fixtures/flake.lock --k8s=fixtures/k8s-ingress-vulnerable.yaml --briefing

# Filtrer par infrastructure cible
go run cmd/sentinel/main.go --target=kubernetes
go run cmd/sentinel/main.go --target=nixos
```

---

## 🗺️ Feuille de route et évolution

Consultez [ROADMAP.md](../../ROADMAP.md) pour découvrir les évolutions prévues, les futurs analyseurs d'entrées Flake et les sondes eBPF pour bare-metal.

---

## 🔒 Politique de sécurité

Pour les procédures de signalement des vulnérabilités et les règles de divulgation responsable, veuillez consulter [SECURITY.md](../../SECURITY.md).
