# 🕵️ OSINT Infrastructure Mapper v7

> **Investigation OSINT & Infrastructure Mapping**  
> Reconstruire l'infrastructure d'un attaquant à partir de sources ouvertes.

---

## 🎯 Objectif

Pipeline complet : **IP Suspecte → Domaines & Emails → Attribution du groupe de menace**

---

## 📁 Structure des fichiers

```
osint_mapper/
├── index.php          ← Page principale (investigation complète)
├── dashboard.php      ← Tableau de bord & statistiques
├── compare.php        ← Comparaison de 2 IPs côte à côte
├── about.php          ← Documentation des outils & APIs
├── api_external.php   ← Proxy backend pour APIs externes
├── clear-data.php     ← Utilitaire de réinitialisation
├── history.json       ← Généré automatiquement (historique)
└── README.md
```

---

## 🚀 Installation

### Prérequis
- PHP 7.4+ avec extensions : `curl`, `json`, `filter`
- Serveur web : Apache / Nginx / XAMPP / WAMP / Laragon

### Lancement rapide (XAMPP)
```bash
# Copier dans htdocs/
cp -r osint_mapper/ C:/xampp/htdocs/

# Ouvrir dans le navigateur
http://localhost/osint_mapper/
```

### Lancement avec PHP built-in server
```bash
cd osint_mapper/
php -S localhost:8080
# Ouvrir http://localhost:8080
```

---

## 🔌 APIs & Configuration

Ouvrir `api_external.php` et renseigner les clés :

```php
define('VT_API_KEY',    'votre_clé_virustotal');   // virustotal.com
define('ABUSEIPDB_KEY', 'votre_clé_abuseipdb');   // abuseipdb.com
define('SHODAN_KEY',    'votre_clé_shodan');       // shodan.io
define('HUNTER_KEY',   'votre_clé_hunter');        // hunter.io
```

> **Sans clés** → Mode démo automatique (données simulées réalistes)

### Obtenir les clés gratuitement
| API | Lien | Plan gratuit |
|-----|------|-------------|
| VirusTotal | https://www.virustotal.com/gui/join-us | 4 req/min |
| AbuseIPDB | https://www.abuseipdb.com/register | 1000 req/jour |
| Shodan | https://account.shodan.io/register | Limité |
| Hunter.io | https://hunter.io/users/sign_up | 25 req/mois |

---

## 🛠️ Outils intégrés

| Outil | Usage dans le projet |
|-------|---------------------|
| **Maltego** | Graphe Canvas interactif (IP → Domaines → Emails → Acteur) |
| **Shodan** | Détection OS, bannières, ports, CVEs |
| **VirusTotal** | Score de réputation, détections multi-moteurs |
| **SpiderFoot** | Méthodologie du pipeline (IP → enrichissement → attribution) |
| **AbuseIPDB** | Score d'abus, catégories d'attaques, historique |
| **Hunter.io** | Découverte d'emails associés au domaine |

---

## 📊 Fonctionnalités

- ✅ Géolocalisation réelle (ip-api.com)
- ✅ Scan de 16 ports TCP (fsockopen)
- ✅ Reverse DNS / PTR Record
- ✅ Analyse VirusTotal (70+ moteurs)
- ✅ Score AbuseIPDB avec catégories
- ✅ Renseignement Shodan (OS, bannières, CVEs)
- ✅ Découverte de domaines associés
- ✅ Découverte d'emails (Hunter.io)
- ✅ **Attribution** — Threat Actor Groups + MITRE ATT&CK TTPs
- ✅ **Graphe Maltego** interactif (Canvas HTML5)
- ✅ Export JSON & PDF
- ✅ Dashboard statistiques (Chart.js)
- ✅ Comparaison de 2 IPs côte à côte
- ✅ Historique des investigations (JSON)

---

## 🔒 Sécurité

- Validation stricte des IPs (FILTER_VALIDATE_IP + no private range)
- Rate limiting basique (20 req/min)
- Fichiers JSON protégés (ajouter `.htaccess` en production)
- Aucune exécution de commandes système

---

## 📝 Notes pédagogiques

Ce projet est développé dans un cadre **académique** pour le cours de Sécurité Informatique.  
Les données Shodan, VirusTotal, AbuseIPDB et Hunter.io sont **simulées** en mode démo  
(seed déterministe basé sur l'IP) pour illustrer le workflow OSINT réel.

---

*OSINT Infrastructure Mapper v7 · Sécurité Informatique 2025/2026*
