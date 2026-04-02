# 🛡️ Web SIEM Detection Rules — Splunk Enterprise

[![Rules: 15](https://img.shields.io/badge/Splunk%20Rules-15-blue?style=flat-square&logo=splunk)](./rules/)
[![Platform: Ubuntu](https://img.shields.io/badge/Platform-Ubuntu-orange?style=flat-square&logo=ubuntu)](https://ubuntu.com/)
[![Web: Nginx+Apache](https://img.shields.io/badge/Web-Nginx%20%2B%20Apache-green?style=flat-square&logo=nginx)](./rules/)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](./LICENSE)

> **Production-grade web attack detection rules** for Ubuntu servers running Nginx and/or Apache.  
> All rules are managed via **GitHub** and deployed to **Splunk Enterprise via REST API**.  
> ⚠️ Rules are **NEVER edited inside Splunk** — only via this repo.

---

## 📁 Repository Structure

```
splunk-web-rules/
├── rules/
│   ├── sql_injection/          # SQLi detection
│   ├── xss/                    # Cross-Site Scripting
│   ├── brute_force/            # Login brute force
│   ├── ddos/                   # HTTP Flood, Slowloris
│   ├── scanning/               # Scanners, 404 enum, traversal, sensitive files
│   ├── rce/                    # Remote Code Execution, Webshell
│   ├── lfi_rfi/                # File Inclusion attacks
│   ├── bot/                    # Credential stuffing, bots
│   └── anomaly/                # 5xx spikes, HTTP smuggling
├── scripts/
│   ├── deploy_to_splunk.py     # Deploy all/filtered rules via API
│   ├── update_rule.py          # Update a single rule via API
│   └── list_rules.py           # List & compare repo vs Splunk
├── docs/
│   └── sourcetype_setup.md     # How to configure Nginx/Apache sourcetypes
├── .github/
│   └── workflows/
│       └── deploy.yml          # CI/CD: auto-deploy on push to main
├── .env.example
├── requirements.txt
└── README.md
```

---

## 📋 Detection Rules (15)

| # | Rule Name | Category | Severity | MITRE |
|---|-----------|----------|----------|-------|
| 01 | SQL Injection Attempt | sql_injection | 🔴 High | T1190 |
| 02 | XSS Attack Attempt | xss | 🔴 High | T1059.007 |
| 03 | Login Brute Force | brute_force | 🔴 High | T1110.001 |
| 04 | HTTP Flood DDoS | ddos | 🔴 Critical | T1498.001 |
| 05 | Directory Traversal | scanning | 🔴 High | T1083 |
| 06 | Web Scanner Detected | scanning | 🟠 Medium | T1595.002 |
| 07 | LFI / RFI Detection | lfi_rfi | 🔴 High | T1190 |
| 08 | Remote Code Execution | rce | 🔴 Critical | T1059 |
| 09 | URL Enumeration (404 scan) | scanning | 🟠 Medium | T1595.003 |
| 10 | Credential Stuffing / Bot | bot | 🔴 High | T1110.004 |
| 11 | Slowloris / Slow HTTP DoS | ddos | 🟠 Medium | T1499.001 |
| 12 | Webshell Upload / Access | rce | 🔴 Critical | T1505.003 |
| 13 | Sensitive File Access | scanning | 🔴 High | T1083 |
| 14 | HTTP 5xx Error Spike | anomaly | 🟠 Medium | T1499 |
| 15 | HTTP Request Smuggling | anomaly | 🟠 Medium | T1190 |

---

## ⚙️ Splunk Sourcetype Configuration

Nginx-i Splunk-a göndərmək üçün `/etc/splunk/inputs.conf`-a əlavə et:

```ini
# Nginx access log
[monitor:///var/log/nginx/access.log]
sourcetype = nginx_access
index = web

# Nginx error log
[monitor:///var/log/nginx/error.log]
sourcetype = nginx_error
index = web

# Apache access log
[monitor:///var/log/apache2/access.log]
sourcetype = apache_access
index = web

# Apache error log
[monitor:///var/log/apache2/error.log]
sourcetype = apache_error
index = web
```

---

## 🚀 Quick Deploy

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USER/splunk-web-rules.git
cd splunk-web-rules

# 2. Set credentials
cp .env.example .env
nano .env   # fill in SPLUNK_HOST, SPLUNK_TOKEN

# 3. Install dependencies
pip install -r requirements.txt

# 4. Deploy ALL 15 rules to Splunk
python scripts/deploy_to_splunk.py --all

# 5. Verify
python scripts/list_rules.py --compare
```

---

## 🔄 Update Workflow

```
Edit rule JSON in GitHub
        ↓
git commit + push to main
        ↓
GitHub Actions CI/CD triggers
        ↓
Only changed rules → Splunk REST API
        ↓
Splunk updated automatically
```

---

## 🔐 GitHub Secrets Required

Go to **Settings → Secrets and Variables → Actions** and add:

| Secret | Example |
|--------|---------|
| `SPLUNK_HOST` | `https://your-server:8089` |
| `SPLUNK_TOKEN` | `your-api-token` |
| `SPLUNK_APP` | `search` |
