# 🔍 Log Security Analyzer

A Python CLI tool to analyze log files and detect security threats: brute force attacks, suspicious IPs, port scans, and HTTP attacks (SQLi, XSS, path traversal).

**Author:** Belaid AZIL — L3 Computer Science, Université de Caen Normandie

---

## 🚀 Features

- 🔴 **Brute Force Detection** — Detects repeated failed login attempts (SSH, generic)
- 🟠 **Suspicious IP Detection** — Identifies port scans, 404 enumeration, sensitive path access
- 🔴 **HTTP Attack Detection** — SQL Injection, XSS, Path Traversal attempts
- 📊 **Statistics** — Top IPs, event types, HTTP status codes
- 💾 **JSON Export** — Full report exportable to JSON
- 🧪 **Demo Mode** — Built-in sample log generator for testing

---

## 📦 Installation

```bash
git clone https://github.com/Azilbelaid/log-security-analyzer.git
cd log-security-analyzer
```

No external dependencies — uses Python standard library only.

---

## ▶️ Usage

```bash
# Analyze a real log file
python3 log_analyzer.py /var/log/auth.log

# Export report to JSON
python3 log_analyzer.py /var/log/auth.log --json report.json

# Run demo with sample logs
python3 log_analyzer.py --demo
```

### Example Output

```
============================================================
  🔍 LOG SECURITY ANALYZER — Rapport d'analyse
  📅 2026-03-20 14:32:00
============================================================

📊 STATISTIQUES GLOBALES
   Événements analysés : 20
   SSH_FAILED               : 14
   SSH_INVALID_USER         : 5
   SSH_SUCCESS              : 1

🔴 ATTAQUES BRUTE FORCE DÉTECTÉES : 2

  🔴 CRITIQUE | IP : 172.16.0.55
  Tentatives  : 8
  Première    : Mar 20 10:02:00
  Dernière    : Mar 20 10:02:07
```

---

## 🛡️ Supported Log Formats

| Format | Events Detected |
|--------|----------------|
| SSH (`/var/log/auth.log`) | Failed passwords, invalid users, successful logins |
| Apache Access Log | HTTP 404 floods, SQLi, XSS, path traversal |
| Generic logs | FAIL / ERROR / DENIED events with IPs |

---

## 🧰 Technologies

| Tool | Usage |
|------|-------|
| Python 3 | Core language |
| `re` | Log parsing with regex |
| `collections` | IP frequency analysis |
| `json` | Report export |
| `argparse` | CLI interface |

---

## 📁 Project Structure

```
log-security-analyzer/
├── log_analyzer.py    # Main script
├── .gitignore
└── README.md
```

---

## 📜 License

MIT License
