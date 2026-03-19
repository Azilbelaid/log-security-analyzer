#!/usr/bin/env python3
"""
Log Security Analyzer
Auteur : Belaid AZIL
Description : Analyse des fichiers de logs pour détecter les attaques brute force,
              les IPs suspectes, les scans de ports et génère des rapports de sécurité.
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────

CONFIG = {
    "brute_force_threshold": 5,      # Tentatives échouées avant alerte
    "scan_threshold": 10,            # Ports différents avant alerte scan
    "time_window_seconds": 60,       # Fenêtre temporelle pour brute force
    "suspicious_ports": [22, 23, 3389, 445, 1433, 3306, 5432],  # SSH, Telnet, RDP, SMB, etc.
}

# Regex pour parser différents formats de logs
LOG_PATTERNS = {
    "ssh_failed": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)'
    ),
    "ssh_success": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password.*from\s+(\d+\.\d+\.\d+\.\d+)'
    ),
    "ssh_invalid_user": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)'
    ),
    "apache_error": re.compile(
        r'\[([^\]]+)\].*\[client\s+(\d+\.\d+\.\d+\.\d+)\]'
    ),
    "apache_access": re.compile(
        r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\]\s+"(\w+)\s+([^\s]+).*"\s+(\d+)'
    ),
    "generic_ip": re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(FAIL|ERROR|INVALID|DENIED).*?(\d+\.\d+\.\d+\.\d+)'
    ),
}


# ─────────────────────────────────────────
#  PARSEURS DE LOGS
# ─────────────────────────────────────────

def parse_log_file(filepath: str) -> list:
    """Parse un fichier de log et retourne les événements structurés."""
    events = []
    path = Path(filepath)

    if not path.exists():
        print(f"❌ Fichier introuvable : {filepath}")
        return events

    with open(filepath, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            # SSH Failed password
            m = LOG_PATTERNS["ssh_failed"].search(line)
            if m:
                events.append({
                    "type": "SSH_FAILED",
                    "timestamp": m.group(1),
                    "ip": m.group(2),
                    "port": int(m.group(3)),
                    "line": line_num,
                    "raw": line
                })
                continue

            # SSH Invalid user
            m = LOG_PATTERNS["ssh_invalid_user"].search(line)
            if m:
                events.append({
                    "type": "SSH_INVALID_USER",
                    "timestamp": m.group(1),
                    "user": m.group(2),
                    "ip": m.group(3),
                    "line": line_num,
                    "raw": line
                })
                continue

            # SSH Success
            m = LOG_PATTERNS["ssh_success"].search(line)
            if m:
                events.append({
                    "type": "SSH_SUCCESS",
                    "timestamp": m.group(1),
                    "ip": m.group(2),
                    "line": line_num,
                    "raw": line
                })
                continue

            # Apache access log
            m = LOG_PATTERNS["apache_access"].search(line)
            if m:
                status = int(m.group(5))
                events.append({
                    "type": "HTTP_ACCESS",
                    "timestamp": m.group(2),
                    "ip": m.group(1),
                    "method": m.group(3),
                    "path": m.group(4),
                    "status": status,
                    "line": line_num,
                    "raw": line
                })
                continue

            # Generic FAIL/ERROR
            m = LOG_PATTERNS["generic_ip"].search(line)
            if m:
                events.append({
                    "type": "GENERIC_FAIL",
                    "timestamp": m.group(1),
                    "event": m.group(2),
                    "ip": m.group(3),
                    "line": line_num,
                    "raw": line
                })

    return events


# ─────────────────────────────────────────
#  DÉTECTION D'ATTAQUES
# ─────────────────────────────────────────

def detect_brute_force(events: list) -> list:
    """Détecte les attaques brute force par IP."""
    alerts = []
    ip_failures = defaultdict(list)

    for event in events:
        if event["type"] in ("SSH_FAILED", "SSH_INVALID_USER", "GENERIC_FAIL"):
            ip_failures[event["ip"]].append(event)

    for ip, fails in ip_failures.items():
        if len(fails) >= CONFIG["brute_force_threshold"]:
            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "🔴 CRITIQUE" if len(fails) >= 20 else "🟠 ÉLEVÉ",
                "ip": ip,
                "attempts": len(fails),
                "first_seen": fails[0]["timestamp"],
                "last_seen": fails[-1]["timestamp"],
                "details": f"{len(fails)} tentatives échouées détectées"
            })

    return sorted(alerts, key=lambda x: x["attempts"], reverse=True)


def detect_suspicious_ips(events: list) -> list:
    """Détecte les IPs avec comportement suspect (scans, accès multiples)."""
    alerts = []
    ip_activity = defaultdict(lambda: {"events": [], "paths": set(), "ports": set()})

    for event in events:
        ip = event.get("ip")
        if not ip:
            continue
        ip_activity[ip]["events"].append(event)
        if "port" in event:
            ip_activity[ip]["ports"].add(event["port"])
        if "path" in event:
            ip_activity[ip]["paths"].add(event["path"])

    for ip, data in ip_activity.items():
        reasons = []

        # Scan de ports
        if len(data["ports"]) >= CONFIG["scan_threshold"]:
            reasons.append(f"Scan de ports ({len(data['ports'])} ports testés)")

        # Nombreuses requêtes 404
        errors_404 = [e for e in data["events"] if e.get("status") == 404]
        if len(errors_404) >= 10:
            reasons.append(f"Énumération de ressources ({len(errors_404)} erreurs 404)")

        # Accès à des chemins sensibles
        sensitive = ["/admin", "/wp-admin", "/.env", "/etc/passwd", "/config",
                     "/phpmyadmin", "/.git", "/backup", "/shell", "/cmd"]
        suspicious_paths = [p for p in data["paths"] if any(s in p.lower() for s in sensitive)]
        if suspicious_paths:
            reasons.append(f"Accès chemin sensible : {', '.join(list(suspicious_paths)[:3])}")

        # Port suspect
        suspect_ports = data["ports"] & set(CONFIG["suspicious_ports"])
        if suspect_ports:
            reasons.append(f"Port(s) sensible(s) ciblé(s) : {suspect_ports}")

        if reasons:
            alerts.append({
                "type": "SUSPICIOUS_IP",
                "severity": "🟠 ÉLEVÉ" if len(reasons) >= 2 else "🟡 MOYEN",
                "ip": ip,
                "total_events": len(data["events"]),
                "reasons": reasons
            })

    return alerts


def detect_http_attacks(events: list) -> list:
    """Détecte les tentatives d'attaques HTTP (SQLi, XSS, path traversal)."""
    alerts = []

    sqli_patterns = ["'", "--", "UNION", "SELECT", "DROP", "1=1", "OR 1"]
    xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "alert("]
    traversal_patterns = ["../", "..\\", "%2e%2e", "etc/passwd", "windows/system32"]

    for event in events:
        if event["type"] != "HTTP_ACCESS":
            continue

        path = event.get("path", "").upper()
        attack_type = None

        if any(p.upper() in path for p in sqli_patterns):
            attack_type = "SQL INJECTION"
        elif any(p.upper() in path for p in [x.upper() for x in xss_patterns]):
            attack_type = "XSS"
        elif any(p.upper() in path for p in [t.upper() for t in traversal_patterns]):
            attack_type = "PATH TRAVERSAL"

        if attack_type:
            alerts.append({
                "type": "HTTP_ATTACK",
                "severity": "🔴 CRITIQUE",
                "ip": event["ip"],
                "attack": attack_type,
                "path": event.get("path", ""),
                "timestamp": event["timestamp"],
                "line": event["line"]
            })

    return alerts


# ─────────────────────────────────────────
#  STATISTIQUES
# ─────────────────────────────────────────

def generate_stats(events: list) -> dict:
    """Génère des statistiques globales sur les logs."""
    ip_counter = defaultdict(int)
    type_counter = defaultdict(int)
    status_counter = defaultdict(int)

    for event in events:
        ip_counter[event.get("ip", "unknown")] += 1
        type_counter[event["type"]] += 1
        if "status" in event:
            status_counter[event["status"]] += 1

    top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_events": len(events),
        "event_types": dict(type_counter),
        "top_ips": top_ips,
        "http_status_codes": dict(status_counter),
    }


# ─────────────────────────────────────────
#  RAPPORT
# ─────────────────────────────────────────

def print_report(events, brute_alerts, suspicious_alerts, http_alerts, stats, output_json=None):
    """Affiche le rapport complet."""
    print("\n" + "="*60)
    print("  🔍 LOG SECURITY ANALYZER — Rapport d'analyse")
    print(f"  📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    # Stats globales
    print(f"\n📊 STATISTIQUES GLOBALES")
    print(f"   Événements analysés : {stats['total_events']}")
    for etype, count in stats["event_types"].items():
        print(f"   {etype:<25} : {count}")

    # Top IPs
    if stats["top_ips"]:
        print(f"\n🌐 TOP IPs LES PLUS ACTIVES")
        for ip, count in stats["top_ips"][:5]:
            print(f"   {ip:<18} : {count} événements")

    # Brute Force
    print(f"\n{'='*60}")
    print(f"🔴 ATTAQUES BRUTE FORCE DÉTECTÉES : {len(brute_alerts)}")
    print("="*60)
    if brute_alerts:
        for alert in brute_alerts[:10]:
            print(f"\n  {alert['severity']} | IP : {alert['ip']}")
            print(f"  Tentatives  : {alert['attempts']}")
            print(f"  Première    : {alert['first_seen']}")
            print(f"  Dernière    : {alert['last_seen']}")
    else:
        print("  ✅ Aucune attaque brute force détectée")

    # IPs suspectes
    print(f"\n{'='*60}")
    print(f"🟠 IPs SUSPECTES DÉTECTÉES : {len(suspicious_alerts)}")
    print("="*60)
    if suspicious_alerts:
        for alert in suspicious_alerts[:10]:
            print(f"\n  {alert['severity']} | IP : {alert['ip']}")
            print(f"  Événements  : {alert['total_events']}")
            for reason in alert["reasons"]:
                print(f"  ⚠️  {reason}")
    else:
        print("  ✅ Aucune IP suspecte détectée")

    # Attaques HTTP
    print(f"\n{'='*60}")
    print(f"🔴 ATTAQUES HTTP DÉTECTÉES : {len(http_alerts)}")
    print("="*60)
    if http_alerts:
        for alert in http_alerts[:10]:
            print(f"\n  {alert['severity']} | {alert['attack']}")
            print(f"  IP          : {alert['ip']}")
            print(f"  Chemin      : {alert['path'][:60]}")
            print(f"  Timestamp   : {alert['timestamp']}")
    else:
        print("  ✅ Aucune attaque HTTP détectée")

    print("\n" + "="*60)
    total = len(brute_alerts) + len(suspicious_alerts) + len(http_alerts)
    print(f"  📋 TOTAL ALERTES : {total}")
    print("="*60 + "\n")

    # Export JSON
    if output_json:
        report = {
            "generated_at": datetime.now().isoformat(),
            "stats": stats,
            "alerts": {
                "brute_force": brute_alerts,
                "suspicious_ips": suspicious_alerts,
                "http_attacks": http_alerts,
            }
        }
        with open(output_json, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  💾 Rapport JSON exporté : {output_json}\n")


# ─────────────────────────────────────────
#  GÉNÉRATEUR DE LOGS DE TEST
# ─────────────────────────────────────────

def generate_sample_logs(filepath: str):
    """Génère un fichier de logs SSH de test."""
    sample = """Mar 20 10:01:02 server sshd[1234]: Failed password for root from 192.168.1.100 port 52341 ssh2
Mar 20 10:01:03 server sshd[1234]: Failed password for root from 192.168.1.100 port 52342 ssh2
Mar 20 10:01:04 server sshd[1234]: Failed password for admin from 192.168.1.100 port 52343 ssh2
Mar 20 10:01:05 server sshd[1234]: Failed password for root from 192.168.1.100 port 52344 ssh2
Mar 20 10:01:06 server sshd[1234]: Failed password for root from 192.168.1.100 port 52345 ssh2
Mar 20 10:01:07 server sshd[1234]: Failed password for root from 192.168.1.100 port 52346 ssh2
Mar 20 10:01:08 server sshd[1234]: Invalid user testuser from 10.0.0.5 port 44321
Mar 20 10:01:09 server sshd[1234]: Invalid user testuser from 10.0.0.5 port 44322
Mar 20 10:01:10 server sshd[1234]: Invalid user admin from 10.0.0.5 port 44323
Mar 20 10:01:11 server sshd[1234]: Invalid user oracle from 10.0.0.5 port 44324
Mar 20 10:01:12 server sshd[1234]: Invalid user ftp from 10.0.0.5 port 44325
Mar 20 10:01:15 server sshd[1234]: Accepted password for belaid from 82.65.200.10 port 55100 ssh2
Mar 20 10:02:00 server sshd[1234]: Failed password for root from 172.16.0.55 port 60001 ssh2
Mar 20 10:02:01 server sshd[1234]: Failed password for root from 172.16.0.55 port 60002 ssh2
Mar 20 10:02:02 server sshd[1234]: Failed password for root from 172.16.0.55 port 60003 ssh2
Mar 20 10:02:03 server sshd[1234]: Failed password for root from 172.16.0.55 port 60004 ssh2
Mar 20 10:02:04 server sshd[1234]: Failed password for root from 172.16.0.55 port 60005 ssh2
Mar 20 10:02:05 server sshd[1234]: Failed password for root from 172.16.0.55 port 60006 ssh2
Mar 20 10:02:06 server sshd[1234]: Failed password for root from 172.16.0.55 port 60007 ssh2
Mar 20 10:02:07 server sshd[1234]: Failed password for root from 172.16.0.55 port 60008 ssh2
"""
    with open(filepath, "w") as f:
        f.write(sample)
    print(f"✅ Fichier de logs de test créé : {filepath}")


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Log Security Analyzer — Détection brute force & IPs suspectes"
    )
    parser.add_argument("logfile", nargs="?", help="Fichier de logs à analyser")
    parser.add_argument("--json", metavar="FILE", help="Exporter le rapport en JSON")
    parser.add_argument("--demo", action="store_true", help="Générer et analyser des logs de démonstration")
    args = parser.parse_args()

    if args.demo:
        demo_file = "sample_auth.log"
        generate_sample_logs(demo_file)
        args.logfile = demo_file

    if not args.logfile:
        parser.print_help()
        print("\n💡 Exemple : python3 log_analyzer.py /var/log/auth.log --json rapport.json")
        print("💡 Démo    : python3 log_analyzer.py --demo\n")
        return

    print(f"\n🔍 Analyse de : {args.logfile}")
    print("⏳ Chargement des événements...")

    events = parse_log_file(args.logfile)
    print(f"✅ {len(events)} événements chargés\n")

    if not events:
        print("⚠️  Aucun événement reconnu. Vérifiez le format du fichier.")
        return

    brute_alerts    = detect_brute_force(events)
    suspicious_alerts = detect_suspicious_ips(events)
    http_alerts     = detect_http_attacks(events)
    stats           = generate_stats(events)

    print_report(events, brute_alerts, suspicious_alerts, http_alerts, stats, args.json)


if __name__ == "__main__":
    main()
