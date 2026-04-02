#!/usr/bin/env python3
"""
list_rules.py — List Splunk saved searches and compare with repo rules.

Usage:
    python list_rules.py
    python list_rules.py --filter sql
    python list_rules.py --json
    python list_rules.py --compare
"""

import os, sys, json, glob, argparse, logging, requests, urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent.parent / "rules"


class Config:
    SPLUNK_HOST  = os.getenv("SPLUNK_HOST",  "https://localhost:8089")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_APP   = os.getenv("SPLUNK_APP",   "search")
    VERIFY_SSL   = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"


def headers():
    return {"Authorization": f"Bearer {Config.SPLUNK_TOKEN}",
            "Content-Type":  "application/x-www-form-urlencoded"}


def list_splunk_rules(name_filter=""):
    url    = f"{Config.SPLUNK_HOST}/servicesNS/nobody/{Config.SPLUNK_APP}/saved/searches"
    params = {"output_mode": "json", "count": 0}
    if name_filter:
        params["search"] = name_filter
    try:
        r = requests.get(url, headers=headers(), verify=Config.VERIFY_SSL,
                         params=params, timeout=30)
        if r.status_code != 200:
            log.error(f"API error [{r.status_code}]"); return []
        return [
            {
                "name":           e["name"],
                "search":         e["content"].get("search",""),
                "cron":           e["content"].get("cron_schedule",""),
                "disabled":       e["content"].get("disabled", False),
                "next_scheduled": e["content"].get("next_scheduled_time","N/A"),
            }
            for e in r.json().get("entry", [])
        ]
    except Exception as ex:
        log.error(f"Cannot connect to Splunk: {ex}"); return []


def load_repo_rules():
    rules = []
    for fp in glob.glob(str(RULES_DIR / "**" / "*.json"), recursive=True):
        try:
            r = json.load(open(fp))
            r["_file"] = fp
            rules.append(r)
        except Exception:
            pass
    return rules


def print_table(rules):
    if not rules:
        log.info("No rules found."); return

    W = max(len(r.get("name","")) for r in rules) + 2
    log.info("\n" + "═" * (W + 30))
    log.info(f"{'RULE NAME':<{W}} {'STATUS':<14} CRON")
    log.info("─" * (W + 30))
    for r in rules:
        status = "🔴 DISABLED" if r.get("disabled") else "🟢 ENABLED"
        log.info(f"{r.get('name','?'):<{W}} {status:<14} {r.get('cron','?')}")
    log.info("═" * (W + 30))
    log.info(f"Total: {len(rules)} rule(s)\n")


def compare():
    repo_rules   = load_repo_rules()
    splunk_rules = list_splunk_rules()
    splunk_names = {r["name"] for r in splunk_rules}
    repo_names   = {r["name"] for r in repo_rules}

    deployed = repo_names & splunk_names
    missing  = repo_names - splunk_names
    extra    = splunk_names - repo_names

    log.info("\n📊 REPO vs SPLUNK")
    log.info("─" * 50)
    log.info(f"\n✅ Deployed ({len(deployed)}):")
    for n in sorted(deployed): log.info(f"   • {n}")

    if missing:
        log.info(f"\n⚠️  In repo but NOT in Splunk ({len(missing)}):")
        for n in sorted(missing): log.info(f"   • {n}")
        log.info("\n  → Run: python deploy_to_splunk.py --all")

    if extra:
        log.info(f"\n🔵 In Splunk but NOT in repo ({len(extra)}):")
        for n in sorted(extra): log.info(f"   • {n}")
    log.info("")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter",  metavar="TEXT")
    ap.add_argument("--json",    action="store_true")
    ap.add_argument("--compare", action="store_true")
    args = ap.parse_args()

    if not Config.SPLUNK_TOKEN:
        log.error("SPLUNK_TOKEN not set!"); sys.exit(1)

    if args.compare:
        compare(); return

    rules = list_splunk_rules(args.filter or "")
    if args.json:
        print(json.dumps(rules, indent=2))
    else:
        print_table(rules)


if __name__ == "__main__":
    main()
