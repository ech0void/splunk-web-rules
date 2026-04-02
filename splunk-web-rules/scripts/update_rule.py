#!/usr/bin/env python3
"""
update_rule.py — Update a single Splunk saved search via REST API.

Usage:
    python update_rule.py --rule rules/scanning/sqli_detection.json
    python update_rule.py --rule rules/scanning/sqli_detection.json --dry-run
"""

import os, sys, json, argparse, logging, requests, urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


class Config:
    SPLUNK_HOST  = os.getenv("SPLUNK_HOST",  "https://localhost:8089")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_APP   = os.getenv("SPLUNK_APP",   "search")
    VERIFY_SSL   = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"


def sev(s):
    return {"critical":"1","high":"2","medium":"3","low":"4"}.get(s.lower(),"3")


def build_payload(rule, create=False):
    p = {
        "search":                 rule["search"],
        "description":            rule.get("description",""),
        "cron_schedule":          rule.get("cron","*/5 * * * *"),
        "dispatch.earliest_time": rule.get("earliest_time","-5m"),
        "dispatch.latest_time":   rule.get("latest_time","now"),
        "is_scheduled":           "1",
        "alert_type":             "number of events",
        "alert_comparator":       "greater than",
        "alert_threshold":        "0",
        "alert.severity":         sev(rule.get("severity","medium")),
        "alert.suppress":         "1" if rule.get("suppression_fields") else "0",
        "alert.suppress.fields":  ",".join(rule.get("suppression_fields",[])),
        "alert.suppress.period":  str(rule.get("suppression_period",3600)),
        "disabled":               "0" if rule.get("enabled",True) else "1",
    }
    if create: p["name"] = rule["name"]
    for act in rule.get("alert_actions",[]):
        if act=="email":   p["action.email"]="1"
        if act=="webhook": p["action.webhook"]="1"
    return p


def check_exists(name, headers, verify):
    enc = requests.utils.quote(name, safe="")
    url = f"{Config.SPLUNK_HOST}/servicesNS/nobody/{Config.SPLUNK_APP}/saved/searches/{enc}"
    try:
        r = requests.get(url, headers=headers, verify=verify,
                         params={"output_mode":"json"}, timeout=20)
        return r.status_code == 200
    except Exception:
        return False


def run(rule, dry_run=False):
    headers = {
        "Authorization": f"Bearer {Config.SPLUNK_TOKEN}",
        "Content-Type":  "application/x-www-form-urlencoded",
    }
    verify = Config.VERIFY_SSL
    name   = rule["name"]
    exists = check_exists(name, headers, verify)
    action = "UPDATE" if exists else "CREATE"

    log.info("─" * 55)
    log.info(f"  Rule     : {name}")
    log.info(f"  Action   : {action}")
    log.info(f"  Severity : {rule.get('severity','?').upper()}")
    log.info(f"  MITRE    : {', '.join(rule.get('mitre',[]))}")
    log.info("─" * 55)

    if dry_run:
        log.info(f"[DRY-RUN] Would {action} '{name}'")
        return True

    base_url = f"{Config.SPLUNK_HOST}/servicesNS/nobody/{Config.SPLUNK_APP}/saved/searches"
    if exists:
        enc = requests.utils.quote(name, safe="")
        r = requests.post(f"{base_url}/{enc}", headers=headers,
                          data=build_payload(rule), verify=verify, timeout=30)
    else:
        r = requests.post(base_url, headers=headers,
                          data=build_payload(rule, create=True),
                          verify=verify, timeout=30)

    if r.status_code in (200,201):
        log.info(f"{'🔄' if exists else '✅'} {action} successful: '{name}'")
        return True
    log.error(f"❌ {action} failed [{r.status_code}]: {r.text[:300]}")
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rule",    required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not Config.SPLUNK_TOKEN:
        log.error("SPLUNK_TOKEN not set!"); sys.exit(1)

    fp = Path(args.rule)
    if not fp.exists():
        log.error(f"File not found: {args.rule}"); sys.exit(1)

    rule = json.load(open(fp))
    for req in ("name","search"):
        if req not in rule:
            log.error(f"Missing field: {req}"); sys.exit(1)

    sys.exit(0 if run(rule, args.dry_run) else 1)


if __name__ == "__main__":
    main()
