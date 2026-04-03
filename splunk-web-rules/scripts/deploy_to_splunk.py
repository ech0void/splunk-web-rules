#!/usr/bin/env python3
"""
deploy_to_splunk.py
====================
Deploy web detection rules from GitHub to Splunk Enterprise via REST API.

Usage:
    python deploy_to_splunk.py --all
    python deploy_to_splunk.py --rule rules/sql_injection/sqli_detection.json
    python deploy_to_splunk.py --category scanning
    python deploy_to_splunk.py --dry-run --all
"""

import os, sys, json, glob, argparse, logging, requests, urllib3
from pathlib import Path
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"deploy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
    ],
)
log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent.parent / "rules"


class Config:
    SPLUNK_HOST  = os.getenv("SPLUNK_HOST",  "https://localhost:8089")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_APP   = os.getenv("SPLUNK_APP",   "search")
    VERIFY_SSL   = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    @classmethod
    def validate(cls):
        if not cls.SPLUNK_TOKEN:
            log.error("❌ SPLUNK_TOKEN environment variable is not set!")
            sys.exit(1)


class SplunkClient:
    def __init__(self):
        self.base = Config.SPLUNK_HOST
        self.app  = Config.SPLUNK_APP
        self.h    = {
            "Authorization": f"Bearer {Config.SPLUNK_TOKEN}",
            "Content-Type":  "application/x-www-form-urlencoded",
        }
        self.v = False # SSL sertifikat yoxlanışını birmənalı olaraq söndürürük

    def _url(self, path):
        return f"{self.base}/servicesNS/nobody/{self.app}/{path}"

    def exists(self, name):
        enc = requests.utils.quote(name, safe="")
        try:
            r = requests.get(self._url(f"saved/searches/{enc}"),
                             headers=self.h, verify=self.v,
                             params={"output_mode": "json"}, timeout=20)
            return r.status_code == 200
        except Exception:
            return False

    def _payload(self, rule, create=False):
        p = {
            "search":                rule["search"],
            "description":           rule.get("description", ""),
            "cron_schedule":          rule.get("cron", "*/5 * * * *"),
            "dispatch.earliest_time": rule.get("earliest_time", "-5m"),
            "dispatch.latest_time":   rule.get("latest_time", "now"),
            "is_scheduled":           "1",
            "alert_type":              "number of events",
            "alert_comparator":        "greater than",
            "alert_threshold":         "0",
            "alert.severity":          {"critical":"1","high":"2","medium":"3","low":"4"}.get(
                                          rule.get("severity","medium"), "3"),
            "alert.suppress":          "1" if rule.get("suppression_fields") else "0",
            "alert.suppress.fields":  ",".join(rule.get("suppression_fields", [])),
            "alert.suppress.period":  str(rule.get("suppression_period", 3600)),
            "disabled":                "0" if rule.get("enabled", True) else "1",
        }
        if create:
            p["name"] = rule["name"]
        for act in rule.get("alert_actions", []):
            if act == "email":   p["action.email"]   = "1"
            if act == "webhook": 
                p["action.webhook"] = "1"
                # Splunk-ın tələb etdiyi Webhook URL-i bura əlavə edirik
                p["action.webhook.uri"] = "http://localhost:1234/fake-webhook"
        return p

    def deploy(self, rule, dry_run=False):
        name   = rule["name"]
        update = self.exists(name)
        action = "UPDATE" if update else "CREATE"

        if dry_run:
            log.info(f"  [DRY-RUN] Would {action}: '{name}'")
            return True

        if update:
            enc = requests.utils.quote(name, safe="")
            r = requests.post(self._url(f"saved/searches/{enc}"),
                              headers=self.h, data=self._payload(rule),
                              verify=self.v, timeout=30)
        else:
            r = requests.post(self._url("saved/searches"),
                              headers=self.h, data=self._payload(rule, create=True),
                              verify=self.v, timeout=30)

        if r.status_code in (200, 201):
            log.info(f"  {'🔄' if update else '✅'} {action}: '{name}'")
            return True
        log.error(f"  ❌ {action} FAILED [{r.status_code}]: {r.text[:250]}")
        return False

    def test(self):
        try:
            r = requests.get(f"{self.base}/services/server/info",
                              headers=self.h, verify=self.v,
                              params={"output_mode": "json"}, timeout=15)
            if r.status_code == 200:
                ver = r.json()["entry"][0]["content"].get("version", "?")
                log.info(f"✅ Splunk {ver} — {self.base}")
                return True
        except Exception as e:
            log.error(f"❌ Cannot reach Splunk: {e}")
        return False


def load_rules(pattern):
    rules = []
    for fp in glob.glob(pattern, recursive=True):
        try:
            rule = json.load(open(fp))
            if "name" in rule and "search" in rule:
                rules.append(rule)
            else:
                log.warning(f"⚠️  Skipping {fp}: missing name/search")
        except json.JSONDecodeError as e:
            log.error(f"❌ Bad JSON in {fp}: {e}")
    return rules


def main():
    ap = argparse.ArgumentParser()
    g  = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all",      action="store_true")
    g.add_argument("--rule",      metavar="FILE")
    g.add_argument("--category", metavar="NAME")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    Config.validate()
    client = SplunkClient()
    if not client.test():
        sys.exit(1)

    if args.all:
        rules = load_rules(str(RULES_DIR / "**" / "*.json"))
    elif args.rule:
        rules = load_rules(args.rule)
    else:
        rules = load_rules(str(RULES_DIR / args.category / "*.json"))

    if not rules:
        log.warning("No rules found.")
        sys.exit(0)

    log.info(f"\n{'═'*55}")
    log.info(f"  Deploying {len(rules)} rule(s) {'[DRY-RUN]' if args.dry_run else 'to Splunk'}")
    log.info(f"{'═'*55}\n")

    ok = fail = 0
    for i, r in enumerate(rules, 1):
        log.info(f"[{i}/{len(rules)}] {r['name']}  [{r.get('severity','?').upper()}]")
        if client.deploy(r, args.dry_run): ok += 1
        else: fail += 1

    log.info(f"\n{'═'*55}")
    log.info(f"  ✅ Success: {ok}   ❌ Failed: {fail}")
    log.info(f"{'═'*55}\n")
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()
