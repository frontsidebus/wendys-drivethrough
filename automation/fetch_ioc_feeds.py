#!/usr/bin/env python3
"""
fetch_ioc_feeds.py - Aggregate IOCs from abuse.ch, CISA KEV, and MISP feeds.

Pulls fresh indicators from URLhaus, MalwareBazaar, ThreatFox, and the
CISA Known Exploited Vulnerabilities catalog. Outputs structured JSON
with IOC type, value, source, and tags.

Usage:
    python fetch_ioc_feeds.py                           # Fetch all IOC feeds
    python fetch_ioc_feeds.py --output iocs.json        # Write to file
    python fetch_ioc_feeds.py --source threatfox        # Single source only
    python fetch_ioc_feeds.py --source cisa_kev         # CISA KEV only
"""

import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "feed_config.json"
USER_AGENT = "WendysDrivethrough-IOCFeed/1.0"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def fetch_urlhaus(url):
    """Fetch recent malicious URLs from URLhaus."""
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        iocs = []
        lines = resp.text.splitlines()
        reader = csv.reader(line for line in lines if not line.startswith("#"))
        for row in reader:
            if len(row) >= 8:
                iocs.append({
                    "type": "url",
                    "value": row[2] if len(row) > 2 else "",
                    "threat_type": row[4] if len(row) > 4 else "",
                    "tags": row[6].split(",") if len(row) > 6 and row[6] else [],
                    "source": "urlhaus",
                    "date_added": row[1] if len(row) > 1 else "",
                })
        return iocs
    except Exception as e:
        print(f"[WARN] URLhaus fetch failed: {e}", file=sys.stderr)
        return []


def fetch_malwarebazaar_hashes(url):
    """Fetch recent malware SHA256 hashes from MalwareBazaar."""
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        iocs = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and len(line) == 64:
                iocs.append({
                    "type": "sha256",
                    "value": line,
                    "source": "malwarebazaar",
                })
        return iocs
    except Exception as e:
        print(f"[WARN] MalwareBazaar fetch failed: {e}", file=sys.stderr)
        return []


def fetch_threatfox_json(url):
    """Fetch recent IOCs from ThreatFox JSON feed."""
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        # ThreatFox JSON is a zip containing CSV; try JSON API instead
        api_url = "https://threatfox-api.abuse.ch/api/v1/"
        api_resp = requests.post(
            api_url,
            json={"query": "get_iocs", "days": 1},
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        api_resp.raise_for_status()
        data = api_resp.json()
        iocs = []
        if data.get("query_status") == "ok" and data.get("data"):
            for item in data["data"]:
                iocs.append({
                    "type": item.get("ioc_type", "unknown"),
                    "value": item.get("ioc", ""),
                    "threat_type": item.get("threat_type", ""),
                    "malware": item.get("malware_printable", ""),
                    "tags": item.get("tags") or [],
                    "confidence": item.get("confidence_level", 0),
                    "source": "threatfox",
                    "date_added": item.get("first_seen_utc", ""),
                    "reference": item.get("reference", ""),
                })
        return iocs
    except Exception as e:
        print(f"[WARN] ThreatFox fetch failed: {e}", file=sys.stderr)
        return []


def fetch_cisa_kev(url):
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
        vulns = []
        for vuln in data.get("vulnerabilities", []):
            vulns.append({
                "type": "cve",
                "value": vuln.get("cveID", ""),
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "known_ransomware": vuln.get("knownRansomwareCampaignUse", ""),
                "source": "cisa_kev",
            })
        return {
            "catalog_version": data.get("catalogVersion", ""),
            "date_released": data.get("dateReleased", ""),
            "total_vulnerabilities": len(vulns),
            "vulnerabilities": vulns,
        }
    except Exception as e:
        print(f"[WARN] CISA KEV fetch failed: {e}", file=sys.stderr)
        return {"vulnerabilities": []}


FETCHERS = {
    "urlhaus": lambda cfg: fetch_urlhaus(cfg["ioc_feeds"]["urlhaus_recent_csv"]),
    "malwarebazaar": lambda cfg: fetch_malwarebazaar_hashes(cfg["ioc_feeds"]["malwarebazaar_recent_sha256"]),
    "threatfox": lambda cfg: fetch_threatfox_json(cfg["ioc_feeds"]["threatfox_recent_json"]),
    "cisa_kev": lambda cfg: fetch_cisa_kev(cfg["ioc_feeds"]["cisa_kev_json"]),
}


def main():
    parser = argparse.ArgumentParser(description="Aggregate IOCs from threat feeds")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--source", "-s", help="Fetch specific source only: urlhaus, malwarebazaar, threatfox, cisa_kev")
    args = parser.parse_args()

    config = load_config()
    sources_to_fetch = [args.source] if args.source else list(FETCHERS.keys())

    results = {}
    for source in sources_to_fetch:
        if source not in FETCHERS:
            print(f"[ERROR] Unknown source: {source}. Options: {list(FETCHERS.keys())}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Fetching {source}...", file=sys.stderr)
        results[source] = FETCHERS[source](config)

    output_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources_fetched": sources_to_fetch,
        "results": results,
    }

    # Summary stats
    for source, data in results.items():
        if isinstance(data, list):
            print(f"    {source}: {len(data)} IOCs", file=sys.stderr)
        elif isinstance(data, dict) and "vulnerabilities" in data:
            print(f"    {source}: {len(data['vulnerabilities'])} vulnerabilities (catalog {data.get('catalog_version', '?')})", file=sys.stderr)

    output = json.dumps(output_data, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"[*] Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
