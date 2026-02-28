#!/usr/bin/env python3
"""
scrape_cisa_advisories.py - Scrape CISA cybersecurity advisories.

Since CISA deprecated their RSS feeds (return 403 as of Feb 2026),
this script scrapes the advisories page directly and filters for
nation-state related advisories.

Usage:
    python scrape_cisa_advisories.py                         # Fetch recent advisories
    python scrape_cisa_advisories.py --output advisories.json
    python scrape_cisa_advisories.py --filter iran
    python scrape_cisa_advisories.py --filter russia
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "feed_config.json"
USER_AGENT = "WendysDrivethrough-CISAScraper/1.0"

CISA_ADVISORIES_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories"

# Known nation-state advisory patterns
NATION_KEYWORDS = {
    "iran": [
        "iran", "irgc", "mois", "muddywater", "apt33", "apt34", "apt35", "apt42",
        "charming kitten", "pioneer kitten", "cyberav3ngers", "unitronics",
        "sandstorm", "emennet",
    ],
    "russia": [
        "russia", "gru", "svr", "fsb", "apt28", "apt29", "sandworm", "turla",
        "fancy bear", "cozy bear", "gamaredon", "coldriver", "star blizzard",
        "blizzard", "solarwinds", "nobelium",
    ],
    "china": [
        "china", "prc", "mss", "pla", "apt10", "apt40", "apt41", "volt typhoon",
        "salt typhoon", "silk typhoon", "hafnium", "mustang panda", "typhoon",
    ],
    "dprk": [
        "dprk", "north korea", "lazarus", "kimsuky", "apt38", "hidden cobra",
        "bluenoroff", "andariel", "sleet", "tradertrait",
    ],
}


def scrape_cisa_page(url):
    """Scrape CISA advisories page for advisory links and titles."""
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        html = resp.text

        # Extract advisory entries using regex (CISA uses Drupal with consistent markup)
        # Look for advisory links and titles
        advisories = []
        # Pattern for advisory links on the page
        link_pattern = re.compile(
            r'href="(/news-events/cybersecurity-advisories/[^"]+)"[^>]*>([^<]+)</a>',
            re.IGNORECASE,
        )
        for match in link_pattern.finditer(html):
            path, title = match.groups()
            title = title.strip()
            if title and not title.startswith("Back to"):
                advisories.append({
                    "title": title,
                    "url": f"https://www.cisa.gov{path}",
                    "advisory_id": path.split("/")[-1] if "/" in path else "",
                })

        # Also look for standalone advisory references (AA-format)
        aa_pattern = re.compile(r'(AA\d{2}-\d{3}[A-Z]?)', re.IGNORECASE)
        aa_refs = set(aa_pattern.findall(html))

        return advisories, aa_refs
    except Exception as e:
        print(f"[WARN] CISA scrape failed: {e}", file=sys.stderr)
        return [], set()


def fetch_kev_for_context(config):
    """Fetch CISA KEV to provide CVE context alongside advisories."""
    try:
        url = config["ioc_feeds"]["cisa_kev_json"]
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
        return {
            "catalog_version": data.get("catalogVersion", ""),
            "date_released": data.get("dateReleased", ""),
            "total_vulns": len(data.get("vulnerabilities", [])),
            "recent_additions": [
                v for v in data.get("vulnerabilities", [])
                if v.get("dateAdded", "") >= (datetime.now(timezone.utc).strftime("%Y-%m-01"))
            ],
        }
    except Exception as e:
        print(f"[WARN] KEV fetch failed: {e}", file=sys.stderr)
        return {}


def tag_advisory(advisory, nation_filter=None):
    """Tag an advisory with matching nation-state categories."""
    text = f"{advisory.get('title', '')} {advisory.get('advisory_id', '')}".lower()
    tags = []
    for nation, keywords in NATION_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            tags.append(nation)
    advisory["nation_tags"] = tags
    if nation_filter:
        return nation_filter.lower() in tags
    return True


def main():
    parser = argparse.ArgumentParser(description="Scrape CISA advisories (RSS deprecated)")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--filter", "-f", help="Filter by nation: iran, russia, china, dprk")
    args = parser.parse_args()

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    print("[*] Scraping CISA advisories page...", file=sys.stderr)
    advisories, aa_refs = scrape_cisa_page(CISA_ADVISORIES_URL)
    print(f"[*] Found {len(advisories)} advisory links, {len(aa_refs)} AA references", file=sys.stderr)

    # Tag advisories
    tagged = []
    for adv in advisories:
        if tag_advisory(adv, args.filter):
            tagged.append(adv)

    if args.filter:
        print(f"[*] {len(tagged)} advisories matching '{args.filter}'", file=sys.stderr)

    # Fetch KEV context
    print("[*] Fetching CISA KEV for context...", file=sys.stderr)
    kev_context = fetch_kev_for_context(config)
    if kev_context.get("recent_additions"):
        print(f"[*] {len(kev_context['recent_additions'])} KEV additions this month", file=sys.stderr)

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "CISA",
        "note": "CISA RSS feeds deprecated (403). This data scraped from advisories page.",
        "filter": args.filter,
        "advisories": tagged,
        "aa_references": sorted(aa_refs),
        "kev_context": kev_context,
    }

    output = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"[*] Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
