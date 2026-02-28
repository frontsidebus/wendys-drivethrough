#!/usr/bin/env python3
"""
fetch_rss_feeds.py - Pull and filter vendor threat intel RSS feeds.

Fetches all configured RSS/Atom feeds, filters entries by nation-state
keywords, and outputs structured JSON. Designed to run on a cron schedule
for continuous threat monitoring.

Usage:
    python fetch_rss_feeds.py                     # Fetch all feeds, output to stdout
    python fetch_rss_feeds.py --output feeds.json  # Write to file
    python fetch_rss_feeds.py --filter iran        # Filter for Iran-related entries only
    python fetch_rss_feeds.py --filter all         # Tag all entries by nation-state
    python fetch_rss_feeds.py --hours 24           # Only entries from last 24 hours
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "feed_config.json"
USER_AGENT = "WendysDrivethrough-ThreatFeed/1.0"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def fetch_feed(name, url, timeout=30):
    """Fetch and parse a single RSS/Atom feed."""
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        entries = []
        for entry in feed.entries:
            published = entry.get("published_parsed") or entry.get("updated_parsed")
            pub_dt = None
            if published:
                pub_dt = datetime(*published[:6], tzinfo=timezone.utc).isoformat()

            entries.append({
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "published": pub_dt,
                "summary": entry.get("summary", "")[:500],
                "source": name,
            })
        return entries
    except Exception as e:
        print(f"[WARN] Failed to fetch {name} ({url}): {e}", file=sys.stderr)
        return []


def match_keywords(text, keywords):
    """Check if any keywords appear in text (case-insensitive)."""
    text_lower = text.lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


def tag_entry(entry, keyword_filters):
    """Tag an entry with matching nation-state categories."""
    searchable = f"{entry['title']} {entry['summary']}"
    tags = {}
    for nation, keywords in keyword_filters.items():
        matches = match_keywords(searchable, keywords)
        if matches:
            tags[nation] = matches
    return tags


def filter_by_time(entries, hours):
    """Filter entries to only those published within the last N hours."""
    if not hours:
        return entries
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    filtered = []
    for entry in entries:
        if entry["published"]:
            try:
                pub = datetime.fromisoformat(entry["published"])
                if pub >= cutoff:
                    filtered.append(entry)
            except (ValueError, TypeError):
                filtered.append(entry)  # Keep entries with unparseable dates
        else:
            filtered.append(entry)  # Keep entries with no date
    return filtered


def main():
    parser = argparse.ArgumentParser(description="Fetch and filter threat intel RSS feeds")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--filter", "-f", help="Filter by nation: iran, russia, china, dprk, all")
    parser.add_argument("--hours", type=int, default=2160,
                        help="Only entries from last N hours (default: 2160 = 90 days)")
    parser.add_argument("--config", help="Path to feed_config.json", default=str(CONFIG_PATH))
    args = parser.parse_args()

    config = load_config() if args.config == str(CONFIG_PATH) else json.loads(Path(args.config).read_text())

    all_feeds = {}
    all_feeds.update(config.get("vendor_rss_feeds", {}))
    all_feeds.update(config.get("government_feeds", {}))

    # Skip JSON endpoints from RSS parsing (they need special handling)
    rss_feeds = {k: v for k, v in all_feeds.items() if not v.endswith(".json")}

    print(f"[*] Fetching {len(rss_feeds)} RSS feeds...", file=sys.stderr)
    all_entries = []
    for name, url in rss_feeds.items():
        print(f"    Fetching {name}...", file=sys.stderr)
        entries = fetch_feed(name, url)
        all_entries.extend(entries)
        time.sleep(0.5)  # Be respectful

    print(f"[*] Fetched {len(all_entries)} total entries", file=sys.stderr)

    # Filter by time (default: 90 days / 2160 hours)
    all_entries = filter_by_time(all_entries, args.hours)
    print(f"[*] {len(all_entries)} entries within last {args.hours} hours", file=sys.stderr)

    # Tag entries with nation-state keywords
    keyword_filters = config.get("keyword_filters", {})
    for entry in all_entries:
        entry["nation_tags"] = tag_entry(entry, keyword_filters)

    # Filter by nation if requested
    if args.filter and args.filter != "all":
        nation = args.filter.lower()
        all_entries = [e for e in all_entries if nation in e.get("nation_tags", {})]
        print(f"[*] {len(all_entries)} entries matching '{nation}'", file=sys.stderr)

    # Sort by published date (newest first)
    all_entries.sort(key=lambda e: e.get("published") or "", reverse=True)

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(all_entries),
        "filter": args.filter,
        "entries": all_entries,
    }

    output = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"[*] Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
