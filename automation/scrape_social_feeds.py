#!/usr/bin/env python3
"""
scrape_social_feeds.py - Scrape social media and video platforms for threat intel.

Fetches content from YouTube, Reddit, Substack, Mastodon, Telegram, Twitch,
and Kick. Filters by nation-state keywords and enforces a 90-day lookback
window by default.

All YouTube/Substack/Mastodon sources use zero-auth RSS. Reddit uses public
RSS with JSON fallback. Telegram scrapes public t.me/s/ pages. Twitch uses
their public GraphQL endpoint. Kick uses their public REST API.

Twitter/X is intentionally excluded -- API read access costs $100+/month
minimum and Nitter is dead.

Usage:
    python scrape_social_feeds.py                          # All sources, 90-day window
    python scrape_social_feeds.py --source youtube         # YouTube only
    python scrape_social_feeds.py --source reddit --days 7 # Reddit, last 7 days
    python scrape_social_feeds.py --filter iran --days 90  # All sources, Iran-tagged
    python scrape_social_feeds.py --output social.json     # Write to file
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests
from bs4 import BeautifulSoup

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "feed_config.json"
USER_AGENT = "WendysDrivethrough-SocialScraper/1.0 (threat intel aggregator)"
REDDIT_USER_AGENT = "WendysDrivethrough-ThreatFeed/1.0 (by /u/wendys-cti; threat intel research)"

DEFAULT_DAYS = 90
REQUEST_DELAY = 0.5
REDDIT_DELAY = 1.0

# Twitch public client ID (used by their web frontend, no auth required)
TWITCH_CLIENT_ID = "kimne78kx3ncx6brgo4mv6wki5h1ko"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def fetch_rss_generic(name, url, source_type, timeout=30):
    """Fetch and parse a generic RSS/Atom feed (YouTube, Substack, Mastodon)."""
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
                "source_type": source_type,
                "author": entry.get("author", ""),
            })
        return entries
    except Exception as e:
        print(f"[WARN] Failed to fetch {name} ({url}): {e}", file=sys.stderr)
        return []


def fetch_youtube_channel(name, channel_id):
    """Fetch YouTube channel feed via their public Atom/RSS endpoint."""
    url = f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"
    return fetch_rss_generic(name, url, "youtube")


def fetch_reddit_rss(subreddit):
    """Fetch subreddit RSS feed."""
    url = f"https://www.reddit.com/r/{subreddit}/new/.rss"
    entries = fetch_rss_generic(f"r/{subreddit}", url, "reddit")
    if entries:
        return entries
    # Fall back to JSON endpoint for richer data
    return fetch_reddit_json(subreddit)


def fetch_reddit_json(subreddit):
    """Fetch subreddit via JSON endpoint for richer metadata."""
    url = f"https://www.reddit.com/r/{subreddit}/new.json?limit=50"
    try:
        resp = requests.get(
            url, timeout=30,
            headers={"User-Agent": REDDIT_USER_AGENT}
        )
        resp.raise_for_status()
        data = resp.json()
        entries = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            created = post.get("created_utc")
            pub_dt = None
            if created:
                pub_dt = datetime.fromtimestamp(created, tz=timezone.utc).isoformat()

            entries.append({
                "title": post.get("title", ""),
                "link": f"https://www.reddit.com{post.get('permalink', '')}",
                "published": pub_dt,
                "summary": post.get("selftext", "")[:500],
                "source": f"r/{subreddit}",
                "source_type": "reddit",
                "author": post.get("author", ""),
                "score": post.get("score", 0),
                "num_comments": post.get("num_comments", 0),
            })
        return entries
    except Exception as e:
        print(f"[WARN] Failed to fetch r/{subreddit} JSON: {e}", file=sys.stderr)
        return []


def fetch_telegram_public(name, handle):
    """Scrape public Telegram channel preview page."""
    url = f"https://t.me/s/{handle}"
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        entries = []
        messages = soup.find_all("div", class_="tgme_widget_message")
        for msg in messages:
            # Extract message text
            text_div = msg.find("div", class_="tgme_widget_message_text")
            text = text_div.get_text(separator=" ", strip=True) if text_div else ""

            # Extract timestamp
            time_tag = msg.find("time")
            pub_dt = None
            if time_tag and time_tag.get("datetime"):
                pub_dt = time_tag["datetime"]

            # Extract message link
            link_tag = msg.get("data-post", "")
            link = f"https://t.me/{link_tag}" if link_tag else ""

            if text:
                entries.append({
                    "title": text[:120] + ("..." if len(text) > 120 else ""),
                    "link": link,
                    "published": pub_dt,
                    "summary": text[:500],
                    "source": name,
                    "source_type": "telegram",
                    "author": handle,
                })
        return entries
    except Exception as e:
        print(f"[WARN] Failed to fetch Telegram {name} ({url}): {e}", file=sys.stderr)
        return []


def fetch_twitch_vods(name, username):
    """Fetch Twitch VODs via their public GraphQL endpoint."""
    url = "https://gql.twitch.tv/gql"
    query = [{
        "operationName": "FilterableVideoTower_Videos",
        "variables": {
            "limit": 30,
            "channelOwnerLogin": username,
            "broadcastType": None,
            "videoSort": "TIME",
        },
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "a937f1d22e269e39a03b509f65a7490f9fc247d7f83d6ac1421523e3b68042cb",
            }
        }
    }]
    try:
        resp = requests.post(
            url, json=query, timeout=30,
            headers={
                "Client-Id": TWITCH_CLIENT_ID,
                "User-Agent": USER_AGENT,
            }
        )
        resp.raise_for_status()
        data = resp.json()
        entries = []
        edges = (data[0].get("data", {})
                 .get("user", {})
                 .get("videos", {})
                 .get("edges", []))
        for edge in edges:
            node = edge.get("node", {})
            pub_dt = node.get("createdAt")
            entries.append({
                "title": node.get("title", ""),
                "link": f"https://www.twitch.tv/videos/{node.get('id', '')}",
                "published": pub_dt,
                "summary": node.get("game", {}).get("name", "") if node.get("game") else "",
                "source": name,
                "source_type": "twitch",
                "author": username,
                "duration": node.get("lengthSeconds"),
                "view_count": node.get("viewCount"),
            })
        return entries
    except Exception as e:
        print(f"[WARN] Failed to fetch Twitch VODs for {name}: {e}", file=sys.stderr)
        return []


def fetch_kick_channel(name, username):
    """Fetch Kick channel videos via their public REST API."""
    url = f"https://kick.com/api/v1/channels/{username}/videos"
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
        entries = []
        videos = data if isinstance(data, list) else data.get("data", [])
        for video in videos:
            pub_dt = video.get("created_at") or video.get("start_time")
            entries.append({
                "title": video.get("title", "") or video.get("session_title", ""),
                "link": f"https://kick.com/{username}/video/{video.get('id', '')}",
                "published": pub_dt,
                "summary": "",
                "source": name,
                "source_type": "kick",
                "author": username,
            })
        return entries
    except Exception as e:
        print(f"[WARN] Failed to fetch Kick channel {name}: {e}", file=sys.stderr)
        return []


def filter_by_days(entries, days):
    """Filter entries to only those published within the last N days."""
    if not days:
        return entries
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    filtered = []
    for entry in entries:
        if entry.get("published"):
            try:
                pub_str = entry["published"]
                # Handle various ISO format variations
                pub = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                if pub >= cutoff:
                    filtered.append(entry)
            except (ValueError, TypeError):
                filtered.append(entry)  # Keep entries with unparseable dates
        else:
            filtered.append(entry)  # Keep entries with no date
    return filtered


def match_keywords(text, keywords):
    """Check if any keywords appear in text (case-insensitive)."""
    text_lower = text.lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


def tag_entry(entry, keyword_filters):
    """Tag an entry with matching nation-state categories."""
    searchable = f"{entry.get('title', '')} {entry.get('summary', '')}"
    tags = {}
    for nation, keywords in keyword_filters.items():
        matches = match_keywords(searchable, keywords)
        if matches:
            tags[nation] = matches
    return tags


def main():
    parser = argparse.ArgumentParser(
        description="Scrape social media and video platforms for threat intel"
    )
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--filter", "-f",
                        help="Filter by nation: iran, russia, china, dprk, all")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help=f"Only entries from last N days (default: {DEFAULT_DAYS})")
    parser.add_argument("--source", "-s",
                        choices=["youtube", "reddit", "substack", "mastodon",
                                 "telegram", "twitch", "kick"],
                        help="Only scrape a specific source type")
    parser.add_argument("--config", help="Path to feed_config.json",
                        default=str(CONFIG_PATH))
    args = parser.parse_args()

    config = (load_config() if args.config == str(CONFIG_PATH)
              else json.loads(Path(args.config).read_text()))

    keyword_filters = config.get("keyword_filters", {})
    all_entries = []

    sources_to_run = [args.source] if args.source else [
        "youtube", "reddit", "substack", "mastodon", "telegram", "twitch", "kick"
    ]

    # YouTube
    if "youtube" in sources_to_run:
        channels = config.get("youtube_channels", {})
        print(f"[*] Fetching {len(channels)} YouTube channels...", file=sys.stderr)
        for name, channel_id in channels.items():
            print(f"    YouTube: {name}...", file=sys.stderr)
            entries = fetch_youtube_channel(name, channel_id)
            all_entries.extend(entries)
            time.sleep(REQUEST_DELAY)

    # Reddit
    if "reddit" in sources_to_run:
        subreddits = config.get("reddit_subreddits", [])
        print(f"[*] Fetching {len(subreddits)} Reddit subreddits...", file=sys.stderr)
        for sub in subreddits:
            print(f"    Reddit: r/{sub}...", file=sys.stderr)
            entries = fetch_reddit_rss(sub)
            all_entries.extend(entries)
            time.sleep(REDDIT_DELAY)

    # Substack
    if "substack" in sources_to_run:
        feeds = config.get("substack_feeds", {})
        print(f"[*] Fetching {len(feeds)} Substack feeds...", file=sys.stderr)
        for name, url in feeds.items():
            print(f"    Substack: {name}...", file=sys.stderr)
            entries = fetch_rss_generic(name, url, "substack")
            all_entries.extend(entries)
            time.sleep(REQUEST_DELAY)

    # Mastodon
    if "mastodon" in sources_to_run:
        accounts = config.get("mastodon_accounts", {})
        print(f"[*] Fetching {len(accounts)} Mastodon accounts...", file=sys.stderr)
        for name, url in accounts.items():
            print(f"    Mastodon: {name}...", file=sys.stderr)
            entries = fetch_rss_generic(name, url, "mastodon")
            all_entries.extend(entries)
            time.sleep(REQUEST_DELAY)

    # Telegram
    if "telegram" in sources_to_run:
        channels = config.get("telegram_channels", {})
        print(f"[*] Fetching {len(channels)} Telegram channels...", file=sys.stderr)
        for name, handle in channels.items():
            print(f"    Telegram: {name}...", file=sys.stderr)
            entries = fetch_telegram_public(name, handle)
            all_entries.extend(entries)
            time.sleep(REQUEST_DELAY)

    # Twitch
    if "twitch" in sources_to_run:
        channels = config.get("twitch_channels", {})
        print(f"[*] Fetching {len(channels)} Twitch channels...", file=sys.stderr)
        for name, username in channels.items():
            print(f"    Twitch: {name}...", file=sys.stderr)
            entries = fetch_twitch_vods(name, username)
            all_entries.extend(entries)
            time.sleep(REQUEST_DELAY)

    # Kick
    if "kick" in sources_to_run:
        channels = config.get("kick_channels", {})
        if channels:
            print(f"[*] Fetching {len(channels)} Kick channels...", file=sys.stderr)
            for name, username in channels.items():
                print(f"    Kick: {name}...", file=sys.stderr)
                entries = fetch_kick_channel(name, username)
                all_entries.extend(entries)
                time.sleep(REQUEST_DELAY)
        else:
            print("[*] Kick: no channels configured (no CTI presence)", file=sys.stderr)

    print(f"[*] Fetched {len(all_entries)} total entries", file=sys.stderr)

    # Filter by time window
    all_entries = filter_by_days(all_entries, args.days)
    print(f"[*] {len(all_entries)} entries within last {args.days} days", file=sys.stderr)

    # Tag entries with nation-state keywords
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
        "days": args.days,
        "source": args.source,
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
