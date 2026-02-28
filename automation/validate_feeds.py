#!/usr/bin/env python3
"""
validate_feeds.py - Validate all configured feed URLs are live and returning data.

Checks HTTP status codes, follows redirects, and reports stale/dead feeds.
Run this monthly to catch deprecated feeds before they rot your pipeline.

Usage:
    python validate_feeds.py                    # Validate all feeds
    python validate_feeds.py --output report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "feed_config.json"
USER_AGENT = "WendysDrivethrough-Validator/1.0"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def check_url(name, url, timeout=15):
    """Check a single URL and return status info."""
    result = {
        "name": name,
        "url": url,
        "status": "unknown",
        "http_code": None,
        "final_url": None,
        "content_size": 0,
        "redirected": False,
        "error": None,
    }
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        result["http_code"] = resp.status_code
        result["final_url"] = resp.url
        result["content_size"] = len(resp.content)
        result["redirected"] = resp.url != url

        if resp.status_code == 200 and result["content_size"] > 100:
            result["status"] = "live"
        elif resp.status_code == 200 and result["content_size"] <= 100:
            result["status"] = "empty"
        elif resp.status_code in (301, 302, 308):
            result["status"] = "redirect"
        elif resp.status_code == 403:
            result["status"] = "forbidden"
        elif resp.status_code == 404:
            result["status"] = "not_found"
        else:
            result["status"] = f"http_{resp.status_code}"
    except requests.exceptions.ConnectionError:
        result["status"] = "connection_failed"
        result["error"] = "Connection refused or DNS failure"
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"] = f"Timed out after {timeout}s"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(description="Validate threat feed URLs")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    args = parser.parse_args()

    config = load_config()

    all_urls = {}
    for category in ["vendor_rss_feeds", "government_feeds", "ioc_feeds"]:
        for name, url in config.get(category, {}).items():
            all_urls[f"{category}/{name}"] = url

    print(f"[*] Validating {len(all_urls)} feed URLs...", file=sys.stderr)

    results = []
    live_count = 0
    dead_count = 0

    for name, url in all_urls.items():
        result = check_url(name, url)
        results.append(result)

        icon = "OK" if result["status"] == "live" else "!!"
        size_kb = result["content_size"] / 1024
        redir = f" -> {result['final_url']}" if result["redirected"] else ""
        print(f"  [{icon}] {name}: {result['status']} ({result['http_code']}, {size_kb:.1f}KB){redir}", file=sys.stderr)

        if result["status"] == "live":
            live_count += 1
        else:
            dead_count += 1

    print(f"\n[*] Results: {live_count} live, {dead_count} issues", file=sys.stderr)

    output_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_checked": len(results),
        "live": live_count,
        "issues": dead_count,
        "results": results,
    }

    output = json.dumps(output_data, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"[*] Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
