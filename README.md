# wendys-drivethrough

Curated cyber threat intelligence feeds, OSINT resources, and adversary tracking focused on geopolitical cyber operations.

## Structure

```
threat-feeds/
  us-iran-israel-cyber-threat-feed.md   # Iran/Israel -- APT33, APT34, APT35, MuddyWater, CyberAv3ngers, etc.
  russia-cyber-threat-feed.md           # Russia -- APT28, APT29, Sandworm, Turla, Gamaredon, etc.
  china-cyber-threat-feed.md            # China -- Volt Typhoon, Salt Typhoon, APT41, APT40, APT10, etc.
  dprk-cyber-threat-feed.md             # DPRK -- Lazarus, Kimsuky, BlueNoroff, TraderTraitor, etc.
automation/
  fetch_rss_feeds.py                    # RSS/Atom feed aggregator with nation-state keyword tagging
  fetch_ioc_feeds.py                    # IOC aggregator (URLhaus, MalwareBazaar, ThreatFox, CISA KEV)
  scrape_cisa_advisories.py             # CISA advisory scraper (RSS deprecated, returns 403)
  validate_feeds.py                     # Feed URL health checker -- run monthly
  feed_config.json                      # Central config: feed URLs + keyword filters
  requirements.txt                      # Python deps: feedparser, requests
detection-rules/
  yara/apt_nation_state_malware.yar     # 30 YARA rules -- malware families across all 4 adversaries
  sigma/                                # 10 Sigma rules -- TTP-based behavioral detection
```

## What This Is

A living collection of vetted, correlated intelligence sources for tracking nation-state cyber operations. Built from cross-referencing defense/government intel blogs, cybersecurity research vendors, OSINT platforms, social media feeds, and IOC repositories.

This is not a raw IOC dump. It's an analyst-curated reference for building and maintaining situational awareness on active threat actors, their TTPs, infrastructure patterns, and the geopolitical context driving their operations.

## How To Use

1. **Standing Up a Feed** -- Use the RSS/Atom feed URLs to build automated ingestion pipelines into your SIEM, TIP, or CTI platform (OpenCTI, MISP, etc.)
2. **Daily Monitoring** -- Follow the tiered monitoring cadence outlined in each threat feed for sustainable intel consumption
3. **Threat Hunting** -- Use the MITRE ATT&CK mappings, cross-vendor naming matrices, and IOC source lists to build detection rules (YARA, Sigma, Suricata)
4. **Incident Response** -- Cross-reference the CVE exploitation tables and wiper malware catalogs when triaging incidents with suspected nation-state involvement

## Automation Scripts

```bash
cd automation && pip install -r requirements.txt

# Fetch all RSS feeds, filter for Iran-related entries from the last 24 hours
python fetch_rss_feeds.py --filter iran --hours 24 --output feeds.json

# Aggregate IOCs from abuse.ch + CISA KEV
python fetch_ioc_feeds.py --output iocs.json

# Scrape CISA advisories (RSS is dead, this scrapes the page directly)
python scrape_cisa_advisories.py --filter russia --output cisa.json

# Validate all configured feed URLs are still alive
python validate_feeds.py --output health.json
```

## Detection Rules

- **YARA** (`detection-rules/yara/`) -- 30 rules covering malware families: Iranian wipers (BiBi, Shamoon), Russian wipers (WhisperGate, HermeticWiper, Industroyer2), Chinese implants (ShadowPad, PlugX, COATHANGER), DPRK tools (AppleJeus, FASTCash, BLINDINGCAN)
- **Sigma** (`detection-rules/sigma/`) -- 10 rules covering TTPs: LOTL techniques, DNS tunneling, password spraying, credential dumping, OAuth token theft, web shells, crypto targeting, browser extension hijacking, wiper behavior

## Classification

All content is derived from **open-source intelligence (OSINT)**. No classified or proprietary data is included. Sources are attributed throughout.

## Updates

Threat feeds should be treated as living documents. The cyber threat landscape shifts with geopolitical events -- review and update quarterly at minimum, or immediately following significant geopolitical escalation.

## Disclaimer

This repository is for **defensive cybersecurity research and education purposes only**. The information provided is intended to help security professionals improve their defensive posture. Always validate IOCs against multiple independent sources before taking blocking actions.
