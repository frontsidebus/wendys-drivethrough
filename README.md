# wendys-drivethrough

Curated cyber threat intelligence feeds, OSINT resources, and adversary tracking focused on geopolitical cyber operations.

## Structure

```
threat-feeds/
  us-iran-israel-cyber-threat-feed.md   # Iran/Israel -- APT33, APT34, APT35, MuddyWater, CyberAv3ngers, etc.
  russia-cyber-threat-feed.md           # Russia -- APT28, APT29, Sandworm, Turla, Gamaredon, etc.
  china-cyber-threat-feed.md            # China -- Volt Typhoon, Salt Typhoon, APT41, APT40, APT10, etc.
  dprk-cyber-threat-feed.md             # DPRK -- Lazarus, Kimsuky, BlueNoroff, TraderTraitor, etc.
automation/                             # (coming) Feed ingestion and IOC aggregation scripts
detection-rules/                        # (coming) YARA and Sigma detection rules
```

## What This Is

A living collection of vetted, correlated intelligence sources for tracking nation-state cyber operations. Built from cross-referencing defense/government intel blogs, cybersecurity research vendors, OSINT platforms, social media feeds, and IOC repositories.

This is not a raw IOC dump. It's an analyst-curated reference for building and maintaining situational awareness on active threat actors, their TTPs, infrastructure patterns, and the geopolitical context driving their operations.

## How To Use

1. **Standing Up a Feed** -- Use the RSS/Atom feed URLs to build automated ingestion pipelines into your SIEM, TIP, or CTI platform (OpenCTI, MISP, etc.)
2. **Daily Monitoring** -- Follow the tiered monitoring cadence outlined in each threat feed for sustainable intel consumption
3. **Threat Hunting** -- Use the MITRE ATT&CK mappings, cross-vendor naming matrices, and IOC source lists to build detection rules (YARA, Sigma, Suricata)
4. **Incident Response** -- Cross-reference the CVE exploitation tables and wiper malware catalogs when triaging incidents with suspected nation-state involvement

## Classification

All content is derived from **open-source intelligence (OSINT)**. No classified or proprietary data is included. Sources are attributed throughout.

## Updates

Threat feeds should be treated as living documents. The cyber threat landscape shifts with geopolitical events -- review and update quarterly at minimum, or immediately following significant geopolitical escalation.

## Disclaimer

This repository is for **defensive cybersecurity research and education purposes only**. The information provided is intended to help security professionals improve their defensive posture. Always validate IOCs against multiple independent sources before taking blocking actions.
