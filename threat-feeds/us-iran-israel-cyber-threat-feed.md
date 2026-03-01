---
feedId: iran-israel-apt-threat-intel-2026
title: US-Iran-Israel Cyber Threat Intelligence Feed
topic: nation-state
industry: critical-infrastructure
country: IR
severity: high
tags: [apt33, apt34, irgc, mois, iran, israel, wiper, hacktivist, predatory-sparrow, scarred-manticore]
summary: Iranian IRGC/MOIS APT operations and Israeli offensive cyber capabilities. Hacktivist persona operations, critical infrastructure pre-positioning, wiper malware campaigns, and N-day exploitation.
---

# US-Iran-Israel Cyber Threat Intelligence Feed

**Classification:** OSINT -- Open Source Intelligence Only
**Initial Compilation:** 2026-02-28
**Last Validated:** 2026-02-28 (all feeds and URLs verified live)
**Baseline Knowledge:** Through May 2025 (see Intelligence Gaps section for coverage limitations)
**Focus:** Iranian APT groups, Israeli cyber operations, US-Iran-Israel geopolitical cyber tensions
**Intended Audience:** Blue team operators, CTI analysts, SOC analysts, incident responders

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Iranian APT Group Profiles](#2-iranian-apt-group-profiles)
3. [Israeli Cyber Operations and Entities](#3-israeli-cyber-operations-and-entities)
4. [Geopolitical Context and Escalation Drivers](#4-geopolitical-context-and-escalation-drivers)
5. [Critical Infrastructure Targeting](#5-critical-infrastructure-targeting)
6. [Wiper Malware and Destructive Campaigns](#6-wiper-malware-and-destructive-campaigns)
7. [Actively Exploited CVEs](#7-actively-exploited-cves)
8. [Cross-Vendor Naming Matrix](#8-cross-vendor-naming-matrix)
9. [MITRE ATT&CK Group Mappings](#9-mitre-attck-group-mappings)
10. [Key Iranian TTPs Summary](#10-key-iranian-ttps-summary)
11. [Government and Defense Intel Sources](#11-government-and-defense-intel-sources)
12. [Vetted Cybersecurity Research Blogs](#12-vetted-cybersecurity-research-blogs)
13. [Social Media and OSINT Feeds](#13-social-media-and-osint-feeds)
14. [OSINT Tools and Platforms](#14-osint-tools-and-platforms)
15. [IOC Sources and Threat Feeds](#15-ioc-sources-and-threat-feeds)
16. [RSS/Atom Feeds for Automated Ingestion](#16-rssatom-feeds-for-automated-ingestion)
17. [Monitoring Cadence and Aggregation Strategy](#17-monitoring-cadence-and-aggregation-strategy)
18. [Intelligence Gaps and Collection Priorities](#18-intelligence-gaps-and-collection-priorities)

---

## 1. Executive Summary

Iranian cyber operations have undergone significant escalation since October 2023, with multiple IRGC and MOIS-affiliated groups conducting concurrent campaigns against Israeli, US, and allied targets. The operational tempo has not decreased during ceasefire periods -- espionage and pre-positioning continue regardless of kinetic activity.

**Key assessments:**

- **MOIS and IRGC groups increasingly coordinate**, with evidence of access-sharing between espionage-focused groups and destructive operators. The Scarred Manticore (access) to Void Manticore (destruction) handoff model represents a matured operational doctrine.
- **Hacktivist persona operations** are now standard in Iranian cyber doctrine. Every major operation includes influence amplification through fake hacktivist fronts.
- **Critical infrastructure pre-positioning** remains the highest-priority concern. CISA and FBI have repeatedly warned about Iranian groups maintaining persistent access to US water, energy, and transportation systems.
- **Iranian groups are rapid N-day adopters** -- they weaponize newly disclosed vulnerabilities in internet-facing appliances (VPNs, firewalls, collaboration platforms) within days to weeks of public disclosure.
- **Israeli offensive cyber capabilities** continue to demonstrate deep access to Iranian infrastructure, as evidenced by operations like Predatory Sparrow's attacks against Iranian gas stations and steel mills.

---

## 2. Iranian APT Group Profiles

### 2.1 APT33 / Elfin / Peach Sandstorm / Refined Kitten

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0064 |
| **Attribution** | IRGC-linked; assessed connected to Nasr Institute |
| **Microsoft** | Peach Sandstorm |
| **CrowdStrike** | Refined Kitten |
| **Dragos** | MAGNALLIUM |
| **Primary Targets** | Aerospace, defense, energy sectors -- US, Saudi Arabia, South Korea |
| **Key TTPs** | Password spray campaigns at scale; abuse of Azure infrastructure; custom backdoors including FalseFont (targeting DIB); use of legitimate remote management tools (AnyDesk, SimpleHelp) for persistence |
| **Key CVEs** | CVE-2022-47966 (Zoho ManageEngine), CVE-2022-26134 (Confluence), CVE-2023-42793 (JetBrains TeamCity) |
| **Infrastructure** | Heavy use of compromised legitimate infrastructure; Azure tenant abuse for C2 |
| **Key Reporting** | Microsoft: Peach Sandstorm FalseFont backdoor against DIB (Nov 2023); continued password spray ops throughout 2024 targeting satellite, defense, and pharmaceutical sectors |

### 2.2 APT34 / OilRig / Hazel Sandstorm / Helix Kitten

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0049 |
| **Attribution** | MOIS (Ministry of Intelligence and Security) |
| **Microsoft** | Hazel Sandstorm |
| **CrowdStrike** | Helix Kitten |
| **Dragos** | CHRYSENE |
| **Primary Targets** | Government, financial, telecom sectors -- Gulf states, Israel, Jordan, Iraq |
| **Key TTPs** | DNS tunneling for C2 and exfiltration (signature TTP); supply chain compromise via IT service providers; deployment of backdoor variants (Karkoff, SideTwist, MrPerfectionManager, Menorah, Solar, Mango); Exchange exploitation |
| **Key CVEs** | ProxyShell variants (CVE-2021-34473/34523/31207), CVE-2024-30088 (Windows Kernel EoP) |
| **Key Reporting** | ESET: OilRig targeting Israeli organizations via supply chain, deploying SC5k downloader and OilBooster tools; Check Point: LIONTAIL framework analysis; Trend Micro: Menorah backdoor campaigns |

### 2.3 APT35 / Charming Kitten / Mint Sandstorm / APT42

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0059 (Magic Hound); G1030 (APT42 subgroup) |
| **Attribution** | IRGC Intelligence Organization (IRGC-IO) |
| **Microsoft** | Mint Sandstorm |
| **CrowdStrike** | Charming Kitten |
| **Proofpoint** | TA453 |
| **Primary Targets** | Think tanks, academia, journalists, dissidents, government officials -- US, Israel, Europe |
| **Key TTPs** | Sophisticated social engineering and spear-phishing; impersonation of journalists/academics; deployment of MediaPl and MischiefTut backdoors; custom PowerShell implants (CharmPower, POWERSTAR); fake interview lures and academic conference invitations; phishing via compromised university email |
| **Critical Activity** | Microsoft (Aug 2024): Mint Sandstorm targeting US presidential campaign staff; corroborated by FBI and ODNI. Google TAG: APT42 credential phishing via fake Google login pages; Volexity: BASICSTAR and KORKULOADER malware |
| **Key CVEs** | CVE-2023-38831 (WinRAR); rapid adoption of Citrix, Fortinet, and Pulse Secure VPN vulns |
| **Infrastructure** | EvilGinx-style adversary-in-the-middle phishing proxies for credential theft and MFA bypass |

### 2.4 MuddyWater / Mango Sandstorm / Static Kitten

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0069 |
| **Attribution** | MOIS -- subordinate element of Ministry of Intelligence |
| **Microsoft** | Mango Sandstorm |
| **CrowdStrike** | Static Kitten |
| **Proofpoint** | TA450 |
| **Primary Targets** | Government, telecom, energy -- Middle East (Turkey, Saudi Arabia, Israel, Jordan, Iraq), Central/South Asia |
| **Key TTPs** | Abuse of legitimate RMM tools as primary C2/persistence (Atera Agent, ScreenConnect, SimpleHelp, Tactical RMM) -- **defining characteristic**; spear-phishing with links to RMM installers on file-sharing services; custom PowerShell frameworks (PhonyC2, MuddyC2Go, DarkBeatC2); lateral movement via compromised partner organizations |
| **Key Reporting** | CISA AA24-290A (Feb 2024): Joint advisory on MuddyWater RMM tool abuse; Deep Instinct: DarkBeatC2 framework; Proofpoint: campaigns targeting Israeli entities with Atera Agent lures |

### 2.5 Cotton Sandstorm / Emennet Pasargad / Haywire Kitten

| Attribute | Detail |
|---|---|
| **Attribution** | IRGC-affiliated; operators indicted by US DOJ, sanctioned by Treasury |
| **Microsoft** | Cotton Sandstorm |
| **CrowdStrike** | Haywire Kitten |
| **Primary Targets** | Influence operations; hack-and-leak; disruptive attacks against Israel, US, Europe |
| **Key TTPs** | Hybrid cyber-influence operations -- hack targets then amplify stolen data through fake hacktivist personas; wiper malware against Israeli organizations; operated as "Homeland Justice" against Albania; AI-generated content for influence amplification; targeting of IP cameras and security systems in Israel |
| **Key Reporting** | FBI (2024): attributed Israeli-related hack-and-leak operations; Microsoft: Cotton Sandstorm posing as multiple hacktivist groups simultaneously; DOJ indictments and Treasury sanctions against Emennet Pasargad operatives |

### 2.6 Void Manticore / Storm-0842 (Destructive Operations)

| Attribute | Detail |
|---|---|
| **Attribution** | MOIS-linked |
| **Also Known As** | Moses Staff, Abraham's Ax (sub-personas) |
| **Microsoft** | Storm-0842 / Crimson Sandstorm |
| **Primary Targets** | Israeli organizations -- destructive/wiper operations |
| **Key TTPs** | Custom wiper malware (BiBi Wiper -- Linux + Windows variants); data destruction disguised as ransomware; website defacement; **collaboration model where Scarred Manticore provides initial access and Void Manticore conducts destructive operations** |
| **Key Reporting** | Check Point Research (2024): documented operational relationship between Scarred Manticore (access broker) and Void Manticore (destructive operator), showing MOIS groups operating in coordinated handoff model |

### 2.7 Scarred Manticore / Storm-0861

| Attribute | Detail |
|---|---|
| **Attribution** | MOIS |
| **Microsoft** | Storm-0861 |
| **Primary Targets** | Government, telecom, ISPs -- Middle East (especially Israel) |
| **Key TTPs** | Access-as-a-service model -- provides initial access to other MOIS groups; LIONTAIL web shell framework (passive, memory-resident implant leveraging Windows HTTP.sys driver); long-dwell espionage operations; access handoff to Void Manticore for destructive ops |
| **Key Reporting** | Check Point Research (Oct 2023/2024): detailed LIONTAIL framework and MOIS collaboration model |

### 2.8 Agrius / Pink Sandstorm / Banished Kitten

| Attribute | Detail |
|---|---|
| **Attribution** | MOIS-linked |
| **Microsoft** | Pink Sandstorm |
| **CrowdStrike** | Banished Kitten |
| **Primary Targets** | Israel (primarily), diamond industry in South Africa, Hong Kong |
| **Key TTPs** | Fantasy and Apostle wipers disguised as ransomware; supply chain compromise through Israeli software vendors; .NET backdoors |
| **Key Reporting** | ESET: Agrius campaigns via supply chain compromise of Israeli HR software vendor; SentinelOne: Fantasy wiper analysis |

### 2.9 Pioneer Kitten / Lemon Sandstorm / Fox Kitten

| Attribute | Detail |
|---|---|
| **Attribution** | MOIS contractor |
| **Microsoft** | Lemon Sandstorm |
| **CrowdStrike** | Pioneer Kitten |
| **Secureworks** | COBALT MIRAGE |
| **Dragos** | PARISITE |
| **Primary Targets** | Initial access broker -- sells access to ransomware affiliates (NoEscape, RansomHouse, ALPHV/BlackCat); targets across US defense, government, healthcare, finance |
| **Key TTPs** | Exploitation of internet-facing VPN/firewall appliances; web shell deployment; credential harvesting; operates at intersection of espionage and cybercrime |
| **Key CVEs** | CVE-2019-19781 (Citrix), CVE-2019-11510 (Pulse Secure), CVE-2020-5902 (F5 BIG-IP), CVE-2023-3519 (Citrix NetScaler), CVE-2024-3400 (PAN-OS) |
| **Key Reporting** | CISA AA24-241A (Aug 2024): Pioneer Kitten as ransomware initial access broker; Microsoft (May 2025): Lemon Sandstorm multi-year intrusion into Middle East CNI |

### 2.10 CyberAv3ngers (ICS/OT Focused)

| Attribute | Detail |
|---|---|
| **Attribution** | IRGC-CEC (Cyber-Electronic Command) affiliated |
| **Primary Targets** | Water/wastewater systems, energy sector ICS/OT -- US and Israel |
| **Key TTPs** | Targeting Unitronics Vision Series PLCs; exploitation of default credentials; exposed HMI targeting |
| **Key Reporting** | CISA AA23-335A (Dec 2023): IRGC-affiliated actors exploiting PLCs in water/wastewater; compromised Aliquippa, PA water authority; Treasury sanctions imposed Feb 2024 |

### 2.11 Imperial Kitten / Crimson Sandstorm / Tortoiseshell

| Attribute | Detail |
|---|---|
| **Attribution** | IRGC-CEC |
| **CrowdStrike** | Imperial Kitten |
| **Proofpoint** | TA456 |
| **Primary Targets** | Israel transportation, logistics, technology |
| **Key TTPs** | Watering hole attacks; job-themed social engineering lures; supply chain operations; fake social media personas (e.g., Marcella Flores operation documented by Proofpoint) |

### 2.12 APT39 / Chafer / Remix Kitten

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0087 |
| **Attribution** | MOIS (Rana Intelligence Computing Company -- sanctioned by US Treasury) |
| **CrowdStrike** | Remix Kitten |
| **Primary Targets** | Travel, telecom, IT -- primarily for surveillance support of MOIS operations |
| **Key TTPs** | Mobile surveillance (custom Android malware), data exfiltration, RDP lateral movement |

### 2.13 HEXANE / Lyceum / Spirlin

| Attribute | Detail |
|---|---|
| **MITRE ID** | G1001 |
| **Secureworks** | COBALT LYCEUM |
| **Primary Targets** | Telecom, oil/gas, ISPs -- Middle East, Africa |
| **Key TTPs** | DNS-based backdoors, spearphishing with malicious attachments, PowerShell execution |

---

## 3. Israeli Cyber Operations and Entities

### 3.1 State-Linked Operations

| Entity | Detail |
|---|---|
| **Unit 8200 (IDF)** | Israel's SIGINT unit. One of the most capable SIGINT/cyber organizations globally. Historically linked to Stuxnet (joint US-Israel), Duqu, Flame. Alumni ecosystem populates Israeli cyber industry. |
| **Predatory Sparrow (Gonjeshke Darande)** | Claimed responsibility for destructive attacks against Iranian infrastructure: December 2023 attack disabling ~70% of Iranian gas stations; 2022 attacks against Iranian steel mills. Operational pattern suggests state affiliation though officially unattributed. |
| **Pager/Communications Device Operation (Sep 2024)** | While primarily physical/supply chain, the operation against Hezbollah pagers and walkie-talkies in Lebanon demonstrated Israeli capabilities at the intersection of cyber, supply chain, and physical operations. |

### 3.2 Private Sector Offensive Cyber

| Entity | Detail |
|---|---|
| **NSO Group** | Pegasus spyware. Remains operational despite sanctions and lawsuits. Tracked by Citizen Lab, Microsoft, Google TAG. |
| **Candiru (Saito Tech)** | DevilsTongue spyware. US Commerce Dept sanctioned. Microsoft/Citizen Lab research published. |
| **QuaDream** | REIGN spyware. Reportedly ceased operations 2023 following Citizen Lab exposure. |

### 3.3 Defensive/Research Entities to Track

| Entity | Description |
|---|---|
| **Israel National Cyber Directorate (INCD)** | National cyber authority. Publishes advisories and coordinates defense. Portal: `gov.il/en/departments/israel_national_cyber_directorate` |
| **Check Point Research** | Major Israeli security firm. Extensive publication record on Iranian threats targeting Israel. |
| **ClearSky Cyber Security** | Israeli CTI firm. Arguably the most prolific tracker of Iranian APTs. Reports are required reading. |
| **Cybereason (Nocturnus Team)** | Israeli-founded EDR company. Publishes research on Iranian operations. |

---

## 4. Geopolitical Context and Escalation Drivers

### 4.1 Key Escalation Timeline

| Timeline | Event | Cyber Implications |
|---|---|---|
| **Oct 7, 2023** | Hamas attack on Israel | Triggered massive escalation in Iranian-linked cyber operations against Israel; activation of multiple hack-and-leak personas |
| **Apr 2024** | Iran direct missile/drone attack on Israel | Accompanied by cyber operations; unprecedented direct state-on-state kinetic+cyber combination |
| **Apr 2024** | Israeli retaliatory strikes on Iran | Bilateral escalation cycle with cyber components |
| **Aug 2024** | US presidential campaign targeting | Mint Sandstorm/APT42 targeting both Republican and Democratic campaign staff |
| **Sep 2024** | Pager/walkie-talkie operation in Lebanon | Demonstrated supply chain interdiction capabilities at scale |
| **Oct 2024** | Israeli strikes on Iranian military targets | Further escalation with assessed cyber accompaniment |
| **Late 2024+** | Ceasefire negotiations and regional dynamics | Cyber operations continued regardless of kinetic tempo -- espionage and pre-positioning do not pause during ceasefires |

### 4.2 Assessed Cyber Escalation Patterns

- Iranian groups **significantly increased operational tempo** post-October 2023, with multiple groups running concurrent operations against Israeli and US-aligned targets
- MOIS and IRGC groups **increasingly coordinate** with evidence of access-sharing and operational handoffs
- **Hacktivist persona operations** are standard doctrine -- virtually every major Iranian cyber operation includes an influence component
- **Critical infrastructure pre-positioning** is ongoing -- CISA/FBI have warned about Iranian groups maintaining access to US water, energy, and transportation systems for potential future destructive use

---

## 5. Critical Infrastructure Targeting

### 5.1 Water Sector

- **CyberAv3ngers (IRGC-CEC)**: CISA AA23-335A documented targeting of Unitronics Vision PLCs in water/wastewater. Compromised Aliquippa, PA water authority. Part of broader campaign against Unitronics PLCs globally.
- Treasury sanctions on IRGC-CEC officials (Feb 2024) specifically for water sector targeting.

### 5.2 Energy Sector

- APT33/Peach Sandstorm maintains sustained focus on energy sector, particularly Gulf states and US
- Dragos tracks multiple Iranian-linked groups (MAGNALLIUM, CHRYSENE, PARISITE) targeting energy OT/ICS
- Historical: Shamoon wiper attacks against Saudi Aramco (2012, 2016-2017) -- established precedent for destructive attacks against energy

### 5.3 Financial Sector

- APT34/OilRig maintains long-term targeting of Gulf state financial institutions
- Cotton Sandstorm influence operations target financial sector for economic disruption

### 5.4 Transportation and Logistics

- Imperial Kitten targeting Israeli transportation and logistics since 2023
- UNC3890 targeting Israeli shipping (Mandiant)

---

## 6. Wiper Malware and Destructive Campaigns

### 6.1 Active Iranian Wiper Arsenal

| Wiper | Associated Group | Characteristics |
|---|---|---|
| **BiBi Wiper** (Linux + Windows) | Void Manticore / Moses Staff | Renames files with ".BiBi" extension; deployed against Israeli targets |
| **Fantasy** | Agrius | Supply-chain deployed; targeted diamond industry |
| **Apostle** | Agrius | Initially masqueraded as ransomware; evolved into pure wiper |
| **Cl Wiper** | Void Manticore | Partition table manipulation for destruction |
| **Partition Wiper** | Void Manticore | Targets disk partition tables |
| **No-Justice Wiper** | Cotton Sandstorm-linked | Deployed against Albanian government systems |
| **SameCoin Wiper** | Possibly Void Manticore | Deployed against Israeli targets via fake security update |
| **DCSrv** | Moses Staff | Custom wiper tool |
| **Shamoon lineage** | APT33/Elfin (historical) | Destructive disk-wiping capability; Saudi Aramco precedent |
| **ZeroCleare** | APT34/OilRig + xHunt | Targeted Middle East energy sector |

### 6.2 Destructive Capability Assessment

Iranian destructive capability has **matured significantly**. Groups now maintain arsenals of multiple wiper variants and can rapidly deploy destructive payloads through access provided by espionage-focused teams. The MOIS collaboration model (Scarred Manticore for access, Void Manticore for destruction) is more dangerous than independent operation.

---

## 7. Actively Exploited CVEs

| CVE | Product | Exploiting Group(s) | CISA KEV |
|---|---|---|---|
| CVE-2024-30088 | Windows Kernel (EoP) | APT34/OilRig | Yes |
| CVE-2024-3400 | Palo Alto PAN-OS GlobalProtect | Multiple Iranian groups, Pioneer Kitten | Yes |
| CVE-2024-1709 | ConnectWise ScreenConnect | Multiple | Yes |
| CVE-2023-46805 + CVE-2024-21887 | Ivanti Connect Secure | Multiple including Iranian | Yes |
| CVE-2023-42793 | JetBrains TeamCity | Peach Sandstorm | Yes |
| CVE-2023-38831 | WinRAR | APT35/Mint Sandstorm, APT42 | Yes |
| CVE-2023-3519 | Citrix NetScaler | Pioneer Kitten | Yes |
| CVE-2023-27997 | Fortinet FortiOS SSL VPN | Mint Sandstorm | Yes |
| CVE-2022-47966 | Zoho ManageEngine | Mint Sandstorm/Peach Sandstorm | Yes |
| CVE-2022-47986 | IBM Aspera Faspex | Mint Sandstorm | Yes |
| CVE-2021-44228 | Apache Log4j (Log4Shell) | Multiple Iranian groups | Yes |
| CVE-2021-34473/34523/31207 | Exchange (ProxyShell) | Multiple Iranian groups | Yes |
| CVE-2021-26855 | Exchange (ProxyLogon) | Multiple Iranian groups | Yes |
| CVE-2020-5902 | F5 BIG-IP | Pioneer Kitten | Yes |
| CVE-2019-19781 | Citrix ADC/Gateway | Pioneer Kitten | Yes |
| CVE-2019-11510 | Pulse Secure VPN | Pioneer Kitten, APT33 | Yes |

**Pattern**: Iranian APTs are known for **rapid N-day adoption** -- they weaponize newly disclosed vulnerabilities in internet-facing appliances within days to weeks of disclosure or PoC availability. VPNs, firewalls, and collaboration platforms are the primary target surface.

---

## 8. Cross-Vendor Naming Matrix

Understanding cross-vendor naming is **critical** for effective monitoring. The same group appears under different names depending on which vendor's reporting you are reading.

| MITRE | Microsoft | CrowdStrike | Mandiant | Secureworks | Dragos | Proofpoint | Check Point |
|---|---|---|---|---|---|---|---|
| Magic Hound / APT42 | Mint Sandstorm | Charming Kitten | APT42 | COBALT ILLUSION | -- | TA453 | Educated Manticore |
| APT33 | Peach Sandstorm | Refined Kitten | APT33 | COBALT TRINITY | MAGNALLIUM | -- | -- |
| OilRig | Hazel Sandstorm | Helix Kitten | APT34 | COBALT GYPSY | CHRYSENE | -- | Scarred Manticore (partial) |
| MuddyWater | Mango Sandstorm | Static Kitten | -- | COBALT ULSTER | -- | TA450 | -- |
| APT39 | -- | Remix Kitten | APT39 | COBALT HICKMAN | -- | -- | Domestic Kitten (partial) |
| -- | Lemon Sandstorm | Pioneer Kitten | UNC757 | COBALT MIRAGE | PARISITE | -- | -- |
| -- | Cotton Sandstorm | Haywire Kitten | -- | -- | -- | -- | -- |
| HEXANE | -- | -- | -- | COBALT LYCEUM | -- | -- | -- |
| Agrius | Pink Sandstorm | Banished Kitten | -- | -- | -- | -- | -- |
| Moses Staff | Crimson Sandstorm | -- | -- | -- | -- | -- | -- |
| -- | -- | Imperial Kitten | -- | -- | -- | TA456 | -- |
| -- | Storm-0861 | -- | -- | -- | -- | -- | Scarred Manticore |
| -- | Storm-0842 | -- | -- | -- | -- | -- | Void Manticore |

**Microsoft Taxonomy Key**: "Sandstorm" = Iran-attributed. Weather phenomena are used for nation-state groups: Sandstorm (Iran), Blizzard (Russia), Typhoon (China), Sleet (North Korea), Hail (South Korea), Dust (Turkey), Rain (Lebanon).

---

## 9. MITRE ATT&CK Group Mappings

**Reference**: `https://attack.mitre.org/groups/`

| MITRE ID | Name | Key Aliases | Affiliation | Primary TTPs |
|---|---|---|---|---|
| G0059 | Magic Hound | APT35, Charming Kitten, Phosphorus, Mint Sandstorm, TA453 | IRGC-IO | T1566 Phishing, T1078 Valid Accounts, T1539 Steal Web Session Cookie, T1059.001 PowerShell |
| G1030 | APT42 | Charming Kitten, Mint Sandstorm (partial), TA453 | IRGC-IO | T1566.002 Spearphishing Link, T1598.003 Spearphishing for Info, T1078 Valid Accounts, T1114 Email Collection |
| G0064 | APT33 | Elfin, Refined Kitten, Peach Sandstorm, MAGNALLIUM | IRGC | T1566.002 Spearphishing Link, T1059.001 PowerShell, T1003 Credential Dumping, T1110 Brute Force |
| G0049 | OilRig | APT34, Helix Kitten, COBALT GYPSY, Crambus, Hazel Sandstorm | MOIS | T1566.001 Spearphishing Attachment, T1071.004 DNS C2, T1053.005 Scheduled Task, T1027 Obfuscated Files |
| G0069 | MuddyWater | Static Kitten, Seedworm, Mango Sandstorm, TA450 | MOIS | T1566.001 Spearphishing Attachment, T1059.001 PowerShell, T1218.005 Mshta, T1219 Remote Access Software |
| G0087 | APT39 | Chafer, Remix Kitten, COBALT HICKMAN | MOIS (Rana Corp) | T1566 Phishing, T1059.001 PowerShell, T1021.001 RDP, T1560 Archive Collected Data |
| G0003 | Cleaver | Tarh Andishan | IRGC-affiliated | T1595 Active Scanning, T1190 Exploit Public-Facing App, T1078 Valid Accounts |
| G1001 | HEXANE | Lyceum, Spirlin, COBALT LYCEUM | Possibly MOIS | T1566.001 Spearphishing Attachment, T1071.004 DNS C2, T1059.001 PowerShell |
| G1029 | Agrius | Pink Sandstorm, Banished Kitten, BlackShadow | MOIS-affiliated | T1486 Data Encrypted for Impact, T1561 Disk Wipe, T1190 Exploit Public-Facing App |
| G1009 | Moses Staff | Crimson Sandstorm, Abraham's Ax | MOIS-affiliated | T1486 Data Encrypted for Impact, T1561.002 Disk Structure Wipe |

**Note**: MITRE ATT&CK does not formally track any Israeli-attributed groups, consistent with their approach to Five Eyes and close allies.

---

## 10. Key Iranian TTPs Summary

### Initial Access
- **Phishing** (T1566): Tailored lures impersonating journalists, academics, conference organizers
- **Exploit Public-Facing Application** (T1190): VPNs (Fortinet, Pulse Secure/Ivanti, Citrix), firewalls (PAN-OS), collaboration platforms (Exchange, ManageEngine)
- **Valid Accounts** (T1078): Password spraying, credential stuffing, MFA push bombing
- **External Remote Services** (T1133): Compromised VPN credentials

### Execution
- **PowerShell** (T1059.001): Dominant across all groups
- **VBScript** (T1059.005): MuddyWater and OilRig
- **User Execution** (T1204): Malicious documents and links

### Persistence
- **Registry Run Keys** (T1547.001)
- **Scheduled Tasks** (T1053.005)
- **Web Shells** (T1505.003): Including memory-resident variants (LIONTAIL)
- **Remote Access Software** (T1219): Atera, SimpleHelp, ScreenConnect, Tactical RMM, Level

### Defense Evasion
- **Mshta/Rundll32** system binary proxy execution (T1218)
- **Obfuscated Files** (T1027)
- **Masquerading** (T1036)

### Credential Access
- **OS Credential Dumping** (T1003): Mimikatz, comsvcs.dll
- **Brute Force** (T1110): Including MFA fatigue/push bombing
- **Adversary-in-the-Middle** (T1557): EvilGinx-style phishing proxies

### Command and Control
- **Web Protocols HTTPS** (T1071.001)
- **DNS Tunneling** (T1071.004): OilRig specialty
- **Cloud Services** (T1102): OneDrive, Google Drive, Dropbox, Exchange Web Services
- **Protocol Tunneling** (T1572)

### Impact
- **Data Encrypted for Impact / Wiper** (T1486): Shamoon, ZeroCleare, BiBi, Apostle, Fantasy
- **Disk Wipe** (T1561)

---

## 11. Government and Defense Intel Sources

### 11.1 US Government

| Source | URL | Description |
|---|---|---|
| **CISA Iran Threat Page** | `https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/iran` | Dedicated portal aggregating all Iran-related advisories |
| **CISA Advisories** | `https://www.cisa.gov/news-events/cybersecurity-advisories` | All cybersecurity advisories including joint Iran advisories |
| **CISA KEV Catalog** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | Tracks actively exploited vulnerabilities including those used by Iranian APTs |
| **NSA Cybersecurity Advisories** | `https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/` | Co-signs joint advisories; publishes defensive guidance against nation-state TTPs |
| **FBI Cyber Division** | `https://www.fbi.gov/investigate/cyber` | FBI cyber threat warnings and joint advisories |
| **FBI IC3** | `https://www.ic3.gov/` | Internet Crime Complaint Center |
| **US-CERT** (now CISA) | `https://www.cisa.gov/news-events/alerts` | Alerts feed |

#### Key CISA Iran Advisories

| Advisory | Date | Subject |
|---|---|---|
| AA24-290A | Oct 2024 | Iranian brute force and credential access targeting critical infrastructure |
| AA24-241A | Aug 2024 | Pioneer Kitten as ransomware initial access broker |
| AA23-335A | Dec 2023 | CyberAv3ngers targeting Unitronics PLCs in water/wastewater |
| AA22-320A | Nov 2022 | Iranian APT exploiting Log4Shell against federal network |
| AA22-055A | Feb 2022 | MuddyWater targeting global telecommunications |
| AA21-321A | Nov 2021 | Iranian APT exploiting Exchange and Fortinet |

### 11.2 UK Government

| Source | URL | Description |
|---|---|---|
| **UK NCSC Threat Reports** | `https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports` | UK National Cyber Security Centre threat reports |
| **UK NCSC Advisories** | `https://www.ncsc.gov.uk/section/keep-up-to-date/advisories` | Technical advisories including joint Iran advisories with Five Eyes partners |

### 11.3 Israeli Government

| Source | URL | Description |
|---|---|---|
| **Israel National Cyber Directorate** | `https://www.gov.il/en/departments/israel_national_cyber_directorate` | National cyber authority |
| **IL-CERT** | `https://www.gov.il/en/departments/units/il-cert` | Israeli CERT -- publishes primarily in Hebrew with selective English translations |

### 11.4 MITRE ATT&CK

| Resource | URL |
|---|---|
| **ATT&CK Groups** | `https://attack.mitre.org/groups/` |
| **ATT&CK Navigator** | `https://mitre-attack.github.io/attack-navigator/` |
| **ATT&CK for ICS** | `https://attack.mitre.org/techniques/ics/` |

---

## 12. Vetted Cybersecurity Research Blogs

### Tier 1 -- Primary Iranian APT Research

| Source | Blog URL | RSS Feed | Focus |
|---|---|---|---|
| **Microsoft Threat Intelligence** | `microsoft.com/en-us/security/blog/topic/threat-intelligence/` | `microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/` | Sandstorm group tracking (Mint, Peach, Cotton, Mango, Lemon, etc.) |
| **Mandiant (Google Cloud)** | `cloud.google.com/blog/topics/threat-intelligence` | `cloudblog.withgoogle.com/topics/threat-intelligence/rss/` | APT42, APT34, APT35, UNC groups; definitive Iranian APT research |
| **Google TAG** | `blog.google/threat-analysis-group/` | `blog.google/threat-analysis-group/rss/` | APT42 credential phishing; Iranian influence operations on Google platforms |
| **CrowdStrike** | `crowdstrike.com/en-us/blog/` | `crowdstrike.com/en-us/blog/feed` | KITTEN taxonomy; Annual Global Threat Report with Iran section |
| **Recorded Future Insikt Group** | `recordedfuture.com/blog` | `recordedfuture.com/feed` | Iran threat landscape assessments; IRGC contractor ecosystem mapping |
| **Check Point Research** | `research.checkpoint.com/` | `research.checkpoint.com/feed/` | Manticore taxonomy; LIONTAIL framework; deep Israel-targeting analysis |
| **ClearSky Cyber Security** | `clearskysec.com` | -- | Most prolific Israeli tracker of Iranian APTs; landmark reports on Charming Kitten, MuddyWater |

### Tier 2 -- Strong Iranian APT Coverage

| Source | Blog URL | RSS Feed | Focus |
|---|---|---|---|
| **Unit 42 (Palo Alto)** | `unit42.paloaltonetworks.com/` | `unit42.paloaltonetworks.com/feed/` | Educated Manticore, Crambus backdoor analysis, Lyceum DNS tunneling |
| **SentinelOne / SentinelLabs** | `sentinelone.com/labs/` | `sentinelone.com/labs/feed/` | Agrius wipers, Moses Staff analysis, BiBi wiper, MuddyWater PhonyC2 |
| **ESET WeLiveSecurity** | `welivesecurity.com/en/` | `welivesecurity.com/en/rss/feed/` | OilRig backdoor analysis, MuddyWater frameworks, Ballistic Bobcat |
| **Proofpoint** | `proofpoint.com/us/blog/threat-insight` | `proofpoint.com/us/rss.xml` | TA453 social engineering, TA456 fake personas, TA450 MuddyWater |
| **Volexity** | `volexity.com/blog/` | `volexity.com/feed/` | CharmingCypress BASICSTAR malware, credential phishing tradecraft |
| **Cisco Talos** | `blog.talosintelligence.com/` | `blog.talosintelligence.com/rss/` | MuddyWater campaign analysis, Lyceum DNS backdoors |
| **Sophos X-Ops** (formerly Secureworks CTU) | `news.sophos.com/en-us/category/threat-research/` | -- | Acquired Secureworks; inherits COBALT taxonomy research. Sophos X-Ops covers nation-state threats |

### Tier 3 -- Supporting Coverage

| Source | Blog URL | RSS Feed | Focus |
|---|---|---|---|
| **Dragos** | `dragos.com/blog/` | -- | ICS/SCADA focus; MAGNALLIUM, CHRYSENE, PARISITE; CyberAv3ngers. **Note: RSS feed deprecated; monitor blog directly** |
| **Kaspersky SecureList** | `securelist.com/` | `securelist.com/feed/` | MuddyWater, OilRig, Domestic Kitten. **Note: Russian-based; cross-reference with Western sources** |
| **Intel 471** | `intel471.com/blog/` | `intel471.com/blog/feed` | Iranian cyber-criminal nexus; underground monitoring. Acquired SpiderFoot OSINT platform |

> **Removed (validated dead as of Feb 2026):**
> - **Trellix** -- Domain completely unreachable (connection refused). Historical FireEye research now hosted under Mandiant/Google Cloud.
> - **Binary Defense** -- RSS feed returns 404. Blog structure changed; limited primary Iranian APT research.
> - **BlackBerry** -- Blog RSS redirects to restructured corporate site; no longer reliably parseable. Limited primary research.
> - **Secureworks** -- Acquired by Sophos; all URLs redirect. Moved to Tier 2 as Sophos X-Ops.

---

## 13. Social Media and OSINT Feeds

### 13.1 X/Twitter -- Government and Official

| Account | Handle | Description |
|---|---|---|
| CISA | @CISAgov | Official alerts and advisories |
| CISA Cyber | @CISACyber | Dedicated cybersecurity feed -- faster on technical advisories |
| NSA Cybersecurity | @NSACyber | Defensive guidance and nation-state threat advisories |
| FBI Cyber Division | @FBICyber | Cyber threat warnings and joint advisories |
| US Cyber Command | @US_CYBERCOM | Occasionally publishes Iranian malware samples to VirusTotal |
| Israel INCD | @Israel_Cyber | Israeli national cyber authority alerts |

### 13.2 X/Twitter -- Threat Intel Researchers

| Account | Handle | Focus |
|---|---|---|
| John Hultquist | @JohnHultquist | VP Mandiant/Google Threat Intel. Leading voice on Iranian cyber ops |
| Dmitri Alperovitch | @DAlperovitch | CrowdStrike co-founder. Deep nation-state cyber expertise |
| Juan Andres Guerrero-Saade | @juanandres_gs | SentinelLabs. Iranian APT malware analysis specialist |
| Costin Raiu | @craiu | Former Kaspersky GReAT director. Decade+ of Iranian ops knowledge |
| Jake Williams | @MalwareJake | Former NSA TAO. Iranian ops in geopolitical context |
| Kim Zetter | @KimZetter | Investigative journalist who broke Stuxnet. Definitive Iran cyber reporting |
| Catalin Cimpanu | @campuscodi | The Record. Covers Iranian APT campaigns as they break |
| The Grugq | @thegrugq | OPSEC and intelligence tradecraft analysis |
| Thomas Rid | @RidT | Johns Hopkins SAIS. Information operations and cyber conflict expert |

### 13.3 X/Twitter -- Vendor and Institutional

| Account | Handle |
|---|---|
| Mandiant | @Mandiant |
| Microsoft Threat Intelligence | @MsftSecIntel |
| CrowdStrike | @CrowdStrike |
| Recorded Future | @RecordedFuture |
| Check Point Research | @_CPResearch_ |
| ClearSky | @ClearSkySec |
| ESET Research | @ESETresearch |
| SentinelOne | @SentinelOne |
| Intel471 | @Intel471Inc |
| Proofpoint Threat Insight | @threatinsight |
| CyberScoop | @CyberScoopNews |
| The Record | @TheRecord_Media |
| DarkReading | @DarkReading |

### 13.4 X/Twitter -- Hashtags to Monitor

```
#APT42  #APT35  #APT34  #APT33  #APT39
#CharmingKitten  #MuddyWater  #OilRig
#MintSandstorm  #PeachSandstorm  #MangoSandstorm  #CottonSandstorm
#CyberAv3ngers  #IranCyber
#CTI  #ThreatIntel  #InfoSec
```

### 13.5 Reddit

#### Tier 1 -- Core CTI

| Subreddit | Description |
|---|---|
| r/cybersecurity | Largest general cybersec community. Breaking nation-state news surfaces fast |
| r/netsec | Technical network security. Higher signal-to-noise. APT campaign write-ups |
| r/threatintel | Dedicated threat intelligence. Highly focused on campaign tracking and IOC sharing |
| r/ReverseEngineering | Deep technical malware analysis. Iranian tooling teardowns |
| r/Malware | Malware analysis community. New Iranian malware families |

#### Tier 2 -- Geopolitical and OSINT Context

| Subreddit | Description |
|---|---|
| r/OSINT | Open source intelligence techniques and findings |
| r/geopolitics | Scholarly-level geopolitical analysis. Strict moderation. |
| r/intelligence | Intelligence community news and analysis |
| r/CredibleDefense | Defense/security analysis with sourcing requirements |
| r/blueteamsec | Defensive security. IOC lists, detection rules, YARA signatures |

### 13.6 YouTube Channels

| Channel | Description |
|---|---|
| SANS Institute | CTI Summit recordings. Regular APT campaign content |
| Black Hat | Conference talks on Iranian APT research and Middle East cyber conflict |
| DEF CON | Deep technical nation-state operations talks |
| Mandiant / Google Cloud Security | Iranian APT webinars and presentations |
| CrowdStrike | KITTEN group threat briefings |
| Recorded Future | Threat intel webinars with Iran/Middle East cyber coverage |
| CISA | Government guidance and Shields Up briefings |
| Caspian Report | Geopolitical analysis -- Iran/Israel/Middle East context |
| John Hammond | Accessible malware analysis including nation-state tooling |

### 13.7 Substack and Newsletters

| Newsletter | Description |
|---|---|
| **Risky Business News** (news.risky.biz) | Best daily CTI digest. Consistent Iranian APT coverage |
| **Kim Zetter's Zero Day** (zetter.substack.com) | Deep investigative Iran-related cyber journalism |
| **Metacurity** (metacurity.substack.com) | Daily cybersecurity news briefing |
| **TLDR InfoSec / tl;dr sec** (tldrsec.com) | Curated security newsletter surfacing key threat reports |
| **The Cipher Brief** (thecipherbrief.com) | IC-adjacent analysis. Iranian cyber ops from national security perspective |
| **Lawfare** (lawfaremedia.org) | Cyber policy including US-Iran cyber conflict legal frameworks |
| **War on the Rocks** (warontherocks.com) | Defense/security analysis with cyber operations context |
| **CFR Net Politics** (cfr.org) | State-sponsored cyber ops tracking. Maintains Cyber Operations Tracker |

### 13.8 Mastodon / Fediverse

| Instance | Description |
|---|---|
| **infosec.exchange** | Primary infosec Mastodon instance. Many CTI analysts migrated here from X |
| **ioc.exchange** | Specifically for IOC and threat intelligence sharing |
| **hackyderm.io** | Tech-focused with strong security researcher presence |
| **defcon.social** | DEF CON community instance |

### 13.9 Telegram

| Channel | Description |
|---|---|
| **vx-underground** | Premier malware research community. Iranian APT samples shared |
| **S.O.V.A.** | Threat intelligence sharing |
| **DarkTracer** | Dark web monitoring and threat intel |

**OPSEC WARNING**: Exercise extreme caution with adversary-operated Telegram channels. Use isolated devices, VPNs, and burner accounts. Do not interact with content.

### 13.10 Streaming and Video Platforms

| Platform | Channel | Description |
|---|---|---|
| **Twitch** | DEF CON (`defcon`) | Live conference streams; nation-state cyber operations talks |
| **Twitch** | Black Hat Events (`blackhatevents`) | Live conference streams and briefings |
| **Kick** | -- | No CTI presence as of February 2026 |

For conference talk archives, see YouTube channels in Section 13.6. Twitch streams are ephemeral -- VODs typically available for 14-60 days after broadcast.

---

## 14. OSINT Tools and Platforms

### 14.1 Malware Analysis and Pivoting

| Tool | URL | Iran/Israel CTI Use Case |
|---|---|---|
| **VirusTotal** | `virustotal.com` | Iranian malware hash search. VT Graph for infrastructure mapping. USCYBERCOM uploads Iranian samples here. VT Intelligence for YARA hunting. |
| **Hybrid Analysis** | `hybrid-analysis.com` | CrowdStrike Falcon Sandbox. Free analysis of suspected Iranian APT samples |
| **ANY.RUN** | `any.run` | Interactive sandbox. Behavioral analysis. Public submissions searchable |
| **Joe Sandbox** | `joesandbox.com` | Deep behavioral analysis reports |
| **OPSWAT MetaDefender** (formerly InQuest Labs) | `metadefender.opswat.com` | Document/file analysis via Deep CDR. InQuest acquired by OPSWAT; specializes in weaponized documents (Iranian APT staple) |
| **Malpedia** | `malpedia.caad.fkie.fraunhofer.de` | Malware family encyclopedia with Iranian APT associations |

### 14.2 Infrastructure Reconnaissance

| Tool | URL | Use Case |
|---|---|---|
| **Shodan** | `shodan.io` | Track Iranian C2 infrastructure. Monitor vulnerable VPN appliances. Unitronics PLC exposure. Iranian ASN monitoring (AS12880, AS44244, AS58224, AS42337, AS56402, AS48159) |
| **Censys** | `search.censys.io` | SSL certificate tracking for Iranian APT infrastructure. Certificate transparency monitoring for impersonation domains |
| **GreyNoise** | `greynoise.io` | Distinguish targeted Iranian attacks from mass scanning. Iranian reconnaissance pattern analysis |
| **Microsoft Defender Threat Intelligence** (formerly RiskIQ/PassiveTotal) | `learn.microsoft.com/en-us/defender/threat-intelligence/` | Passive DNS, WHOIS history, threat analytics. RiskIQ fully absorbed into Microsoft Defender TI. Map Iranian domain infrastructure over time |
| **DomainTools** | `domaintools.com` | WHOIS intelligence. Iranian domain registration pattern identification |
| **SecurityTrails** | `securitytrails.com` | Historical DNS data. Infrastructure change tracking |
| **Pulsedive** | `pulsedive.com` | Free threat intel with community-enriched IOCs and risk scoring |
| **AbuseIPDB** | `abuseipdb.com` | IP reputation for Iranian scanning/attack infrastructure |

### 14.3 Detection Engineering

| Tool | URL | Use Case |
|---|---|---|
| **YARA** | `github.com/virustotal/yara` | Pattern matching for Iranian APT malware. Extensive public rulesets exist |
| **Sigma** | `github.com/SigmaHQ/sigma` | Generic SIEM signatures. Community rules include Iranian APT TTPs |
| **Suricata / ET Rules** | `rules.emergingthreats.net` | Network-level detection for known Iranian APT C2 traffic patterns |

### 14.4 CTI Platforms and Aggregation

| Tool | URL | Use Case |
|---|---|---|
| **OpenCTI** (by Filigran) | `github.com/OpenCTI-Platform/opencti` | Open source CTI platform. STIX/TAXII compatible. Central aggregation. Company rebranded to Filigran (`filigran.io`) |
| **MISP** | `misp-project.org` | Threat sharing platform. Multiple Iranian APT community feeds |
| **Maltego** | `maltego.com` | Link analysis and visualization for Iranian infrastructure/persona mapping |
| **Intel 471 OSINT** (formerly SpiderFoot) | `intel471.com` | OSINT automation for investigating Iranian threat infrastructure. SpiderFoot acquired by Intel 471 |

### 14.5 Iranian ASN Space

Key autonomous systems for infrastructure monitoring:

| ASN | Organization |
|---|---|
| AS12880 | Information Technology Company (ITC) |
| AS44244 | Iran Cell Service and Communication Company |
| AS58224 | Iran Telecommunication Company PJS (TCI) |
| AS42337 | Respina Networks |
| AS56402 | Dadeh Gostar Asr Novin (Asiatech) |
| AS48159 | Telecommunication Infrastructure Company (state backbone) |
| AS197207 | Mobile Communication Company of Iran |

**Caveat**: Iranian APTs frequently use non-Iranian infrastructure (AWS, Azure, DigitalOcean, compromised hosts, VPNs, Tor) to evade attribution. ASN monitoring is supplementary, not definitive.

---

## 15. IOC Sources and Threat Feeds

### 15.1 AlienVault OTX

| Resource | URL |
|---|---|
| Portal | `https://otx.alienvault.com/` |
| API | `https://otx.alienvault.com/api` |
| Iran Search | `https://otx.alienvault.com/browse/global/pulses?q=iran` |

**Search terms for Iranian pulses**: APT33, APT34, APT35, APT42, MuddyWater, OilRig, Charming Kitten, Mint Sandstorm, Pioneer Kitten, CyberAv3ngers, Iran

### 15.2 Abuse.ch Ecosystem

| Feed | URL | Relevant Tags |
|---|---|---|
| **URLhaus** | `https://urlhaus.abuse.ch/` | Iranian APT phishing URLs and payload delivery |
| **MalwareBazaar** | `https://bazaar.abuse.ch/` | Tags: MuddyWater, POWERSTATS, PowGoop, BiBi, PhonyC2, POWERSTAR, CharmPower, Sponsor, FalseFont, BASICSTAR, MuddyC2Go |
| **ThreatFox** | `https://threatfox.abuse.ch/` | Iranian APT IOCs (IPs, domains, hashes) |

### 15.3 MISP Feeds

| Feed | URL |
|---|---|
| CIRCL OSINT | `https://www.circl.lu/doc/misp/feed-osint/` |
| Botvrij.eu | `https://www.botvrij.eu/data/feed-osint/` |
| Default feeds list | `https://www.misp-project.org/feeds/` |

**Relevant MISP galaxy tags**: `misp-galaxy:threat-actor="APT33"`, `"APT34"`, `"APT35"`, `"APT42"`, `"MuddyWater"`, `"OilRig"`, `"Charming Kitten"`

### 15.4 Other IOC Sources

| Source | URL | Use Case |
|---|---|---|
| **CISA KEV** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | Actively exploited CVEs including those used by Iranian APTs |
| **IBM X-Force Exchange** | `https://exchange.xforce.ibmcloud.com` | Search for Iranian APT indicators and reports |
| **OpenCTI** (by Filigran) | `https://github.com/OpenCTI-Platform/opencti` | Aggregation platform with connectors for all above sources |
| **MalTrail** | `https://github.com/stamparm/maltrail` | Trail-based IOC feeds including Iranian indicators |
| **YARA Rules Repo** | `https://github.com/Yara-Rules/rules` | Community YARA rules for Iranian malware families |
| **CFR Cyber Ops Tracker** | `https://cfr.org/cyber-operations` | Database of all state-sponsored cyber operations including Iran |

---

## 16. RSS/Atom Feeds for Automated Ingestion

### Government / Institutional

```
CISA KEV JSON:          https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
UK NCSC Reports:        https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml
UK NCSC All:            https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml
```

> **Note (Feb 2026):** CISA RSS feeds (`all.xml`, `ics-advisories.xml`) now return 403 -- deprecated.
> NSA RSS feed also returns 403. Monitor CISA advisories page directly and use the KEV JSON API for automated ingestion.
> CISA KEV JSON is actively maintained (catalog version 2026.02.26, 1529 vulnerabilities tracked).

### Vendor Research Blogs

```
Microsoft Threat Intel: https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/
Google TAG:             https://blog.google/threat-analysis-group/rss/
Mandiant:               https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/
CrowdStrike:            https://www.crowdstrike.com/en-us/blog/feed
Recorded Future:        https://www.recordedfuture.com/feed
Unit 42:                https://unit42.paloaltonetworks.com/feed/
Check Point Research:   https://research.checkpoint.com/feed/
SentinelLabs:           https://www.sentinelone.com/labs/feed/
ESET WeLiveSecurity:    https://www.welivesecurity.com/en/rss/feed/
Cisco Talos:            https://blog.talosintelligence.com/rss/
Proofpoint:             https://www.proofpoint.com/us/rss.xml
Kaspersky SecureList:   https://securelist.com/feed/
Volexity:               https://www.volexity.com/feed/
Intel 471:              https://www.intel471.com/blog/feed
```

> **Removed from RSS list (validated dead Feb 2026):**
> - Dragos (`dragos.com/feed/`) -- 404; RSS deprecated. Monitor blog directly.
> - Secureworks (`secureworks.com/rss`) -- Redirects to Sophos. Acquired.
> - Trellix (`trellix.com/blogs/research/rss/`) -- Domain unreachable.
> - Binary Defense (`binarydefense.com/feed/`) -- 404.
> - BlackBerry (`blogs.blackberry.com/en/feed`) -- Redirects to restructured corporate site.

### IOC / Threat Data Feeds

```
OTX Subscribed Pulses:  https://otx.alienvault.com/api/v1/pulses/subscribed
URLhaus CSV (recent):   https://urlhaus.abuse.ch/downloads/csv_recent/
MalwareBazaar CSV:      https://bazaar.abuse.ch/export/csv/recent/
MalwareBazaar SHA256:   https://bazaar.abuse.ch/export/txt/sha256/recent/
ThreatFox CSV:          https://threatfox.abuse.ch/export/csv/recent/
ThreatFox JSON:         https://threatfox.abuse.ch/export/json/recent/
CIRCL MISP OSINT:       https://www.circl.lu/doc/misp/feed-osint/manifest.json
CISA KEV JSON:          https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### Ingestion Priority

| Tier | Sources | Cadence |
|---|---|---|
| **Tier 1 (Critical)** | CISA advisories, CISA KEV, Microsoft/Mandiant/CrowdStrike blogs | Real-time / hourly |
| **Tier 2 (High)** | Abuse.ch feeds, OTX pulses, MISP feeds | Daily |
| **Tier 3 (Standard)** | MITRE ATT&CK updates, Malpedia, full vendor blog reviews | Weekly |
| **Tier 4 (Enrichment)** | VirusTotal, Shodan, Censys for infrastructure pivoting | As-needed |

---

## 17. Monitoring Cadence and Aggregation Strategy

### Daily (15-30 minutes)

1. RSS feed review: CISA alerts, top-tier vendor blogs (Microsoft, Mandiant, CrowdStrike, ClearSky, Recorded Future)
2. X/Twitter private list of accounts in Section 13.2-13.3
3. Risky Business News newsletter
4. CyberScoop and The Record email digests

### Weekly (1-2 hours)

1. AlienVault OTX pulse review for Iranian APT tags
2. VirusTotal hunting rule results (YARA rules targeting Iranian tooling)
3. Reddit multireddit: r/netsec + r/cybersecurity + r/threatintel + r/geopolitics
4. Substack newsletter digest
5. Mastodon infosec.exchange review

### Monthly (half day)

1. MITRE ATT&CK updates to Iranian group pages
2. Vendor quarterly/annual reports (Mandiant M-Trends, CrowdStrike Global Threat Report, Microsoft Digital Defense Report)
3. Academic and policy papers from think tanks (CFR, IISS, Carnegie, CSIS)
4. Conference talk recordings: SANS CTI Summit, Black Hat, DEF CON (YouTube)
5. Update Shodan/Censys saved infrastructure searches

### Platform Integration

- Use **OpenCTI** or **MISP** as central aggregation platform
- Feed VirusTotal, OTX, ThreatFox, URLhaus, MalwareBazaar via STIX/TAXII
- Build **YARA** and **Sigma** detection rules from published Iranian APT TTPs
- Configure **Shodan** and **Censys** automated alerts for known Iranian infrastructure patterns
- Set **GreyNoise** alerts for scanning from monitored Iranian ASNs

---

## 18. Intelligence Gaps and Collection Priorities

> **Automation Note**: The `automation/scrape_social_feeds.py` and `automation/fetch_rss_feeds.py` scripts both enforce a 90-day lookback window by default. Run `python scrape_social_feeds.py --filter iran` and `python fetch_rss_feeds.py --filter iran` to pull the latest Iran-tagged intelligence from all configured social media, video, and vendor RSS sources. This should be your first step when triaging the gaps below.

### Coverage Gap: June 2025 -- February 2026

This feed's baseline knowledge extends through May 2025. The following areas require immediate live intelligence collection:

| Gap | Where to Look |
|---|---|
| **Post-May 2025 CISA advisories** | `cisa.gov/news-events/cybersecurity-advisories` -- filter for Iran |
| **New Microsoft reporting** | `microsoft.com/en-us/security/blog` -- search Sandstorm groups |
| **New CVE exploitation** | CISA KEV catalog filtered for recent additions |
| **Geopolitical shifts** | Any changes in Iran nuclear status, US-Iran diplomatic posture, Israel-Iran kinetic operations |
| **New wiper/destructive malware** | Given development pace, new tools are likely deployed |
| **Dragos Year in Review** | Published annually (usually February) -- 2026 edition critical for OT threat data |
| **CrowdStrike Global Threat Report** | Published annually (usually February) -- 2026 edition for updated Iran data |
| **Recorded Future Insikt Group** | Near-real-time Iranian operations reporting |

### Priority Collection Requirements

1. **Has Lemon Sandstorm/Pioneer Kitten expanded ransomware affiliate partnerships beyond ALPHV/BlackCat?**
2. **Have CyberAv3ngers expanded targeting beyond Unitronics PLCs to other ICS/SCADA platforms?**
3. **What new wipers or destructive tools have been deployed since BiBi/SameCoin?**
4. **Has the MOIS access-broker model (Scarred Manticore -> Void Manticore) been replicated by IRGC groups?**
5. **What new CVEs are Iranian groups exploiting in the June 2025 -- Feb 2026 window?**
6. **Has Iranian cyber operational tempo increased or decreased with current geopolitical tensions?**

---

*This document is a living reference. Review and update quarterly at minimum, or immediately following significant geopolitical escalation. All content is derived from open-source intelligence. Validate IOCs against multiple independent sources before taking blocking actions.*
