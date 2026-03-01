# Israel-Iran Cyber Operations Deep Dive -- February 2026

**Classification:** OSINT -- Open Source Intelligence Only
**Compiled:** 2026-02-28
**Last Validated:** 2026-02-28
**Baseline Knowledge:** Through February 2026
**Focus:** Israeli offensive cyberattack against Iran (February 28, 2026), Iranian cyber retaliation, historical cyber-kinetic integration, technical malware analysis, and strategic assessment
**Intended Audience:** Blue team operators, CTI analysts, SOC analysts, OT/ICS security engineers, incident responders
**Cross-Reference:** [US-Iran-Israel Cyber Threat Intelligence Feed](us-iran-israel-cyber-threat-feed.md) for standing APT profiles; [Iran/Middle East 24-Hour SITREP](iran-middle-east-24hr-sitrep-2026-02-28.md) for kinetic operations context

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The February 28 Cyberattack -- Technical Analysis](#2-the-february-28-cyberattack--technical-analysis)
3. [Attack Vectors and Methods](#3-attack-vectors-and-methods)
4. [Systems and Infrastructure Targeted](#4-systems-and-infrastructure-targeted)
5. [Impact Assessment](#5-impact-assessment)
6. [Dual-Nature Analysis -- Cyberattack vs Self-Imposed Shutdown](#6-dual-nature-analysis--cyberattack-vs-self-imposed-shutdown)
7. [Iran's Internet Control Architecture](#7-irans-internet-control-architecture)
8. [Attribution and Responsible Units](#8-attribution-and-responsible-units)
9. [Historical Precedent -- Israeli Cyber Operations Against Iran](#9-historical-precedent--israeli-cyber-operations-against-iran)
10. [The 2025 Twelve-Day War -- Cyber-Kinetic Integration Case Study](#10-the-2025-twelve-day-war--cyber-kinetic-integration-case-study)
11. [Iranian Offensive Cyber Operations and Retaliation](#11-iranian-offensive-cyber-operations-and-retaliation)
12. [MuddyWater Operation Olalampo -- Technical Deep Dive](#12-muddywater-operation-olalampo--technical-deep-dive)
13. [CyberAv3ngers / BAUXITE -- ICS/OT Threat Analysis](#13-cyberav3ngers--bauxite--icsot-threat-analysis)
14. [Iranian Wiper Malware Families](#14-iranian-wiper-malware-families)
15. [Additional Active Iranian APT Groups](#15-additional-active-iranian-apt-groups)
16. [Complete Iranian APT Landscape](#16-complete-iranian-apt-landscape)
17. [Israel-Iran Cyber War Timeline](#17-israel-iran-cyber-war-timeline)
18. [CISA / US Government Defensive Guidance](#18-cisa--us-government-defensive-guidance)
19. [Strategic Assessment and Expert Analysis](#19-strategic-assessment-and-expert-analysis)
20. [Sources and References](#20-sources-and-references)

---

## 1. Executive Summary

On **February 28, 2026**, Israel launched what has been described as the **largest cyberattack in history** against Iran, executed as the cyber and electronic warfare component of **Operation Roaring Lion** (Israel) / **Operation Epic Fury** (US). The cyberattack accompanied a massive joint Israeli-US kinetic strike campaign involving hundreds of fighter jets, cruise missiles, and ballistic missiles.

**Key findings:**

- **Iran's internet connectivity was reduced to 4% of normal levels** (NetBlocks), ultimately dropping to **effectively zero** (Cloudflare Radar at 18:45 UTC). 87 million people were affected. The attack persisted for 12+ hours, with connectivity remaining at ~1% after 24 hours.
- **The operation combined five simultaneous attack vectors:** DDoS at massive scale, deep network intrusions into energy and aviation systems, electronic warfare disrupting navigation and communications, BGP route manipulation severing Iran from the global internet, and information operations hacking state media to broadcast anti-regime content.
- **Iran's fallback National Information Network (NIN)** -- the domestic intranet designed as a resilient alternative to the global internet -- **also failed**, representing a significant intelligence and operational achievement by the attackers.
- **IRGC communications infrastructure was specifically targeted** to prevent coordination of counterattacks, disrupt drone and ballistic missile launch coordination, and deny situational awareness during kinetic operations.
- **The attack was the culmination of a multi-month campaign:** DDoS probing at 720 million PPS in January, satellite broadcast hacking on January 18, and exploitation of Iran's self-imposed internet blackout during the protest crackdown.
- **Iranian APT groups continued offensive operations despite the blackout**, circumventing domestic internet restrictions through privileged state network access. Active campaigns include MuddyWater's Operation Olalampo (new Rust-based malware), CyberAv3ngers' OT/ICS targeting, and Handala's healthcare data breach.
- **Cyber operations are now Iran's "sole remaining instrument of asymmetric retaliation"** after the destruction of conventional military options. US critical infrastructure operators should assume elevated threat posture.

---

## 2. The February 28 Cyberattack -- Technical Analysis

### 2.1 Timeline

| Time (UTC) | Event |
|---|---|
| **Jan 8, 2026** | Iranian authorities impose internet blackout during protests; IPv6 BGP routes withdrawn at 11:49 UTC, dropping IPv6 address space by 98.5% |
| **Jan 18, 2026 ~17:30 UTC** | Iranian state TV satellite transmission via **Badr satellite** hacked for ~10 minutes; exiled Crown Prince Reza Pahlavi broadcast calling on security forces to defect; "Woman, Life, Freedom" footage aired to millions |
| **Jan 2026** | IRGC installs **Mohammed Hossein Soleimaniyan** (senior IRGC member) as CEO of MTN-Irancell (70M subscribers, 42% market share) after predecessor fired for slow compliance with shutdown orders |
| **Late Jan 2026** | Iran's TIC reports foiling a DDoS attack exceeding **720 million packets per second** from **125,000 distributed sources** -- ranked among world's 12 largest DDoS attacks by PPS |
| **Feb 28, ~06:10 UTC** | Main compound kinetic strike occurs |
| **Feb 28, ~07:10 UTC** | Telecommunications disruption begins |
| **Feb 28, ~08:00 UTC** | Blackout largely in effect |
| **Feb 28, ~08:30 UTC** | Connectivity at ~1% (NetBlocks CEO Alp Toker confirms) |
| **Feb 28, 16:30 UTC** | Traffic volumes into Iran begin steady descent |
| **Feb 28, 18:45 UTC** | Cloudflare confirms Iran traffic drops to **effectively zero** -- complete disconnection from global internet |
| **Mar 1, 2026** | After 24 hours, connectivity remains at approximately **1% of ordinary levels** |

### 2.2 Campaign Phasing

The February 28 attack was the culmination of a multi-phase campaign:

1. **Pre-positioning phase** (months prior): Dormant explosive drones and intelligence assets placed inside Iran; cyber implants established in target networks
2. **Probing phase** (late Dec 2025 -- Jan 2026): DDoS probing attacks (720M PPS from 125K sources) testing defensive capacity and response
3. **Psychological preparation** (Jan 18): Badr satellite hack broadcasting anti-regime content to millions of Iranian households
4. **Exploitation of domestic crisis** (Jan 8 onwards): Leveraging Iran's self-imposed internet blackout during protests to mask reconnaissance and pre-positioning
5. **Full-spectrum attack** (Feb 28): Simultaneous cyber, electronic warfare, kinetic, and PSYOP operations

---

## 3. Attack Vectors and Methods

### 3.1 Distributed Denial-of-Service (DDoS)

- Massive volumetric DDoS attacks targeting telecommunications infrastructure
- Preceded by January probe attack of **720 million PPS** from **125,000+ globally distributed sources**
- February 28 attack volume assessed to exceed the January probing attacks
- Targeted both international gateway infrastructure and domestic routing

### 3.2 Deep Network Intrusions

- Penetration of data systems tied to **energy infrastructure**
- Penetration of data systems tied to **aviation infrastructure**
- Compromise of government digital services platforms across Tehran, Isfahan, and Shiraz
- Intrusion into state news agency systems (IRNA, Tasnim, ISNA, Fars News, Iribnews, PressTv)
- Targeting of IRGC command-and-control networks

### 3.3 Electronic Warfare (EW)

- Disruption of **navigation systems** -- GPS accuracy degraded to 200-300 km error radius near military sites
- Disruption of **communications systems** -- military and civilian channels
- Jamming of IRGC command-and-control channels
- Targeted interference with drone and ballistic missile launch coordination systems
- **Ku-band frequency jamming (12-18 GHz)** targeting Starlink satellite internet kits, resulting in **50-70% packet loss rates**
- Israel deployed F-35I and F-16I aircraft carrying domestic EW systems; Israel described as "a world leader in EW defense technology"

### 3.4 BGP Route Manipulation / Infrastructure Severing

- **IPv6 BGP route withdrawals** -- Iranian ISPs withdrew IPv6 prefixes from the Border Gateway Protocol, removing Iran from global routing maps
- **IPv4 connectivity disabled** at 18:45 UTC via BGP announcement withdrawal
- Staged approach: IPv6 first (kills mobile internet), then IPv4 (kills remaining broadband)
- Leveraged the **TIC (Telecommunications Infrastructure Company)** chokepoint -- all international traffic flows through state-controlled TIC gateways
- Demonstrates sophisticated understanding of Iranian network architecture and its single points of failure

### 3.5 Deep Packet Inspection (DPI) and DNS Manipulation

- DPI technology deployed (or exploited) to filter traffic systematically
- Foreign websites redirected or blocked through corrupted DNS responses
- Protocol whitelisting enforced: only approved domestic services permitted

### 3.6 Information and Psychological Operations

- Hacking of **Tasnim News Agency** (IRGC-affiliated) to display **subversive messages against Khamenei**
- IRNA (official state news agency) taken offline for extended period
- ISNA, Fars News, Iribnews, PressTv all rendered inaccessible
- Media and phone apps hacked with messages calling on Iranians to "rise up against their government"
- Mossad launched a **Farsi-language Telegram channel** calling on Iranians to share photos/videos, promising to "return Iran to its glorious days"
- **IRINN (Islamic Republic of Iran News Network) headquarters** physically struck -- "melted computers" photographed, indicating either kinetic strike on cyber infrastructure or possible destructive malware

---

## 4. Systems and Infrastructure Targeted

### 4.1 Military and Security Infrastructure

| Target | Detail |
|---|---|
| **IRGC communications** | Command-and-control channels targeted to prevent coordination of counterattacks |
| **IRGC command centers** | Struck simultaneously with kinetic operations |
| **Missile launch coordination** | Drone and ballistic missile launch systems disrupted |
| **MOIS headquarters** | Ministry of Intelligence and Security facilities targeted |
| **Law Enforcement Command** | LEC headquarters communications disrupted |
| **Air defense systems** | S-300, Bavar-373, Khordad-15, Sevom Khordad systems targeted; during June 2025 war, 120-150 rocket launchers reportedly "exploded the moment they were activated" |
| **GPS/Navigation** | Military-grade jamming disrupted GPS accuracy by 200-300 km near military sites; affected ~970 ships/day in Arabian Gulf |

### 4.2 Telecommunications Infrastructure

| Target | Detail |
|---|---|
| **MTN-Irancell** | Iran's largest mobile operator; 70M+ active SIMs; 42% market share; 51% owned by Ministry of Defence-linked entities; IRGC takeover of CEO position in January |
| **TIC** | Telecommunications Infrastructure Company; state-owned; controls all international internet gateways; single point of failure for all Iranian internet |
| **MCI** | Mobile Communication Company of Iran and other major operators |
| **Landlines** | Telephone networks across Tehran disabled |
| **SMS** | Text messaging services nationwide disrupted |
| **National Information Network (NIN)** | Iran's domestic intranet -- designed as resilient fallback -- **also failed** under combined offensive |

### 4.3 Media and Propaganda

| Target | Detail |
|---|---|
| **IRNA** | Official state news agency -- taken offline |
| **Tasnim** | IRGC-affiliated -- hacked with anti-Khamenei messaging |
| **ISNA** | Iranian Students' News Agency -- inaccessible |
| **Fars News** | Semi-official -- inaccessible |
| **PressTv** | English-language state media -- inaccessible |
| **IRIB** | State broadcaster -- satellite transmission compromised (January); headquarters struck (February) |
| **IRINN** | News network headquarters -- physically struck; "melted computers" documented |

### 4.4 Civilian and Government Services

| Target | Detail |
|---|---|
| **Government digital services** | Failed across Tehran, Isfahan, Shiraz |
| **Local applications** | Ride-hailing (Snapp), delivery platforms, mapping services (Neshan, Balad, Waze) rendered inoperable |
| **Payment systems** | Digital payment infrastructure disrupted |
| **Fuel distribution** | Networks affected (Predatory Sparrow precedent) |
| **Healthcare systems** | Digital services disrupted |
| **Tehran Stock Exchange** | Lost 450,000 points over four-day period |

---

## 5. Impact Assessment

### 5.1 Connectivity Impact

| Metric | Detail |
|---|---|
| **NetBlocks measurement** | 4% of normal traffic levels |
| **Cloudflare Radar (18:45 UTC)** | Effectively zero traffic |
| **24-hour status** | ~1% of ordinary levels persisting |
| **Population affected** | 87 million people |
| **NIN (domestic intranet)** | Also failed -- unprecedented; in previous shutdowns NIN remained functional |
| **Starlink** | 40,000 connections cut via Ku-band jamming |

### 5.2 Military Impact

- IRGC unable to coordinate counterattack responses in the critical first hours
- Disrupted ability to launch drones and ballistic missiles
- Severed high-level military communications
- Prevented emergency protocol activation
- Created leadership vacuum and operational uncertainty across IRGC divisions
- Prevented dispersal of senior personnel during kinetic strikes
- NetBlocks CEO Alp Toker noted smartphone metadata "may well have played a part in determining" compound meeting location, attendees, and timing of kinetic strikes

### 5.3 Economic Impact

| Metric | Detail |
|---|---|
| **Daily economic cost** | **$35.7 million/day** (acknowledged by Minister of Communications) |
| **Online sales** | Fell **80%** during shutdown |
| **Tehran Stock Exchange** | Lost **450,000 points** over four days |
| **Daily losses** | 130 trillion tomans |
| **Digital economy employment** | Dropped **30%** -- approximately 10 million Iranians depend on this sector |
| **Recovery timeline** | Government spokeswoman indicated international online services would **not be restored before Nowruz (March 20)** |

### 5.4 Information Control Impact

- Regime deployed blackout partly to **prevent metadata leakage** of senior leaders' locations
- Supreme National Security Council (SNSC) warned population of "severe judicial punishment" for providing "targeting information to the enemy"
- Blackout prevented citizens from documenting strikes on social media
- State media outlets used as vehicles for anti-regime messaging by attackers

---

## 6. Dual-Nature Analysis -- Cyberattack vs Self-Imposed Shutdown

A critical analytical nuance: the blackout was a **combination** of both external attack and internal defensive action.

### 6.1 Evidence of External Cyberattack

- Multi-vector assault combining DDoS, deep intrusions, EW, and information operations
- Compromise and defacement of state media outlets (requires offensive access)
- Disruption of IRGC communications systems (targeted military capability)
- Failure of the National Information Network (NIN) -- a system designed to operate independently of the global internet
- January probing attacks (720M PPS) consistent with pre-operational reconnaissance
- Satellite broadcast hack demonstrating pre-positioned access

### 6.2 Evidence of Self-Imposed Shutdown

- BGP route withdrawals consistent with deliberate administrative action by Iranian ISPs
- Regime has precedent for self-imposed shutdowns (January 2026 protest crackdown, June 2025 twelve-day war, November 2019 protests)
- Metadata denial motivation: preventing intelligence collection on leadership locations
- Preventing citizen documentation and coordination during strikes
- NetBlocks CEO noted disruption "matches measures" taken during previous conflicts

### 6.3 Assessment

The most likely explanation is a **synergistic combination**: Israel's cyberattack created genuine degradation of Iranian systems, and the Iranian regime then extended the blackout through administrative action to prevent further exploitation and metadata leakage. The failure of the NIN domestic intranet -- which should have been resilient to both external attack and deliberate international gateway shutdown -- suggests the offensive component achieved effects beyond what self-imposed shutdown alone would explain.

---

## 7. Iran's Internet Control Architecture

### 7.1 Telecommunications Infrastructure Company (TIC)

- **Role:** State-owned entity controlling all international internet gateways
- **Architecture:** All Iranian ISPs must route international traffic through TIC, creating a single chokepoint for shutdown
- **Shutdown capability:** Executes blackouts under direct security agency oversight
- **Legal framework:** Technical delays in implementing shutdown orders are now "legally classified as treason"

### 7.2 Huawei-Supplied Kill Switch

| Attribute | Detail |
|---|---|
| **Project cost** | Estimated $700 million -- $1 billion |
| **Status** | Final stages of construction at a fortified data center near Tehran |
| **Capability** | Centralized internet kill switch enabling instant nationwide shutdown |
| **DPI systems** | Supplied by Huawei and ZTE; deployed by Doran Group engineers for traffic monitoring and filtering |

### 7.3 Chinese Technology Integration

| Supplier | Technology |
|---|---|
| **Huawei** | Telecom equipment, DPI tools, kill switch project |
| **ZTE Corporation** | Nationwide integrated monitoring system (December 2010 contract) for voice, SMS, email, chat, and internet surveillance via DPI; operated through front companies Beijing 8 Star International and ZTE Parsian |
| **Tiandy Technologies, Hikvision, Dahua** | AI-powered surveillance cameras, facial recognition, ethnicity tracking |
| **BeiDou** | Military-grade satellite navigation transferred to Iran since 2021; Iran transitioning away from US-controlled GPS |

### 7.4 "Barracks Internet" Model

- **Architecture:** Two-tiered system separating elite regime access from general population
- **White SIM cards:** Approximately **16,000 people** hold unrestricted global internet access cards
- **General population:** 85-90 million citizens confined to state-controlled intranet with whitelist filtering
- **Implications for cyber operations:** Iranian APT groups maintain operational capability through the privileged tier during domestic blackouts

### 7.5 MTN-Irancell as Control Mechanism

| Attribute | Detail |
|---|---|
| **Ownership** | 51% controlled by Ministry of Defence and Supreme Leader-linked foundation; 49% by South Africa's MTN Group |
| **IRGC takeover** | Mohammed Hossein Soleimaniyan (IRGC, reportedly related to late Gen. Qasem Soleimani) installed as CEO after predecessor fired for delaying shutdown orders |
| **Scale** | 70 million active SIM cards; 42% market share |
| **Incentive structure** | Operators receive 20% bandwidth cost discount for implementing filtering during crackdowns |

---

## 8. Attribution and Responsible Units

### 8.1 Unit 8200 (IDF Signal Intelligence)

| Attribute | Detail |
|---|---|
| **Role** | Israel's premier cyber-intelligence unit; assessed primary executor of the February 28 cyberattack |
| **Equivalent** | Often compared to US NSA |
| **Capabilities** | Global SIGINT; offensive cyber operations (dedicated internal team since 2011); infrastructure includes Urim SIGINT Base (Negev desert), covert listening posts in embassies, undersea cable taps, Gulfstream jets with electronic surveillance |
| **Historical attribution** | Stuxnet (co-developed with NSA), 2017 attack on Lebanon's Ogero telecoms, thwarting ISIS airliner attack (2018), numerous operations via Predatory Sparrow proxy |
| **Talent pipeline** | Functions as incubator for Israel's private cybersecurity sector |

### 8.2 Mossad (External Intelligence)

- Launched Farsi-language Telegram PSYOP channel during the operation
- Implicated in January satellite TV hack
- Coordinates with Unit 8200 on combined intelligence-cyber operations

### 8.3 US Cyber Command

- Retired three-star General **Charles Moore** stated the US likely deployed "powerful toolset[s] of cyber and electronic operations against Iranian targets"
- During June 2025's Operation Midnight Hammer, US Cyber Command attacked network "aim points" (routers, servers, peripheral devices) connected to air defense systems at Fordo, Natanz, and Isfahan, preventing Iran from launching SAMs at US warplanes
- Officials described "layering different effects" within a 30-minute window across all three nuclear sites
- NSA provided intelligence enabling Cyber Command to identify vulnerabilities without directly breaching main military networks

### 8.4 Predatory Sparrow (Gonjeshke Darande)

Israel's primary cyber proxy group for deniable operations against civilian-facing infrastructure (see Section 9.3 for full history).

---

## 9. Historical Precedent -- Israeli Cyber Operations Against Iran

### 9.1 Stuxnet / Operation Olympic Games (2005-2010)

| Attribute | Detail |
|---|---|
| **Discovery** | June 17, 2010 |
| **Development** | ~2005, joint US NSA-Israeli Unit 8200 |
| **Target** | SCADA systems at Natanz uranium enrichment facility |
| **Method** | Malicious worm targeting Siemens S7-300 PLCs controlling centrifuge speed; caused centrifuges to tear apart while masking malfunction from operators |
| **Impact** | ~1,000 centrifuges destroyed; 30,000 computers across 14+ Iranian facilities infected |
| **Significance** | First confirmed cyberattack to cause physical destruction of industrial equipment; established the paradigm of cyber-physical warfare |

### 9.2 Post-Stuxnet Malware Family

| Malware | Date | Target | Purpose |
|---|---|---|---|
| **Duqu** | November 2011 | Iranian systems | Reconnaissance; keystrokes and system information for future operations |
| **Wiper** | April 2012 | Oil Ministry / National Iranian Oil Company | Destructive; hard drives erased |
| **Flame** | May 2012 | Government computers | Intelligence collection; prepare for wider campaigns |

### 9.3 Predatory Sparrow Operations (2021-2025)

| Date | Operation | Target | Impact |
|---|---|---|---|
| **Oct 2021** | Fuel system attack | 4,300 gas stations nationwide | National fuel distribution shutdown; digital messages blaming Khamenei; accessed fuel storage tanks and international oil sales data revealing sanctions breaches |
| **2021** | Railway attack | National railway system | Widespread railway paralysis |
| **Jun 2022** | Steel mill attack | Mobarakeh, Hormozgan, Khuzestan steel companies | Loss of control of ladle metallurgy at Khuzestan; catastrophic failure within 12 minutes; CCTV footage and ICS dashboard screenshots published as proof. **One of the first confirmed cases of a cyberattack causing physical destruction to non-nuclear industrial infrastructure.** |
| **Dec 2023** | Gas station repeat | ~70% of gas stations | Fuel distribution disrupted; repeat of 2021 playbook |
| **Jun 17, 2025** | Bank Sepah attack | State-owned bank (IRGC's central financial institution) | Data erased; military payroll inoperative; ATMs dark; all banking services shut down |
| **Jun 18, 2025** | Nobitex crypto attack | Iran's largest cryptocurrency exchange | $90M in crypto transferred to vanity addresses containing "F--kIRGterrorists" and burned; source code and documentation leaked |

### 9.4 Evolution Assessment

Israeli cyber operations have evolved through three distinct phases:

1. **Precision sabotage (2005-2012):** Stuxnet era -- bespoke malware targeting specific industrial equipment for physical destruction
2. **Civilian infrastructure disruption (2021-2023):** Predatory Sparrow era -- deniable proxy operations against fuel, rail, steel, and civilian systems
3. **Full-spectrum digital warfare (2025-2026):** Combined cyber-kinetic operations capable of "plunging a country into darkness" -- simultaneous EW, DDoS, intrusions, PSYOP, and infrastructure severing coordinated with kinetic strikes

---

## 10. The 2025 Twelve-Day War -- Cyber-Kinetic Integration Case Study

### 10.1 Timeline

| Date | Event |
|---|---|
| **Jun 4-12** | Pre-conflict escalation: 3-4 DDoS attacks/day targeting Israel |
| **Jun 10** | Peak in cyber attacks against Iran (3 days before kinetic strikes) |
| **Jun 13** | Israel launched Operation Rising Lion; kinetic strikes on nuclear facilities, military bases, command centers |
| **Jun 13-17** | 35+ distinct pro-Iranian hacktivist groups launched coordinated DDoS, defacement, and data breach attacks against Israel (vs. 4-5 pro-Israeli groups) |
| **Jun 14** | Peak: 40 DDoS attacks claimed against Israel in a single day |
| **Jun 17** | Predatory Sparrow destroyed Bank Sepah data |
| **Jun 18** | Predatory Sparrow burned $90M in Nobitex crypto |
| **Jun 23** | Iranian hackers infiltrated accounts of Israeli journalists via phishing |
| **Jun 25** | Conflict ended |

### 10.2 US Cyber Command -- Operation Midnight Hammer

| Attribute | Detail |
|---|---|
| **Date** | June 22, 2025 |
| **Kinetic component** | B-2 bombers and Tomahawk missiles struck Fordo, Natanz, Isfahan nuclear facilities |
| **Cyber component** | US Cyber Command attacked network "aim points" -- mapped nodes (routers, servers, peripheral devices) on Iranian military networks connected to air defense systems at all three sites |
| **Effect** | Prevented Iran from launching surface-to-air missiles at American warplanes; Iran's fighters did not fly; "Iran's surface to air missile systems did not see us" |
| **Method** | "Layering different effects" within a 30-minute window across all three sites |
| **Described as** | "Some of the most sophisticated action Cyber Command has taken against Iran in its nearly 16-year history" |
| **Assessment** | Erica Lonergan (FDD): reflects "the routinization of the use of cyber capabilities during military operations" |

### 10.3 Key Statistics

- **700% increase** in cyberattacks against Israeli targets in two days following kinetic strikes
- **64%** of all Iranian cyber activity worldwide aimed at Israeli targets
- **120-150 rocket launchers** reportedly "exploded the moment they were activated" -- indicating either cyber sabotage or physical pre-positioning
- Israel achieved **full aerial superiority** over Iran, losing **zero manned aircraft or pilots**
- Israeli cyber alerts: **367 in 2023 → 736 in 2024** (doubled)

---

## 11. Iranian Offensive Cyber Operations and Retaliation

**CRITICAL: Iranian APT groups are conducting active offensive operations despite Iran's domestic internet blackout. State hackers circumvented the shutdown through privileged "white SIM" access on the two-tiered internet architecture.**

### 11.1 Active Campaigns (February 2026)

| Actor | Campaign | Targets | Detail |
|---|---|---|---|
| **MuddyWater** | Operation Olalampo | MENA organizations | New malware: GhostFetch, CHAR (Rust), HTTP_VIP; AI-assisted development; active since Jan 26 (see Section 12) |
| **MuddyWater** | RustyWater RAT | Diplomatic, maritime, financial, telecom entities | Rust-based implant delivered via spear-phishing with malicious Office macros |
| **Handala** | Clalit healthcare breach | Israel's largest healthcare network (4.8M patients) | 10,000+ patient records leaked: medical referrals, sick leave certs, test referrals, internal correspondence (Feb 25) |
| **CyberAv3ngers / BAUXITE** | OT/ICS targeting | Worldwide ICS/SCADA | IOCONTROL malware targeting PLCs, HMIs, routers; deployed 2 custom wipers against Israel in June 2025 (see Section 13) |
| **Infy (Prince of Persia)** | Tornado v51 / ZZ Stealer | Espionage targets | Resumed operations Jan 26 with new C2; dual HTTP/Telegram C2; WinRAR CVE exploitation |
| **Void Manticore** | Wiper operations | Israeli organizations, NGOs, Western think tanks | 40+ Israeli orgs targeted since Oct 2023; custom wipers targeting files and partition tables |
| **Unattributed** | Anticipated retaliation | US critical infrastructure | CISA/FBI/NSA warning: expect website defacements, DDoS, OT/ICS exploitation, ransomware, hack-and-leak |

### 11.2 Shin Bet Disclosure (February 12, 2026)

Shin Bet and Israel's National Cyber Directorate disclosed that **hundreds of Iranian cyberattacks** targeting senior Israelis were detected and foiled in recent months.

| Attribute | Detail |
|---|---|
| **Targets** | Senior government/defense officials; academics; journalists; former PM Bennett; National Security Minister Ben-Gvir; PMO Chief of Staff Braverman |
| **Methods** | Targeted phishing via WhatsApp, Telegram, email; tailored cover stories matching professional fields; **fake Google Meet links** stealing Google credentials |
| **Trend** | Increased targeting of personal Google accounts since June 2025 war |
| **Purpose** | Intelligence collection, advancing terrorist activity, influence operations |

---

## 12. MuddyWater Operation Olalampo -- Technical Deep Dive

### 12.1 Campaign Overview

| Attribute | Detail |
|---|---|
| **First observed** | January 26, 2026 |
| **Attribution** | MuddyWater (aka Earth Vetala, Mango Sandstorm, MUDDYCOAST); MOIS-aligned |
| **Target region** | MENA (Middle East and North Africa) |
| **Reported by** | Group-IB, The Hacker News, Dark Reading, SecurityOnline |
| **Significance** | Demonstrates MuddyWater's tool modernization with Rust-based malware and AI-assisted development |

### 12.2 Malware Arsenal

| Malware | Type | Language | Key Capabilities |
|---|---|---|---|
| **CHAR** | Backdoor | **Rust** | Directory navigation, cmd.exe/PowerShell execution, SOCKS5 reverse proxy, browser data exfiltration. Shares structural overlap with **BlackBeard** (Archer RAT / RUSTRIC). |
| **GhostFetch** | First-stage downloader | Unknown | System profiling, mouse/screen validation (anti-sandbox), VM detection, AV detection, in-memory payload execution |
| **GhostBackDoor** | Second-stage backdoor | Unknown | Interactive shell, file read/write, re-run GhostFetch for re-staging |
| **HTTP_VIP** | Native downloader | Unknown | System reconnaissance, AnyDesk deployment, interactive shell, file transfer, clipboard capture |
| **Kalim** | Backdoor | Unknown | Deployed via CHAR PowerShell functionality |

### 12.3 AI-Assisted Malware Development

Analysis of CHAR's source code revealed **debug strings containing emojis** -- "a trait rarely seen in human-authored code" -- with four instances suggesting the adversary used an **AI/LLM to generate specific code segments** and failed to sanitize debug strings before compilation. This is one of the first documented cases of a nation-state APT group using AI-assisted malware development in operational tooling.

### 12.4 C2 Infrastructure

| Channel | Detail |
|---|---|
| **Telegram bot** | Display name "Olalampo"; username `stager_51_bot` |
| **HTTP C2 domain** | `codefusiontech[.]org` (used by HTTP_VIP) |
| **Infrastructure history** | Limited historical usage dating to late 2025 |
| **Dual C2** | Infy (Prince of Persia) group also using dual HTTP and Telegram C2 channels -- emerging pattern across Iranian APTs |

### 12.5 Infection Vectors

1. Spear-phishing with malicious Excel/Word documents containing macro code
2. Exploitation of recently disclosed vulnerabilities on public-facing servers
3. Social engineering themes: flight tickets, operational reports, energy company impersonation

### 12.6 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Initial Access | T1566 | Phishing (spear-phishing with macro-enabled Office documents) |
| Initial Access | T1190 | Exploit Public-Facing Application |
| Execution | T1204 | User Execution |
| Execution | T1059 | Command and Scripting Interpreter (PowerShell, cmd) |
| Defense Evasion | T1112 | Modify Registry |
| Defense Evasion | T1140 | Deobfuscate/Decode Files |
| Discovery | T1518 | Software Discovery |
| Discovery | T1518.001 | Security Software Discovery |
| Collection | T1115 | Clipboard Data |
| Collection | T1005 | Data from Local System |
| Command & Control | T1071 | Application Layer Protocol |
| Command & Control | T1095 | Non-Application Layer Protocol |
| Command & Control | T1102 | Web Service (Telegram bot) |
| Exfiltration | T1020 | Automated Exfiltration |

---

## 13. CyberAv3ngers / BAUXITE -- ICS/OT Threat Analysis

### 13.1 Group Profile

| Attribute | Detail |
|---|---|
| **Dragos designation** | BAUXITE |
| **Attribution** | Technical overlap with CyberAv3ngers and IRGC-CEC (Islamic Revolutionary Guard Corps Cyber-Electronic Command) |
| **Active since** | 2017 |
| **Global victims** | US, Australia, UK, Israel |
| **US Government bounty** | **$10 million** (Rewards for Justice) |

### 13.2 IOCONTROL Malware

| Attribute | Detail |
|---|---|
| **Reported by** | Claroty Team82 (December 2024, ongoing) |
| **Also known as** | OrpaCrab (QiAnXin XLab, February 2024) |
| **Significance** | The **10th documented ICS-specific malware family since Stuxnet** |
| **Platform** | Linux-based, compiled per target device type |
| **C2 Protocol** | MQTT (machine-to-machine IoT protocol) |
| **DNS** | DNS over HTTPS (DoH) via Cloudflare to evade detection |
| **Encryption** | AES-256-CBC for configuration data |
| **Persistence** | Executes automatically upon device restart |
| **IOC (SHA-256)** | `1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498` |

**IOCONTROL Command Structure:**
- Device information transmission (hostname, user, firmware version, location)
- Arbitrary OS command execution
- Self-deletion capability
- IP range scanning on specific ports
- Lateral movement support

### 13.3 Targeted Device Types and Vendors

Baicells, D-Link, Hikvision, Red Lion, Orpak, Phoenix Contact, Teltonika, Unitronics, Gasboy

### 13.4 Capabilities and TTPs

- Ability to **compromise PLCs and modify ladder logic**
- Custom backdoor deployment on OT devices
- **Linux backdoor with C2 over MQTT**
- Uses publicly known exploits and Kali Linux tools
- Consumes OT/ICS OEM security advisories to identify vulnerabilities
- Bulletproof hosting and segmented operational infrastructure
- Targets **internet-exposed HMIs, misconfigured engineering workstations**
- Exploits open field protocols: **Modbus/TCP** and **DNP3**

### 13.5 ICS Impact Categories

- Denial of Control
- Loss of Availability
- Loss of Productivity/Revenue
- Loss of View

### 13.6 Notable Incidents

| Incident | Detail |
|---|---|
| **Israeli fuel systems (Oct 2023)** | Claimed disruption of 200 gas pumps |
| **Ireland water facility** | 2-day water supply disruption |
| **Pennsylvania, USA** | Attack on water facility |
| **Israeli targets (Jun 2025)** | Deployed **two custom wiper malware variants** -- escalation from access/disruption to destruction |
| **Orpak/Gasboy systems** | Compromise of several hundred Israel-made Orpak and US-made Gasboy fuel management systems |

---

## 14. Iranian Wiper Malware Families

### 14.1 New Families (2025)

| Malware | Attribution | Targets | Detail |
|---|---|---|---|
| **BlueWipe** | Iran-linked | Israeli critical infrastructure | Wipe/disable storage devices |
| **SewerGoo** | Iran-linked | Israeli government networks | Wipe/disable storage devices |
| **BeepFreeze** | Iran-linked | Albanian networks | Destructive attacks |
| **BAUXITE custom wipers (x2)** | CyberAv3ngers | Israeli targets | Deployed during June 2025 twelve-day war |

### 14.2 Established Families

| Malware | Group | First Seen | Notable Usage |
|---|---|---|---|
| **BiBi Wiper** | Void Manticore (Storm-842) | 2023 | Linux and Windows variants; named after PM Netanyahu; targets both files and partition tables |
| **Shamoon** | APT33/Iran-linked | 2012 | Destroyed 35,000 Saudi Aramco workstations; multiple variants through 2018 |
| **MeteorExpress** | Iran-linked | 2021 | Used in Iranian railway attack |
| **ZeroCleare** | Iran-linked | 2019 | Targeted energy/industrial sectors in Middle East |
| **Dustman** | Iran-linked | 2019 | Targeted Middle East petroleum organizations |

### 14.3 Void Manticore (Storm-842) Profile

| Attribute | Detail |
|---|---|
| **Attribution** | MOIS-aligned |
| **Personas** | "Homeland Justice" (Albania); "Karma" (Israel) |
| **Claimed targets** | 40+ Israeli organizations since October 2023 |
| **Collaboration** | Works with Scarred Manticore for initial access, then conducts destruction |
| **Evolution** | Expanded beyond Israel and Albania to NGOs and Western think tanks (2024-2025) |
| **Methods** | Publicly available tools plus custom wipers targeting files and partition tables |

---

## 15. Additional Active Iranian APT Groups

### 15.1 Handala Hack Team

| Attribute | Detail |
|---|---|
| **Affiliation** | MOIS |
| **Established** | December 2023 (web presence) |
| **Recent operation** | Clalit healthcare breach (Feb 25, 2026): 10,000+ patient records |
| **Prior operations** | "Bibi Gate" (Dec 2025, PM Chief of Staff phone data); Israel Police breach (Feb 2025); Nahal Soreq nuclear facility (Sep 2024); Maagar-Tec PA system hack (Jan 2025); Iran International journalists hack-and-leak (Jul 2025) |
| **Tradecraft** | Targets personal devices of assistants, advisers, family members rather than classified systems; phishing and social engineering for initial access; amplifies leaks via AI chatbots, X, Facebook, Instagram, Telegram, Iranian news websites |

### 15.2 Infy (Prince of Persia)

| Attribute | Detail |
|---|---|
| **Status** | Resumed operations January 26, 2026 (after pausing since January 8 blackout) |
| **Malware** | Tornado v51: self-extracting RAR containing AuthFWSnapin.dll (main DLL) and reg7989.dll (installer with Avast detection checks) |
| **C2** | Dual HTTP and Telegram; Telegram group "sarafraz"; bot `@ttestro1bot` |
| **Tool** | ZZ Stealer: custom StormKitty infostealer variant; activated by command `8==3`; linked to PyPI package `testfiwldsd21233s` |
| **Exploitation** | WinRAR CVEs (CVE-2025-8088 / CVE-2025-6218) via crafted RAR files |
| **Collection** | SafeBreach extracted 118 files and 14 shared links from Telegram C2 group (Feb 3-16, 2026) |

### 15.3 Dragos 2026 OT Report -- New IRGC-Aligned Groups

Released February 17, 2026; Dragos now tracks **26 threat groups globally** with three new IRGC-aligned additions:

| Group | Focus | Sectors |
|---|---|---|
| **PYROXENE** | Supply chain compromises, IT-to-OT lateral movement | Aviation, aerospace, defense, maritime |
| **AZURITE** | Long-term OT data theft | Manufacturing, defense, automotive, electric, oil & gas |
| **SYLVANITE** | Initial access brokering for OT intrusion | US utilities; hands off to VOLTZITE for deeper access |

---

## 16. Complete Iranian APT Landscape

### 16.1 IRGC-Aligned Groups

| Group | Also Known As | Primary Activity |
|---|---|---|
| **APT33** | Elfin, Refined Kitten, Peach Sandstorm | Destructive attacks, aerospace/energy targeting, password spraying |
| **APT35/APT42** | Charming Kitten, Mint Sandstorm, GreenCharlie | Credential theft, phishing, espionage targeting US/Israeli officials |
| **CyberAv3ngers / BAUXITE** | IRGC-CEC | ICS/OT attacks, IOCONTROL malware, wiper deployment |
| **PYROXENE** | (New, Dragos 2026) | Supply chain, aviation/defense OT targeting |
| **Infy** | Prince of Persia | Espionage, Tornado malware, ZZ Stealer |

### 16.2 MOIS-Aligned Groups

| Group | Also Known As | Primary Activity |
|---|---|---|
| **APT34** | OilRig, Helix Kitten | Espionage, lateral movement, credential harvesting |
| **APT39** | Chafer, Remix Kitten, Cotton Sandstorm | Telecommunications targeting, surveillance |
| **MuddyWater** | Mango Sandstorm, Earth Vetala, MUDDYCOAST | Operation Olalampo, MENA espionage, AI-assisted malware |
| **Void Manticore** | Storm-842 | Wiper attacks (BiBi), destructive campaigns |
| **Scarred Manticore** | -- | Initial access provision for Void Manticore |
| **Handala Hack Team** | -- | Healthcare breaches, hack-and-leak, PSYOP |

### 16.3 Hacktivist Proxies (State-Coordinated)

An estimated **35-100+ groups** declared involvement during the June 2025 conflict. Key groups: Handala Hack Team, Fatimion Cyber Team, Cyber Fattah, Cyber Islamic Resistance. These groups provide deniability while executing operations coordinated by IRGC-CEC or MOIS.

---

## 17. Israel-Iran Cyber War Timeline

| Date | Event | Attribution |
|---|---|---|
| **2005-2010** | Stuxnet destroys ~1,000 Natanz centrifuges | US/Israel (Operation Olympic Games) |
| **Nov 2011** | Duqu reconnaissance tool deployed | US/Israel |
| **Apr 2012** | Wiper erases Oil Ministry/NIOC hard drives | US/Israel |
| **May 2012** | Flame intelligence collection malware | US/Israel |
| **Aug 2012** | Shamoon wiper destroys 35,000 Saudi Aramco workstations | Iran (retaliation) |
| **2012-2013** | DDoS campaigns against US banks | Iran (retaliation) |
| **2019** | ZeroCleare wiper targets Middle East energy sector | Iran |
| **Oct 2021** | Predatory Sparrow shuts 4,300 gas stations | Israel-linked |
| **2021** | Iranian railway system paralyzed | Israel-linked |
| **Jun 2022** | Steel mill attack -- physical destruction at Khuzestan | Israel (Predatory Sparrow) |
| **Oct 2023** | CyberAv3ngers claim 200 gas pump disruptions; attack US water systems | Iran (IRGC-CEC) |
| **Dec 2023** | Repeat gas station attack (~70% shutdown) | Israel-linked |
| **2024** | APT42 intensifies Israeli military/defense targeting; IOCONTROL discovered | Iran |
| **Jun 4-12, 2025** | Pre-war: 3-4 DDoS/day targeting Israel | Iran-aligned hacktivists |
| **Jun 13, 2025** | Operation Rising Lion begins; 700% increase in cyberattacks | Both sides |
| **Jun 17, 2025** | Bank Sepah data erased | Israel (Predatory Sparrow) |
| **Jun 18, 2025** | Nobitex $90M crypto theft/burn | Israel (Predatory Sparrow) |
| **Jun 22, 2025** | Operation Midnight Hammer: US Cyber Command disables air defenses | US |
| **Jun 2025** | BAUXITE deploys 2 custom wipers; BlueWipe, SewerGoo, BeepFreeze identified | Iran |
| **Dec 2025** | Handala "Bibi Gate" operation | Iran (MOIS) |
| **Jan 8, 2026** | Iran internet blackout begins; Infy C2 goes offline | Iran (self-imposed) |
| **Jan 18, 2026** | Badr satellite TV hack -- anti-regime broadcast to millions | Israel |
| **Jan 26, 2026** | Operation Olalampo begins; Infy resumes with new C2 | Iran (MuddyWater/Infy) |
| **Feb 12, 2026** | Shin Bet discloses hundreds of foiled Iranian cyberattacks | Iran → Israel |
| **Feb 17, 2026** | Dragos 2026 OT report: 3 new IRGC-aligned groups | Iran |
| **Feb 25, 2026** | Handala claims Clalit healthcare breach | Iran (MOIS) |
| **Feb 28, 2026** | Largest cyberattack in history: Iran to 4% connectivity | Israel/US |
| **Feb 28, 2026** | CISA/FBI/NSA issue Iran cyber warnings | US (defensive) |

---

## 18. CISA / US Government Defensive Guidance

### 18.1 Joint Advisory

**CISA, FBI, DC3, and NSA** published joint fact sheet (January 2026): "Iranian Cyber Actors May Target Vulnerable US Networks and Entities of Interest"

**Key warnings:**
- Defense Industrial Base companies with ties to Israeli research/defense firms at **increased risk**
- No coordinated Iranian campaign detected in US at time of statement, but urged vigilance
- Iranian groups collaborating with ransomware affiliates

**Highlighted Iranian TTPs:**
- Exploiting known vulnerabilities in unpatched/outdated software
- Compromising internet-connected accounts/devices with default or weak passwords
- Working with ransomware affiliates to encrypt, steal, and leak sensitive information
- Brute force and credential access against critical infrastructure (AA24-290A)
- IRGC-affiliated PLC exploitation in water/wastewater systems (AA23-335A)

### 18.2 CISA Staffing Alert

CISA is operating with **approximately one-third reduced workforce** due to DHS funding lapse, degrading public-private collaboration and timely threat information sharing.

### 18.3 Recommended Defensive Actions

1. **Patch all internet-facing systems** -- prioritize VPN appliances, firewalls, Exchange, Fortinet, Citrix, Ivanti (known Iranian APT exploitation targets)
2. **Enable phishing-resistant MFA** on all accounts; verify no default/weak passwords remain
3. **Monitor for Operation Olalampo IOCs**: GhostFetch, CHAR, HTTP_VIP, RustyWater RAT; C2 domain `codefusiontech[.]org`; Telegram bot `stager_51_bot`
4. **OT/ICS operators**: Review IOCONTROL indicators (SHA-256: `1b39f9b...b84498`); monitor MQTT-based C2; check for exposed HMIs, Modbus/TCP, DNP3 endpoints; disconnect OT from internet where possible
5. **Review CISA advisories**: AA24-290A (brute force), AA23-335A (PLC exploitation), Iran APT overview page
6. **Increase SOC monitoring cadence** to continuous during current threat period
7. **Pre-position incident response** for potential wiper or destructive malware deployment
8. **Monitor for Predatory Sparrow indicators** -- potential Israeli escalation against Iranian financial/infrastructure targets
9. **Brief executive leadership** on elevated threat posture and potential business continuity impacts

---

## 19. Strategic Assessment and Expert Analysis

### 19.1 Expert Assessments

| Expert | Assessment |
|---|---|
| **Ret. Lt. Gen. Charles Moore** (former US Cyber Command) | "Anything that Iran is using to communicate, anything they're using to keep situational awareness or visibility on the battle space, and any systems they're using to try to defend themselves -- would be targets of interest from a cyber perspective." |
| **Anomali** (cybersecurity firm) | "The operation has destroyed Iran's conventional military options, making cyber operations the regime's sole remaining instrument of asymmetric retaliation." Iran-linked units were "activated and retooling before the kinetic trigger." |
| **Annie Fixler** (FDD) | Iran "might also see some limited success against targets that do not have proper cyber hygiene -- exposed edge devices with default passwords." |
| **Erica Lonergan** (FDD) | The 2025-2026 operations reflect "the routinization of the use of cyber capabilities during military operations." |
| **Atlantic Council** | Cyber operations "offered an incremental edge in warfare, rather than a revolutionary one" -- supporting tools rather than conflict-deciding mechanisms. |
| **Yossi Karadi** (Israeli Cyber Defense Chief) | "The first cyber war driven by AI agents won't begin with a siren; it will begin with the disruption of services, of decision-making, and of daily life." |
| **RUSI** (Prerana Joshi) | "If there is to be a kinetic US operation against Iran, it is no longer a question of if offensive cyber might be involved, but how -- and to support what objective." |

### 19.2 Iran Cyber Capability Assessment

| Attribute | Assessment |
|---|---|
| **Global ranking** | Second tier -- ahead of most nations, below China and Russia; described as "right behind Russia and China" as Tier 1 cyber aggressors |
| **Organizational maturity** | 15+ years of operational experience across IRGC, MOIS, Basij, and proxy groups |
| **Key capabilities** | ICS/OT-specific malware (IOCONTROL); 6+ wiper families; AI-assisted development; 35-100+ hacktivist proxies; dual-use internet enabling ops during blackouts |
| **Key weakness** | "Dire lack" of defensive capabilities; critical infrastructure frequently compromised; cyber tools primarily oriented toward domestic surveillance rather than defense |
| **Strategic shift** | With conventional military options destroyed, cyber is now Iran's "sole remaining instrument of asymmetric retaliation" |

### 19.3 Key Strategic Conclusions

1. **Full-spectrum integration achieved:** Israeli cyber operations have evolved from standalone sabotage (Stuxnet) to fully integrated cyber-kinetic warfare, with cyberattacks timed to suppress air defenses, disrupt C2, and amplify psychological effects of kinetic strikes.
2. **Proxy architecture for deniability:** Israel operates through Predatory Sparrow for deniable destructive operations against civilian infrastructure, while maintaining state-level capabilities through Unit 8200 for military operations.
3. **Unprecedented scale:** The February 2026 attack reducing Iran to 4% connectivity is the largest documented cyberattack in history, surpassing all previous operations in scope and coordination.
4. **NIN failure is significant:** The failure of Iran's National Information Network -- the domestic intranet designed to operate independently -- indicates either deep pre-positioned access or vulnerabilities in the NIN architecture that attackers exploited.
5. **Cyber as Iran's last resort:** With conventional military options degraded, Iran will escalate cyber operations. US critical infrastructure (water, energy, telecom, healthcare) should assume elevated threat posture.
6. **AI entering the battlefield:** Both sides are incorporating AI -- MuddyWater's AI-assisted malware development, Israel's AI-enhanced targeting and EW. Israeli Cyber Defense Chief warned the next cyber war will be "driven by AI agents."
7. **Domestic vulnerability window:** CISA's one-third workforce reduction during an active Iranian cyber escalation creates a concerning domestic vulnerability gap.

---

## 20. Sources and References

### 20.1 Primary Reporting on February 28 Cyberattack

| Source | URL |
|---|---|
| Jerusalem Post | `https://www.jpost.com/israel-news/defense-news/article-888271` |
| RFE/RL | `https://www.rferl.org/a/iran-internet-blackout-us-israel-military-attack/33690399.html` |
| Security Affairs | `https://securityaffairs.com/188648/cyber-warfare-2/iran-s-internet-near-totally-blacked-out-amid-us-israeli-strikes.html` |
| Kentik Analysis | `https://www.kentik.com/analysis/iran-goes-dark-as-government-cuts-itself-off-from-internet/` |
| National Security News | `https://nationalsecuritynews.com/2026/02/irgc-commander-runs-mtn-irancell-as-irans-internet-goes-dark-under-us-and-israeli-strikes/` |
| NowLebanon | `https://nowlebanon.com/irans-internet-blackout-engineering-silence/` |
| Hudson Institute | `https://www.hudson.org/defense-strategy/how-israels-operation-rising-lion-dismantled-iran-within-case-study-art-deception` |

### 20.2 Iran Internet Architecture

| Source | URL |
|---|---|
| Wikipedia: 2026 Internet Blackout | `https://en.wikipedia.org/wiki/2026_Internet_blackout_in_Iran` |
| Foreign Policy: Two-Tiered Internet | `https://foreignpolicy.com/2026/02/24/tehran-internet-tiered-connectivity-shutdown/` |
| Rest of World: Two-Tier Internet | `https://restofworld.org/2026/iran-blackout-tiered-internet/` |
| Chatham House: Digital Isolation | `https://www.chathamhouse.org/2026/01/irans-internet-shutdown-signals-new-stage-digital-isolation` |
| Filterwatch: Technical Breakdown | `https://filter.watch/english/2026/01/16/investigative-report-technical-breakdown-of-the-january-2026-shutdown/` |
| Georgia Tech IODA: Comparative Analysis | `https://ioda.inetintel.cc.gatech.edu/reports/a-comparative-look-at-internet-shutdowns-in-iran-2019-2022-2026-and-2026/` |

### 20.3 Cyber Operations and Malware

| Source | URL |
|---|---|
| Group-IB: Operation Olalampo | `https://www.group-ib.com/blog/muddywater-operation-olalampo/` |
| Claroty Team82: IOCONTROL | `https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol` |
| Dragos: BAUXITE | `https://www.dragos.com/threat/bauxite` |
| Dragos 2026 OT Report | `https://www.dragos.com/resources/press-release/dragos-2026-year-in-review-new-ot-threats-ransomware` |
| The Hacker News: MuddyWater | `https://thehackernews.com/2026/02/muddywater-targets-mena-organizations.html` |
| The Hacker News: Infy Resumes | `https://thehackernews.com/2026/02/infy-hackers-resume-operations-with-new.html` |
| Palo Alto Unit 42: Iranian Cyberattacks 2025 | `https://unit42.paloaltonetworks.com/iranian-cyberattacks-2025/` |
| SentinelOne: Iranian Cyber Outlook | `https://www.sentinelone.com/blog/sentinelone-intelligence-brief-iranian-cyber-activity-outlook/` |

### 20.4 Historical Operations and Strategic Analysis

| Source | URL |
|---|---|
| Atlantic Council: Cyber Conflict Lessons | `https://www.atlanticcouncil.org/blogs/new-atlanticist/what-the-israel-iran-conflict-revealed-about-wartime-cyber-operations/` |
| The Record: Cyber Command Iran | `https://therecord.media/iran-nuclear-cyber-strikes-us` |
| Defense One: Cyber Strategy | `https://www.defenseone.com/threats/2026/02/strikes-iran-will-test-us-cyber-strategy-abroad-and-defenses-home/411782/` |
| RUSI: Cyber Operations in Iran | `https://www.rusi.org/explore-our-research/publications/commentary/control-alt-influence-potential-us-cyber-operations-iran` |
| Picus Security: Predatory Sparrow | `https://www.picussecurity.com/resource/blog/predatory-sparrow-inside-the-cyber-warfare-targeting-irans-critical-infrastructure` |
| CSIS: Iran and Cyber Power | `https://www.csis.org/analysis/iran-and-cyber-power` |
| CSIS: Beyond Hacktivism | `https://www.csis.org/blogs/strategic-technologies-blog/beyond-hacktivism-irans-coordinated-cyber-threat-landscape` |

### 20.5 US Government and CISA

| Source | URL |
|---|---|
| CISA: Iranian Cyber Actors Warning | `https://www.cisa.gov/resources-tools/resources/iranian-cyber-actors-may-target-vulnerable-us-networks-and-entities-interest` |
| CISA: Joint Statement | `https://www.cisa.gov/news-events/news/joint-statement-cisa-fbi-dc3-and-nsa-potential-targeted-cyber-activity-against-us-critical` |
| CISA: Iran Threat Overview | `https://www.cisa.gov/topics/cyber-threats-and-advisories/advanced-persistent-threats/iran` |
| Rewards for Justice: CyberAv3ngers | `https://rewardsforjustice.net/rewards/cyberav3ngers/` |

---

*This document is OSINT only and does not contain classified or controlled information. It is intended as a reference for defensive cyber operations, threat intelligence analysis, and OT/ICS security engineering. All attributions reflect assessments from cited open sources, government publications, and cybersecurity vendor research. The dual-nature of the Iran internet blackout (external attack + self-imposed shutdown) means connectivity impact figures reflect the combined effect. Validate all IOCs and intelligence against multiple independent sources before taking action.*
