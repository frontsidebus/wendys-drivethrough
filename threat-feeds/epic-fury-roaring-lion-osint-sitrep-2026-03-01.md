---
feedId: epic-fury-roaring-lion-osint-sitrep-2026-03-01
title: Operation Epic Fury / Roaring Lion — OSINT SITREP (96-Hour Compilation)
topic: nation-state
industry: critical-infrastructure
country: IR
severity: critical
tags: [operation-epic-fury, operation-roaring-lion, operation-true-promise-4, operation-midnight-hammer, iran, israel, irgc, khamenei, hormuz, cyber-kinetic, nuclear, ot-security, muddywater, cyberav3ngers, houthi, red-sea, osint]
summary: 96-hour open-source intelligence compilation on the US-Israeli joint military campaign against Iran. Covers operation codenames, cyber-kinetic integration, Iranian retaliation waves, leadership decapitation, Hormuz closure, non-mainstream OSINT sourcing, and ground-level signals not covered by major outlets.
---

# Operation Epic Fury / Operation Roaring Lion — OSINT SITREP
## 96-Hour Open Source Intelligence Compilation
**Period Covered:** 2026-02-26 00:00 UTC — 2026-03-01 23:59 UTC
**Compiled:** 2026-03-01
**Classification:** OSINT — Open Source Intelligence Only
**Methodology:** Web, Substack, Reddit megathread aggregation, OSINT platform cross-referencing, CENTCOM press releases, regional outlet monitoring
**Focus:** Non-mainstream signals, ground-level reporting, cyber-kinetic integration, operational details underreported in Western media
**Cross-Reference:** [US-Iran-Israel Cyber Threat Intelligence Feed](us-iran-israel-cyber-threat-feed.md) | [Iran/Middle East 24-Hour SITREP](iran-middle-east-24hr-sitrep-2026-02-28.md) | [Israel-Iran Cyber Operations Deep Dive](israel-iran-cyber-operations-2026-02-28.md)

---

## Table of Contents

1. [Operation Codename Reference Matrix](#1-operation-codename-reference-matrix)
2. [Pre-Strike Indicators — What OSINT Caught in Advance](#2-pre-strike-indicators--what-osint-caught-in-advance)
3. [Strike Architecture — Beyond the Headlines](#3-strike-architecture--beyond-the-headlines)
4. [Leadership Decapitation — Full Casualty Assessment](#4-leadership-decapitation--full-casualty-assessment)
5. [Operation True Promise 4 — Iranian Retaliation Detail](#5-operation-true-promise-4--iranian-retaliation-detail)
6. [Cyber-Kinetic Integration — Technical Assessment](#6-cyber-kinetic-integration--technical-assessment)
7. [Strait of Hormuz — Closure Indicators and Shipping Intelligence](#7-strait-of-hormuz--closure-indicators-and-shipping-intelligence)
8. [Iranian Leadership Succession — Intelligence Picture](#8-iranian-leadership-succession--intelligence-picture)
9. [Ground-Level Signals — Social Media, Substack, Reddit Compilation](#9-ground-level-signals--social-media-substack-reddit-compilation)
10. [Houthi Re-Activation and Red Sea Threat Posture](#10-houthi-re-activation-and-red-sea-threat-posture)
11. [Non-Mainstream OSINT Sources and Analysts](#11-non-mainstream-osint-sources-and-analysts)
12. [Blue Team Threat Posture Recommendations](#12-blue-team-threat-posture-recommendations)

---

## 1. Operation Codename Reference Matrix

| Codename | Nation | Context |
|---|---|---|
| **Operation Epic Fury** | 🇺🇸 US / CENTCOM | Primary US designation for Feb 28 strikes on Iran |
| **Operation Roaring Lion** (also "Raging Lion" / "Lion's Roar") | 🇮🇱 Israel / IDF | Israeli designation; also umbrella for cyber/EW component |
| **Operation Genesis** | 🇮🇱 IDF | Sub-codename for Israeli first-wave opening salvo |
| **Operation Midnight Hammer** | 🇺🇸 US DoD | June 22, 2025 B-2 strikes on Fordow, Natanz, Isfahan — the precursor operation |
| **Operation True Promise 4** | 🇮🇷 IRGC | Iranian retaliatory campaign (continuing series from TP1–TP3 in 2024) |
| **Operation Rough Rider** | 🇺🇸 US | March–May 2025 air campaign against Houthi forces in Yemen |
| **Operation Prosperity Guardian** | 🇺🇸 US-led multinational | Naval task force protecting Red Sea/Gulf of Aden shipping (Dec 2023 onward, ongoing) |
| **Operation Olalampo** | 🇮🇷 MuddyWater / MOIS | Iranian cyber retaliation campaign (active since Jan 26, 2026) — new malware families |

**Note on "Roaring Lion" vs "Lion's Roar":** Israeli and Western outlets have rendered the Hebrew name inconsistently. Times of Israel, JNS, and IDF official statements use "Roaring Lion." Israel Hayom uses "Lion's Roar." OSINT community has largely standardized on "Roaring Lion." For search purposes, both variants return relevant results.

---

## 2. Pre-Strike Indicators — What OSINT Caught in Advance

This section is of particular interest to blue teams: **several open-source signals preceded the strikes**, some captured in real time by OSINT accounts that went largely unnoticed by mainstream media.

### 2.1 AI Prediction (Grok)
Grok AI reportedly generated an "accurate prediction" of the Feb 28 strikes in advance of the operation, based on publicly available signals aggregation. Reported by INCPak and independently noted by multiple OSINT accounts on X. This raises a significant CI/OPSEC question: **if an AI LLM could synthesize available signals into an accurate prediction, so could any sophisticated adversary monitoring the same open-source environment.**

### 2.2 Covert Maritime Interdiction (November 2025 — Unreported at Time)
US Special Operations Forces boarded a **Chinese-flagged vessel in the Indian Ocean off Sri Lanka** in November 2025, seizing and destroying missile-related components bound for Iran. Key details that distinguish this from standard interdiction:
- **No press conference held**
- **No unit named** (SOF, not conventional Navy boarding teams)
- Cargo destroyed on site; ship released
- Only surfaced in reporting weeks later, buried in broader Iran sanctions coverage
- Indicates US had established an active maritime interdiction posture against Iran-bound WMD components months before the Feb 28 strikes — part of a longer-running covert pressure campaign

### 2.3 Port System Disruptions (January 20–26, 2026)
Covert cyber/physical attacks struck **Bandar Abbas** and **Chabahar** port systems, disrupting container management and oil export operations. Iranian losses: "tens of millions of dollars per day." Attributed to Israel (no official claim). This pre-strike economic degradation has been underreported — it was part of the multi-month campaign to degrade Iranian economic and logistics capacity ahead of kinetic operations.

### 2.4 January 18 Satellite Broadcast Hack
Government satellite broadcasts were hacked; content calling for regime overthrow was aired to millions of Iranian households via **Badr satellite** for approximately 10 minutes at ~17:30 UTC. Exiled Crown Prince Reza Pahlavi broadcast, "Woman, Life, Freedom" footage. This was **the most significant PSYOP precursor** and was widely reported inside Iran on Telegram before government suppression — but received minimal Western coverage.

### 2.5 720 Million PPS DDoS Probe (Late January)
Iran's Telecommunications Infrastructure Company (TIC) reported foiling a DDoS attack exceeding **720 million packets per second** from 125,000+ distributed sources — ranked among the world's 12 largest DDoS attacks by PPS. Iran publicly attributed this to Israel. In retrospect this was a **reconnaissance-in-force operation**: testing Iran's network defenses, mapping response infrastructure, and calibrating the scale needed to achieve the Feb 28 blackout. Not reported by any major Western outlet at the time.

---

## 3. Strike Architecture — Beyond the Headlines

### 3.1 Sequencing and Sub-Operation Structure
The Feb 28 operation had a documented phased structure not widely reported:

1. **Electronic warfare** — Pre-strike GPS spoofing and radar jamming across western Iran
2. **Cyber component** — BGP route manipulation, DDoS, IRGC comms disruption initiated before kinetic phase
3. **Operation Genesis** (IDF sub-codename) — Opening Israeli salvo, ~200 IAF jets, largest combat sortie in Israeli Air Force history
4. **US Navy/Air strikes** — Tomahawks from USS Spruance (DDG-111) and other destroyers/submarines; F-35C and F/A-18E/F from USS Abraham Lincoln (CVN-72) and USS Gerald R. Ford (CVN-78)
5. **PSYOP layer** — State media defacement, satellite broadcast disruption concurrent with kinetic strikes
6. **Leadership decapitation** — Khamenei compound struck in Pasteur district, Tehran, "shortly before midnight" Iran time

**Launch time:** 1:15 AM ET, February 28, 2026. Trump video statement at approximately 2:30 AM EST.

### 3.2 Naval Forces (USNI-Confirmed)
| Asset | Type | Location | Role |
|---|---|---|---|
| USS Abraham Lincoln (CVN-72) | Carrier | North Arabian Sea | CVW-9 strike package: Marine F-35C + Navy F/A-18E/F |
| USS Gerald R. Ford (CVN-78) | Carrier | Eastern Mediterranean | CVW-8; VFA-213 "Blacklions" F/A-18F |
| USS Spruance (DDG-111) | Guided-missile destroyer | Gulf | Tomahawk BGM-109 launches (CENTCOM footage confirmed) |
| 14 additional guided-missile destroyers | DDGs | Mediterranean + Middle East | Tomahawk strikes |

### 3.3 Weapon Systems
- **Tomahawk cruise missiles (BGM-109)** — destroyers and submarines
- **GBU-57 Massive Ordnance Penetrators (MOPs)** — 30,000 lb bunker-busters, repeat deployment from June 2025 Midnight Hammer against Fordow
- **F-35C Lightning II** (USS Abraham Lincoln)
- **F/A-18E/F Super Hornets** (both carriers)
- **F-22 Raptors** (supporting)
- Drones (type unconfirmed)

### 3.4 Nuclear Targets
- **Fordow Uranium Enrichment Plant** — underground hardened facility; MOP strike
- **Natanz Nuclear Facility** — primary enrichment complex
- **Isfahan Nuclear Technology Center** — Tomahawk strikes
- Pre-strike satellite imagery had confirmed Iran was actively hardening two additional sites: **Pickaxe Mountain** (south of Natanz, under rapid underground construction) and **Taleghan 2 at Parchin** (being encased in concrete). Status of these sites post-strike not confirmed.

### 3.5 Strike Volume
- ~900 US strikes in first 12 hours
- IDF: 500 Iranian military targets in opening wave
- 1,200+ munitions dropped by IAF in Day 1
- Defense Secretary Hegseth: "the most lethal, most complex, and most-precision aerial operation in history"

---

## 4. Leadership Decapitation — Full Casualty Assessment

The scope of senior leadership killed in the opening salvo is significantly broader than mainstream coverage has conveyed. IDF claimed "40 senior commanders killed in first 60 seconds" — a claim that has not been independently denied.

### 4.1 Confirmed Killed
| Name | Position |
|---|---|
| **Ayatollah Ali Khamenei, 86** | Supreme Leader of Iran (1989–2026) |
| **Abdolrahim Mousavi** | Chief of Staff, Iranian Armed Forces |
| **Mohammad Pakpour** | IRGC Commander |
| **Ali Shamkhani** | Secretary, Supreme National Defense Council; senior adviser |
| **Aziz Nasirzadeh** | Defense Minister |
| **Javad Pourhossein** | Head of Foreign Intelligence Unit |
| **Mohammad-Reza Bajestani** | Head of Security Unit |
| **Ali Kheirandish** | Head of Counterterrorism Unit |
| **Saeed Ehya Hamidi** | Adviser on the war with Israel |
| **4 members of Khamenei's immediate family** | — |

**IDF assessment:** "A majority" of Iran's senior military leaders killed in the opening wave.

### 4.2 Khamenei Death — OSINT Note
Iran initially denied Khamenei's death. Iran's Supreme National Security Council confirmed early March 1, after Israeli officials confirmed "shortly before midnight" Iran time Feb 28. The destroyed compound at the Pasteur district (also location of presidential palace and National Security Council) was confirmed via satellite imagery by multiple commercial satellite providers — one of the fastest satellite confirmation cycles observed in any conflict, with images circulating within 4 hours on GeoConfirmed and Bellingcat.

---

## 5. Operation True Promise 4 — Iranian Retaliation Detail

### 5.1 Context
"True Promise" is Iran's series designation for direct retaliatory operations against Israel. This marks the fourth in the series (TP1 and TP2 in April and October 2024; TP3 during the June 2025 Twelve-Day War). The serial numbering is significant: **Iran has been systematically escalating each True Promise operation** in scale and geographic scope.

### 5.2 Targets Struck
| Target | Location | Notes |
|---|---|---|
| Al Udeid Air Base | Qatar | Largest US air base in the Middle East |
| Ali Al Salem Air Base | Kuwait | 3 Kuwaiti soldiers injured by shrapnel |
| Al Dhafra Air Base | UAE | 1 person killed in Abu Dhabi |
| NSA Bahrain / US Fifth Fleet HQ | Bahrain | Direct strike attempted |
| Muwaffaq al-Salti Air Base | Jordan | — |
| US base, northern Iraq | Iraq | — |
| Israel | — | Ballistic missiles + drones |
| Saudi Arabia (Riyadh, eastern region) | Saudi Arabia | Saudi Arabia confirmed strikes on its territory; reserved right to retaliate |
| Cyprus | Cyprus | UK confirmed Iran fired missiles at Cyprus (Ynet report) |
| MV Skylight (oil tanker) | ~5nm north of Khasab Port, Oman | First confirmed tanker attack in Hormuz closure (Euronews, March 1) |
| "MSP" vessel, Jebel Ali anchorage | Indian Ocean | Iran claims 4 drones hit the vessel, "severely damaged"; carrying ammunition for US vessels per IRGC claim |

**IRGC claimed** strikes on 27 US military bases and "a major defense-industrial complex in Tel Aviv." Unverified by Western sources.

### 5.3 Waves
IRGC announced **7th and 8th waves** of Operation True Promise 4 by March 1 (Tasnim News). This multi-wave structure — rather than a single saturation strike — suggests Iran is pacing its remaining missile inventory, likely due to intercept losses. Each wave incorporates mix of ballistic missiles (including **Fattah hypersonic missiles** in the second wave per IRGC claims), cruise missiles, and Shahed drones.

### 5.4 US Casualties
CENTCOM (March 1): **3 US service members KIA, 5 seriously wounded.** Iranian IRGC claimed "at least 200 US and allied military personnel killed or injured" — no independent Western confirmation. Additionally, Iranian IRGC UAVs attacked US oil rigs in retaliation.

---

## 6. Cyber-Kinetic Integration — Technical Assessment

### 6.1 The Five-Vector Simultaneous Attack
The cyber component of Operation Roaring Lion was not a supporting effect — it was a coordinated operational layer executed simultaneously with the kinetic strikes. Five attack vectors deployed concurrently:

1. **BGP route manipulation** — severed Iran from the global internet at the routing level; not just content filtering
2. **Massive DDoS** — building on the January 720M PPS reconnaissance data; overwhelmed remaining capacity
3. **Deep network intrusions** — targeted energy grid, aviation, and IRGC communications systems
4. **Electronic warfare** — GPS spoofing, radar jamming, IRGC communications disruption to prevent missile launch coordination
5. **Information operations** — state media defacement, satellite broadcast disruption (continuation of Jan 18 operation)

The failure of Iran's **National Information Network (NIN)** — the hardened domestic intranet explicitly designed as a resilient fallback — is the most operationally significant detail in the public record. The NIN was built specifically to survive external internet cuts. Its failure indicates **deep pre-positioned access to domestic Iranian network infrastructure** that the attackers had established prior to Feb 28.

### 6.2 Connectivity Impact (NetBlocks / Cloudflare Confirmed)
- Iran's internet connectivity: **4% of normal** at peak of attack → **effectively zero** by 18:45 UTC
- Duration: 12+ hours of near-total blackout; ~1% connectivity remaining after 24 hours
- 87 million people affected
- Daily economic cost: **$35.7 million/day** (acknowledged by Iran's Minister of Communications)
- Digital economy employment dropped 30% — ~10 million Iranians depend on this sector
- Daily losses: 130 trillion tomans

### 6.3 Iranian Offensive Cyber (Active Despite Blackout)
**CRITICAL FOR BLUE TEAMS:** Iranian APT groups maintained offensive capability during and after the blackout by exploiting **privileged state network access** — they were not subject to the same civilian internet restrictions.

| Group | Operation | Activity |
|---|---|---|
| **MuddyWater (Earth Vetala / Mango Sandstorm)** | Operation Olalampo (active Jan 26+) | New malware families: **GhostFetch** (downloader), **GhostBackDoor** (implant), **CHAR** (Rust-based backdoor), **HTTP_VIP** (downloader), **RustyWater RAT**. Targeting Israeli companies, MENA organizations, diplomatic/maritime/financial/telecom entities. Spear-phishing with malicious Office macros. AI-assisted malware development noted. |
| **CyberAv3ngers (BAUXITE / IRGC-CEC)** | — | Previously deployed two custom wiper variants against Israeli targets during June 2025 conflict. IOCONTROL malware targeting worldwide ICS/SCADA (Baicells, D-Link, Hikvision, Red Lion, Orpak, Phoenix Contact, Teltonika, Unitronics). Dragos 2026 OT Report flagged as continued significant threat. US Rewards for Justice maintains active bounty. |
| **Handala** | — | Active healthcare data breach operations. |

**Shin Bet assessed:** "hundreds of cyber attacks" against Israeli politicians, senior defense officials, journalists, and academics in 2026 prior to Feb 28 — establishing access and intelligence collection ahead of retaliation.

---

## 7. Strait of Hormuz — Closure Indicators and Shipping Intelligence

### 7.1 IRGC Radio Broadcast
IRGC forces issued VHF radio messages: **"No ship is allowed to pass the Strait of Hormuz."** Not formally confirmed by Iranian government but picked up on maritime monitoring networks and reported by multiple shipping intelligence services. This is operationally significant — IRGC action authority at sea does not require formal government declaration.

### 7.2 Confirmed Tanker Attack
- **MV Skylight** targeted approximately **5 nautical miles north of Khasab Port, Oman** (Euronews, March 1)
- First confirmed attack since IRGC VHF closure announcement
- Hormuz handles ~25% of global seaborne oil trade (~20 million barrels/day, ~20% of global oil consumption)

### 7.3 Shipping Intelligence Signals
- Oil tanker traffic dropped sharply; only a trickle of vessels moving out, none entering the Gulf
- Trading houses suspended oil shipments through the Gulf
- Marine insurance halted coverage for Gulf voyages
- Marine risk premiums hit a **6-year high**; rates expected to rise 50%+
- Bloomberg analysis: "Can Iran Close the Strait?" — assessed Iranian mining capability vs. US counter-mine assets

### 7.4 CENTCOM Naval Action
- Iranian Navy **Jamaran-class corvette** struck at pier in **Chabahar Port** (Gulf of Oman) — CENTCOM stated the vessel was "currently sinking to the bottom of the Gulf of Oman" (March 1 statement)
- Iranian frigate reported ablaze after being struck in port (The War Zone, imagery confirmed)
- IRGC UAVs counterattacked US oil rigs in retaliation — first confirmed IRGC offensive action against US commercial energy infrastructure

---

## 8. Iranian Leadership Succession — Intelligence Picture

### 8.1 Transitional Council (Formed Immediately)
Per Iranian constitution and confirmed by Al Jazeera:
- **Ayatollah Alireza Arafi** (clerical representative)
- **President Masoud Pezeshkian**
- **Gholam-Hossein Mohseni-Ejei** (Supreme Court Chief Justice)

Assembly of Experts (88 members) must formally elect successor Supreme Leader.

### 8.2 Succession Candidates — Intelligence Assessment
| Candidate | Background | OSINT Assessment |
|---|---|---|
| **Mojtaba Khamenei, 56** | Supreme Leader's son; IRGC/Basij ties; long-rumored heir | Most discussed candidate on Persian-language Telegram channels; seen as IRGC-backed continuity choice; however dynastic succession has no precedent in the Islamic Republic |
| **Ali Larijani** | Former parliament speaker; former National Security Council secretary | Described as "most senior civilian official still standing"; pragmatist; may be acceptable compromise between factions |
| **Gholam-Hossein Mohseni-Ejei** | Supreme Court Chief Justice; already on transitional council | Hardliner; operational position gives him immediate institutional leverage |
| **Hassan Khomeini** | Grandson of Islamic Republic founder | Reform-aligned; unlikely without clerical backing |
| **Asghar Hejazi** | — | Named in succession speculation; limited public profile |

**Key intelligence factor:** Any successor will require IRGC backing. The IRGC lost significant command structure in the opening salvo. Its institutional position in succession negotiations is weaker than at any point since 1979 — but remaining IRGC officers retain physical control of weapons systems and may exercise decisive informal influence regardless of formal clerical process.

**March 1:** Trump stated he "will be talking" to Iranian leaders — the first public signal of a potential negotiated offramp (Times of Israel).

---

## 9. Ground-Level Signals — Social Media, Substack, Reddit Compilation

### 9.1 Reddit Megathreads
The following threads served as primary real-time OSINT aggregation points during the first 96 hours. "Megathread" posts in r/worldnews, r/geopolitics, r/CredibleDefense, and r/iran served as the most information-dense ground-level sources:

**Key Reddit signal patterns observed:**
- Users in Tehran reported **total mobile and home internet blackout** from approximately 18:45 UTC Feb 28, corroborating NetBlocks data independently and in real-time
- Multiple Iranian diaspora users reported family contacts inside Iran going silent within the same 30-minute window — consistent with the NIN failure as well as external cut
- r/CredibleDefense threads contained the most technically accurate early analysis of the five-vector cyber attack, with users correctly identifying BGP hijacking within 2 hours of the blackout — before any mainstream reporting
- Users claiming to be sailors or contractors at Gulf bases reported hearing intercept fire and "a lot of Patriot launches" through the night of Feb 28 — consistent with CENTCOM multi-base targeting reports
- r/iran megathread contained Persian-language posts translated by bilingual users showing Iranians in major cities celebrating in the streets despite deployed security forces — notably Tehran, Isfahan, Shiraz, and Mashad all reported celebrations

### 9.2 Substack — Non-Mainstream Analysis

**Highest-signal Substack posts identified:**

| Author | Post | Key Insight |
|---|---|---|
| **sinosoviran.substack.com** | "The Iranian Crisis of February 2026: From Ultimatum to Operation Epic Fury" | Deep contextualization of the 18-month escalation ladder from Twelve-Day War to Feb 28 |
| **safehousebriefing.substack.com** (Brian O'Neill) | "The Iran Standoff in the Age of OSINT" | Strong analysis of how real-time OSINT changed the information environment during the strikes — satellite imagery, AIS tracking, NetBlocks data all publicly available within hours |
| **centeredamerica.substack.com** | "Operation Epic Fury: Day One Analysis" | **Key insight:** "The U.S. and Israel can likely sustain the current pace of operations for up to four days, but by Day 3 to Day 4, missile defense interceptor depletion becomes the decisive constraint, creating a clear inflection point: intensify strikes on launch infrastructure, tolerate higher rates of successful missile breakthroughs, or move toward a negotiated pause." |
| **tatsuikeda.substack.com** | "They Killed Khamenei. It Won't Matter." | Contrarian take arguing structural factors (IRGC, Revolutionary Guard institutions, Basij network) outlast any leadership decapitation; historically grounded |
| **geopoliticsunplugged.substack.com** | "SPECIAL EDITION: ATTACK ON IRAN — FULL REPORT" | Most comprehensive open-source compilation of Iranian retaliation targeting across Gulf states |

### 9.3 Key On-the-Ground Signals

**From Persian-language Telegram channels (translated and cross-referenced):**
- Reports of **IRGC vehicle convoys moving through Tehran residential neighborhoods** at approximately 3 AM local time on Feb 28, consistent with forces dispersing from command facilities before further strikes
- Reports of **celebrations at Tehran University and Sharif University of Technology** — the same campuses where "Death to Khamenei" protests had been ongoing for the prior 5 days
- Multiple accounts of Iranian civilians providing real-time location data of military convoys to unknown parties via Telegram — a crowd-sourced ISR phenomenon first observed in the Ukraine conflict, now appearing in Iran
- **Significant Telegram channel growth:** pro-Pahlavi restoration channels reportedly added hundreds of thousands of followers within hours of Khamenei's death confirmation; Shahzadeh channel (Crown Prince Reza Pahlavi's platform) described as "overwhelmed with traffic"

**From X/Twitter OSINT accounts:**
- @GeoConfirmed and @BellingcatInvestigates both posted satellite imagery confirmation of Khamenei compound destruction within 4 hours of the initial strike — using Maxar and Planet commercial imagery
- AIS (Automatic Identification System) vessel tracking showed **complete AIS signal dropout** across the northern Gulf within 90 minutes of the Hormuz closure announcement — consistent with vessels either sheltering in place or disabling transponders
- IDF Spokesperson X account posted real-time strike confirmation updates in Hebrew, English, and Arabic — unprecedented multilingual real-time transparency for an active operation, assessed as deliberate PSYOP to reach Arab-speaking audiences in the Gulf and Iran
- IRGC Telegram channels claimed strikes on 27 US bases; cross-referencing against confirmed damage reports suggests actual hits on 6–7 bases with varying severity

### 9.4 Saudi Arabia — Underreported Signal
**Saudi Arabia confirmed Iranian strikes on its own territory** (Riyadh and eastern region). Saudi Arabia has formally "reserved the right to retaliate." This is underreported in Western media: if Saudi Arabia conducts its own retaliatory strikes against Iran, it would represent a fundamental shift in Gulf geopolitics — direct Saudi-Iranian military engagement for the first time. Saudi ADA (air defense artillery) units were reportedly firing through the night of Feb 28–March 1 across the eastern region near oil infrastructure.

---

## 10. Houthi Re-Activation and Red Sea Threat Posture

### 10.1 Announcement
February 28: Houthis **formally announced resumption of missile and drone attacks** on US and Israeli-flagged ships in the Red Sea in solidarity with Iran. This came despite **Operation Rough Rider** (March–May 2025), the US air campaign that degraded but did not eliminate Houthi capabilities.

### 10.2 Significance
The Houthi re-activation creates a **two-front maritime threat** that strains US naval resources:
- Strait of Hormuz (Iranian IRGC) — primary Gulf corridor, 25% of world seaborne oil
- Red Sea / Bab-el-Mandeb (Houthis) — secondary corridor used when Hormuz tension spikes

Operation Prosperity Guardian (the existing multinational Red Sea task force) was designed for one-front operations. Simultaneous Gulf + Red Sea threat has no current US naval counter-posture that doesn't require drawing down assets from one theater to cover the other.

### 10.3 Yemen Concerns
Local reporting from Sana'a suggests Yemeni civilians and non-Houthi groups fear another round of US airstrikes, with population movement observed in areas previously targeted during Operation Rough Rider.

---

## 11. Non-Mainstream OSINT Sources and Analysts

Recommended for ongoing monitoring of this situation:

| Source | Type | Value |
|---|---|---|
| **IranMonitor.org** | Real-time OSINT dashboard | Most comprehensive Iran-specific monitoring platform; aggregates social media, satellite, AIS, NetBlocks |
| **The War Zone (TWZ)** | Defense journalism | Best open-source naval/air asset tracking; published Iranian frigate imagery within hours |
| **USNI News** | US Naval Institute | Most detailed and accurate naval order-of-battle reporting |
| **SOFREP** | SOF-community publication | Detailed strike strategy analysis; well-connected to SOF community for ground truth |
| **SOF News** | SOF-focused | First to publish details on the Nov 2025 Indian Ocean missile component interdiction |
| **GeoConfirmed** | Volunteer OSINT geolocation | Fastest satellite imagery cross-referencing; Khamenei compound confirmed here before mainstream reporting |
| **Bellingcat** | Investigative OSINT | Systematic video geolocation of strike footage; useful for target BDA (Battle Damage Assessment) |
| **Erkan Saka / Medium** | OSINT aggregator | Published comprehensive OSINT source list for the conflict within 24 hours (Feb 2026) |
| **Brian O'Neill / Safehouse Briefing (Substack)** | Independent analyst | Best single-author analysis of how OSINT changed the information environment in this conflict |
| **gCaptain** | Maritime intelligence | Best coverage of Hormuz closure, tanker attacks, insurance market signals |
| **ISIS (Institute for Science and International Security)** | Nuclear policy | Gold standard for post-strike nuclear facility BDA and enrichment program assessment |

---

## 12. Blue Team Threat Posture Recommendations

Based on the 96-hour intelligence picture, the following threat posture guidance applies to organizations in critical infrastructure, defense industrial base, government, financial services, and technology sectors:

**CRITICAL — Immediate Action:**
- Assume Iranian APT groups (MuddyWater, CyberAv3ngers, Handala) are operating at elevated tempo. Operation Olalampo is active and deploying novel malware families. Treat all Office macro-based phishing as potentially nation-state attributed until proven otherwise.
- OT/ICS operators: CyberAv3ngers' IOCONTROL malware targets a wide range of devices (Baicells, D-Link, Hikvision, Red Lion, Orpak, Phoenix Contact, Teltonika, Unitronics). Audit all internet-exposed OT/ICS devices against this list immediately.
- Iranian groups are using **AI-assisted malware development** (confirmed in Operation Olalampo context). Expect faster iteration on implant variants that evade signature-based detection.

**HIGH — Within 48 Hours:**
- The interceptor depletion constraint identified by Substack analysts (Day 3–4 inflection point) means **Iranian missile throughput against US and allied targets may increase** as interceptor magazines deplete. US-based organizations supporting DoD or defense contractors should review incident response plans.
- Saudi Arabia's reservation of the right to retaliate creates potential for **rapid regional expansion**. Organizations with Gulf operations should activate contingency plans.
- Houthi re-activation in the Red Sea + Hormuz closure creates energy price volatility. Financial sector and supply chain operators should model disruption scenarios.

**MEDIUM — Watch:**
- Iranian succession dynamics: A hardline successor with IRGC backing may escalate cyber operations as the primary remaining asymmetric tool. A pragmatist successor may seek negotiated pause — Trump's "will be talking" signal suggests this channel is open.
- The satellite broadcast hack (Badr satellite, January) and port system disruptions (Chabahar/Bandar Abbas) demonstrated Israeli capability to reach into Iranian infrastructure through non-internet vectors. Mirror threats exist in reverse — assess your satellite communications dependencies.
- Monitor IRGC Telegram for True Promise 4 wave announcements (7th and 8th waves confirmed by March 1; further waves assessed likely).

---

*Feed compiled from: CENTCOM press releases, USNI News, The War Zone, SOFREP, SOF News, Jerusalem Post, Times of Israel, Al Jazeera, Bloomberg, Reuters, Tasnim News Agency, IranMonitor.org, NetBlocks, Cloudflare Radar, GeoConfirmed, Bellingcat, gCaptain, ISIS Nuclear, CSIS, Atlantic Council, Stimson Center, CFR, Chatham House, Substack (sinosoviran, safehousebriefing, centeredamerica, tatsuikeda, geopoliticsunplugged, normanjansen, anniedance, tscsw), Reddit megathreads (r/worldnews, r/geopolitics, r/CredibleDefense, r/iran), Persian-language Telegram channel monitoring.*

*All content derived from open-source intelligence. No classified or proprietary data included. Sources cross-referenced where possible. Unverified claims are marked as such.*
