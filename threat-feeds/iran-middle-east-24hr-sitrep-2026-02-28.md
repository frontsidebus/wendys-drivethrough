---
feedId: iran-middle-east-sitrep-2026-02-28
title: Iran / Middle East 24-Hour Threat Intelligence SITREP
topic: nation-state
industry: critical-infrastructure
country: IR
severity: critical
tags: [iran, middle-east, sitrep, kinetic, hormuz, irgc, cyber-ops, proxy-forces]
summary: 24-hour SITREP for 2026-02-28 covering US-Israeli joint military strikes on Iran, Iranian retaliation, proxy force activation, Strait of Hormuz closure, and concurrent cyber operations.
---

# Iran / Middle East 24-Hour Threat Intelligence SITREP

**Classification:** OSINT -- Open Source Intelligence Only
**Period Covered:** 2026-02-28 00:00 UTC -- 2026-02-28 23:59 UTC
**Compiled:** 2026-02-28
**Threat Level:** CRITICAL -- Active kinetic and cyber conflict
**Focus:** US-Israeli joint military operation against Iran, Iranian retaliation, proxy force activation, cyber operations, and global cascading effects
**Intended Audience:** Blue team operators, CTI analysts, SOC analysts, incident responders, infrastructure security engineers
**Cross-Reference:** [US-Iran-Israel Cyber Threat Intelligence Feed](us-iran-israel-cyber-threat-feed.md) for standing APT profiles and baseline TTPs

---

## Table of Contents

1. [Executive Summary -- FLASH](#1-executive-summary--flash)
2. [Operation Epic Fury / Roaring Lion -- US-Israeli Strikes on Iran](#2-operation-epic-fury--roaring-lion--us-israeli-strikes-on-iran)
3. [Iranian Retaliatory Strikes](#3-iranian-retaliatory-strikes)
4. [Leadership Decapitation -- Khamenei Status](#4-leadership-decapitation--khamenei-status)
5. [Strait of Hormuz -- Effective Closure](#5-strait-of-hormuz--effective-closure)
6. [Cyber Operations](#6-cyber-operations)
7. [Proxy Force Activation](#7-proxy-force-activation)
8. [Nuclear Program Context](#8-nuclear-program-context)
9. [Diplomatic Collapse Timeline](#9-diplomatic-collapse-timeline)
10. [Sanctions and Economic Warfare](#10-sanctions-and-economic-warfare)
11. [Global Economic Impact](#11-global-economic-impact)
12. [International Reactions](#12-international-reactions)
13. [Iran Internal Situation](#13-iran-internal-situation)
14. [Gaza, West Bank, and Lebanon](#14-gaza-west-bank-and-lebanon)
15. [Key Indicators to Watch -- Next 24-72 Hours](#15-key-indicators-to-watch--next-24-72-hours)
16. [Sources and Collection Notes](#16-sources-and-collection-notes)

---

## 1. Executive Summary -- FLASH

On **28 February 2026**, the United States and Israel launched a joint military operation against Iran -- codenamed **Operation Epic Fury** (US) and **Operation Roaring Lion** (Israel). This is the most significant military escalation in the Middle East since the 2003 Iraq War.

**Critical developments in the last 24 hours:**

- **US-Israeli strikes hit 500+ targets across 28 regions of Iran** including Tehran, Isfahan, Qom, Karaj, Kermanshah, and nuclear facilities at Natanz, Fordow, and Isfahan. Approximately 200 IAF jets conducted the largest Israeli Air Force sortie in history. The US deployed 300+ aircraft.
- **Supreme Leader Ayatollah Ali Khamenei is reported killed.** The White House and President Trump confirmed the death. Israeli sources stated "99% certainty." **Iran's FM Araghchi stated Khamenei is "still alive as far as I know."** Status remains **DISPUTED**.
- **Confirmed killed:** IRGC Commander General Mohammad Pakpour, Defense Minister Amir Nasirzadeh, Armed Forces Chief of Staff Mohammad Bagheri, and advisor Ali Shamkhani.
- **Iran launched unprecedented retaliatory strikes** using ballistic missiles (including Fattah hypersonic missiles) and drones against Israel, and simultaneously against **all US military bases in the Persian Gulf** -- the first time in history Iran has struck US bases across the region simultaneously. Gulf states targeted: Bahrain, Kuwait, Qatar, UAE, Jordan, Saudi Arabia.
- **Iran effectively closed the Strait of Hormuz.** Ships received radio broadcasts from the Iranian Navy stating "no ship is allowed to pass." Oil tankers are actively avoiding the strait. This waterway carries ~20% of global oil consumption.
- **Israel launched the largest cyberattack in history** against Iran, reducing internet connectivity to 4% of normal levels and disabling IRGC communications infrastructure.
- **Iranian APT groups (MuddyWater, Handala, CyberAv3ngers)** are conducting active cyber operations against Israeli and Western targets despite Iran's own internet blackout.
- **Houthis announced resumption of Red Sea shipping attacks** in support of Iran, with strikes possible "as soon as tonight."
- **Iraqi Shia militias (Kataib Hezbollah)** declared imminent attacks on all US bases in Iraq. Two fighters killed at Jurf al-Sakher base.
- **Hezbollah raised alert levels** and declared the killing of Khamenei a "red line" -- a threshold now potentially crossed.
- **Saudi Arabia condemned Iranian strikes on its territory** (Riyadh and eastern region) and **reserved the right to retaliate**, potentially widening the conflict.

**CYBER THREAT POSTURE: US/Western organizations should assume ELEVATED THREAT from Iranian cyber actors. CISA, FBI, DC3, and NSA issued joint guidance warning of potential targeted cyber activity against US critical infrastructure. All organizations should review Iranian APT TTPs and ensure patching, MFA, and monitoring are current.**

---

## 2. Operation Epic Fury / Roaring Lion -- US-Israeli Strikes on Iran

### 2.1 Operation Parameters

| Attribute | Detail |
|---|---|
| **US Codename** | Operation Epic Fury |
| **Israeli Codename** | Operation Roaring Lion |
| **Start Time** | ~01:00 EST / 09:30 Tehran local, 28 February 2026 |
| **US Assets** | 300+ aircraft deployed to theater since January; ship-launched Tomahawk cruise missiles; USAF and USN fighter jets; first combat use of **LUCAS** (Low-cost Unmanned Combat Attack System) one-way attack drone (~500-mile range, 40-lb payload, ~$35,000/unit, reverse-engineered from Iran's Shahed-136) |
| **Israeli Assets** | ~200 IAF fighter jets (largest IAF sortie in history); air-launched munitions; 12 F-22s deployed to Ovda Airbase |
| **Target Count** | 500+ targets across 28 regions of Iran |
| **Accompanying Cyber** | Largest cyberattack in history (see Section 6) |
| **Congressional Auth** | Strikes launched **without Congressional approval**; deeply divided US lawmakers |

### 2.2 Confirmed Targets

| Target Category | Locations | Detail |
|---|---|---|
| **Supreme Leader Compound** | Tehran | Heavily damaged/destroyed per satellite imagery |
| **Ministry of Defense** | Tehran | Struck |
| **Ministry of Intelligence** | Tehran | Struck |
| **Atomic Energy HQ** | Tehran | Struck |
| **Judiciary Building** | Tehran | Struck |
| **Presidential Building** | Tehran | Struck |
| **Parchin Military Complex** | Tehran outskirts | Major military/nuclear research facility |
| **Nuclear Facilities** | Natanz, Fordow, Isfahan, Karaj, Qom | Enrichment and weapons research sites |
| **IRGC Command Hubs** | Multiple cities | Command and control infrastructure |
| **Missile/Drone Launch Sites** | Multiple locations | Short- and medium-range ballistic missile TELs and fixed silos (2,000+ targeted) |
| **Air Defense Systems** | Nationwide | Degraded prior to and during strikes |
| **Naval Infrastructure** | Bushehr | Port and naval facilities |

### 2.3 Confirmed Killed

| Individual | Position | Source |
|---|---|---|
| **Gen. Mohammad Pakpour** | IRGC Ground Forces Commander | Gulf News, Iran International (confirmed) |
| **Amir Nasirzadeh** | Defense Minister | Gulf News, Iran International (confirmed) |
| **Mohammad Bagheri** | Armed Forces Chief of Staff | Multiple sources (confirmed) |
| **Ali Shamkhani** | Senior Advisor / Former SNSC Secretary | Multiple sources (confirmed) |
| **Ayatollah Ali Khamenei** | Supreme Leader | White House confirmed; **Iran disputes** (see Section 4) |

### 2.4 Civilian Casualties (Reported)

| Claim | Detail | Verification |
|---|---|---|
| **Girls' school strike (Minab, Hormozgan)** | Iranian state media: 85-108 children killed | **Not independently verified** |
| **School east of Tehran** | At least 2 students killed | Reported by multiple Iranian sources |
| **Iranian Red Crescent totals** | 200+ killed across Iran | Iranian government figure |
| **HRANA (Iran)** | At least 133 civilians killed, 200+ injured | Human rights organization figure |

### 2.5 US Stated Objectives

1. Permanent end to all uranium enrichment
2. Strict limits on Iran's ballistic missile program
3. Complete halt to support for proxy groups (Hamas, Hezbollah, Houthis)
4. Trump explicitly called for regime change: "Freedom for Iran... seize control of your destiny"

---

## 3. Iranian Retaliatory Strikes

### 3.1 Scope

Iran launched an **unprecedented multi-axis retaliatory strike** using ballistic missiles (including **Fattah hypersonic missiles** in second wave), cruise missiles, and UAVs. This marks the **first time Iran simultaneously struck all US military bases in the Persian Gulf region**.

### 3.2 Targets and Impact

| Target | Country | Detail |
|---|---|---|
| **Al Udeid Air Base** | Qatar | Targeted by IRGC; largest US base in Middle East |
| **US Navy 5th Fleet HQ** | Bahrain | Direct strike attempted |
| **Ali al-Salem Air Base** | Kuwait | Ballistic missiles fired; shrapnel caused minor injuries to 3 Kuwaiti military; all missiles intercepted |
| **Kuwait International Airport** | Kuwait | Drone strike; minor injuries to employees; material damage to passenger terminal |
| **Al-Dhafra Air Base** | UAE | Iranian missiles intercepted; 1 Pakistani civilian killed by falling debris in Abu Dhabi |
| **Israel (Tel Aviv, Haifa, Northern Israel)** | Israel | 23 attack waves; 9 killed in Beit Shemesh; 121 injured; 1 9-story building damaged in north; defense systems intercepted missiles over Haifa |
| **US bases in Iraq** | Iraq | Erbil International Airport drone attack intercepted |
| **US bases in Jordan** | Jordan | Targeted; debris fell near houses in Amman |
| **US bases in Syria** | Syria | Targeted; Iranian missile debris struck residential building in Suwayda, killing 4 civilians |
| **Riyadh and Eastern Region** | Saudi Arabia | Saudi Arabia confirmed strikes on its territory; explosions heard in Riyadh |

### 3.3 Defense Performance

| Country | Detail |
|---|---|
| **UAE** | Intercepted **132 missiles** and **195 drones** |
| **Kuwait** | All incoming missiles intercepted by air defense |
| **Israel** | Multiple intercepts over Haifa; 90 casualties treated (mostly mild); 9 killed in Beit Shemesh |
| **Saudi Arabia** | Strikes partially intercepted; kingdom reserves right to retaliate |

### 3.4 IRGC Naval Actions

- IRGC Navy struck a **US MST (mobile sea terminal) ship** with a volley of missiles
- Six IRGC Navy gunboats attempted to stop/seize the US tanker *Stena Imperative* in the Strait of Hormuz earlier in February (February 3); tanker continued under USS McFaul escort
- Two foreign oil tankers seized near Farsi Island (February 5)

### 3.5 Airspace Closures

Bahrain, Iraq, Israel, Kuwait, Qatar, Syria, UAE, and Saudi Arabia all closed airspace. Approximately **14,000 flights affected**. Turkish Airlines suspended flights to 10 Middle East countries until at least March 2.

---

## 4. Leadership Decapitation -- Khamenei Status

| Source | Claim | Date |
|---|---|---|
| **President Trump** | Khamenei killed in Israeli airstrike | 28 Feb 2026 |
| **White House (official)** | Confirmed death of Supreme Leader | 28 Feb 2026 |
| **Israeli officials** | "99% certainty" Khamenei killed | 28 Feb 2026 |
| **FM Abbas Araghchi (Iran)** | "Still alive as far as I know" (NBC News) | 28 Feb 2026 |
| **Iranian semi-official media** | Khamenei "steadfast" and commanding the field | 28 Feb 2026 |

**Assessment:** Status remains **DISPUTED**. The destruction of the Supreme Leader's compound (confirmed via satellite imagery) is consistent with a targeted decapitation strike. Iran has strong incentive to deny the killing regardless of ground truth. Independent verification is not currently possible.

**Succession implications (if confirmed):**
- CIA had previously assessed that Khamenei's death could lead to direct **IRGC military rule**
- Iran declared **40 days of national mourning**
- IRGC command and control during potential leadership transition is unpredictable
- An IRGC commander has been placed in charge of MTN-Irancell (major telecom), consolidating military control over communications

---

## 5. Strait of Hormuz -- Effective Closure

| Attribute | Detail |
|---|---|
| **Status** | **Effectively closed** |
| **Method** | Ships received VHF radio broadcasts from Iranian Navy: "no ship is allowed to pass the Strait of Hormuz" |
| **Formal declaration** | No formal government announcement; semiofficial Iranian media described the strait as shut |
| **Commercial impact** | Oil tankers actively avoiding the strait; major trading houses suspended shipments |
| **Strategic significance** | Handles ~25% of global seaborne oil trade; ~20 million barrels/day (~20% of global oil consumption) |
| **US MARAD Advisory** | Active alert 2026-001A for Strait of Hormuz, Persian Gulf, Gulf of Oman, Arabian Sea -- valid through **7 March 2026** |
| **Houthi overlay** | Houthis simultaneously announced resumption of Red Sea attacks, creating dual chokepoint pressure (Hormuz + Bab el-Mandeb) |

**Oil price projections:**
- Pre-strike close: Brent $72.48/bbl (+2.45%), WTI $67.02/bbl (+2.78%)
- Analyst projections when markets open: **$5-7/bbl immediate jump**
- Sustained closure scenario: **$100+/bbl** plausible
- Full blockade scenario: **$120-130/bbl** (70%+ increase)

---

## 6. Cyber Operations

### 6.1 Israeli Offensive Cyber Operations (28 February)

| Attribute | Detail |
|---|---|
| **Description** | Described as the **largest cyberattack in history** |
| **Effect** | Iran's internet connectivity dropped to **4% of normal traffic** -- near-total blackout |
| **Methods** | Combined electronic warfare (disrupted navigation/comms), DDoS attacks, and deep intrusions into IRGC data systems |
| **Targets** | IRGC communications infrastructure; government digital services; local apps; official news sites; military coordination systems |
| **Objective** | Prevent IRGC coordination of counterattacks; disrupt ability to launch drones and ballistic missiles |
| **Preceding operation** | January 2026: government satellite broadcasts hacked; content calling for regime overthrow aired to millions of Iranian households |

### 6.2 US Offensive Cyber Operations

- The Record (Recorded Future News) reported the US used **cyber weapons to disrupt Iranian air defenses** during prior strikes, with similar capabilities assessed deployed on 28 February
- Defense One analysis: strikes on Iran "will test US cyber strategy abroad and defenses at home"

### 6.3 Iranian Offensive Cyber Operations

**CRITICAL FOR BLUE TEAMS: Iranian APT groups are conducting active offensive operations despite Iran's own internet blackout. These groups circumvented domestic internet restrictions to maintain offensive capability.**

| Actor | Activity | Detail |
|---|---|---|
| **MuddyWater (Earth Vetala / Mango Sandstorm)** | Active campaigns against Israeli companies and MENA organizations | **Operation Olalampo** (active since 26 January 2026): deploying new malware families -- **GhostFetch** (downloader), **GhostBackDoor** (implant), **CHAR** (Rust-based backdoor), **HTTP_VIP** (downloader). AI-assisted malware development noted. Spear-phishing with malicious Microsoft Office macros. **RustyWater RAT** targeting diplomatic, maritime, financial, and telecom entities. |
| **Handala (Iran-linked)** | Healthcare data breach | Infiltrated and released sensitive medical data of **10,000+ patients** from Clalit, Israel's largest healthcare network |
| **CyberAv3ngers (BAUXITE / IRGC-CEC)** | OT/ICS threat | Previously deployed **two custom wiper malware variants** against Israeli targets during June 2025 conflict. Deployed **IOCONTROL** malware targeting worldwide ICS/SCADA devices (Baicells, D-Link, Hikvision, Red Lion, Orpak, Phoenix Contact, Teltonika, Unitronics). Dragos 2026 OT Report flagged continued significant threat. US Rewards for Justice maintains active bounty. |
| **RedKitten** | Espionage campaign | January 2026 campaign targeting human rights NGOs and activists |
| **Unattributed Iranian actors** | Expected retaliation | DHS, CISA, and private sector on high alert for Iranian cyber retaliation against US critical infrastructure. Analysts warn Iran will deploy every available cyber capability. |

### 6.4 CISA/FBI/NSA Joint Guidance

- **CISA, FBI, DC3, and NSA** published joint fact sheet (January 2026): "Iranian Cyber Actors May Target Vulnerable US Networks and Entities of Interest"
- Defense Industrial Base companies with ties to Israeli research/defense firms flagged as at **increased risk**
- Highlighted Iranian TTPs: exploiting known unpatched vulnerabilities, compromising devices with default/weak passwords, collaborating with ransomware affiliates
- Recommended mitigations: strong passwords, MFA, proactive defensive measures, patching, network monitoring

### 6.5 MuddyWater -- New Malware Technical Details

| Malware | Type | Language | Detail |
|---|---|---|---|
| **GhostFetch** | Downloader | Unknown | Drops GhostBackDoor implant; part of Operation Olalampo |
| **GhostBackDoor** | Backdoor/Implant | Unknown | Persistent access; C2 communication |
| **CHAR** | Backdoor | Rust | New Rust-based backdoor; indicates MuddyWater tool modernization |
| **HTTP_VIP** | Downloader | Unknown | Additional downloader variant in Olalampo toolkit |
| **RustyWater RAT** | RAT | Rust | Spear-phishing delivery via malicious Office macros; targets diplomatic, maritime, financial, telecom entities |
| **IOCONTROL** | ICS malware | Unknown | Deployed by CyberAv3ngers; targets routers, PLCs, HMIs, firewalls, IP cameras from multiple vendors |

---

## 7. Proxy Force Activation

### 7.1 Houthis (Ansar Allah) -- Yemen

| Attribute | Detail |
|---|---|
| **Threat Level** | **IMMINENT ATTACK RESUMPTION** |
| **Declaration** | Two senior Houthi officials confirmed decision to resume missile and drone attacks on Red Sea shipping and Israel |
| **Timeline** | One official indicated strikes could commence "tonight" (28 February) |
| **Prior pause** | Attacks suspended after October 2025 Israel-Hamas ceasefire |
| **Capability** | Hundreds of thousands of fighters; advanced missile and drone systems supplied by Iran |
| **Impact** | Dual chokepoint pressure: Strait of Hormuz + Bab el-Mandeb simultaneously threatened |
| **UN action** | Resolution 2812 (2026) extended reporting on Houthi Red Sea attacks for 6 months |

### 7.2 Hezbollah -- Lebanon

| Attribute | Detail |
|---|---|
| **Threat Level** | **CONDITIONAL ESCALATION -- RED LINE CROSSED** |
| **Response** | Condemned "treacherous American-Israeli aggression"; stated "Iran doesn't need anyone to defend it" |
| **Red line** | Hezbollah defined attacks on Khamenei as a **"red line"** -- with Khamenei now reportedly killed, this threshold has been crossed |
| **Force strength** | 40,000-50,000 active combatants + 30,000-50,000 reservists |
| **Radwan Force** | Special operations unit for offensive operations against Israel; actively being rebuilt |
| **Recent Israeli strikes on Hezbollah** | 8 airstrikes on Radwan Force camps in Baalbek/Hermel (Feb 26); 3 missile commanders targeted (Feb 20); strikes as far north as Baalbek (Feb 16-22); al-Tuffah region struck (Feb 28) |
| **Disarmament** | Hezbollah Secretary-General Naim Qassem rejected disarmament (Feb 16); Unit 4400 continues weapons smuggling from Iran via Syria |
| **Since Nov 2024 ceasefire** | 300+ people killed in Lebanon including 127 civilians (UN figures) |

### 7.3 Iraqi Shia Militias

| Attribute | Detail |
|---|---|
| **Threat Level** | **ACTIVE HOSTILITIES -- IMMINENT ATTACKS DECLARED** |
| **Kataib Hezbollah** | Jurf al-Sakher base struck by US/Israeli forces: 2 fighters killed, 5 wounded. Statement issued: **"We will soon begin attacking American bases."** Declared "fateful battle" requiring no neutrality. Called to "drag the enemy into a long war of attrition." |
| **Al Nujaba Movement / Sayyed Al Shuhada** | Joined fight by attacking US troops; among 4 militias in Iraqi Resistance Coordination Committee that decided to provide military support to Iran and "open fronts" |
| **Iraqi militia deployments to Iran** | ~800 members of Shia militia groups sent to Iran; ~5,000 Iraqi Shia militants entered Iran to suppress domestic protests (as of January 9) |
| **Kataib Hezbollah threats to Kurdistan** | Feb 26: warned Kurdistan Region against cooperating with "hostile foreign forces"; threatened Kurdistan's "security and future" |
| **Assessment** | Former Iraqi official characterized these militias as "loose cannons, completely out of control" with younger leaders using aggression to prove loyalty to Iran |

### 7.4 Proxy Force Activation Summary

| Group | Status | Immediate Threat |
|---|---|---|
| **Houthis (Yemen)** | Attack resumption announced | Red Sea shipping attacks imminent; Israel strikes expected |
| **Hezbollah (Lebanon)** | Alert raised; red line crossed | Conditional response; Radwan Force rebuilding |
| **Kataib Hezbollah (Iraq)** | Active hostilities declared | Imminent attacks on US bases in Iraq |
| **Al Nujaba / Sayyed Al Shuhada (Iraq)** | Joined fight | Supporting attacks on US forces |
| **Hamas (Gaza)** | Fragile ceasefire holding | Rejected disarmament; monitoring situation |

---

## 8. Nuclear Program Context

### 8.1 Pre-Strike Status

| Attribute | Detail |
|---|---|
| **Enriched uranium stockpile** | ~400 kg at 60% enrichment (enough for weapons if further processed) |
| **Key facilities** | Natanz (reconstruction observed -- new roof over damaged pilot plant), Fordow (underground), Isfahan |
| **Post-June 2025 assessment** | DoD estimated nuclear program set back ~2 years by June 2025 Israeli strikes |
| **IAEA verification** | Cannot verify whether Iran has suspended enrichment-related activities; cannot confirm location/size/composition of stockpile |
| **Breakout timeline** | DIA assessed at least a decade for missiles capable of reaching the US; nuclear weapon assembly timeline unclear from OSINT |

### 8.2 Diplomatic Breakthrough -- Then Strikes

| Date | Event |
|---|---|
| **6 Feb 2026** | First round of indirect nuclear talks (Muscat, Oman); US sanctions on shadow fleet same day |
| **26-27 Feb 2026** | Third round of talks in Geneva; described as "longest, most serious" round |
| **27 Feb 2026** | Oman FM announced **breakthrough**: Iran agreed to never stockpile enriched uranium, full IAEA verification; "peace within reach" |
| **27 Feb 2026** | Trump said he was "not happy" with talks but would give negotiators more time |
| **28 Feb 2026** | Hours later: US-Israeli strikes launched |

---

## 9. Diplomatic Collapse Timeline

| Date | Event |
|---|---|
| Late Dec 2025 | Massive anti-government protests erupt across Iran (100+ cities) |
| 8-10 Jan 2026 | Deadliest crackdowns; est. 36,500 killed over weeks; internet blackout imposed |
| 13 Jan 2026 | Iranian officials warn they are "ready for war" |
| 25 Jan 2026 | Kataib Hezbollah calls fighters to prepare for war |
| 3 Feb 2026 | IRGC gunboats attempt to seize US tanker *Stena Imperative*; US F-35 shoots down Shahed-139 drone approaching USS Abraham Lincoln |
| 5 Feb 2026 | IRGC seizes two foreign oil tankers near Farsi Island |
| 6 Feb 2026 | First round indirect nuclear talks (Muscat); US sanctions on shadow fleet |
| Early Feb 2026 | USS Gerald R. Ford (2nd carrier) deployed to Middle East; largest US buildup since 2003 |
| 14 Feb 2026 | US officials tell Reuters military preparing for "weeks-long sustained operations" |
| 24 Feb 2026 | IRGC concludes "Combined 1404" military exercises on southern coasts |
| 25 Feb 2026 | Major US sanctions package (30+ targets); Russia agrees to sell Iran Verba air defense systems |
| 26-27 Feb 2026 | Third round nuclear talks in Geneva ("longest, most serious") |
| 27 Feb 2026 | Oman FM announces breakthrough -- Iran agrees to zero enriched uranium stockpile |
| 27 Feb 2026 | Trump: "I'd love not to attack Iran, but sometimes you have to" |
| 27 Feb 2026 | US formally designates Iran as state sponsor of wrongful detention |
| 28 Feb 2026, ~01:00 EST | US-Israeli strikes begin (Operation Epic Fury / Roaring Lion) |
| 28 Feb 2026, morning | Trump announces Khamenei killed; calls for regime change |
| 28 Feb 2026, daytime | Iran launches multi-axis retaliatory strikes across Gulf and against Israel |
| 28 Feb 2026 | Iran effectively closes Strait of Hormuz |
| 28 Feb 2026 | Houthis announce resumption of Red Sea attacks |
| 28 Feb 2026 | Iran declares 40 days of national mourning |
| 28 Feb 2026, midnight | UN Emergency Security Council meeting convened |

---

## 10. Sanctions and Economic Warfare

### 10.1 Recent US Sanctions Actions

| Date | Action | Detail |
|---|---|---|
| **25 Feb 2026** | OFAC/State Department | 30+ individuals, entities, and vessels sanctioned targeting shadow fleet, ballistic missile production, advanced conventional weapons procurement, illicit petroleum sales |
| **6 Feb 2026** | OFAC | 14 shadow fleet vessels; 15 entities trading Iranian crude; 2 associated individuals |
| **Feb 2026** | Treasury | 9 individuals and entities in Iran, Turkey, and UAE facilitating precursor chemicals and machinery for IRGC missile programs |
| **Feb 2026** | Treasury | Sanctions on Iranian regime officials for violent repression during protest crackdown |
| **Feb 2026** | Executive Order | Trump signed 25% tariff on Iran's trading partners |
| **2 Feb 2026** | UK | Sanctions under Iran regime targeting Iranian officials |

### 10.2 Sanctions Impact on Iranian Oil

- Iran's crude oil loadings fell to **below 1.39 million bpd** in January 2026 -- a **26% drop** year-over-year
- Chinese discharges of Iranian crude fell to **1.13 million bpd** (from 1.4 million average in 2025)
- China remains largest buyer: **80% of Iranian seaborne exports**
- Iran relying on "oil trustees" and shadow fleet to circumvent sanctions

---

## 11. Global Economic Impact

### 11.1 Energy Markets

| Metric | Detail |
|---|---|
| **Pre-strike oil prices (Fri close)** | Brent $72.48/bbl (+2.45%); WTI $67.02/bbl (+2.78%) |
| **Analyst projections (markets open Mon)** | Immediate $5-7/bbl jump; sustained closure: $100+/bbl; full blockade: $120-130/bbl |
| **Strait of Hormuz throughput** | ~20 million bbl/day (~20% of global oil demand) |
| **Red Sea overlay** | Houthi resumption creates dual chokepoint pressure |
| **Shipping response** | Major oil firms and trading houses suspended Strait of Hormuz shipments; at least 17 tankers attempted transit despite warnings |

### 11.2 Aviation

- **14,000+ flights affected** by Middle East airspace closures
- Israeli, UAE, Qatari, Iraqi, Kuwaiti, Bahraini, Syrian airspace closed
- Turkish Airlines suspended flights to 10 Middle East countries until at least March 2
- Dubai airports and major transit hubs severely disrupted

---

## 12. International Reactions

| Actor | Position |
|---|---|
| **UN Secretary-General Guterres** | Condemned "military escalation"; warned of "grave consequences for civilians and regional stability" |
| **UN Security Council** | Emergency midnight session convened 28 February |
| **France (Macron)** | Called for emergency UNSC session; advocated negotiations |
| **UK** | PM issued formal statement; E3 joint leaders' statement with France and Germany |
| **Saudi Arabia** | Condemned Iranian strikes "in strongest terms"; confirmed strikes on Riyadh/eastern region; **reserved right to retaliate** |
| **Turkey** | Opposes military intervention on Iran; suspended flights to 10 countries; evaluating measures |
| **Russia** | Verbal condemnation of US/Israel; no military support despite 20-year strategic partnership treaty |
| **China** | Called for "dialogue and restraint"; urged parties to "cherish peace" and stop "inciting confrontation"; no military support |
| **Pakistan** | Condemned the operation |
| **Iran FM Araghchi** | Accused Israel and US of violating UN Charter |
| **Egypt** | Condemned Iranian strikes on Arab nations |
| **UK, Canada, Australia** | Expressed support for US/Israeli action |

**Assessment:** Despite formal pacts (Iran-Russia 20-year strategic partnership; Iran-China-Russia trilateral pact signed January 29, 2026), neither Russia nor China has offered material military support. The "CRINK" axis (China, Russia, Iran, North Korea) has not activated meaningful collective defense mechanisms. Iran faces this conflict with proxy forces and its own capabilities, not great-power backing.

---

## 13. Iran Internal Situation

### 13.1 Protests and Crackdown (Pre-Strike Context)

| Attribute | Detail |
|---|---|
| **Protests** | Largest since 1979 revolution; 100+ cities; driven by economic crisis, rial collapse, rising prices (began late December 2025) |
| **Crackdown casualties** | IRGC and Basij forces killed est. **36,500 protesters** during January 2026 -- deadliest crackdown on civilians in modern Middle East history |
| **Arrests** | 51,790 people arrested (per HRANA, as of Feb 9) |
| **Executions** | At least 2,016 executions carried out in the current period |
| **Internet blackout** | Imposed 8 January 2026; 20+ day shutdown providing cover for killings; continued through 28 February strikes |
| **Human Rights Watch** | Documented "tsunami of arbitrary arrests, enforced disappearances"; situation described as "spiraling into deeper crisis" |

### 13.2 Weapons Supply

| System | Supplier | Detail |
|---|---|---|
| **Su-35 Fighter Jets** | Russia | 48 contracted; deliveries scheduled 2026-2028 |
| **Yak-130 Combat Trainers** | Russia | 1+ squadron delivered starting 2024 via An-124 flights |
| **Mi-28 Attack Helicopters** | Russia | Up to 6 delivered by January 2026 |
| **Verba MANPADS** | Russia | EUR 500M contract signed February 2026 |
| **Kamikaze drones, HQ-16 air defense** | China | Deliveries since summer 2025 |
| **CM-302 anti-ship missiles, DF-17 hypersonic** | China | Negotiations ongoing |

---

## 14. Gaza, West Bank, and Lebanon

### 14.1 Gaza

- **Cumulative casualties:** At least 75,227 killed (73,188+ Palestinians, 2,039+ Israelis)
- Phase 2 ceasefire commenced January 14, 2026; focused on demilitarization and reconstruction
- Since ceasefire: Israel killed at least **576 Palestinians**, wounded **1,543**
- Hamas rejected disarmament; rejected 60-day ultimatum (February 17)
- Israeli airstrikes during Ramadan killed at least 32 people including 7 children
- Israel ordered ban on **37 humanitarian agencies** (effective March 1); top court temporarily overrode ban (February 27)
- OHCHR raised **ethnic cleansing concerns** in Gaza and West Bank

### 14.2 West Bank

- **130+ raids** between January 20 and February 2; 3 Palestinians killed, 111 injured
- **Unprecedented settlement expansion** since December 2025 (Amnesty International)
- February 15: Israel signed plans for land registration across Area C (~60% of West Bank)
- **694 Palestinians displaced** since January 2026 (including ~350 children)
- **Nearly 20 countries** condemned "de facto annexation"

### 14.3 Lebanon

- Israeli air attacks in January 2026 were the **highest since November 2024 ceasefire** -- at least 50 air raids
- February 20: IDF struck Hamas command center in Ain al Hilweh refugee camp
- February 26: 8 airstrikes on Hezbollah Radwan Force camps
- February 28: Strikes on southern Lebanon simultaneous with Iran operation
- Israeli forces maintain **5 outposts** in southern Lebanon; have not fully withdrawn per ceasefire terms
- 300+ killed since ceasefire (127 civilians per UN figures)

---

## 15. Key Indicators to Watch -- Next 24-72 Hours

### 15.1 Kinetic

| Priority | Indicator |
|---|---|
| **CRITICAL** | Houthi missile/drone launches against Red Sea shipping or Israel -- officials stated "tonight" |
| **CRITICAL** | Kataib Hezbollah attacks on US bases in Iraq -- explicitly threatened "imminent" |
| **CRITICAL** | Strait of Hormuz status and oil market reaction when markets open Monday |
| **CRITICAL** | Confirmation or denial of Khamenei's death -- succession implications are profound |
| **HIGH** | Hezbollah military response -- Khamenei "red line" threshold reportedly crossed |
| **HIGH** | Additional Iranian retaliatory waves -- 23 attack waves hit Israel on 28 Feb; further escalation possible |
| **HIGH** | Saudi Arabia response -- reserved right to retaliate against Iran; potential widening |
| **HIGH** | Iran nuclear breakout indicators -- with 400 kg at 60% enrichment and facilities under attack, urgency increases |
| **MEDIUM** | Gulf state diplomatic realignment -- 5 Arab countries struck by Iranian missiles |
| **MEDIUM** | ISIS opportunistic attacks in Syria/Iraq exploiting power vacuum and chaos |

### 15.2 Cyber

| Priority | Indicator |
|---|---|
| **CRITICAL** | Iranian cyber retaliation against US critical infrastructure (water, energy, telecom, transportation) |
| **CRITICAL** | CyberAv3ngers / BAUXITE targeting OT/ICS systems globally |
| **CRITICAL** | MuddyWater Operation Olalampo expansion to Western targets |
| **HIGH** | Wiper malware deployment against Israeli or Western targets |
| **HIGH** | Ransomware attacks with Iranian nexus (APT groups collaborating with ransomware affiliates per CISA advisory) |
| **HIGH** | DDoS attacks against US government, financial, and defense sector websites |
| **MEDIUM** | Hacktivist activation (pro-Iran and pro-Israel groups) |
| **MEDIUM** | Disinformation campaigns exploiting fog of war (Khamenei status, civilian casualty claims) |

### 15.3 Recommended Defensive Actions

1. **Review and implement CISA Joint Advisory** on Iranian cyber actors targeting vulnerable US networks
2. **Verify patching status** for all internet-facing systems, particularly those with known Iranian APT exploitation (VPN appliances, Exchange, Fortinet, Citrix)
3. **Enable MFA** on all accounts; verify no default/weak passwords remain
4. **Monitor for MuddyWater IOCs** from Operation Olalampo (GhostFetch, CHAR, HTTP_VIP, RustyWater RAT)
5. **OT/ICS operators**: Review CyberAv3ngers / IOCONTROL indicators; monitor Dragos alerts
6. **Increase SOC monitoring cadence** to continuous during the current threat period
7. **Pre-position incident response** for potential wiper or destructive malware deployment
8. **Brief executive leadership** on elevated threat posture and potential business continuity impacts (energy prices, supply chain disruption, aviation)

---

## 16. Sources and Collection Notes

### 16.1 Primary Sources Consulted

| Source Category | Sources |
|---|---|
| **Wire Services / Major Media** | Reuters, AP, Bloomberg, Washington Post, NPR, CNN, CNBC, PBS, Al Jazeera, BBC |
| **Defense / Military** | Defense One, Military Times, USNI News, Stars and Stripes, War on the Rocks |
| **Regional Media** | Iran International, Gulf News, Al Arabiya, Arab News, Haaretz, Times of Israel, Anadolu Agency |
| **Government** | White House, State Department, Treasury/OFAC, CISA, US MARAD, UK PM Office, E3 Joint Statement, UN Security Council, UN Secretary-General |
| **Threat Intelligence** | Critical Threats (AEI), FDD Long War Journal, Atlantic Council, Alma Center (Israel), SOCRadar |
| **Cybersecurity** | The Hacker News, Dark Reading, GovInfoSecurity, Bloomberg Cybersecurity, The Record, Group-IB, Dragos, SentinelOne |
| **Think Tanks** | Brookings, RAND, Washington Institute, CFR, Responsible Statecraft, Carnegie |

### 16.2 Collection Limitations

- **Fog of war**: Active combat operations produce conflicting reports. Casualty figures, target damage assessments, and leadership kill claims may be revised.
- **Iranian internet blackout**: Ground truth from inside Iran is severely limited due to near-total internet blackout (4% connectivity).
- **Khamenei status**: Conflicting claims from US/Israel vs. Iranian government. Independent verification is not possible from OSINT sources at this time.
- **Civilian casualty claims**: Iranian state media claims (girls' school strike, 85-108 children killed) have not been independently verified.
- **Proxy force actions**: Declared intentions (Houthis, Kataib Hezbollah) may not translate to immediate action. Monitor for confirmed attacks vs. rhetoric.
- **Classification boundary**: This report is OSINT only. Classified intelligence assessments from IC agencies (DIA, CIA, NSA) may contain significantly different operational pictures.

### 16.3 Key URLs for Continuous Monitoring

| Source | URL |
|---|---|
| CISA Iran Advisories | `https://www.cisa.gov/topics/cyber-threats-and-advisories/advanced-persistent-threats/iran` |
| Critical Threats Daily Updates | `https://www.criticalthreats.org/analysis` |
| FDD Long War Journal | `https://www.longwarjournal.org/` |
| Al Jazeera Live Blog | `https://www.aljazeera.com/news/liveblog/` |
| US MARAD Advisories | `https://www.maritime.dot.gov/msci` |
| Dragos OT Threat Intel | `https://www.dragos.com/threat/` |
| The Hacker News | `https://thehackernews.com/` |
| Rewards for Justice (CyberAv3ngers) | `https://rewardsforjustice.net/rewards/cyberav3ngers/` |

---

*This document is OSINT only and does not contain classified or controlled information. It is compiled from open sources during an active, rapidly evolving conflict. All assessments reflect information available as of 2026-02-28 and are subject to revision as the situation develops. Casualty figures and damage assessments should be treated as preliminary. Validate all intelligence against multiple independent sources before taking action.*
