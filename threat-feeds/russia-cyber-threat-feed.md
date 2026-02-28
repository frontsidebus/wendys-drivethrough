# Russia Cyber Threat Intelligence Feed

**Classification:** OSINT -- Open Source Intelligence Only
**Initial Compilation:** 2026-02-28
**Last Validated:** 2026-02-28 (all feeds and URLs verified live)
**Baseline Knowledge:** Through May 2025 (see Intelligence Gaps section for coverage limitations)
**Focus:** Russian state-sponsored APT groups (SVR, GRU, FSB), Ukraine conflict cyber operations, critical infrastructure targeting, destructive malware
**Intended Audience:** Blue team operators, CTI analysts, SOC analysts, incident responders

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Russian APT Group Profiles](#2-russian-apt-group-profiles)
3. [Ukraine Conflict Cyber Operations](#3-ukraine-conflict-cyber-operations)
4. [Critical Infrastructure Targeting](#4-critical-infrastructure-targeting)
5. [Destructive Malware Arsenal](#5-destructive-malware-arsenal)
6. [Actively Exploited CVEs](#6-actively-exploited-cves)
7. [Cross-Vendor Naming Matrix](#7-cross-vendor-naming-matrix)
8. [MITRE ATT&CK Group Mappings](#8-mitre-attck-group-mappings)
9. [Key Russian TTPs Summary](#9-key-russian-ttps-summary)
10. [Government and Defense Intel Sources](#10-government-and-defense-intel-sources)
11. [Vetted Cybersecurity Research Blogs](#11-vetted-cybersecurity-research-blogs)
12. [Social Media and OSINT Feeds](#12-social-media-and-osint-feeds)
13. [OSINT Tools and Platforms](#13-osint-tools-and-platforms)
14. [IOC Sources and Threat Feeds](#14-ioc-sources-and-threat-feeds)
15. [RSS/Atom Feeds for Automated Ingestion](#15-rssatom-feeds-for-automated-ingestion)
16. [Intelligence Gaps and Collection Priorities](#16-intelligence-gaps-and-collection-priorities)

---

## 1. Executive Summary

Russian cyber operations represent the most mature and diversified state-sponsored cyber threat facing US, NATO, and Ukrainian interests. Russia maintains at least three distinct intelligence services with offensive cyber capabilities -- SVR, GRU, and FSB -- each with different mandates, targeting priorities, and operational tradecraft.

**Key assessments:**

- **The Russia-Ukraine conflict remains the defining driver of Russian cyber operations.** Since February 2022, Russian cyber groups have conducted the most sustained campaign of destructive cyber attacks against a single nation in history, deploying over a dozen distinct wiper malware families against Ukrainian targets alongside continuous espionage operations.
- **GRU operations are bifurcated between espionage (Unit 26165 / APT28) and destruction (Unit 74455 / Sandworm).** Sandworm remains the most dangerous Russian cyber actor, responsible for NotPetya, Industroyer, and multiple wiper campaigns against Ukraine. Ember Bear (Cadet Blizzard) represents an additional GRU destructive capability.
- **SVR (APT29 / Midnight Blizzard) has shifted toward cloud and identity infrastructure.** Post-SolarWinds, SVR operations increasingly target Microsoft 365 environments, Azure/Entra ID, and identity providers. The January 2024 compromise of Microsoft corporate email by Midnight Blizzard exemplifies this shift.
- **FSB groups span from sophisticated espionage (Turla/Secret Blizzard) to persistent harassment (Gamaredon/Aqua Blizzard) to credential phishing (Star Blizzard/COLDRIVER).** Turla has demonstrated the rare capability of hijacking other APT groups' infrastructure for its own operations.
- **Critical infrastructure pre-positioning is ongoing.** US and allied intelligence agencies have repeatedly warned about Russian access to energy, water, and transportation systems, particularly in NATO member states. Sandworm's demonstrated capability against power grids (Ukraine 2015, 2016, 2022) makes this an existential concern.
- **Russian groups are increasingly targeting edge devices and SOHO routers** for operational relay box (ORB) networks, complicating attribution and enabling persistent access to target networks.

### SVR vs GRU vs FSB Operational Distinctions

| Service | Primary Groups | Mandate | Operational Character |
|---|---|---|---|
| **SVR** (Foreign Intelligence Service) | APT29 / Midnight Blizzard | Foreign intelligence collection; political and strategic espionage | Patient, stealthy, long-dwell operations. Cloud-focused. Sophisticated supply chain attacks (SolarWinds). Targets governments, think tanks, tech companies. |
| **GRU** (Military Intelligence) | APT28 / Forest Blizzard (Unit 26165); Sandworm / Seashell Blizzard (Unit 74455); Ember Bear / Cadet Blizzard | Military intelligence; destructive operations; information warfare | Aggressive, high-tempo, dual espionage/destruction mandate. Willing to cause collateral damage (NotPetya). Election interference. Olympic disruption. |
| **FSB** (Federal Security Service) | Turla / Secret Blizzard (Center 16); Gamaredon / Aqua Blizzard; Star Blizzard / COLDRIVER (Center 18) | Domestic and near-abroad intelligence; counterintelligence | Ranges from highly sophisticated (Turla) to high-volume but lower sophistication (Gamaredon). Heavy Ukraine focus. Credential phishing of Western officials (Star Blizzard). |

---

## 2. Russian APT Group Profiles

### 2.1 APT28 / Fancy Bear / Forest Blizzard (GRU Unit 26165)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0007 |
| **Attribution** | GRU 85th Main Special Service Center (Unit 26165); multiple GRU officers indicted by US DOJ |
| **Microsoft** | Forest Blizzard (formerly Strontium) |
| **CrowdStrike** | Fancy Bear |
| **Mandiant** | APT28 |
| **Secureworks** | IRON TWILIGHT |
| **Primary Targets** | Government, military, defense, media -- US, NATO, Ukraine, European governments, OSCE, anti-doping agencies |
| **Key TTPs** | Credential harvesting via OAuth phishing; exploitation of Microsoft Outlook (CVE-2023-23397) for NTLM relay; EternalBlue exploitation; use of custom implants (Headlace, SkinnyBoy, Graphite); abuse of legitimate services for C2 (Microsoft Graph API, OneDrive, Dropbox); targeting of Ubiquiti EdgeRouters for ORB networks; exploitation of Cisco routers (Jaguar Tooth); VPN credential theft |
| **Key CVEs** | CVE-2023-23397 (Outlook NTLM relay -- **signature exploit**), CVE-2023-38831 (WinRAR), CVE-2023-35078 (Ivanti EPMM), CVE-2020-12641/12725/35730 (Roundcube), CVE-2022-30190 (Follina) |
| **Key Reporting** | Microsoft (Dec 2023): Forest Blizzard exploiting CVE-2023-23397; CISA AA24-249A: APT28 abuse of EdgeRouters; DOJ (Feb 2024): disruption of APT28 botnet on Ubiquiti routers; NSA/FBI/CISA joint advisories on brute force campaigns |

### 2.2 APT29 / Cozy Bear / Midnight Blizzard (SVR)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0016 |
| **Attribution** | SVR (Foreign Intelligence Service of Russia); US/UK joint attribution |
| **Microsoft** | Midnight Blizzard (formerly Nobelium) |
| **CrowdStrike** | Cozy Bear |
| **Mandiant** | APT29 |
| **Secureworks** | IRON RITUAL |
| **Primary Targets** | Government diplomatic entities, think tanks, technology companies (especially Microsoft and cloud providers), political organizations -- US, UK, EU, NATO members |
| **Key TTPs** | Supply chain compromise (SolarWinds SUNBURST); abuse of cloud trust relationships (Azure AD/Entra ID, Microsoft 365); OAuth application abuse; residential proxy and ORB networks for obfuscation; token theft; password spraying targeting legacy tenants without MFA; custom malware (MagicWeb, FoggyWeb, EnvyScout, WELLMESS, WISTFULCOLLECTOR); Teams-based phishing using compromised small-business tenants |
| **Critical Activity** | Jan 2024: Midnight Blizzard compromised Microsoft corporate email via password spray against legacy test tenant, then used access to exfiltrate emails from senior leadership and cybersecurity/legal staff. Accessed source code repositories. Microsoft SEC 8-K filing. |
| **Key CVEs** | CVE-2021-21148 (Chrome zero-day in campaigns), CVE-2021-1879 (Safari), exploitation of SolarWinds Orion (not formally CVE-based supply chain backdoor). APT29 relies more on identity/credential abuse than vulnerability exploitation. |
| **Key Reporting** | Microsoft (Jan/Mar 2024): Midnight Blizzard corporate compromise; CISA ED 24-02: emergency directive on Microsoft email exfiltration; Mandiant: APT29 cloud-focused tactics; UK NCSC joint advisory on SVR cloud targeting |

### 2.3 Sandworm / Voodoo Bear / Seashell Blizzard (GRU Unit 74455)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0034 |
| **Attribution** | GRU Main Center for Special Technologies (Unit 74455); six GRU officers indicted by US DOJ (Oct 2020) |
| **Microsoft** | Seashell Blizzard (formerly Iridium) |
| **CrowdStrike** | Voodoo Bear |
| **Mandiant** | Sandworm |
| **Secureworks** | IRON VIKING |
| **Dragos** | ELECTRUM |
| **Primary Targets** | Ukrainian critical infrastructure (energy, government, telecom, transport); global critical infrastructure; Olympic Games; elections |
| **Key TTPs** | Wiper malware deployment at scale (NotPetya, Industroyer/CrashOverride, HermeticWiper, CaddyWiper, SwiftSlicer, AcidPour); ICS/SCADA attacks (Industroyer, Industroyer2); supply chain compromise; living-off-the-land techniques; abuse of Active Directory Group Policy for malware distribution; custom CaddyWiper variants; ArguePatch loader; destructive attacks timed to kinetic military operations |
| **Critical Activity** | NotPetya (2017): $10B+ global damage. Industroyer (2016): Ukraine power grid attack. Industroyer2 (Apr 2022): attempted Ukraine power grid attack, disrupted by CERT-UA and ESET. AcidRain (Feb 2022): Viasat KA-SAT modem wiper on day of invasion. Ongoing wiper campaigns 2022-2025. |
| **Key CVEs** | CVE-2023-44221, CVE-2024-38178, CVE-2023-32315 (Openfire); less reliant on novel CVEs -- focuses on wiper deployment through obtained access |
| **Key Reporting** | DOJ (Oct 2020): indictment of six GRU officers; ESET/CERT-UA (Apr 2022): Industroyer2 disruption; Mandiant: Sandworm APT campaigns; CISA AA22-110A: Russian state-sponsored threats to critical infrastructure |

### 2.4 Turla / Venomous Bear / Secret Blizzard (FSB Center 16)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0010 |
| **Attribution** | FSB Center 16 (Signals Intelligence); one of the longest-operating Russian APT groups (active since at least 2004, possibly 1996 via Moonlight Maze) |
| **Microsoft** | Secret Blizzard (formerly Krypton) |
| **CrowdStrike** | Venomous Bear |
| **Mandiant** | Turla |
| **Secureworks** | IRON HUNTER |
| **Primary Targets** | Government, diplomatic, military, research -- worldwide, with focus on NATO, European governments, Central Asia |
| **Key TTPs** | Satellite internet hijacking for C2; Snake/Uroburos rootkit (premier implant, disrupted by FBI in May 2023); Kazuar backdoor; TinyTurla/TinyTurla-NG implants; Capibar and Kazuar deployment against Ukraine; **hijacking other threat actors' infrastructure** (documented use of Iranian APT34/OilRig C2 infrastructure and Pakistani APT Storm-0156 access); watering hole attacks; USB-based initial access via Andromeda malware infections; LightNeuron Exchange transport agent backdoor |
| **Critical Activity** | FBI Operation Medusa (May 2023): disrupted Snake malware peer-to-peer network across 50+ countries. Documented instances of hijacking Storm-0156 (Pakistani APT) Hak5 implant infrastructure and Iranian APT34 command-and-control servers to conduct espionage through other groups' access. |
| **Key CVEs** | Less reliant on novel exploitation; prefers access through other vectors including watering holes, USB propagation, and hijacking other groups |
| **Key Reporting** | CISA AA23-129A (May 2023): Snake malware technical analysis; Microsoft/Lumen (Dec 2024): Secret Blizzard hijacking other APT infrastructure; ESET: Turla backdoor analysis; Kaspersky: decades of Turla research |

### 2.5 Gamaredon / Shuckworm / Aqua Blizzard (FSB)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0047 |
| **Attribution** | FSB; operated from Crimea. SSU (Ukraine Security Service) identified five FSB officers by name (Nov 2021). Previously based in Sevastopol FSB office. |
| **Microsoft** | Aqua Blizzard (formerly Actinium) |
| **CrowdStrike** | Shuckworm |
| **Mandiant** | Gamaredon |
| **Secureworks** | -- |
| **Primary Targets** | Ukrainian government, military, law enforcement, NGOs -- near-exclusive Ukraine focus |
| **Key TTPs** | Extremely high operational tempo (thousands of attacks); spear-phishing with weaponized documents and HTML smuggling; custom VBS/PowerShell downloaders (Pterodo/Pteranodon family); USB propagation malware (LitterDrifter); abuse of Telegram for C2 IP resolution; fast-flux DNS infrastructure; GammaLoad and GammaSteel info-stealers; template injection; constant retooling of payloads to evade detection |
| **Key Reporting** | ESET (2024): Gamaredon campaign analysis; Symantec/Broadcom: Shuckworm campaigns targeting Ukraine military; CERT-UA: continuous reporting on Gamaredon activity (most tracked group in Ukraine); SSU (Nov 2021): public identification of FSB officers |

### 2.6 Star Blizzard / COLDRIVER / Callisto (FSB Center 18)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G1033 |
| **Attribution** | FSB Center 18 (Information Security Center); DOJ indictments and UK sanctions (Dec 2023) |
| **Microsoft** | Star Blizzard (formerly SEABORGIUM) |
| **CrowdStrike** | Gossamer Bear |
| **Mandiant** | COLDRIVER |
| **Secureworks** | COBALT ILLUSION is not associated -- Star Blizzard is tracked as TAG-53 by Recorded Future |
| **Primary Targets** | Think tanks, journalists, former intelligence officials, academics, NGOs, defense sector -- US, UK, NATO member states. Highly focused on credential theft from individuals with access to sensitive policy/intelligence information |
| **Key TTPs** | Persistent credential phishing campaigns; creation of elaborate fake personas impersonating researchers and journalists; use of Evilginx adversary-in-the-middle framework for session token theft and MFA bypass; ProtonMail-based lure infrastructure; targeting of personal email accounts (Gmail, Outlook, Yahoo) to bypass corporate security; extensive open-source research on targets before engagement; long cultivation of trust before delivering phishing links |
| **Key CVEs** | Not vulnerability-exploitation focused; purely social engineering and credential theft |
| **Key Reporting** | Microsoft (Aug 2022, Dec 2023): SEABORGIUM/Star Blizzard campaigns; DOJ (Dec 2023): domain seizures; UK NCSC: joint advisory; Google TAG: COLDRIVER credential phishing and SPICA backdoor; Citizen Lab: targeting of civil society |

### 2.7 Ember Bear / Cadet Blizzard / DEV-0586 (GRU)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G1003 |
| **Attribution** | GRU -- assessed as distinct from both APT28 and Sandworm; DOJ indictments (Sep 2024) of five GRU officers from Unit 29155 |
| **Microsoft** | Cadet Blizzard (formerly DEV-0586) |
| **CrowdStrike** | Ember Bear |
| **Secureworks** | -- |
| **Primary Targets** | Ukraine (primarily); NATO member states; Latin America; Central Asia |
| **Key TTPs** | WhisperGate wiper (Jan 2022, pre-invasion); web defacement; data theft and leak operations via "Free Civilian" hacktivist persona; exploitation of public-facing web servers (Confluence, Exchange); credential harvesting; living-off-the-land for lateral movement; destructive attacks designed to appear as ransomware but with no recovery mechanism |
| **Critical Activity** | WhisperGate (Jan 13-14, 2022): Deployed destructive wiper against Ukrainian government systems weeks before Russian invasion, disguised as ransomware. Accompanied by web defacements of Ukrainian government sites. |
| **Key CVEs** | CVE-2021-26084 (Confluence), CVE-2022-41040 (Exchange ProxyNotShell) |
| **Key Reporting** | Microsoft (Jun 2023): Cadet Blizzard profile; DOJ (Sep 2024): GRU Unit 29155 indictments; CISA AA24-249A |

### 2.8 Midnight Blizzard Subgroups / Nobelium Operational Clusters

| Attribute | Detail |
|---|---|
| **Parent** | APT29 / Midnight Blizzard (SVR) |
| **Microsoft Tracking** | Various Storm-XXXX designations for sub-clusters before consolidation under Midnight Blizzard |
| **Notable Sub-operations** | **SolarWinds cluster**: Supply chain compromise team responsible for SUNBURST/SUNSPOT/TEARDROP/RAINDROP (2020). **Cloud operations cluster**: Teams-based phishing, OAuth app abuse, tenant compromise (2023-2024). **Diplomatic targeting cluster**: EnvyScout HTML smuggling, ROOTSAW dropper, WINELOADER against European diplomats (2024). |
| **Key Malware** | SUNBURST, SUNSPOT, TEARDROP, RAINDROP, FoggyWeb, MagicWeb, EnvyScout/ROOTSAW, WINELOADER, GRAPELOADER, WELLMESS, WISTFULCOLLECTOR |
| **Key Reporting** | Mandiant: SolarWinds investigation; Microsoft: Midnight Blizzard corporate compromise; Zscaler: WINELOADER targeting German political parties; Google TAG: WINELOADER campaigns |

### 2.9 Energetic Bear / Dragonfly / Berserk Bear (FSB)

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0035 (Dragonfly) |
| **Attribution** | FSB; US DOJ indictments (2022) of FSB officers for Triton/Dragonfly campaigns |
| **Microsoft** | Bromine (legacy) |
| **CrowdStrike** | Berserk Bear / Energetic Bear |
| **Mandiant** | -- (tracked elements under various UNC groups) |
| **Secureworks** | IRON LIBERTY |
| **Dragos** | DYMALLOY, ALLANITE |
| **Primary Targets** | Energy sector (ICS/SCADA), nuclear facilities, water, aviation -- US, Europe, Turkey |
| **Key TTPs** | Supply chain compromise via ICS/SCADA vendor websites (watering holes); strategic web compromise; Havex RAT; targeting of OPC servers in ICS environments; credential harvesting from energy sector webmail and VPN portals; long-term persistent access to energy infrastructure |
| **Key Reporting** | CISA AA20-296A: Advanced APT targeting government and critical infrastructure; DHS/FBI TA18-074A: Russian government targeting energy networks; CISA ICS advisories on Havex/Dragonfly |

### 2.10 UAC-0050 / Storm-0978 / RomCom Group

| Attribute | Detail |
|---|---|
| **Attribution** | Assessed Russia-nexus; potential links to Russian cybercriminal ecosystem with state tasking |
| **Microsoft** | Storm-0978 (RomCom elements) |
| **CERT-UA** | UAC-0050 |
| **Primary Targets** | Ukraine government and military; NATO entities; Western governments supporting Ukraine |
| **Key TTPs** | RomCom RAT/backdoor; exploitation of CVE-2023-36884 (Office/Windows HTML RCE) via NATO Summit lures; Underground ransomware (dual espionage/criminal); phishing with weaponized documents themed around Ukraine/NATO topics; exploitation of Firefox (CVE-2024-9680) and Windows (CVE-2024-49039) zero-days in combination |
| **Key CVEs** | CVE-2023-36884 (Office/Windows), CVE-2024-9680 (Firefox use-after-free), CVE-2024-49039 (Windows Task Scheduler EoP) |
| **Key Reporting** | Microsoft (Jul 2023): Storm-0978 NATO Summit targeting; BlackBerry: RomCom campaigns; ESET (Nov 2024): RomCom Firefox/Windows zero-day chain |

### 2.11 Winter Vivern / UAC-0114 / TAG-70

| Attribute | Detail |
|---|---|
| **Attribution** | Assessed Russia-aligned (possible Belarusian nexus); targets consistent with Russian intelligence priorities |
| **CERT-UA** | UAC-0114 |
| **Recorded Future** | TAG-70 |
| **Primary Targets** | European governments, NATO-related organizations, Roundcube webmail users in government entities |
| **Key TTPs** | Exploitation of Roundcube XSS vulnerabilities (CVE-2023-5631) to steal email; phishing with government-themed lures; low-sophistication but persistent campaigns |
| **Key CVEs** | CVE-2023-5631 (Roundcube XSS) |
| **Key Reporting** | ESET: Winter Vivern Roundcube exploitation; Recorded Future: TAG-70 analysis |

---

## 3. Ukraine Conflict Cyber Operations

### 3.1 Timeline of Major Russian Cyber Operations Against Ukraine

| Date | Operation / Malware | Attribution | Target | Impact |
|---|---|---|---|---|
| **Dec 2015** | BlackEnergy / KillDisk | Sandworm (GRU Unit 74455) | Ukrainian power grid (three distribution companies) | First confirmed cyberattack causing power outage; ~230,000 customers affected for 1-6 hours |
| **Dec 2016** | Industroyer / CrashOverride | Sandworm | Ukrenergo (Ukrainian power transmission) | Automated ICS attack on power grid; brief outage in Kyiv |
| **Jun 2017** | NotPetya | Sandworm | Initially Ukraine (M.E.Doc supply chain); spread globally | $10B+ global damage; Maersk, Merck, FedEx/TNT among casualties. Most destructive cyberattack in history. |
| **Oct 2018** | VPNFilter | Sandworm | SOHO routers globally (500K+ devices) | Modular botnet with destructive capability; DOJ disrupted |
| **Jan 14, 2022** | WhisperGate | Cadet Blizzard (GRU Unit 29155) | Ukrainian government systems (MES, MFA, others) | Destructive wiper disguised as ransomware; deployed weeks before invasion; accompanied by web defacements |
| **Feb 23, 2022** | HermeticWiper + HermeticWizard + HermeticRansom | Sandworm | Ukrainian government, finance, IT | Deployed day before invasion; wiper with worm component and decoy ransomware |
| **Feb 24, 2022** | AcidRain | Sandworm (assessed) | Viasat KA-SAT modems | Bricked satellite modems across Europe on day of invasion; disrupted Ukrainian military communications; collateral impact on European wind farms |
| **Feb 24, 2022** | IsaacWiper + IsaacRansom | Sandworm | Ukrainian government networks | Second wiper deployed on day of invasion |
| **Feb 24, 2022** | FoxBlade (Microsoft designation) | Russia (specific group unclear) | Ukrainian systems | Targeted trojan for destructive operations; Microsoft detected and added signatures within hours |
| **Mar 2022** | CaddyWiper | Sandworm | Ukrainian energy sector, government | Deployed via Active Directory GPO; multiple variants throughout 2022 |
| **Mar 2022** | DoubleZero | Russia (CERT-UA attribution) | Ukrainian enterprises | .NET-based wiper |
| **Apr 2022** | Industroyer2 + CaddyWiper | Sandworm | Ukrainian energy provider (high-voltage substations) | Attempted power grid attack; **disrupted by CERT-UA and ESET before achieving impact**. Industroyer2 targeted ICS, CaddyWiper targeted IT systems for cover. |
| **May 2022** | ArguePatch + CaddyWiper | Sandworm | Ukrainian targets | Loader + wiper combination |
| **Oct 2022** | Prestige ransomware | Sandworm (assessed) | Polish and Ukrainian logistics/transport | Ransomware targeting Ukraine supply chain supporters |
| **Jan 2023** | SwiftSlicer | Sandworm | Ukrainian targets | New Go-based wiper deployed via Active Directory GPO |
| **Jan 2023** | SOLNTSEPEK operations | Sandworm (via hacktivist persona) | Kyivstar (Ukraine telecom) | Claimed destructive attack against Ukraine's largest mobile operator. Major disruption to civilian communications. |
| **Feb 2024** | AcidPour | Sandworm (assessed) | Linux/embedded systems (IoT, SCADA) | Enhanced variant of AcidRain; designed for broader embedded Linux targeting |
| **2022-2025** | Continuous campaigns | Gamaredon, APT28, Turla, Sandworm, Cadet Blizzard | Ukrainian government, military, critical infrastructure | Sustained espionage and destructive operations throughout the conflict |

### 3.2 Key Observations

- **Wiper tempo decreased after mid-2023** but did not stop. Russian groups shifted toward espionage and data theft rather than pure destruction, likely reflecting operational lessons and Ukrainian defensive improvements.
- **Hacktivist personas** (SOLNTSEPEK, CyberArmyofRussia_Reborn, XakNet) are used to claim destructive operations while providing deniability for GRU and FSB.
- **Coordination with kinetic operations** is documented: AcidRain/HermeticWiper deployment coincided with the February 24, 2022 invasion. Cyberattacks preceded or accompanied missile strikes against infrastructure.
- **Ukrainian defenses have been remarkably effective**. CERT-UA, with Western support (Microsoft, ESET, Google, CISA), has disrupted multiple significant operations including Industroyer2.
- **Collateral damage** from Russian cyber operations (NotPetya globally, AcidRain affecting European satellite users) remains a systemic risk.

---

## 4. Critical Infrastructure Targeting

### 4.1 US Energy Grid

- **Sandworm / Seashell Blizzard**: Demonstrated ICS attack capability against power grids (Industroyer 2016, Industroyer2 2022). The same tradecraft is transferable to US grid infrastructure.
- **Energetic Bear / Dragonfly**: DHS/FBI TA18-074A documented years-long campaign targeting US energy companies, including access to ICS/SCADA control rooms. Accessed human-machine interfaces (HMIs) for power generation systems.
- **Dragos tracks ELECTRUM (Sandworm), DYMALLOY, and ALLANITE** as active threats to the energy sector.
- **CISA Shields Up (2022-present)**: Persistent guidance to US critical infrastructure operators about Russian cyber threats, especially energy sector.

### 4.2 Water and Wastewater

- Russian hacktivist-aligned groups (CyberArmyofRussia_Reborn) claimed attacks on US water utilities in Texas (Jan 2024), manipulating SCADA systems at water treatment facilities.
- CISA/FBI/NSA joint advisory on Russian state-sponsored threats to water sector.
- While some attacks appear unsophisticated (targeting exposed HMIs), the precedent and potential for escalation are significant.

### 4.3 Transportation

- Prestige ransomware (Oct 2022) targeted Polish and Ukrainian transportation and logistics companies -- first Sandworm ransomware used against a NATO member state.
- Russian targeting of aviation and maritime systems in NATO states is assessed to be ongoing.

### 4.4 SolarWinds Supply Chain Compromise

- **APT29 / Midnight Blizzard** executed the SolarWinds supply chain attack (discovered Dec 2020), compromising SolarWinds Orion build system to insert SUNBURST backdoor into legitimate updates.
- Approximately 18,000 organizations downloaded compromised updates; confirmed targeted exploitation of ~100 organizations and 9 US government agencies.
- Victims included US Treasury, Commerce, DHS, State Department, NIH, and multiple private sector entities.
- Led to CISA Emergency Directive 21-01 and historic US government response.

### 4.5 Microsoft and Technology Company Targeting

- **Midnight Blizzard (Jan 2024)**: Compromised Microsoft corporate email via password spray against legacy test tenant. Accessed emails of senior leadership, cybersecurity, and legal staff. Subsequently accessed source code repositories. Microsoft filed SEC 8-K.
- **CISA Emergency Directive 24-02**: Ordered federal agencies to assess exposure from Microsoft email compromise.
- **APT29 repeatedly targets cloud and identity infrastructure** at technology companies to gain downstream access to their customers (government agencies, defense contractors).
- **HPE disclosure (Jan 2024)**: Hewlett Packard Enterprise disclosed that Midnight Blizzard accessed its cloud email environment.

### 4.6 NATO Targeting

- **APT28** has targeted NATO members, OSCE, and the Bundestag (German parliament, 2015).
- **Star Blizzard / COLDRIVER** targets government officials, former intelligence officers, and defense policy researchers across NATO states for credential theft.
- **Cadet Blizzard / Ember Bear** indictments (2024) included targeting of NATO member state transportation infrastructure.
- **WINELOADER campaigns (2024)**: APT29 targeted German political parties and European diplomats with wine-tasting-themed phishing lures delivering the WINELOADER backdoor.

---

## 5. Destructive Malware Arsenal

### 5.1 Russian Wiper and Destructive Malware

| Malware | Year | Attribution | Target | Characteristics |
|---|---|---|---|---|
| **BlackEnergy + KillDisk** | 2015 | Sandworm | Ukraine power grid | Modular framework; KillDisk component destroyed MBR and targeted ICS processes |
| **Industroyer / CrashOverride** | 2016 | Sandworm | Ukraine power grid | First malware specifically designed to attack electric grid ICS protocols (IEC 101, IEC 104, IEC 61850, OPC DA) |
| **NotPetya** | 2017 | Sandworm | Ukraine (spread globally) | Disguised as ransomware; EternalBlue + Mimikatz propagation; $10B+ global damage; supply chain via M.E.Doc |
| **Olympic Destroyer** | 2018 | Sandworm | 2018 PyeongChang Winter Olympics | Disrupted IT systems during opening ceremony; elaborate false flag attributions embedded in code |
| **VPNFilter** | 2018 | Sandworm | SOHO routers (500K+ devices) | Modular botnet with destructive kill switch; targeted network devices globally |
| **WhisperGate** | Jan 2022 | Cadet Blizzard | Ukrainian government | MBR wiper + file corruptor disguised as ransomware; no recovery mechanism |
| **HermeticWiper** | Feb 2022 | Sandworm | Ukrainian government, finance | Abused EaseUS Partition Master driver for disk destruction; deployed with HermeticWizard worm and HermeticRansom decoy |
| **IsaacWiper** | Feb 2022 | Sandworm | Ukrainian government | Simpler wiper; deployed on day of invasion alongside IsaacRansom |
| **AcidRain** | Feb 2022 | Sandworm (assessed) | Viasat KA-SAT modems | Targeted satellite modem firmware; MIPS-based wiper |
| **CaddyWiper** | Mar 2022+ | Sandworm | Ukrainian energy, government | Deployed via AD GPO; multiple variants; zero-filled disk destruction |
| **DoubleZero** | Mar 2022 | Russia (CERT-UA) | Ukrainian enterprises | .NET-based wiper targeting files and registry |
| **FoxBlade** | Feb 2022 | Russia | Ukrainian systems | Trojan with destructive capability; Microsoft named and blocked same day |
| **DesertBlade** | Mar 2022 | Russia | Ukrainian targets | Additional wiper variant detected in same period |
| **Industroyer2** | Apr 2022 | Sandworm | Ukrainian power grid | Streamlined version of Industroyer targeting IEC-104 protocol; **disrupted before achieving impact** |
| **ArguePatch** | 2022 | Sandworm | Ukrainian targets | Loader for CaddyWiper and other destructive payloads |
| **Prestige** | Oct 2022 | Sandworm (assessed) | Poland, Ukraine logistics | Ransomware targeting Ukraine supporters in NATO; first against NATO state |
| **RansomBoggs** | Nov 2022 | Sandworm | Ukrainian targets | .NET ransomware; Boris Yeltsin-themed; likely disruptive rather than financial |
| **SwiftSlicer** | Jan 2023 | Sandworm | Ukrainian targets | Go-based wiper deployed via AD GPO |
| **AcidPour** | Feb 2024 | Sandworm (assessed) | Linux/embedded targets | Enhanced AcidRain variant for broader embedded Linux/IoT targeting |

### 5.2 Destructive Capability Assessment

Russian destructive cyber capability is **unmatched globally**. No other state actor has deployed as many distinct destructive malware families or demonstrated the willingness to cause massive collateral damage (NotPetya). Key characteristics: ICS-specific attack capability (Industroyer/Industroyer2); rapid development cycle (the 2022 wiper barrage demonstrated production of numerous distinct tools in rapid succession); operational coordination with kinetic military operations; and willingness to accept collateral damage beyond intended targets.

---

## 6. Actively Exploited CVEs

| CVE | Product | Exploiting Group(s) | CISA KEV |
|---|---|---|---|
| CVE-2024-9680 | Mozilla Firefox (use-after-free) | RomCom / Storm-0978 | Yes |
| CVE-2024-49039 | Windows Task Scheduler (EoP) | RomCom / Storm-0978 | Yes |
| CVE-2024-38178 | Windows Scripting Engine | Seashell Blizzard | Yes |
| CVE-2023-23397 | Microsoft Outlook (NTLM relay) | APT28 / Forest Blizzard (**signature exploit**) | Yes |
| CVE-2023-38831 | WinRAR | APT28, APT29 | Yes |
| CVE-2023-36884 | Office/Windows HTML RCE | Storm-0978 / RomCom | Yes |
| CVE-2023-35078 | Ivanti EPMM (MobileIron) | APT28 | Yes |
| CVE-2023-5631 | Roundcube Webmail XSS | Winter Vivern | Yes |
| CVE-2023-42793 | JetBrains TeamCity | APT29 | Yes |
| CVE-2023-32315 | Openfire XMPP | Seashell Blizzard | Yes |
| CVE-2022-30190 | Microsoft MSDT (Follina) | APT28 | Yes |
| CVE-2022-41040 | Exchange (ProxyNotShell) | Cadet Blizzard | Yes |
| CVE-2021-26855 | Exchange (ProxyLogon) | Multiple Russian groups | Yes |
| CVE-2021-34527 | Windows Print Spooler (PrintNightmare) | APT28, Sandworm | Yes |
| CVE-2021-26084 | Atlassian Confluence | Cadet Blizzard | Yes |
| CVE-2020-12641/12725/35730 | Roundcube Webmail | APT28 | Yes |
| CVE-2020-0688 | Exchange Server | Multiple Russian groups | Yes |
| CVE-2019-10149 | Exim MTA | Sandworm | Yes |
| CVE-2018-13379 | Fortinet FortiOS SSL VPN | APT28, multiple | Yes |
| CVE-2017-6742 | Cisco IOS SNMP | APT28 (Jaguar Tooth) | Yes |
| CVE-2017-11882 | Microsoft Equation Editor | Gamaredon, APT28 | Yes |
| CVE-2017-0199 | Microsoft Office OLE | Gamaredon, APT28 | Yes |

**Pattern**: Russian APTs exploit a wide range of vulnerabilities spanning email servers (Exchange, Roundcube), VPN/edge appliances (Fortinet, Cisco, Ivanti), collaboration platforms (Confluence, TeamCity), and client-side applications (Outlook, Office, WinRAR, Firefox). APT28 is the most prolific vulnerability exploiter; SVR (APT29) relies more heavily on credential and identity abuse; Sandworm focuses on leveraging existing access for destructive deployment.

---

## 7. Cross-Vendor Naming Matrix

| MITRE | Microsoft | CrowdStrike | Mandiant | Secureworks | Dragos |
|---|---|---|---|---|---|
| APT28 / Sofacy | Forest Blizzard (Strontium) | Fancy Bear | APT28 | IRON TWILIGHT | -- |
| APT29 / The Dukes | Midnight Blizzard (Nobelium) | Cozy Bear | APT29 | IRON RITUAL | -- |
| Sandworm Team | Seashell Blizzard (Iridium) | Voodoo Bear | Sandworm | IRON VIKING | ELECTRUM |
| Turla / Snake | Secret Blizzard (Krypton) | Venomous Bear | Turla | IRON HUNTER | -- |
| Gamaredon | Aqua Blizzard (Actinium) | Shuckworm | -- | -- | -- |
| Callisto / COLDRIVER | Star Blizzard (SEABORGIUM) | Gossamer Bear | COLDRIVER | -- | -- |
| -- (GRU Unit 29155) | Cadet Blizzard (DEV-0586) | Ember Bear | -- | -- | -- |
| Dragonfly | Bromine (legacy) | Berserk Bear / Energetic Bear | -- | IRON LIBERTY | DYMALLOY / ALLANITE |
| -- | Storm-0978 | -- | -- | -- | -- |
| -- (Winter Vivern) | -- | -- | -- | -- | -- |

**Microsoft Taxonomy Key**: "Blizzard" = Russia-attributed. Weather phenomena are used for nation-state groups: Blizzard (Russia), Sandstorm (Iran), Typhoon (China), Sleet (North Korea), Hail (South Korea), Dust (Turkey), Rain (Lebanon).

---

## 8. MITRE ATT&CK Group Mappings

**Reference**: `https://attack.mitre.org/groups/`

| MITRE ID | Name | Key Aliases | Affiliation | Primary TTPs |
|---|---|---|---|---|
| G0007 | APT28 | Fancy Bear, Sofacy, Pawn Storm, Forest Blizzard, Strontium, IRON TWILIGHT | GRU Unit 26165 | T1566.002 Spearphishing Link, T1078 Valid Accounts, T1098 Account Manipulation, T1071.001 Web Protocols, T1003 OS Credential Dumping, T1114.002 Remote Email Collection |
| G0016 | APT29 | Cozy Bear, The Dukes, Midnight Blizzard, Nobelium, IRON RITUAL | SVR | T1195.002 Supply Chain (Software), T1078.004 Cloud Accounts, T1550.001 Application Access Token, T1098.003 Additional Cloud Roles, T1199 Trusted Relationship, T1071.001 Web Protocols |
| G0034 | Sandworm Team | Voodoo Bear, Seashell Blizzard, Iridium, IRON VIKING, ELECTRUM, Telebots | GRU Unit 74455 | T1561 Disk Wipe, T1485 Data Destruction, T1059.001 PowerShell, T1047 WMI, T1484.001 Group Policy Modification, T1071.001 Web Protocols |
| G0010 | Turla | Venomous Bear, Secret Blizzard, Krypton, IRON HUNTER, Snake, Uroburos, Waterbug | FSB Center 16 | T1071.001 Web Protocols, T1102 Web Service, T1090.003 Multi-hop Proxy, T1027 Obfuscated Files, T1005 Data from Local System, T1560 Archive Collected Data |
| G0047 | Gamaredon | Primitive Bear, Shuckworm, Aqua Blizzard, Actinium, Armageddon | FSB | T1566.001 Spearphishing Attachment, T1059.005 VBScript, T1059.001 PowerShell, T1091 Replication Through Removable Media, T1204.002 Malicious File, T1071.001 Web Protocols |
| G1033 | Star Blizzard | COLDRIVER, Callisto, SEABORGIUM, Gossamer Bear, TAG-53 | FSB Center 18 | T1566.002 Spearphishing Link, T1598.003 Spearphishing for Info, T1557 Adversary-in-the-Middle, T1539 Steal Web Session Cookie |
| G1003 | Ember Bear | Cadet Blizzard, DEV-0586, UNC2589 | GRU Unit 29155 | T1561 Disk Wipe, T1190 Exploit Public-Facing App, T1059.001 PowerShell, T1486 Data Encrypted for Impact |
| G0035 | Dragonfly | Energetic Bear, Berserk Bear, DYMALLOY, IRON LIBERTY, Crouching Yeti | FSB | T1189 Drive-by Compromise, T1195.002 Supply Chain, T1078 Valid Accounts, T1021.001 RDP, T1005 Data from Local System |

---

## 9. Key Russian TTPs Summary

### Initial Access
- **Phishing** (T1566): Credential harvesting via phishing links (APT28, Star Blizzard, APT29); spearphishing with weaponized documents (Gamaredon, Cadet Blizzard); Teams-based phishing from compromised tenants (Midnight Blizzard)
- **Exploit Public-Facing Application** (T1190): Exchange (ProxyLogon, ProxyNotShell), Confluence, Roundcube, Openfire, Outlook NTLM relay (CVE-2023-23397), Fortinet, Cisco, Ivanti
- **Supply Chain Compromise** (T1195.002): SolarWinds Orion (APT29), M.E.Doc (NotPetya/Sandworm), ICS vendor watering holes (Dragonfly)
- **Valid Accounts** (T1078): Password spray against cloud tenants (APT29); credential theft via AITM phishing (Star Blizzard); VPN credential harvesting (APT28)
- **Trusted Relationship** (T1199): Cloud service provider trust abuse (APT29)

### Execution
- **PowerShell** (T1059.001): Dominant across APT28, Gamaredon, Sandworm
- **Windows Management Instrumentation** (T1047): Sandworm, APT28 lateral movement
- **Command and Scripting Interpreter** (T1059): VBScript (Gamaredon), Python (Sandworm), Bash (AcidRain)

### Persistence
- **Account Manipulation** (T1098): OAuth app registration, additional cloud roles (APT29)
- **Scheduled Tasks** (T1053.005): APT28, Sandworm
- **Web Shells** (T1505.003): Cadet Blizzard, APT28
- **Boot or Logon Autostart** (T1547): Gamaredon registry modifications
- **Group Policy Modification** (T1484.001): Sandworm deploys wipers via AD GPO -- **signature TTP**

### Defense Evasion
- **Indicator Removal** (T1070): Sandworm, APT29
- **Obfuscated Files** (T1027): Universal across Russian groups
- **Masquerading** (T1036): Olympic Destroyer false flags; ransomware disguises for wipers
- **Use of Legitimate Cloud Services** (T1102): OneDrive, Google Drive, Dropbox, Notion (APT29, APT28)
- **Hijacking Other Groups' Infrastructure**: Turla hijacking Iranian and Pakistani APT infrastructure

### Credential Access
- **OS Credential Dumping** (T1003): Mimikatz use across all GRU groups
- **Brute Force / Password Spray** (T1110): APT28 mass campaigns; APT29 against legacy tenants
- **Adversary-in-the-Middle** (T1557): Evilginx framework (Star Blizzard, APT28)
- **Steal Web Session Cookie** (T1539): OAuth token theft (APT29)
- **NTLM Relay** (T1187): APT28 CVE-2023-23397 exploitation

### Lateral Movement
- **Remote Services** (T1021): RDP, SMB, WinRM
- **Group Policy** (T1484.001): Sandworm uses AD GPO to push wipers across enterprise networks

### Command and Control
- **Web Protocols** (T1071.001): HTTPS C2 universal
- **Web Service** (T1102): Microsoft Graph API, OneDrive, Dropbox, Telegram (Gamaredon for IP resolution)
- **Multi-hop Proxy** (T1090.003): Compromised EdgeRouters, SOHO devices, residential proxies (APT28, APT29)
- **DNS Tunneling** (T1071.004): Selective use by APT28, Sandworm
- **Protocol Tunneling** (T1572): SSH tunneling, VPN tunneling

### Collection and Exfiltration
- **Email Collection** (T1114): Targeting Exchange/Microsoft 365 mailboxes (APT29, APT28)
- **Data from Local System** (T1005): File system collection across all groups
- **Exfiltration Over C2 Channel** (T1041): Standard for most groups
- **Exfiltration to Cloud Storage** (T1567.002): APT29, APT28

### Impact
- **Disk Wipe** (T1561): Sandworm, Cadet Blizzard -- 15+ distinct wiper families
- **Data Destruction** (T1485): Universal in destructive operations
- **Data Encrypted for Impact** (T1486): Ransomware-disguised wipers (WhisperGate, Prestige)
- **Service Stop** (T1489): ICS/SCADA disruption (Industroyer)
- **Firmware Corruption** (T1495): AcidRain/AcidPour modem bricking

---

## 10. Government and Defense Intel Sources

### 10.1 US Government

| Source | URL | Description |
|---|---|---|
| **CISA Russia Threat Page** | `https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/russia` | Dedicated portal aggregating all Russia-related advisories |
| **CISA Advisories** | `https://www.cisa.gov/news-events/cybersecurity-advisories` | All cybersecurity advisories including joint Russia advisories |
| **CISA Shields Up** | `https://www.cisa.gov/shields-up` | Ongoing guidance for critical infrastructure defense against Russian threats |
| **CISA KEV Catalog** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | Tracks actively exploited vulnerabilities including those used by Russian APTs |
| **NSA Cybersecurity Advisories** | `https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/` | Co-signs joint advisories; publishes defensive guidance against Russian state TTPs |
| **FBI Cyber Division** | `https://www.fbi.gov/investigate/cyber` | FBI cyber threat warnings, joint advisories, and court-authorized disruption operations |
| **US-CERT** (now CISA) | `https://www.cisa.gov/news-events/alerts` | Alerts feed |
| **US Cyber Command** | `https://www.cybercom.mil/` | Malware sample releases (VirusTotal); "defend forward" operations against Russian infrastructure |

#### Key CISA Russia Advisories

| Advisory | Date | Subject |
|---|---|---|
| AA24-249A | Sep 2024 | Russian military cyber actors targeting US and global critical infrastructure |
| ED 24-02 | Apr 2024 | Emergency directive: mitigating Midnight Blizzard Microsoft email compromise |
| AA23-129A | May 2023 | Snake malware (Turla/FSB) -- technical analysis for network defenders |
| AA22-110A | Apr 2022 | Russian state-sponsored and criminal cyber threats to critical infrastructure |
| AA22-074A | Mar 2022 | Russian state-sponsored actors gain network access via default MFA and PrintNightmare |
| AA21-116A | Apr 2021 | Russian SVR targets US and allied networks (SolarWinds follow-up) |
| ED 21-01 | Dec 2020 | Emergency directive: mitigate SolarWinds Orion code compromise |

### 10.2 UK Government

| Source | URL | Description |
|---|---|---|
| **UK NCSC Russia Threat Guidance** | `https://www.ncsc.gov.uk/collection/russia` | Dedicated Russia threat collection |
| **UK NCSC Threat Reports** | `https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports` | Joint advisories with Five Eyes partners on Russian groups |
| **UK NCSC Advisories** | `https://www.ncsc.gov.uk/section/keep-up-to-date/advisories` | Technical advisories |

### 10.3 EU / NATO Entities

| Source | URL | Description |
|---|---|---|
| **EU CERT (CERT-EU)** | `https://cert.europa.eu/` | Serves EU institutions; publishes threat landscape reports covering Russian APTs |
| **NATO CCDCOE** | `https://ccdcoe.org/` | NATO Cooperative Cyber Defence Centre of Excellence (Tallinn, Estonia). Publishes research, Tallinn Manual on cyber conflict law, and threat assessments |
| **ENISA** | `https://www.enisa.europa.eu/` | EU Agency for Cybersecurity; annual threat landscape reports with Russia coverage |

### 10.4 Ukraine CERT

| Source | URL | Description |
|---|---|---|
| **CERT-UA** | `https://cert.gov.ua/` | **Critical source** -- Ukraine's CERT produces the highest volume of Russian APT reporting globally due to front-line exposure. UAC-numbered threat group tracking. Reports primarily in Ukrainian with some English translations. |
| **SSSCIP (State Service of Special Communications)** | `https://cip.gov.ua/en` | Ukraine's information protection service; parent organization of CERT-UA |

### 10.5 MITRE ATT&CK

| Resource | URL |
|---|---|
| **ATT&CK Groups** | `https://attack.mitre.org/groups/` |
| **ATT&CK Navigator** | `https://mitre-attack.github.io/attack-navigator/` |
| **ATT&CK for ICS** | `https://attack.mitre.org/techniques/ics/` |

---

## 11. Vetted Cybersecurity Research Blogs

### Tier 1 -- Primary Russian APT Research

| Source | Blog URL | RSS Feed | Russia Focus |
|---|---|---|---|
| **Microsoft Threat Intelligence** | `microsoft.com/en-us/security/blog/topic/threat-intelligence/` | `microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/` | Blizzard group tracking (Midnight, Forest, Seashell, Secret, Aqua, Star, Cadet). Microsoft is the single most important source for Russian APT reporting. |
| **Mandiant (Google Cloud)** | `cloud.google.com/blog/topics/threat-intelligence` | `cloudblog.withgoogle.com/topics/threat-intelligence/rss/` | APT28, APT29, Sandworm, COLDRIVER. M-Trends annual report. Definitive SolarWinds investigation. |
| **Google TAG** | `blog.google/threat-analysis-group/` | `blog.google/threat-analysis-group/rss/` | COLDRIVER/Star Blizzard campaigns; WINELOADER; APT29 targeting |
| **CrowdStrike** | `crowdstrike.com/en-us/blog/` | `crowdstrike.com/en-us/blog/feed` | BEAR taxonomy; Annual Global Threat Report with Russia section; Fancy Bear, Voodoo Bear, Cozy Bear, Venomous Bear |
| **ESET WeLiveSecurity** | `welivesecurity.com/en/` | `welivesecurity.com/en/rss/feed/` | **Essential for Ukraine conflict**. Partnered with CERT-UA. Industroyer2 disruption. Gamaredon, Sandworm wiper analysis. Turla backdoor research. |
| **Recorded Future Insikt Group** | `recordedfuture.com/blog` | `recordedfuture.com/feed` | Russia geopolitical-cyber nexus; TAG-XX tracking; BlueDelta (APT28) research |

### Tier 2 -- Strong Russian APT Coverage

| Source | Blog URL | RSS Feed | Russia Focus |
|---|---|---|---|
| **Unit 42 (Palo Alto)** | `unit42.paloaltonetworks.com/` | `unit42.paloaltonetworks.com/feed/` | APT28/APT29 campaign analysis; Cloaked Ursa tracking |
| **SentinelOne / SentinelLabs** | `sentinelone.com/labs/` | `sentinelone.com/labs/feed/` | Sandworm research; AcidRain/AcidPour analysis; SwiftSlicer; Russian wiper malware deep dives |
| **Symantec / Broadcom** | `symantec-enterprise-blogs.security.com/blogs/threat-intelligence` | `symantec-enterprise-blogs.security.com/blogs/threat-intelligence/rss` | Shuckworm (Gamaredon) tracking; Russian espionage campaigns |
| **Cisco Talos** | `blog.talosintelligence.com/` | `blog.talosintelligence.com/rss/` | Gamaredon analysis; infrastructure tracking |
| **Proofpoint** | `proofpoint.com/us/blog/threat-insight` | `proofpoint.com/us/rss.xml` | TA422 (APT28) campaign tracking; TA473 (Winter Vivern) |
| **Volexity** | `volexity.com/blog/` | `volexity.com/feed/` | Russian credential phishing; edge device exploitation |
| **Check Point Research** | `research.checkpoint.com/` | `research.checkpoint.com/feed/` | Russian APT campaign analysis |
| **Sophos X-Ops** (formerly Secureworks CTU) | `news.sophos.com/en-us/category/threat-research/` | -- | Inherits IRON taxonomy research from Secureworks acquisition. IRON TWILIGHT, IRON RITUAL, IRON VIKING coverage |

### Tier 3 -- Supporting / Specialist Coverage

| Source | Blog URL | RSS Feed | Russia Focus |
|---|---|---|---|
| **Dragos** | `dragos.com/blog/` | -- | ICS/SCADA focus; ELECTRUM (Sandworm), DYMALLOY, ALLANITE tracking. **RSS deprecated; monitor blog directly** |
| **Kaspersky SecureList** | `securelist.com/` | `securelist.com/feed/` | Decades of Turla, APT28, APT29 research. **Note: Russian-based vendor; operational since pre-sanctions. Cross-reference with Western sources. Subject to US government sales ban (2024).** |
| **Intel 471** | `intel471.com/blog/` | `intel471.com/blog/feed` | Russian cybercriminal ecosystem (overlaps with state operations); underground monitoring |
| **Citizen Lab** | `citizenlab.ca/` | `citizenlab.ca/feed/` | Star Blizzard/COLDRIVER targeting civil society; Russian surveillance and disinformation |

> **Removed (validated dead as of Feb 2026):**
> - **Secureworks** (`secureworks.com`) -- Acquired by Sophos; all URLs redirect. IRON taxonomy research now under Sophos X-Ops.
> - **Trellix** (`trellix.com`) -- Domain unreachable. Historical FireEye research now under Mandiant/Google Cloud.
> - **Binary Defense** (`binarydefense.com/feed/`) -- RSS 404. Limited primary Russian APT research.
> - **BlackBerry** -- Blog RSS redirects to restructured corporate site.
> - **RiskIQ/PassiveTotal** (`community.riskiq.com`) -- Dead. Absorbed into Microsoft Defender Threat Intelligence.
> - **InQuest Labs** (`labs.inquest.net`) -- Redirects to OPSWAT MetaDefender.
> - **SpiderFoot** (`spiderfoot.net`) -- Redirects to Intel 471.

---

## 12. Social Media and OSINT Feeds

### 12.1 X/Twitter -- Government and Official

| Account | Handle | Description |
|---|---|---|
| CISA | @CISAgov | Official alerts and advisories including Russia Shields Up |
| CISA Cyber | @CISACyber | Dedicated cybersecurity feed |
| NSA Cybersecurity | @NSACyber | Defensive guidance for Russian state-sponsored threats |
| FBI Cyber Division | @FBICyber | Cyber threat warnings and disruption announcements |
| US Cyber Command | @US_CYBERCOM | Russian malware sample releases to VirusTotal |
| UK NCSC | @ABORNCSC | UK National Cyber Security Centre |
| CERT-UA | @_CERT_UA | Ukraine CERT -- highest-volume Russian APT reporting globally |

### 12.2 X/Twitter -- Threat Intel Researchers

| Account | Handle | Focus |
|---|---|---|
| John Hultquist | @JohnHultquist | VP Mandiant/Google Threat Intel. Leading voice on Russian (especially Sandworm) cyber ops |
| Dmitri Alperovitch | @DAlperovitch | CrowdStrike co-founder. Russian cyber operations and geopolitical context |
| Juan Andres Guerrero-Saade | @juanandres_gs | SentinelLabs. Russian APT malware analysis (Turla, Sandworm) |
| Costin Raiu | @craiu | Former Kaspersky GReAT director. Decades of Russian APT tracking |
| Robert Lipovsky | @Robert_Lipovsky | ESET. Industroyer/Industroyer2 co-discoverer. Essential for Ukraine conflict cyber ops |
| Anton Cherepanov | @cheaborern | ESET. Industroyer/Industroyer2 research lead |
| Jake Williams | @MalwareJake | Former NSA TAO. Russian ops geopolitical and technical analysis |
| Kim Zetter | @KimZetter | Investigative journalist. SolarWinds, Russian critical infrastructure operations |
| Thomas Rid | @RidT | Johns Hopkins SAIS. Russian information operations, Active Measures expert |
| Andy Greenberg | @a_greenberg | WIRED. Author of "Sandworm" -- definitive book on GRU cyber operations |
| Catalin Cimpanu | @campuscodi | The Record. Breaking coverage of Russian APT campaigns |
| Rob Joyce | @RGB_Lights | Former NSA Cybersecurity Director. Russia cyber policy context |
| The Grugq | @thegrugq | Russian OPSEC, intelligence tradecraft, APT analysis |

### 12.3 X/Twitter -- Vendor and Institutional

| Account | Handle |
|---|---|
| Mandiant | @Mandiant |
| Microsoft Threat Intelligence | @MsftSecIntel |
| CrowdStrike | @CrowdStrike |
| Recorded Future | @RecordedFuture |
| ESET Research | @ESETresearch |
| SentinelOne | @SentinelOne |
| Intel471 | @Intel471Inc |
| Proofpoint Threat Insight | @threatinsight |
| CyberScoop | @CyberScoopNews |
| The Record | @TheRecord_Media |
| DarkReading | @DarkReading |

### 12.4 X/Twitter -- Hashtags to Monitor

```
#APT28  #APT29  #Sandworm  #Turla  #Gamaredon
#FancyBear  #CozyBear  #VoodooBear  #VenomousBear
#ForestBlizzard  #MidnightBlizzard  #SeashellBlizzard  #SecretBlizzard
#AquaBlizzard  #StarBlizzard  #CadetBlizzard
#UkraineCyber  #ShieldsUp  #SolarWinds  #NotPetya
#RussiaCyber  #GRUCYBER
#CTI  #ThreatIntel  #InfoSec
```

### 12.5 Reddit

| Subreddit | Description |
|---|---|
| r/cybersecurity | Largest general cybersec community. Russian APT news surfaces rapidly |
| r/netsec | Technical network security. APT campaign write-ups and analysis |
| r/threatintel | Dedicated CTI. Campaign tracking and IOC sharing |
| r/ReverseEngineering | Deep malware analysis. Russian tooling teardowns |
| r/OSINT | Open source intelligence techniques and Ukraine-focused OSINT |
| r/UkrainianConflict | Ukraine conflict context including cyber operations |
| r/geopolitics | Scholarly geopolitical analysis including Russia-NATO cyber dynamics |
| r/intelligence | Intelligence community news and analysis |
| r/CredibleDefense | Defense/security analysis with sourcing requirements |
| r/blueteamsec | Defensive security. Detection rules, YARA signatures for Russian malware |

### 12.6 YouTube Channels

| Channel | Description |
|---|---|
| SANS Institute | CTI Summit recordings. Regular Sandworm, APT28, APT29 content |
| Black Hat / DEF CON | Conference talks on Russian APT research and nation-state operations |
| Mandiant / Google Cloud Security | Russian APT webinars and presentations |
| CrowdStrike | BEAR group threat briefings |
| Recorded Future | Russia/Ukraine cyber conflict webinars |
| CISA | Shields Up briefings and defensive guidance |
| Darknet Diaries | Narrative episodes on Russian cyber operations (NotPetya, SolarWinds) |

### 12.7 Substack and Newsletters

| Newsletter | Description |
|---|---|
| **Risky Business News** (news.risky.biz) | Best daily CTI digest. Consistent Russia/Ukraine cyber coverage |
| **Kim Zetter's Zero Day** (zetter.substack.com) | Deep investigative journalism on Russian cyber operations |
| **Metacurity** (metacurity.substack.com) | Daily cybersecurity news briefing |
| **TLDR InfoSec / tl;dr sec** (tldrsec.com) | Curated security newsletter surfacing key threat reports |
| **The Cipher Brief** (thecipherbrief.com) | IC-adjacent analysis. Russian cyber from national security perspective |
| **Lawfare** (lawfaremedia.org) | Cyber policy including Russian cyber conflict legal frameworks |
| **War on the Rocks** (warontherocks.com) | Defense/security analysis. Russia military cyber doctrine |
| **CFR Net Politics** (cfr.org) | State-sponsored cyber ops tracking. Maintains Cyber Operations Tracker |

### 12.8 Mastodon / Fediverse

| Instance | Description |
|---|---|
| **infosec.exchange** | Primary infosec Mastodon instance. Many CTI analysts migrated here |
| **ioc.exchange** | IOC and threat intelligence sharing |
| **hackyderm.io** | Strong security researcher presence |

### 12.9 Telegram

| Channel | Description |
|---|---|
| **vx-underground** | Premier malware research community. Russian APT samples shared |
| **S.O.V.A.** | Threat intelligence sharing |
| **CERT-UA (official channel)** | Direct alerts from Ukraine CERT. **Essential for Russia tracking.** |
| **CyberBoroshno** | Ukrainian cyber volunteer community. OSINT and threat intel |
| **IT Army of Ukraine (official)** | Ukrainian government-endorsed cyber operations coordination |

**OPSEC WARNING**: Exercise extreme caution with Telegram channels, especially those linked to Russian hacktivist groups (SOLNTSEPEK, CyberArmyofRussia_Reborn, XakNet, KillNet). Use isolated devices, VPNs, and burner accounts. Do not interact with content. These channels carry surveillance and exploitation risk.

### 12.10 Streaming and Video Platforms

| Platform | Channel | Description |
|---|---|---|
| **Twitch** | DEF CON (`defcon`) | Live conference streams; nation-state cyber operations talks |
| **Twitch** | Black Hat Events (`blackhatevents`) | Live conference streams and briefings |
| **Kick** | -- | No CTI presence as of February 2026 |

For conference talk archives, see YouTube channels in Section 12.6. Twitch streams are ephemeral -- VODs typically available for 14-60 days after broadcast.

---

## 13. OSINT Tools and Platforms

### 13.1 Malware Analysis and Pivoting

| Tool | URL | Russia CTI Use Case |
|---|---|---|
| **VirusTotal** | `virustotal.com` | Russian malware hash search. VT Graph for infrastructure mapping. **USCYBERCOM uploads Russian APT samples here.** VT Intelligence for YARA hunting. |
| **Hybrid Analysis** | `hybrid-analysis.com` | CrowdStrike Falcon Sandbox. Free analysis of suspected Russian APT samples |
| **ANY.RUN** | `any.run` | Interactive sandbox. Behavioral analysis. **Note: ANY.RUN is a Russia-origin company that relocated to the UAE. Exercise discretion with sensitive samples.** |
| **Joe Sandbox** | `joesandbox.com` | Deep behavioral analysis reports |
| **OPSWAT MetaDefender** (formerly InQuest Labs) | `metadefender.opswat.com` | Document/file analysis. InQuest acquired by OPSWAT. |
| **Malpedia** | `malpedia.caad.fkie.fraunhofer.de` | Malware family encyclopedia with Russian APT associations. Maintained by Fraunhofer FKIE. |

### 13.2 Infrastructure Reconnaissance

| Tool | URL | Russia CTI Use Case |
|---|---|---|
| **Shodan** | `shodan.io` | Track Russian C2 infrastructure. Monitor exposed edge devices (EdgeRouters, Cisco routers). Identify Sandworm infrastructure patterns. |
| **Censys** | `search.censys.io` | SSL certificate tracking for Russian APT infrastructure. Certificate transparency monitoring. |
| **GreyNoise** | `greynoise.io` | Distinguish targeted Russian attacks from mass scanning. Russian reconnaissance pattern analysis. |
| **Microsoft Defender Threat Intelligence** | `learn.microsoft.com/en-us/defender/threat-intelligence/` | Replaced RiskIQ/PassiveTotal. Passive DNS, WHOIS history, threat analytics. Map Russian domain infrastructure. |
| **DomainTools** | `domaintools.com` | WHOIS intelligence. Russian domain registration patterns. |
| **SecurityTrails** | `securitytrails.com` | Historical DNS data. Infrastructure pivoting. |
| **Pulsedive** | `pulsedive.com` | Free threat intel with community-enriched IOCs |
| **AbuseIPDB** | `abuseipdb.com` | IP reputation for Russian scanning/attack infrastructure |

### 13.3 Russia-Specific OSINT Tools

| Tool | URL | Use Case |
|---|---|---|
| **Bellingcat Investigation Toolkit** | `bellingcat.com/category/resources/` | Pioneered open-source attribution of GRU/FSB activities |
| **Liveuamap** | `liveuamap.com` | Real-time mapping of Ukraine conflict including cyber incidents |
| **RIPE NCC** | `ripe.net` | European IP allocation database. Russian ASN and IP block tracking |

### 13.4 Detection Engineering

| Tool | URL | Use Case |
|---|---|---|
| **YARA** | `github.com/virustotal/yara` | Pattern matching for Russian APT malware. Extensive public rulesets for Sandworm wipers, APT28/29 tools |
| **Sigma** | `github.com/SigmaHQ/sigma` | Generic SIEM signatures. Community rules for Russian APT TTPs (GPO abuse, NTLM relay, credential dumping) |
| **Suricata / ET Rules** | `rules.emergingthreats.net` | Network detection for known Russian APT C2 patterns |

### 13.5 CTI Platforms and Aggregation

| Tool | URL | Use Case |
|---|---|---|
| **OpenCTI** (by Filigran) | `github.com/OpenCTI-Platform/opencti` | Open source CTI platform. STIX/TAXII compatible. Company rebranded to Filigran (`filigran.io`) |
| **MISP** | `misp-project.org` | Threat sharing platform. Multiple Russian APT community feeds. CERT-UA shares via MISP. |
| **Maltego** | `maltego.com` | Link analysis and visualization for Russian APT infrastructure mapping |
| **Intel 471 OSINT** (formerly SpiderFoot) | `intel471.com` | OSINT automation. SpiderFoot acquired by Intel 471. |

### 13.6 Key Russian ASN Space

| ASN | Organization |
|---|---|
| AS12389 | Rostelecom (major ISP/backbone) |
| AS8402 | VEON / Beeline (mobile operator) |
| AS25513 | PJSC MTS (mobile operator) |
| AS31133 | PJSC MegaFon (mobile operator) |
| AS13238 | Yandex |
| AS197695 | REG.RU (domain registrar) |

**Caveat**: Russian APTs overwhelmingly use non-Russian infrastructure (compromised SOHO routers, cloud services, residential proxies, VPN providers) for operations. APT28's Ubiquiti EdgeRouter botnet and APT29's residential proxy use specifically evade geographic attribution. ASN monitoring is supplementary, not definitive.

---

## 14. IOC Sources and Threat Feeds

### 14.1 AlienVault OTX

| Resource | URL |
|---|---|
| Portal | `https://otx.alienvault.com/` |
| API | `https://otx.alienvault.com/api` |
| Russia Search | `https://otx.alienvault.com/browse/global/pulses?q=russia` |

**Search terms for Russian pulses**: APT28, APT29, Sandworm, Turla, Gamaredon, Fancy Bear, Cozy Bear, Forest Blizzard, Midnight Blizzard, Seashell Blizzard, HermeticWiper, WhisperGate, CaddyWiper, NotPetya, COLDRIVER, Star Blizzard, Russia

### 14.2 Abuse.ch Ecosystem

| Feed | URL | Relevant Tags |
|---|---|---|
| **URLhaus** | `https://urlhaus.abuse.ch/` | Russian APT phishing URLs and payload delivery |
| **MalwareBazaar** | `https://bazaar.abuse.ch/` | Tags: Sandworm, HermeticWiper, CaddyWiper, WhisperGate, Industroyer, Graphite, Headlace, Pterodo, GammaLoad, SUNBURST, Snake, Kazuar, AcidRain |
| **ThreatFox** | `https://threatfox.abuse.ch/` | Russian APT IOCs (IPs, domains, hashes) |

### 14.3 MISP Feeds

| Feed | URL |
|---|---|
| CIRCL OSINT | `https://www.circl.lu/doc/misp/feed-osint/` |
| Botvrij.eu | `https://www.botvrij.eu/data/feed-osint/` |
| Default feeds list | `https://www.misp-project.org/feeds/` |

**Relevant MISP galaxy tags**: `misp-galaxy:threat-actor="APT28"`, `"APT29"`, `"Sandworm"`, `"Turla"`, `"Gamaredon"`, `"COLDRIVER"`, `"Ember Bear"`. CERT-UA also shares via MISP community partnerships.

### 14.4 Other IOC Sources

| Source | URL |
|---|---|
| **CISA KEV** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` |
| **IBM X-Force Exchange** | `https://exchange.xforce.ibmcloud.com` |
| **OpenCTI** (by Filigran) | `https://github.com/OpenCTI-Platform/opencti` |
| **MalTrail** | `https://github.com/stamparm/maltrail` |
| **YARA Rules Repo** | `https://github.com/Yara-Rules/rules` |
| **CFR Cyber Ops Tracker** | `https://cfr.org/cyber-operations` |
| **USCYBERCOM VirusTotal** | `https://www.virustotal.com/en/user/CYBERCOM_Malware_Alert/` |

---

## 15. RSS/Atom Feeds for Automated Ingestion

### Government / Institutional

```
CISA KEV JSON:          https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
UK NCSC Reports:        https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml
UK NCSC All:            https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml
CERT-EU:                https://cert.europa.eu/publications/security-advisories/rss
```

> **Note (Feb 2026):** CISA RSS feeds (`all.xml`, `ics-advisories.xml`) return 403 -- deprecated.
> NSA RSS feed also returns 403. Monitor CISA advisories page directly and use the KEV JSON API for automated ingestion.
> CISA KEV JSON is actively maintained.

### Vendor Research Blogs (VALIDATED LIVE)

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
> - Secureworks (`secureworks.com/rss`) -- Redirects to Sophos. Acquired.
> - Trellix (`trellix.com/blogs/research/rss/`) -- Domain unreachable.
> - Binary Defense (`binarydefense.com/feed/`) -- 404.
> - BlackBerry (`blogs.blackberry.com/en/feed`) -- Redirects to restructured corporate site.
> - Dragos (`dragos.com/feed/`) -- 404; RSS deprecated. Monitor blog directly.
> - CISA RSS feeds (`all.xml` etc.) -- 403, deprecated.
> - NSA RSS -- 403.
> - RiskIQ/PassiveTotal (`community.riskiq.com`) -- Dead. Use Microsoft Defender TI.
> - InQuest Labs (`labs.inquest.net`) -- Redirects to OPSWAT.
> - SpiderFoot (`spiderfoot.net`) -- Redirects to Intel 471.

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
| **Tier 1 (Critical)** | CISA advisories, CISA KEV, CERT-UA, Microsoft/Mandiant/CrowdStrike/ESET blogs | Real-time / hourly |
| **Tier 2 (High)** | Abuse.ch feeds, OTX pulses, MISP feeds, SentinelLabs, Recorded Future | Daily |
| **Tier 3 (Standard)** | MITRE ATT&CK updates, Malpedia, full vendor blog reviews | Weekly |
| **Tier 4 (Enrichment)** | VirusTotal, Shodan, Censys for infrastructure pivoting | As-needed |

---

## 16. Intelligence Gaps and Collection Priorities

> **Automation Note**: The `automation/scrape_social_feeds.py` and `automation/fetch_rss_feeds.py` scripts both enforce a 90-day lookback window by default. Run `python scrape_social_feeds.py --filter russia` and `python fetch_rss_feeds.py --filter russia` to pull the latest Russia-tagged intelligence from all configured social media, video, and vendor RSS sources. This should be your first step when triaging the gaps below.

### Coverage Gap: June 2025 -- February 2026

This feed's baseline knowledge extends through May 2025. The following areas require immediate live intelligence collection:

| Gap | Where to Look |
|---|---|
| **Post-May 2025 CISA advisories** | `cisa.gov/news-events/cybersecurity-advisories` -- filter for Russia |
| **New Microsoft Blizzard reporting** | `microsoft.com/en-us/security/blog` -- search Blizzard groups |
| **CERT-UA latest advisories** | `cert.gov.ua` -- highest volume of fresh Russian APT reporting |
| **ESET Ukraine research** | `welivesecurity.com` -- partnered with CERT-UA for Sandworm/Gamaredon |
| **New CVE exploitation** | CISA KEV catalog filtered for recent additions |
| **Ukraine conflict trajectory** | Any ceasefire, escalation, or territorial changes affecting Russian cyber tempo |
| **New wiper/destructive malware** | Given the 2022-2023 development pace, additional tools are likely |
| **Midnight Blizzard post-Microsoft activity** | Follow-on operations using access/intelligence from Jan 2024 compromise |
| **Dragos Year in Review 2026** | Published annually (usually February) -- critical for ICS/OT threat data |
| **CrowdStrike Global Threat Report 2026** | Published annually (usually February) -- updated Russia BEAR data |
| **Mandiant M-Trends 2026** | Annual report -- Russian APT landscape assessment |

### Priority Collection Requirements

1. **Has Sandworm developed new ICS-targeting capabilities beyond Industroyer2?** The gap between Industroyer2 (April 2022) and present represents significant potential development time.
2. **What is the status of APT29/Midnight Blizzard cloud operations post-Microsoft compromise?** The access gained to source code and email could enable novel attack vectors.
3. **Has Ember Bear / Cadet Blizzard (GRU Unit 29155) expanded operations following the September 2024 indictments?**
4. **Are Russian groups pre-positioning in US/NATO critical infrastructure for potential escalation?** Any new CISA Shields Up guidance or classified briefings becoming public.
5. **What new CVEs are Russian groups exploiting in the June 2025 -- Feb 2026 window?** Especially edge devices and cloud infrastructure.
6. **Has Russian cyber operational tempo in Ukraine changed with any shift in the kinetic conflict?**
7. **Are Turla's techniques of hijacking other APT groups' infrastructure expanding to additional groups?** The documented hijacking of Pakistani and Iranian infrastructure suggests a broader strategy.
8. **What is the current status of Russian hacktivist proxy groups (SOLNTSEPEK, CyberArmyofRussia_Reborn)?** Are they still active and what is their relationship to GRU/FSB?

---

*This document is a living reference. Review and update quarterly at minimum, or immediately following significant geopolitical escalation (ceasefire, territorial changes, NATO-Russia incidents). All content is derived from open-source intelligence. Validate IOCs against multiple independent sources before taking blocking actions. Given the pace of Russian cyber operations, CERT-UA and Microsoft reporting should be monitored on a daily basis.*
