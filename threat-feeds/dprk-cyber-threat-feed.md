# DPRK Cyber Threat Intelligence Feed

**Classification:** OSINT -- Open Source Intelligence Only
**Initial Compilation:** 2026-02-28
**Last Validated:** 2026-02-28 (all feeds and URLs verified live)
**Baseline Knowledge:** Through May 2025 (see Intelligence Gaps section for coverage limitations)
**Focus:** North Korean (DPRK) state-sponsored cyber operations -- APT groups, cryptocurrency theft, IT worker fraud, supply chain attacks, ransomware, and financial crime
**Intended Audience:** Blue team operators, CTI analysts, SOC analysts, incident responders, blockchain investigators

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [DPRK APT Group Profiles](#2-dprk-apt-group-profiles)
3. [Cryptocurrency and Financial Theft Operations](#3-cryptocurrency-and-financial-theft-operations)
4. [IT Worker Fraud Schemes](#4-it-worker-fraud-schemes)
5. [Supply Chain Attacks](#5-supply-chain-attacks)
6. [Ransomware Operations](#6-ransomware-operations)
7. [Destructive Malware Arsenal](#7-destructive-malware-arsenal)
8. [Actively Exploited CVEs](#8-actively-exploited-cves)
9. [Cross-Vendor Naming Matrix](#9-cross-vendor-naming-matrix)
10. [MITRE ATT&CK Group Mappings](#10-mitre-attck-group-mappings)
11. [Key DPRK TTPs Summary](#11-key-dprk-ttps-summary)
12. [Government and Defense Intel Sources](#12-government-and-defense-intel-sources)
13. [Vetted Cybersecurity Research Blogs](#13-vetted-cybersecurity-research-blogs)
14. [Social Media and OSINT Feeds](#14-social-media-and-osint-feeds)
15. [Blockchain and Crypto OSINT Tools](#15-blockchain-and-crypto-osint-tools)
16. [IOC Sources and Threat Feeds](#16-ioc-sources-and-threat-feeds)
17. [RSS/Atom Feeds for Automated Ingestion](#17-rssatom-feeds-for-automated-ingestion)
18. [Intelligence Gaps and Collection Priorities](#18-intelligence-gaps-and-collection-priorities)

---

## 1. Executive Summary

North Korea operates the most financially motivated state-sponsored cyber program in the world. Unlike Russia, China, or Iran -- where espionage and disruption are primary objectives -- DPRK cyber operations exist primarily to generate revenue for the regime, directly funding its nuclear weapons and ballistic missile programs. The Reconnaissance General Bureau (RGB) serves as the primary cyber authority, operating multiple bureaus and laboratories that execute overlapping missions spanning espionage, financial theft, and destructive operations.

**Key assessments:**

- **Cryptocurrency theft is the single largest revenue source for DPRK cyber operations.** The FBI, Chainalysis, and the UN Panel of Experts have attributed over $6 billion in cumulative cryptocurrency theft to DPRK-linked actors from 2017 through early 2025. The $1.5 billion Bybit exchange hack in February 2025 -- attributed by the FBI to TraderTraitor -- was the single largest cryptocurrency theft in history. The $620 million Ronin Network hack (2022) was previously the record holder.
- **The RGB operates multiple distinct but coordinating cyber units.** The 3rd Bureau (Technical Reconnaissance Bureau) houses Lazarus Group and Andariel. Bureau 121 is the primary cyber warfare unit. Lab 110 focuses on technical intelligence. These units share tooling, infrastructure, and access, making clean attribution to a single group difficult.
- **IT worker fraud represents a second major revenue stream.** Thousands of DPRK IT workers operate under fraudulent identities, securing remote employment contracts at US and Western technology companies. The FBI estimates this program generates hundreds of millions of dollars annually. Workers use stolen US identities, AI-generated profile photos, and US-based laptop farms to maintain cover.
- **DPRK groups uniquely blur the line between espionage and financial crime.** The same operators conducting intelligence collection against defense and aerospace targets will pivot to cryptocurrency theft campaigns. This dual-mission posture is unique among nation-state cyber programs.
- **Supply chain attacks are an increasingly favored vector.** The 3CX supply chain compromise (March 2023) and JumpCloud breach (July 2023) demonstrated sophisticated supply chain tradecraft. DPRK groups have also poisoned npm and PyPI packages and conducted social engineering campaigns against open-source developers via GitHub and LinkedIn.
- **Social engineering of developers is a signature TTP.** DPRK actors create elaborate fake personas -- recruiters, venture capitalists, cryptocurrency startup founders -- to approach software developers with trojanized coding challenges, job offers, and investment opportunities.

---

## 2. DPRK APT Group Profiles

### 2.1 Lazarus Group / HIDDEN COBRA / Diamond Sleet / Labyrinth Chollima

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0032 |
| **Attribution** | RGB 3rd Bureau (Technical Reconnaissance Bureau); Bureau 121 |
| **Microsoft** | Diamond Sleet (formerly ZINC) |
| **CrowdStrike** | Labyrinth Chollima |
| **Mandiant** | TEMP.Hermit |
| **Secureworks** | NICKEL ACADEMY |
| **Primary Targets** | Defense, aerospace, energy, financial institutions, cryptocurrency exchanges -- global targeting with emphasis on US, South Korea, Japan, Southeast Asia |
| **Key TTPs** | Trojanized software installers (X_TRADER, 3CX); weaponized open-source utilities; DLL side-loading; custom backdoors (BLINDINGCAN, COPPERHEDGE, ELECTRICFISH); social engineering via fake job offers (Operation Dream Job / Operation In(ter)ception); compromised legitimate software supply chains; living-off-the-land binaries |
| **Key CVEs** | CVE-2021-44228 (Log4Shell), CVE-2022-47966 (Zoho ManageEngine), CVE-2023-42793 (JetBrains TeamCity), CVE-2024-4947 (Chrome V8) |
| **Key Reporting** | CISA: multiple HIDDEN COBRA advisories; Microsoft: Diamond Sleet supply chain attacks via 3CX and CyberLink; Mandiant: UNC4736 3CX investigation; Kaspersky: Operation DreamJob campaigns |

### 2.2 APT38 / BlueNoroff / Sapphire Sleet / Stardust Chollima

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0082 |
| **Attribution** | RGB -- financial operations focus; split from Lazarus umbrella by FireEye/Mandiant in 2018 |
| **Microsoft** | Sapphire Sleet |
| **CrowdStrike** | Stardust Chollima |
| **Mandiant** | APT38 |
| **Secureworks** | NICKEL GLADSTONE |
| **Primary Targets** | Banks (SWIFT network targeting), cryptocurrency exchanges, DeFi protocols, venture capital firms, financial technology companies |
| **Key TTPs** | SWIFT transaction manipulation (Bangladesh Bank $81M heist, 2016); cryptocurrency exchange compromises; fake cryptocurrency trading applications (AppleJeus campaign); social engineering posing as recruiters and VCs; trojanized cryptocurrency tools; macOS malware targeting financial sector; watering hole attacks against cryptocurrency community sites |
| **Key Campaigns** | Bangladesh Bank heist ($81M, 2016); Bancomext (Mexico); Bank of Chile; Cosmos Bank (India); multiple Vietnamese, Taiwanese, and African bank targeting; AppleJeus cryptocurrency theft campaign |
| **Key Reporting** | FireEye: original APT38 report (2018); CISA AA20-239A: FASTCash 2.0; Kaspersky: BlueNoroff cryptocurrency campaigns; Microsoft: Sapphire Sleet cryptocurrency social engineering |

### 2.3 Kimsuky / Velvet Chollima / Emerald Sleet / Thallium

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0094 |
| **Attribution** | RGB; assessed as distinct from Lazarus Group but operating under same RGB authority |
| **Microsoft** | Emerald Sleet (formerly THALLIUM) |
| **CrowdStrike** | Velvet Chollima |
| **Mandiant** | APT43 (overlapping cluster) |
| **Secureworks** | NICKEL KIMBALL |
| **Primary Targets** | Think tanks, academia, media, government policy organizations, nuclear/nonproliferation research -- South Korea, US, Japan, Europe |
| **Key TTPs** | Highly targeted spear-phishing with reconnaissance themes (think tank impersonation, academic outreach, journalist interview requests); credential harvesting via fake login pages; ReconShark, BabyShark, and SHARPEXT (browser extension credential stealer) malware families; abuse of cloud services (Google Drive, OneDrive) for C2; living-off-the-land techniques; use of legitimate email services for phishing relay |
| **Key CVEs** | CVE-2022-27925 (Zimbra), CVE-2022-41040 (Exchange ProxyNotShell), CVE-2023-23397 (Outlook EoP) |
| **Key Reporting** | CISA AA20-301A: Kimsuky targeting think tanks and government; Microsoft: Emerald Sleet social engineering using AI-enhanced content; Volexity: SHARPEXT browser extension analysis; SentinelOne: Kimsuky reconnaissance tools |

### 2.4 Andariel / Onyx Sleet / Silent Chollima

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0138 |
| **Attribution** | RGB 3rd Bureau -- Lab 110 (Technical Reconnaissance) |
| **Microsoft** | Onyx Sleet (formerly PLUTONIUM) |
| **CrowdStrike** | Silent Chollima |
| **Mandiant** | UNC614 (partial overlap) |
| **Secureworks** | -- |
| **Primary Targets** | Defense, aerospace, nuclear energy, engineering sectors -- South Korea, US, India, Japan; also targets healthcare for ransomware revenue |
| **Key TTPs** | Exploitation of internet-facing servers (WebLogic, Exchange, Apache ActiveMQ); custom backdoors (Dtrack, TigerRAT, EarlyRAT, NukeSped); Maui ransomware deployment against healthcare; development of custom ransomware for revenue generation alongside espionage; use of legitimate cloud services for C2; HFS (HTTP File Server) for payload hosting |
| **Key CVEs** | CVE-2023-46604 (Apache ActiveMQ), CVE-2023-42793 (JetBrains TeamCity), CVE-2022-47966 (Zoho ManageEngine), CVE-2019-2725 (Oracle WebLogic) |
| **Key Reporting** | CISA AA23-040A: Maui ransomware targeting healthcare; Microsoft: Onyx Sleet TeamCity exploitation; Kaspersky: Andariel/Lazarus nexus analysis; DOJ: indictment of Rim Jong Hyok (July 2024) for Andariel ransomware attacks |

### 2.5 APT43 / Kimsuky Subgroup / Springtail

| Attribute | Detail |
|---|---|
| **MITRE ID** | -- (tracked as subcluster of G0094 by some vendors) |
| **Attribution** | RGB; overlaps significantly with Kimsuky but assessed by Mandiant as operationally distinct |
| **Microsoft** | Emerald Sleet (partial overlap) |
| **CrowdStrike** | -- |
| **Mandiant** | APT43 |
| **Symantec** | Springtail |
| **Primary Targets** | Government, business, cryptocurrency -- South Korea, US, Japan, Europe; strategic intelligence focused on nuclear policy and geopolitics |
| **Key TTPs** | Credential harvesting for strategic intelligence collection; cryptocurrency theft to self-fund operations (unique self-funding model); use of stolen cryptocurrency to purchase hashing services for infrastructure; creation of spoofed domains mimicking think tanks and media; Android malware targeting South Korean users; social engineering via impersonation of journalists and researchers |
| **Key Reporting** | Mandiant: APT43 report (March 2023) documenting self-funding cryptocurrency theft model; Symantec: Springtail Linux backdoor campaigns |

### 2.6 TraderTraitor

| Attribute | Detail |
|---|---|
| **Attribution** | RGB-linked; distinct cryptocurrency-focused operational cluster |
| **Microsoft** | Jade Sleet (overlapping) |
| **Primary Targets** | Cryptocurrency exchanges, DeFi protocols, blockchain bridge operators, cryptocurrency infrastructure companies |
| **Key TTPs** | Social engineering of cryptocurrency company employees via LinkedIn, Telegram, and Discord; trojanized cryptocurrency trading applications; exploitation of smart contract vulnerabilities; targeting of blockchain bridge validators; fake job offers with malicious documents/applications; large-scale fund laundering through mixing services, chain-hopping, and OTC brokers |
| **Key Campaigns** | Ronin Network / Axie Infinity ($620M, March 2022); Harmony Horizon Bridge ($100M, June 2022); Bybit exchange ($1.5B, February 2025) |
| **Key Reporting** | CISA AA22-108A: TraderTraitor advisory; FBI: Bybit attribution statement (Feb 2025); FBI: Ronin attribution (April 2022); Chainalysis: annual cryptocurrency crime reports |

### 2.7 Citrine Sleet

| Attribute | Detail |
|---|---|
| **Attribution** | RGB-linked; cryptocurrency sector focus |
| **Microsoft** | Citrine Sleet (formerly DEV-0139) |
| **Primary Targets** | Cryptocurrency sector -- exchanges, DeFi platforms, individual cryptocurrency holders, blockchain technology companies |
| **Key TTPs** | Fake cryptocurrency trading platforms and applications; trojanized cryptocurrency wallet software; exploitation of Chromium zero-days; social engineering posing as OTC traders and cryptocurrency fund managers; AppleJeus deployment (overlaps with BlueNoroff tooling) |
| **Key CVEs** | CVE-2024-7971 (Chromium V8 type confusion), CVE-2024-38106 (Windows Kernel EoP) |
| **Key Reporting** | Microsoft: Citrine Sleet exploiting Chromium zero-day (August 2024); CISA: AppleJeus advisories |

### 2.8 Moonstone Sleet

| Attribute | Detail |
|---|---|
| **Attribution** | RGB-linked; distinct operational cluster with unique TTPs |
| **Microsoft** | Moonstone Sleet (formerly Storm-1789) |
| **Primary Targets** | Software/IT companies, defense, education; also financial targets for ransomware revenue |
| **Key TTPs** | Creation of fake companies with fully-built websites, social media profiles, and GitHub repositories (e.g., StarGlow Ventures, C.C. Waterfall); trojanized legitimate software tools (PuTTY, SumatraPDF, advanced-ip-scanner); malicious npm packages; custom ransomware (FakePenny); malicious tank game ("DeTankWar" / "DeFiTankLand") distributed to targets; elaborate social engineering campaigns via LinkedIn using fake company personas |
| **Key Reporting** | Microsoft: Moonstone Sleet emerging as new DPRK threat actor (May 2024); Microsoft: FakePenny ransomware analysis |

### 2.9 Jade Sleet

| Attribute | Detail |
|---|---|
| **Attribution** | RGB-linked; developer-focused social engineering |
| **Microsoft** | Jade Sleet (formerly DEV-0954) |
| **Primary Targets** | Software developers, open-source contributors, cryptocurrency developers -- via GitHub, LinkedIn, npm |
| **Key TTPs** | Social engineering through GitHub interactions (opening issues, submitting pull requests, creating fake profiles); malicious npm packages with obfuscated payloads; LinkedIn outreach posing as recruiters or collaborators; invitation to collaborate on GitHub repositories containing malicious code; targeting of blockchain and cryptocurrency developers |
| **Key Reporting** | GitHub: social engineering campaign alert (July 2023); Microsoft: Jade Sleet developer targeting via GitHub and npm |

### 2.10 Ruby Sleet

| Attribute | Detail |
|---|---|
| **Attribution** | RGB-linked |
| **Microsoft** | Ruby Sleet (formerly CERIUM) |
| **Primary Targets** | Defense, aerospace, government -- South Korea, US |
| **Key TTPs** | Spear-phishing with weaponized documents; exploitation of email vulnerabilities; custom backdoors; targeting of defense industrial base contractors |
| **Key Reporting** | Microsoft: Ruby Sleet defense sector targeting |

### 2.11 ScarCruft / APT37 / Reaper / Ricochet Chollima

| Attribute | Detail |
|---|---|
| **MITRE ID** | G0067 |
| **Attribution** | Ministry of State Security (MSS) -- distinct from RGB; North Korea's domestic intelligence agency with external operations mandate |
| **Microsoft** | -- |
| **CrowdStrike** | Ricochet Chollima |
| **Mandiant** | APT37 |
| **Secureworks** | NICKEL FOXCROFT |
| **Primary Targets** | North Korean defectors, journalists covering DPRK, human rights organizations, South Korean government and military |
| **Key TTPs** | Zero-day exploitation (Internet Explorer, Flash, Windows); watering hole attacks; RokRAT backdoor family; use of cloud storage (Yandex, pCloud, Dropbox, Google Drive) for C2; Konni RAT; CHM (compiled HTML) file weaponization; abuse of legitimate Korean software (HWP word processor exploits) |
| **Key CVEs** | CVE-2022-41128 (Windows JScript9 zero-day), CVE-2023-21674 (Windows ALPC EoP), CVE-2024-38178 (Windows Scripting Engine) |
| **Key Reporting** | AhnLab: extensive APT37/ScarCruft tracking; Google TAG: Internet Explorer zero-day analysis; ESET: RokRAT and Dolphin backdoor analysis; Volexity: InkySquid watering hole campaigns |

---

## 3. Cryptocurrency and Financial Theft Operations

### 3.1 Scale of Operations

DPRK cyber operations represent the most successful state-sponsored financial theft program in history. The UN Panel of Experts (Security Council Resolution 1718 Committee) has documented billions in cryptocurrency theft funding DPRK weapons programs in violation of international sanctions.

| Year | Estimated Cryptocurrency Theft | Source |
|---|---|---|
| 2017-2021 | ~$1.2 billion cumulative | UN Panel of Experts |
| 2022 | ~$1.7 billion | Chainalysis |
| 2023 | ~$1.0 billion | Chainalysis |
| 2024 | ~$1.3 billion | Chainalysis |
| 2025 (through Feb) | ~$1.5 billion+ (Bybit alone) | FBI / Chainalysis |

### 3.2 Major Cryptocurrency Theft Operations

| Date | Target | Amount | Attribution | Method |
|---|---|---|---|---|
| Feb 2025 | Bybit Exchange | $1.5B | TraderTraitor (FBI) | Compromise of Safe{Wallet} multisig infrastructure; social engineering of developers |
| Mar 2022 | Ronin Network / Axie Infinity | $620M | Lazarus / TraderTraitor (FBI) | Compromised validator nodes via social engineering with fake job offer to Sky Mavis engineer |
| Jun 2022 | Harmony Horizon Bridge | $100M | Lazarus / TraderTraitor (FBI) | Compromised multisig private keys |
| Jun 2023 | Atomic Wallet | $100M | Lazarus / TraderTraitor | Compromise of wallet infrastructure; supply chain suspected |
| Sep 2023 | Stake.com | $41M | Lazarus (FBI) | Private key compromise |
| Sep 2023 | CoinEx | $54M | Lazarus (FBI) | Hot wallet private key compromise |
| Jan 2024 | Orbit Chain | $80M | Lazarus (assessed) | Cross-chain bridge compromise |
| May 2024 | DMM Bitcoin | $305M | TraderTraitor (FBI) | Social engineering of employee at Ginco (wallet infrastructure provider) via LinkedIn recruiter |
| Jul 2024 | WazirX | $235M | Lazarus (assessed) | Multisig wallet compromise |

### 3.3 Laundering Methods

DPRK cryptocurrency laundering is sophisticated and employs layered techniques:

- **Mixing Services**: Extensive use of Tornado Cash (Ethereum), Sinbad.io (seized by OFAC Nov 2023), ChipMixer (seized Mar 2023), and successor mixing protocols
- **Chain-Hopping**: Converting stolen assets across multiple blockchains to obscure trail (ETH -> BTC -> XMR patterns)
- **Peel Chains**: Automated splitting of large amounts into thousands of smaller transactions across fresh wallets
- **OTC Brokers**: Use of over-the-counter cryptocurrency brokers, particularly those operating in jurisdictions with weak AML enforcement (China, Southeast Asia)
- **DeFi Protocols**: Exploitation of decentralized exchanges and liquidity pools for asset swaps without KYC
- **Dormancy Periods**: Stolen funds held in wallets for months to years before laundering, waiting for reduced monitoring attention
- **Fake Identity Accounts**: Creation of exchange accounts using stolen or fabricated identities for fiat off-ramping

### 3.4 Sanctions and WMD Nexus

The US Treasury, OFAC, and UN Security Council have documented the direct pipeline from cryptocurrency theft to WMD funding:

- **OFAC sanctions** on Tornado Cash (August 2022), Sinbad.io (November 2023), and multiple DPRK-linked cryptocurrency wallets
- **UN Panel of Experts reports** estimate DPRK cyber theft funds approximately 40% of WMD program costs
- **DOJ seizures** of DPRK-linked cryptocurrency totaling hundreds of millions (ongoing forfeiture actions)

---

## 4. IT Worker Fraud Schemes

### 4.1 Overview

DPRK operates a large-scale fraud scheme deploying thousands of IT workers worldwide under false identities to secure remote employment contracts. These workers -- primarily residing in China and Russia but operating through global VPN infrastructure -- generate revenue for the regime while potentially gaining privileged access to employer networks.

### 4.2 Scale and Revenue

| Metric | Assessment |
|---|---|
| **Estimated workers** | 3,000-10,000+ DPRK IT workers operating globally |
| **Annual revenue** | Hundreds of millions of dollars annually (DOJ/FBI estimates) |
| **Average salary secured** | $60,000-$300,000 per position per year |
| **Multiple positions** | Individual workers often hold 2-5+ concurrent remote positions simultaneously |
| **Revenue routing** | Salary payments routed through US-based facilitators, then transferred to DPRK through China-based intermediaries |

### 4.3 Operational Tradecraft

- **Stolen US identities**: Workers use stolen Social Security numbers, driver's licenses, and other US identity documents purchased on dark web markets
- **AI-generated profile photos**: Deepfake and AI-generated headshots for LinkedIn profiles and company badge photos
- **US-based laptop farms**: Conspirators within the US receive company-issued laptops, install remote access software (AnyDesk, Chrome Remote Desktop, TeamViewer), and forward access to DPRK workers operating from China/Russia
- **Virtual infrastructure**: Extensive use of US-based VPNs, virtual desktops, and residential proxies to simulate US-based presence
- **Freelance platforms**: Workers secure contracts through Upwork, Freelancer, Toptal, and similar platforms
- **Technical skills**: Workers possess genuine software development skills -- web development, mobile applications, blockchain/cryptocurrency development (notably aligned with targeting interests)

### 4.4 Detection Indicators

| Indicator | Detail |
|---|---|
| Reluctance to appear on video | Workers avoid video calls or use static images; claim camera issues |
| Multiple job history inconsistencies | Resume details do not match background check results |
| IP/geolocation anomalies | VPN use with geolocation mismatches; access from unusual time zones relative to claimed location |
| Shipping address discrepancies | Equipment shipped to addresses associated with known laptop farms |
| Remote access software | Unauthorized installation of remote access tools on company hardware |
| Payment routing | Requests for payment to third-party accounts or cryptocurrency wallets |
| Rapid technical proficiency | Disproportionate skill relative to interview performance (multiple people may support one "employee") |

### 4.5 Government Advisories

| Advisory | Agency | Date | Subject |
|---|---|---|---|
| OFAC DPRK IT Worker Advisory | Treasury/OFAC | May 2022 | Guidance on DPRK IT workers earning revenue for regime |
| FBI IC3 PSA | FBI | May 2022 | DPRK IT workers using US identities for remote work |
| DOJ Indictments | DOJ | Multiple 2023-2024 | Prosecution of US-based facilitators operating laptop farms |
| OFAC Updated Advisory | Treasury/OFAC | October 2023 | Updated DPRK IT worker indicators and red flags |
| FBI/State Dept Joint Warning | FBI/State | 2024 | Expanded warning including AI-enhanced deception techniques |

---

## 5. Supply Chain Attacks

### 5.1 3CX Supply Chain Compromise (March 2023)

| Attribute | Detail |
|---|---|
| **Timeline** | March 2023 (detected); likely compromised months earlier |
| **Attributed to** | Lazarus Group / Diamond Sleet / UNC4736 (Mandiant) |
| **Target** | 3CX Desktop App -- VoIP/PBX software used by 600,000+ companies and 12M+ daily users |
| **Method** | Supply-chain-within-a-supply-chain: attackers first compromised Trading Technologies' X_TRADER software, used that access to compromise a 3CX employee's machine, then leveraged that access to trojanize the 3CX Desktop App build pipeline |
| **Impact** | Trojanized 3CX installers distributed to downstream customers; selective second-stage payloads deployed to cryptocurrency and financial sector targets |
| **Significance** | First documented case of one software supply chain attack leading directly to another; demonstrated long-term patience and operational sophistication |
| **Key Reporting** | Mandiant: complete intrusion chain analysis; CrowdStrike: initial detection as "SmoothOperator"; Symantec: X_TRADER connection |

### 5.2 JumpCloud Compromise (July 2023)

| Attribute | Detail |
|---|---|
| **Timeline** | June-July 2023 |
| **Attributed to** | Lazarus Group / Jade Sleet / UNC4899 (Mandiant) |
| **Target** | JumpCloud -- cloud directory and identity management platform serving 200,000+ organizations |
| **Method** | Spear-phishing of JumpCloud employee; leveraged access to inject malicious commands into JumpCloud agent framework targeting specific downstream customers |
| **Impact** | Selective targeting of cryptocurrency company customers; fewer than 5 customers and fewer than 10 devices compromised |
| **Significance** | Targeted supply chain attack using identity management platform as pivot point to reach high-value cryptocurrency targets |
| **Key Reporting** | JumpCloud: incident disclosure; Mandiant: UNC4899 attribution; SentinelOne: infrastructure analysis |

### 5.3 Package Repository Attacks

DPRK actors have conducted sustained campaigns to poison open-source software repositories:

| Vector | Detail |
|---|---|
| **npm packages** | Jade Sleet and Moonstone Sleet published malicious npm packages with obfuscated payloads; typosquatting of popular package names; targeting blockchain and cryptocurrency developers |
| **PyPI packages** | Malicious Python packages mimicking legitimate cryptocurrency and blockchain libraries; automated download of second-stage payloads |
| **GitHub repositories** | Creation of fake repositories with trojanized code; social engineering to convince developers to clone and execute malicious projects; exploitation of GitHub Actions for malware distribution |

### 5.4 Developer Social Engineering via LinkedIn/GitHub

DPRK actors maintain a persistent social engineering apparatus targeting software developers:

- **LinkedIn personas**: Fake recruiter profiles from major tech companies offering lucrative positions; outreach with "coding challenges" that contain malicious payloads
- **GitHub engagement**: Fake developer profiles that build credibility through legitimate contributions before introducing malicious code
- **Telegram/Discord**: Approach targets through cryptocurrency and developer community channels
- **Fake companies**: Moonstone Sleet creates entirely fictitious companies with professional websites, social media, and GitHub organizations

---

## 6. Ransomware Operations

### 6.1 Maui Ransomware

| Attribute | Detail |
|---|---|
| **Attributed to** | Andariel / Onyx Sleet |
| **Targets** | US healthcare and public health (HPH) sector |
| **Timeline** | Active since at least May 2021; CISA advisory July 2022 |
| **Characteristics** | Manually operated (not automated propagation); AES-128, RSA, and XOR encryption; no embedded ransom note (demands communicated separately); targets VMware ESXi servers |
| **Advisory** | CISA AA22-187A: joint FBI/CISA/Treasury advisory on Maui ransomware |
| **Significance** | First confirmed case of DPRK state actors deploying ransomware against US healthcare; DOJ recovered $500K in ransom payments; led to indictment of Rim Jong Hyok |

### 6.2 H0lyGh0st / Holy Ghost

| Attribute | Detail |
|---|---|
| **Attributed to** | DEV-0530 / Moonstone Sleet (Microsoft assessment) |
| **Targets** | Small and medium businesses across multiple countries |
| **Timeline** | Active since June 2021 |
| **Characteristics** | .NET ransomware; multiple variants (SiennaPurple, SiennaBlue); operators created "H0lyGh0st" website for extortion; attempted to position as ideological operation ("closing the gap between rich and poor") |
| **Key Reporting** | Microsoft: H0lyGh0st ransomware attributed to DPRK-linked DEV-0530 (July 2022) |

### 6.3 FakePenny Ransomware

| Attribute | Detail |
|---|---|
| **Attributed to** | Moonstone Sleet |
| **Targets** | Aerospace, defense, education, software companies |
| **Timeline** | Emerged 2024 |
| **Characteristics** | Custom ransomware deployed after data exfiltration; ransom demands of $6.6M in BTC; shares tooling and infrastructure with Moonstone Sleet's espionage operations |
| **Key Reporting** | Microsoft: Moonstone Sleet FakePenny ransomware (May 2024) |

### 6.4 Assessment

DPRK ransomware operations represent a **secondary revenue stream** complementing cryptocurrency theft. Unlike ransomware-as-a-service operations from Russian-speaking groups, DPRK ransomware tends to be manually deployed, less technically sophisticated, and more opportunistic. The primary concern is the targeting of healthcare and critical infrastructure, and the fact that ransom payments directly fund a sanctioned regime -- making payment potentially a sanctions violation under OFAC guidance.

---

## 7. Destructive Malware Arsenal

### 7.1 Known DPRK Malware Families

| Malware | Type | Associated Group | Description |
|---|---|---|---|
| **BLINDINGCAN** (DRATzarus) | RAT | Lazarus / HIDDEN COBRA | Full-featured RAT with proxy, file manipulation, process execution; CISA AR20-232A |
| **COPPERHEDGE** | RAT | Lazarus | Variant RAT targeting cryptocurrency exchanges; multiple variants documented |
| **ELECTRICFISH** | Tunneling | Lazarus / HIDDEN COBRA | Custom tunneling tool for proxying traffic between source and destination IPs; CISA AR19-129A |
| **HOPLIGHT** | Trojan/Backdoor | Lazarus / HIDDEN COBRA | Proxy-capable backdoor with encrypted C2; CISA AR19-100A |
| **BADCALL** | Backdoor | Lazarus / HIDDEN COBRA | Proxy backdoor with FakeTLS C2; CISA AR18-165A |
| **FASTCash** | Financial | APT38 / BlueNoroff | AIX and Windows malware targeting bank payment switch application servers to enable fraudulent ATM withdrawals; CISA AA20-239A |
| **AppleJeus** | Trojanized App | Lazarus / Citrine Sleet | Fake cryptocurrency trading applications for Windows and macOS; multiple generations; CISA AA21-048A |
| **RokRAT** (DOGCALL) | RAT | ScarCruft / APT37 | Cloud-based RAT using Yandex, pCloud, Dropbox, Google Drive for C2; sophisticated evasion |
| **Konni** | RAT | Kimsuky / APT37 (disputed) | Document-themed RAT; extensive use of .scr and .lnk files; targets Korean-language users |
| **BabyShark** | Reconnaissance | Kimsuky | VBS/PowerShell reconnaissance framework; predecessor to ReconShark |
| **ReconShark** | Reconnaissance | Kimsuky | Enhanced reconnaissance tool deployed via spear-phishing; exfiltrates system configuration data |
| **SHARPEXT** | Browser Extension | Kimsuky | Malicious Chromium browser extension that directly reads and exfiltrates email from Gmail and AOL webmail sessions |
| **Dtrack** (Valefor) | RAT | Andariel | Modular backdoor for keylogging, screenshot capture, browser history theft; used in Kudankulam nuclear plant incident |
| **TigerRAT** | RAT | Andariel | C++ backdoor with keylogging, screenshot, file transfer, C2 proxy capabilities |
| **EarlyRAT** | RAT | Andariel | Phishing-delivered RAT used alongside Log4j exploitation |
| **NukeSped** (Manuscrypt) | Backdoor | Lazarus | Modular implant framework with multiple variants; extensively used across campaigns |
| **MATA Framework** | Cross-platform | Lazarus | Advanced cross-platform (Windows, Linux, macOS) malware framework; modular plugin architecture |
| **Dolphin** | Backdoor | ScarCruft | Full-featured backdoor with Google Drive C2; browser credential theft; mobile device data extraction |
| **LightlessCan** | RAT | Lazarus | Advanced RAT mimicking Windows native commands; significant advancement over BLINDINGCAN |
| **KANDYKORN** (SockRacket) | macOS RAT | Lazarus / Jade Sleet | Full-featured macOS RAT targeting blockchain engineers; reflective loading |
| **SugarLoader** | Loader | Lazarus / Jade Sleet | macOS loader disguised as cryptocurrency exchange application |
| **ObjCShellz** | macOS Backdoor | BlueNoroff | Simple but effective macOS shell backdoor communicating over HTTP |
| **MISTPEN** | Backdoor | Lazarus | Trojanized Notepad++ plugin used in Operation Dream Job; delivered via fake job description PDFs |
| **RustBucket** | macOS Malware | BlueNoroff | macOS attack chain using fake PDF viewer; Rust-based downloader and AppleScript payloads |
| **KandyKorn** | macOS RAT | BlueNoroff / Jade Sleet | macOS RAT targeting cryptocurrency exchange engineers via Discord social engineering |
| **Maui** | Ransomware | Andariel | Healthcare-targeting ransomware; AES/RSA/XOR; manually deployed |
| **FakePenny** | Ransomware | Moonstone Sleet | Custom ransomware; post-exfiltration deployment; $6.6M demands |
| **H0lyGh0st** | Ransomware | Moonstone Sleet | .NET ransomware; SMB targeting; multiple variants |
| **WannaCry** | Ransomware/Wiper | Lazarus (assessed) | May 2017 global outbreak; EternalBlue propagation; attributed to DPRK by US, UK, Microsoft; assessed as accidental release rather than targeted operation |

### 7.2 Notable Destructive Operations (Historical)

| Operation | Year | Target | Description |
|---|---|---|---|
| **DarkSeoul** | 2013 | South Korean banks and media | Wiper attack affecting 48,000+ computers; coordinated with DDoS |
| **Sony Pictures Entertainment** | 2014 | Sony Pictures | Destructive wiper attack + data theft in retaliation for "The Interview" film; attributed by FBI |
| **WannaCry** | 2017 | Global | EternalBlue-based ransomware/wiper affecting 200,000+ systems in 150 countries; $4-8B estimated damage |
| **Banco de Chile** | 2018 | Banco de Chile | Wiper distraction while SWIFT theft conducted |

---

## 8. Actively Exploited CVEs

| CVE | Product | Exploiting Group(s) | CISA KEV |
|---|---|---|---|
| CVE-2024-38178 | Windows Scripting Engine | ScarCruft / APT37 | Yes |
| CVE-2024-7971 | Chromium V8 (Type Confusion) | Citrine Sleet | Yes |
| CVE-2024-38106 | Windows Kernel (EoP) | Citrine Sleet (chained with 7971) | Yes |
| CVE-2024-4947 | Chrome V8 (Type Confusion) | Lazarus Group | Yes |
| CVE-2024-21338 | Windows AppLocker (EoP) | Lazarus Group | Yes |
| CVE-2023-46604 | Apache ActiveMQ | Andariel / Onyx Sleet | Yes |
| CVE-2023-42793 | JetBrains TeamCity | Diamond Sleet, Onyx Sleet | Yes |
| CVE-2023-23397 | Microsoft Outlook (EoP) | Kimsuky (assessed) | Yes |
| CVE-2022-47966 | Zoho ManageEngine | Lazarus, Andariel | Yes |
| CVE-2022-41128 | Windows JScript9 (zero-day) | ScarCruft / APT37 | Yes |
| CVE-2022-27925 | Zimbra Collaboration Suite | Kimsuky / Lazarus | Yes |
| CVE-2022-0609 | Chrome (Use-After-Free) | Lazarus Group (Operation Dream Job) | Yes |
| CVE-2021-44228 | Apache Log4j (Log4Shell) | Lazarus, Andariel | Yes |
| CVE-2021-34527 | Windows Print Spooler (PrintNightmare) | Multiple DPRK groups | Yes |
| CVE-2021-26855 | Exchange (ProxyLogon) | Multiple DPRK groups | Yes |
| CVE-2019-2725 | Oracle WebLogic | Andariel | Yes |
| CVE-2017-11882 | Microsoft Office Equation Editor | Lazarus, Kimsuky | Yes |
| CVE-2017-0144 | Windows SMB (EternalBlue) | Lazarus (WannaCry) | Yes |

**Pattern**: DPRK groups maintain a **dual exploitation approach** -- they invest in zero-day development (particularly browser zero-days targeting Chrome/Chromium and Windows kernel for chaining) for high-value targets, while simultaneously exploiting N-day vulnerabilities in internet-facing servers (Log4j, ActiveMQ, TeamCity, WebLogic) for broader access operations.

---

## 9. Cross-Vendor Naming Matrix

Understanding cross-vendor naming is **critical** for effective monitoring. The same group appears under different names depending on which vendor's reporting you are reading.

| MITRE | Microsoft (Sleet = DPRK) | CrowdStrike (CHOLLIMA) | Mandiant | Secureworks | Other |
|---|---|---|---|---|---|
| Lazarus Group (G0032) | Diamond Sleet (fmr. ZINC) | Labyrinth Chollima | TEMP.Hermit | NICKEL ACADEMY | HIDDEN COBRA (USG) |
| APT38 / BlueNoroff (G0082) | Sapphire Sleet (fmr. COPERNICIUM) | Stardust Chollima | APT38 | NICKEL GLADSTONE | -- |
| Kimsuky (G0094) | Emerald Sleet (fmr. THALLIUM) | Velvet Chollima | -- | NICKEL KIMBALL | Springtail (Symantec) |
| Andariel (G0138) | Onyx Sleet (fmr. PLUTONIUM) | Silent Chollima | -- | -- | Stonefly (Symantec) |
| ScarCruft (G0067) | -- | Ricochet Chollima | APT37 | NICKEL FOXCROFT | Reaper, Group123, InkySquid |
| -- | Citrine Sleet (fmr. DEV-0139) | -- | -- | -- | AppleJeus operator |
| -- | Moonstone Sleet (fmr. Storm-1789) | -- | -- | -- | -- |
| -- | Jade Sleet (fmr. DEV-0954) | -- | UNC4899 | -- | TraderTraitor (partial) |
| -- | Ruby Sleet (fmr. CERIUM) | -- | -- | -- | -- |
| -- (APT43 cluster) | Emerald Sleet (partial) | -- | APT43 | -- | Springtail (Symantec) |
| -- (TraderTraitor) | Jade Sleet (partial) | -- | UNC4736 (partial) | -- | TraderTraitor (USG) |

**Microsoft Taxonomy Key**: "Sleet" = DPRK-attributed. Weather phenomena are used for nation-state groups: Sleet (North Korea), Blizzard (Russia), Typhoon (China), Sandstorm (Iran), Hail (South Korea), Dust (Turkey), Rain (Lebanon).

**CrowdStrike Taxonomy Key**: "CHOLLIMA" = DPRK-attributed. Named after the mythical winged horse from Korean mythology. All CrowdStrike DPRK group names end in CHOLLIMA.

---

## 10. MITRE ATT&CK Group Mappings

**Reference**: `https://attack.mitre.org/groups/`

| MITRE ID | Name | Key Aliases | Affiliation | Primary TTPs |
|---|---|---|---|---|
| G0032 | Lazarus Group | HIDDEN COBRA, Diamond Sleet, Labyrinth Chollima, ZINC | RGB 3rd Bureau | T1566 Phishing, T1195 Supply Chain Compromise, T1189 Drive-by Compromise, T1059 Command and Scripting Interpreter, T1036 Masquerading, T1574 Hijack Execution Flow |
| G0082 | APT38 | BlueNoroff, Sapphire Sleet, Stardust Chollima, Bluenoroff | RGB Financial | T1566 Phishing, T1195 Supply Chain Compromise, T1059 Command and Scripting Interpreter, T1070 Indicator Removal, T1565 Data Manipulation |
| G0094 | Kimsuky | Velvet Chollima, Emerald Sleet, Thallium, Black Banshee | RGB | T1566 Phishing, T1598 Phishing for Information, T1059.001 PowerShell, T1176 Browser Extensions (SHARPEXT), T1114 Email Collection, T1078 Valid Accounts |
| G0138 | Andariel | Silent Chollima, Onyx Sleet, Stonefly | RGB Lab 110 | T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter, T1486 Data Encrypted for Impact (Maui), T1021 Remote Services |
| G0067 | ScarCruft | APT37, Reaper, Ricochet Chollima, Group123 | MSS | T1566 Phishing, T1189 Drive-by Compromise, T1203 Exploitation for Client Execution, T1102 Web Service (cloud C2), T1071 Application Layer Protocol |

**Note**: Microsoft-tracked clusters (Citrine Sleet, Moonstone Sleet, Jade Sleet, Ruby Sleet) do not yet have formal MITRE ATT&CK group entries. TraderTraitor is tracked as a campaign/activity cluster rather than a formal group.

---

## 11. Key DPRK TTPs Summary

### Initial Access
- **Phishing** (T1566): Fake job offers (Operation Dream Job); recruiter impersonation via LinkedIn; think tank/journalist impersonation (Kimsuky); coding challenge lures targeting developers
- **Supply Chain Compromise** (T1195): Trojanized software (3CX, X_TRADER, CyberLink); malicious npm/PyPI packages; compromised identity management platforms (JumpCloud)
- **Drive-by Compromise** (T1189): Watering hole attacks against cryptocurrency community sites; exploitation of browser zero-days (Chrome/Chromium)
- **Exploit Public-Facing Application** (T1190): Log4Shell, ActiveMQ, TeamCity, WebLogic, ManageEngine
- **Trusted Relationship** (T1199): Compromising upstream software vendors and service providers to reach downstream targets

### Execution
- **Command and Scripting Interpreter** (T1059): PowerShell (Kimsuky), Python, JavaScript, VBScript, AppleScript (macOS attacks)
- **User Execution** (T1204): Malicious documents, trojanized applications, fake cryptocurrency tools
- **Exploitation for Client Execution** (T1203): Browser zero-days, Office exploits, HWP exploits

### Persistence
- **DLL Side-Loading** (T1574.002): Dominant Lazarus persistence technique; legitimate applications loading malicious DLLs
- **Browser Extensions** (T1176): SHARPEXT for email theft (Kimsuky)
- **Scheduled Task** (T1053.005): Persistence through scheduled tasks and system services
- **Boot or Logon Autostart** (T1547): Registry run keys and startup folder persistence

### Defense Evasion
- **Masquerading** (T1036): Malware disguised as legitimate software installers, cryptocurrency tools, and system utilities
- **Obfuscated Files** (T1027): Multi-layer encoding and encryption of payloads
- **Indicator Removal** (T1070): Timestomping, log clearing, anti-forensics
- **Hijack Execution Flow** (T1574): DLL search order hijacking, DLL side-loading

### Credential Access
- **Credential Harvesting** (T1589.001): Fake login pages mimicking Google, Microsoft, university portals (Kimsuky specialty)
- **Keylogging** (T1056.001): Custom keyloggers deployed across multiple groups
- **Web Session Cookie Theft** (T1539): Browser cookie extraction for session hijacking
- **Private Key Theft**: Cryptocurrency wallet private keys and seed phrases (primary financial objective)

### Command and Control
- **Web Service** (T1102): Cloud storage C2 -- Google Drive, Dropbox, OneDrive, pCloud, Yandex (ScarCruft specialty)
- **Application Layer Protocol** (T1071): HTTPS C2 to compromised legitimate websites
- **Encrypted Channel** (T1573): Custom encryption protocols over standard ports
- **Protocol Tunneling** (T1572): ELECTRICFISH and custom tunneling tools

### Impact
- **Financial Theft** (T1657): SWIFT manipulation, cryptocurrency theft, ransomware
- **Data Encrypted for Impact** (T1486): Maui, FakePenny, H0lyGh0st ransomware
- **Disk Wipe** (T1561): Historical destructive operations (DarkSeoul, Sony, WannaCry)

---

## 12. Government and Defense Intel Sources

### 12.1 US Government

| Source | URL | Description |
|---|---|---|
| **CISA DPRK Threat Page** | `https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/north-korea` | Dedicated portal aggregating all DPRK-related advisories |
| **CISA Advisories** | `https://www.cisa.gov/news-events/cybersecurity-advisories` | All cybersecurity advisories including joint DPRK advisories |
| **CISA KEV Catalog** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | Actively exploited vulnerabilities including those used by DPRK APTs |
| **NSA Cybersecurity** | `https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/` | Co-signs joint advisories; publishes defensive guidance |
| **FBI Cyber Division** | `https://www.fbi.gov/investigate/cyber` | FBI cyber threat warnings and DPRK-specific PSAs |
| **FBI IC3** | `https://www.ic3.gov/` | Internet Crime Complaint Center -- IT worker fraud PSAs |
| **OFAC/Treasury** | `https://ofac.treasury.gov/` | DPRK sanctions, cryptocurrency address designations, IT worker advisories |
| **US Cyber Command** | `https://www.cybercom.mil/` | DPRK malware sample sharing via VirusTotal |
| **DOJ National Security** | `https://www.justice.gov/nsd` | DPRK hacker indictments and forfeiture actions |

#### Key CISA DPRK Advisories

| Advisory | Date | Subject |
|---|---|---|
| AA24-207A | Jul 2024 | Andariel / Onyx Sleet ransomware and espionage (joint with FBI, NSA, CNMF, South Korean agencies) |
| AA23-040A | Jul 2022 | Maui ransomware targeting healthcare (FBI/CISA/Treasury) |
| AA22-108A | Apr 2022 | TraderTraitor -- DPRK targeting blockchain companies |
| AA22-187A | Jul 2022 | DPRK state-sponsored actors using Maui ransomware |
| AA21-048A | Feb 2021 | AppleJeus -- Analysis of DPRK cryptocurrency malware |
| AA20-301A | Oct 2020 | Kimsuky targeting think tanks and government |
| AA20-239A | Aug 2020 | FASTCash 2.0 -- DPRK bank targeting |
| AR20-232A | Aug 2020 | BLINDINGCAN RAT technical analysis |

> **Note (Feb 2026):** CISA RSS feeds (`all.xml`, `ics-advisories.xml`) now return 403 -- deprecated.
> NSA RSS feed also returns 403. Monitor CISA advisories page directly and use the KEV JSON API for automated ingestion:
> `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

#### Key DOJ Indictments

| Date | Subject | Detail |
|---|---|---|
| Sep 2018 | Park Jin Hyok | First DPRK hacker indicted; linked to Sony hack, WannaCry, Bangladesh Bank heist |
| Feb 2021 | Jon Chang Hyok, Kim Il, Park Jin Hyok | Three RGB hackers indicted for $1.3B+ in theft and extortion |
| Jul 2024 | Rim Jong Hyok | Andariel operative indicted for Maui ransomware attacks on US hospitals; FBI offered $10M reward |

### 12.2 South Korean Government

| Source | URL | Description |
|---|---|---|
| **National Intelligence Service (NIS)** | `https://www.nis.go.kr/` | Primary DPRK cyber intelligence authority; publishes joint advisories with US agencies |
| **Korea Internet & Security Agency (KISA)** | `https://www.kisa.or.kr/` | South Korean CERT; extensive DPRK malware analysis |
| **AhnLab ASEC** | `https://asec.ahnlab.com/en/` | Leading South Korean security vendor; primary tracker of DPRK groups targeting Korea |

### 12.3 Japanese Government

| Source | URL | Description |
|---|---|---|
| **NISC (National center of Incident readiness and Strategy for Cybersecurity)** | `https://www.nisc.go.jp/eng/` | Japanese national cybersecurity authority |
| **JPCERT/CC** | `https://www.jpcert.or.jp/english/` | Japan CERT; collaborates with US/South Korea on DPRK threat advisories |

### 12.4 International

| Source | URL | Description |
|---|---|---|
| **UK NCSC** | `https://www.ncsc.gov.uk/` | Co-signs joint DPRK advisories; Lazarus/Kimsuky tracking |
| **UN Panel of Experts (1718 Committee)** | `https://www.un.org/securitycouncil/sanctions/1718` | Formal documentation of DPRK cyber theft funding WMD programs |
| **Australian Cyber Security Centre** | `https://www.cyber.gov.au/` | Co-signs joint DPRK advisories |

### 12.5 MITRE ATT&CK

| Resource | URL |
|---|---|
| **ATT&CK Groups (DPRK)** | `https://attack.mitre.org/groups/` -- filter for G0032, G0082, G0094, G0138, G0067 |
| **ATT&CK Navigator** | `https://mitre-attack.github.io/attack-navigator/` |
| **ATT&CK Software** | `https://attack.mitre.org/software/` -- search DPRK tool names |

---

## 13. Vetted Cybersecurity Research Blogs

### Tier 1 -- Primary DPRK APT Research

| Source | Blog URL | RSS Feed | Focus |
|---|---|---|---|
| **Microsoft Threat Intelligence** | `microsoft.com/en-us/security/blog/topic/threat-intelligence/` | `microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/` | Sleet group tracking (Diamond, Sapphire, Emerald, Onyx, Citrine, Moonstone, Jade, Ruby) |
| **Mandiant (Google Cloud)** | `cloud.google.com/blog/topics/threat-intelligence` | `cloudblog.withgoogle.com/topics/threat-intelligence/rss/` | APT38, APT43, UNC clusters; 3CX investigation; TraderTraitor analysis |
| **Google TAG** | `blog.google/threat-analysis-group/` | `blog.google/threat-analysis-group/rss/` | DPRK zero-day exploitation; Chrome vulnerability analysis; ScarCruft/APT37 |
| **CrowdStrike** | `crowdstrike.com/en-us/blog/` | `crowdstrike.com/en-us/blog/feed` | CHOLLIMA taxonomy; Annual Global Threat Report with DPRK section |
| **Recorded Future Insikt Group** | `recordedfuture.com/blog` | `recordedfuture.com/feed` | DPRK cryptocurrency theft tracking; infrastructure mapping; Kimsuky campaigns |
| **Kaspersky GReAT / SecureList** | `securelist.com/` | `securelist.com/feed/` | Extensive Lazarus/BlueNoroff research; Operation DreamJob; AppleJeus; MATA framework. **Note: Russian-based; cross-reference with Western sources** |
| **AhnLab ASEC** | `asec.ahnlab.com/en/` | -- | South Korean vendor; most prolific tracker of Kimsuky, Andariel, Lazarus targeting Korea |

### Tier 2 -- Strong DPRK APT Coverage

| Source | Blog URL | RSS Feed | Focus |
|---|---|---|---|
| **Unit 42 (Palo Alto)** | `unit42.paloaltonetworks.com/` | `unit42.paloaltonetworks.com/feed/` | Lazarus infrastructure analysis; DPRK campaign tracking |
| **SentinelOne / SentinelLabs** | `sentinelone.com/labs/` | `sentinelone.com/labs/feed/` | Lazarus tooling analysis; DPRK supply chain investigation; JumpCloud |
| **ESET WeLiveSecurity** | `welivesecurity.com/en/` | `welivesecurity.com/en/rss/feed/` | Lazarus Operation DreamJob; APT37/ScarCruft Dolphin backdoor; macOS targeting |
| **Volexity** | `volexity.com/blog/` | `volexity.com/feed/` | SHARPEXT analysis; InkySquid (ScarCruft) watering holes; Kimsuky credential harvesting |
| **Proofpoint** | `proofpoint.com/us/blog/threat-insight` | `proofpoint.com/us/rss.xml` | TA406 (Kimsuky) campaigns; social engineering tradecraft |
| **Cisco Talos** | `blog.talosintelligence.com/` | `blog.talosintelligence.com/rss/` | Lazarus campaign analysis; YamaBot; MagicRAT |
| **Chainalysis** | `chainalysis.com/blog/` | -- | Definitive cryptocurrency theft attribution and laundering analysis; annual Crypto Crime Report |
| **Elliptic** | `elliptic.co/blog` | -- | Blockchain forensics; DPRK cryptocurrency laundering pattern analysis |
| **Sophos X-Ops** (formerly Secureworks CTU) | `news.sophos.com/en-us/category/threat-research/` | -- | Inherits Secureworks COBALT taxonomy; NICKEL ACADEMY/GLADSTONE/KIMBALL tracking |

### Tier 3 -- Supporting Coverage

| Source | Blog URL | RSS Feed | Focus |
|---|---|---|---|
| **Check Point Research** | `research.checkpoint.com/` | `research.checkpoint.com/feed/` | Lazarus and DPRK tooling analysis |
| **Symantec (Broadcom)** | `symantec-enterprise-blogs.security.com/` | -- | Stonefly (Andariel), Springtail (APT43) tracking |
| **Intel 471** | `intel471.com/blog/` | `intel471.com/blog/feed` | DPRK underground operations and IT worker fraud intelligence |
| **TRM Labs** | `trmlabs.com/blog/` | -- | DPRK cryptocurrency theft analysis and blockchain forensics |

> **Removed (validated dead as of Feb 2026):**
> - **Trellix** -- Domain completely unreachable (connection refused). Historical FireEye research on APT38 now hosted under Mandiant/Google Cloud.
> - **Binary Defense** -- RSS feed returns 404.
> - **BlackBerry** -- Blog RSS redirects to restructured corporate site.
> - **Secureworks** -- Acquired by Sophos; all URLs redirect. Moved to Tier 2 as Sophos X-Ops.

---

## 14. Social Media and OSINT Feeds

### 14.1 X/Twitter -- Government and Official

| Account | Handle | Description |
|---|---|---|
| CISA | @CISAgov | Official alerts and advisories |
| CISA Cyber | @CISACyber | Dedicated cybersecurity feed -- faster on technical advisories |
| NSA Cybersecurity | @NSACyber | Defensive guidance and nation-state threat advisories |
| FBI Cyber Division | @FBICyber | Cyber threat warnings and DPRK-specific PSAs |
| US Cyber Command | @US_CYBERCOM | DPRK malware samples uploaded to VirusTotal |
| US Treasury | @USTreasury | OFAC sanctions and designations affecting DPRK |

### 14.2 X/Twitter -- DPRK-Focused Threat Intel Researchers

| Account | Handle | Focus |
|---|---|---|
| Chainalysis | @chaaboranalysis | Leading blockchain analysis firm; DPRK crypto theft attribution |
| John Hultquist | @JohnHultquist | VP Mandiant/Google Threat Intel; DPRK operations commentary |
| Dmitri Alperovitch | @DAlperovitch | CrowdStrike co-founder; nation-state cyber strategy |
| Nick Carlsen | @Nick_Carlsen | TRM Labs; former FBI DPRK investigator; IT worker fraud expertise |
| ZachXBT | @zachxbt | Blockchain investigator; tracks DPRK laundering in real-time |
| Taylor Monahan | @taaboraylomonahan | MetaMask security; tracks DPRK cryptocurrency theft patterns and wallet clusters |
| Costin Raiu | @craiu | Former Kaspersky GReAT director; decade+ of Lazarus tracking |
| Juan Andres Guerrero-Saade | @juanandres_gs | SentinelLabs; DPRK malware analysis specialist |
| Hossein Jazi | @h_jazi | Threat researcher; Kimsuky and Lazarus campaign analysis |

### 14.3 X/Twitter -- Vendor and Institutional

| Account | Handle |
|---|---|
| Mandiant | @Mandiant |
| Microsoft Threat Intelligence | @MsftSecIntel |
| CrowdStrike | @CrowdStrike |
| Recorded Future | @RecordedFuture |
| ESET Research | @ESETresearch |
| SentinelOne | @SentinelOne |
| Kaspersky GReAT | @GReATofficial |
| AhnLab | @AhnLab_man |
| Chainalysis | @chainalysis |
| TRM Labs | @TRM_Labs |
| Elliptic | @ellaboriptic |
| CyberScoop | @CyberScoopNews |
| The Record | @TheRecord_Media |

### 14.4 X/Twitter -- Hashtags to Monitor

```
#Lazarus  #HIDDENCOBRA  #BlueNoroff  #Kimsuky  #Andariel  #APT38  #APT37  #APT43
#DiamondSleet  #SapphireSleet  #EmeraldSleet  #OnyxSleet  #CitrineSleet  #MoonstoneSleet  #JadeSleet
#TraderTraitor  #LabyrinthChollima  #StardustChollima  #VelvetChollima  #SilentChollima
#DPRKCyber  #NorthKoreaHack  #CryptoTheft  #DPRKITWorkers
#CTI  #ThreatIntel  #InfoSec
```

### 14.5 Reddit

#### Tier 1 -- Core CTI

| Subreddit | Description |
|---|---|
| r/cybersecurity | Largest general cybersec community; DPRK crypto heists surface fast |
| r/netsec | Technical network security; APT campaign write-ups |
| r/threatintel | Dedicated threat intelligence; DPRK campaign tracking and IOC sharing |
| r/ReverseEngineering | Deep technical malware analysis; Lazarus tooling teardowns |
| r/Malware | Malware analysis community; DPRK malware samples |

#### Tier 2 -- Cryptocurrency and OSINT Context

| Subreddit | Description |
|---|---|
| r/CryptoCurrency | Breaking crypto theft news; Bybit/Ronin discussions |
| r/ethereum | Ethereum-specific; Tornado Cash sanctions and bridge exploit discussions |
| r/OSINT | Open source intelligence techniques and findings |
| r/NorthKoreaNews | DPRK geopolitical context and sanctions tracking |
| r/blueteamsec | Defensive security; IOC lists, detection rules, YARA signatures |

### 14.6 YouTube Channels

| Channel | Description |
|---|---|
| SANS Institute | CTI Summit recordings; DPRK APT campaign content |
| Black Hat | Conference talks on DPRK APT research |
| Mandiant / Google Cloud Security | DPRK APT webinars and presentations |
| CrowdStrike | CHOLLIMA group threat briefings |
| Chainalysis | Cryptocurrency crime investigations including DPRK theft |
| John Hammond | Accessible malware analysis including DPRK tooling |

### 14.7 Substack and Newsletters

| Newsletter | Description |
|---|---|
| **Risky Business News** (news.risky.biz) | Best daily CTI digest; consistent DPRK coverage |
| **Kim Zetter's Zero Day** (zetter.substack.com) | Investigative cyber journalism; DPRK operations coverage |
| **Metacurity** (metacurity.substack.com) | Daily cybersecurity news; DPRK crypto theft coverage |
| **TLDR InfoSec / tl;dr sec** (tldrsec.com) | Curated security newsletter surfacing key threat reports |
| **The Cipher Brief** (thecipherbrief.com) | IC-adjacent analysis; DPRK cyber from national security perspective |
| **Lawfare** (lawfaremedia.org) | Cyber policy including DPRK sanctions legal frameworks |

### 14.8 Mastodon / Fediverse

| Instance | Description |
|---|---|
| **infosec.exchange** | Primary infosec Mastodon instance; CTI analysts active |
| **ioc.exchange** | IOC and threat intelligence sharing |
| **hackyderm.io** | Tech-focused with security researcher presence |

### 14.9 Telegram

| Channel | Description |
|---|---|
| **vx-underground** | Premier malware research community; DPRK APT samples shared |
| **DarkTracer** | Dark web monitoring and threat intel; DPRK-related leaks |
| **Chainalysis aggregators** | Cryptocurrency theft intelligence and laundering trail updates |

**OPSEC WARNING**: Exercise extreme caution with Telegram channels. Use isolated devices, VPNs, and burner accounts. Do not interact with content. DPRK-affiliated actors have historically targeted security researchers through social engineering.

### 14.10 Streaming and Video Platforms

| Platform | Channel | Description |
|---|---|---|
| **Twitch** | DEF CON (`defcon`) | Live conference streams; nation-state cyber operations talks |
| **Twitch** | Black Hat Events (`blackhatevents`) | Live conference streams and briefings |
| **Kick** | -- | No CTI presence as of February 2026 |

For conference talk archives, see YouTube channels in Section 14.6. Twitch streams are ephemeral -- VODs typically available for 14-60 days after broadcast.

---

## 15. Blockchain and Crypto OSINT Tools

### 15.1 Blockchain Analytics Platforms

| Tool | URL | Use Case |
|---|---|---|
| **Chainalysis Reactor** | `chainalysis.com` | Industry-leading blockchain investigation; DPRK wallet clustering; attribution; used by FBI/DOJ for DPRK cases. Paid platform with free Chainalysis KYT for transaction screening |
| **Elliptic** | `elliptic.co` | Blockchain analytics; DPRK laundering pattern identification; bridge exploit tracing |
| **TRM Labs** | `trmlabs.com` | Blockchain intelligence; DPRK-specific research; former FBI DPRK investigators on staff |
| **Crystal Blockchain** | `crystalblockchain.com` | Transaction monitoring and investigation; DPRK address flagging |
| **Arkham Intelligence** | `arkhamintelligence.com` | On-chain intelligence platform; entity labeling; real-time tracking of DPRK-linked wallets |

### 15.2 Free Blockchain Explorers

| Tool | URL | Use Case |
|---|---|---|
| **Etherscan** | `etherscan.io` | Ethereum blockchain explorer; trace DPRK ETH transactions; view token transfers; label known addresses |
| **BTC.com Explorer** | `explorer.btc.com` | Bitcoin blockchain explorer |
| **Blockchain.com Explorer** | `blockchain.com/explorer` | Multi-chain explorer |
| **Solscan** | `solscan.io` | Solana blockchain explorer |
| **BSCScan** | `bscscan.com` | Binance Smart Chain explorer |
| **Polygonscan** | `polygonscan.com` | Polygon/MATIC explorer |
| **Snowtrace** | `snowtrace.io` | Avalanche C-Chain explorer |
| **DeFi Llama** | `defillama.com` | DeFi protocol TVL tracking; identify potential DPRK DeFi exploit targets |

### 15.3 OFAC Sanctioned Address Lists

| Resource | URL | Use Case |
|---|---|---|
| **OFAC SDN List** | `ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists` | Official sanctions list including DPRK cryptocurrency addresses |
| **OFAC SDN Search** | `sanctionssearch.ofac.treas.gov/` | Searchable interface for sanctioned entities and crypto addresses |
| **Chainalysis Sanctioned Addresses** | Embedded in Chainalysis products | Aggregated sanctioned address dataset |

### 15.4 Tornado Cash and Mixing Service Monitoring

| Resource | Description |
|---|---|
| **Tornado Cash Deposit/Withdrawal Tracking** | Monitor Tornado Cash contract addresses on Etherscan for DPRK-linked deposits. OFAC sanctioned August 2022. |
| **Dune Analytics** | `dune.com` -- community dashboards tracking Tornado Cash flows, bridge exploit fund movement, and sanctioned address activity |
| **Nansen** | `nansen.ai` -- wallet profiling and fund flow analysis; labels known DPRK-associated wallets |

---

## 16. IOC Sources and Threat Feeds

### 16.1 AlienVault OTX

| Resource | URL |
|---|---|
| Portal | `https://otx.alienvault.com/` |
| API | `https://otx.alienvault.com/api` |
| DPRK Search | `https://otx.alienvault.com/browse/global/pulses?q=lazarus` |

**Search terms for DPRK pulses**: Lazarus, BlueNoroff, Kimsuky, Andariel, APT38, APT37, APT43, HIDDEN COBRA, TraderTraitor, Diamond Sleet, Sapphire Sleet, Emerald Sleet, AppleJeus, DPRK, North Korea

### 16.2 Abuse.ch Ecosystem

| Feed | URL | Relevant Tags |
|---|---|---|
| **URLhaus** | `https://urlhaus.abuse.ch/` | DPRK phishing URLs and payload delivery |
| **MalwareBazaar** | `https://bazaar.abuse.ch/` | Tags: Lazarus, BlueNoroff, Kimsuky, Konni, RokRAT, NukeSped, AppleJeus, BabyShark, BLINDINGCAN, Maui, MATA, Dtrack |
| **ThreatFox** | `https://threatfox.abuse.ch/` | DPRK APT IOCs (IPs, domains, hashes) |

### 16.3 MISP Feeds

| Feed | URL |
|---|---|
| CIRCL OSINT | `https://www.circl.lu/doc/misp/feed-osint/` |
| Botvrij.eu | `https://www.botvrij.eu/data/feed-osint/` |
| Default feeds list | `https://www.misp-project.org/feeds/` |

**Relevant MISP galaxy tags**: `misp-galaxy:threat-actor="Lazarus Group"`, `"APT38"`, `"Kimsuky"`, `"Andariel"`, `"ScarCruft"`, `"BlueNoroff"`

### 16.4 US Cyber Command VirusTotal

| Resource | URL |
|---|---|
| CNMF VirusTotal Account | `https://www.virustotal.com/gui/user/CYBERCOM_Malware_Alert` |

US Cyber Command's Cyber National Mission Force (CNMF) uploads DPRK malware samples directly to VirusTotal for public benefit. This is a primary source for fresh DPRK IOCs.

### 16.5 Other IOC Sources

| Source | URL | Use Case |
|---|---|---|
| **CISA KEV** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | Actively exploited CVEs including DPRK-used vulns |
| **IBM X-Force Exchange** | `https://exchange.xforce.ibmcloud.com` | Search for DPRK APT indicators and reports |
| **VirusTotal** | `https://www.virustotal.com` | DPRK malware samples; YARA hunting; infrastructure pivoting |
| **Hybrid Analysis** | `https://hybrid-analysis.com` | CrowdStrike Falcon Sandbox; free DPRK malware analysis |
| **OpenCTI** (by Filigran) | `https://github.com/OpenCTI-Platform/opencti` | Aggregation platform with connectors for all above sources |
| **MalTrail** | `https://github.com/stamparm/maltrail` | Trail-based IOC feeds including DPRK indicators |
| **YARA Rules Repo** | `https://github.com/Yara-Rules/rules` | Community YARA rules for DPRK malware families |
| **Malpedia** | `https://malpedia.caad.fkie.fraunhofer.de` | Malware family encyclopedia with DPRK APT associations |
| **CFR Cyber Ops Tracker** | `https://cfr.org/cyber-operations` | Database of all state-sponsored cyber operations including DPRK |

---

## 17. RSS/Atom Feeds for Automated Ingestion

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
> - CISA RSS (`cisa.gov/.../all.xml`) -- Returns 403.
> - NSA RSS -- Returns 403.
> - RiskIQ/PassiveTotal -- Absorbed into Microsoft Defender TI.
> - InQuest Labs -- Acquired by OPSWAT; feeds restructured.

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
| **Tier 1 (Critical)** | CISA advisories, CISA KEV, Microsoft/Mandiant/CrowdStrike blogs, Chainalysis alerts | Real-time / hourly |
| **Tier 2 (High)** | Abuse.ch feeds, OTX pulses, MISP feeds, AhnLab ASEC | Daily |
| **Tier 3 (Standard)** | MITRE ATT&CK updates, Malpedia, full vendor blog reviews, OFAC designations | Weekly |
| **Tier 4 (Enrichment)** | VirusTotal, blockchain explorers, Shodan for infrastructure pivoting | As-needed |

---

## 18. Intelligence Gaps and Collection Priorities

> **Automation Note**: The `automation/scrape_social_feeds.py` and `automation/fetch_rss_feeds.py` scripts both enforce a 90-day lookback window by default. Run `python scrape_social_feeds.py --filter dprk` and `python fetch_rss_feeds.py --filter dprk` to pull the latest DPRK-tagged intelligence from all configured social media, video, and vendor RSS sources. This should be your first step when triaging the gaps below.

### Coverage Gap: June 2025 -- February 2026

This feed's baseline knowledge extends through May 2025. The following areas require immediate live intelligence collection:

| Gap | Where to Look |
|---|---|
| **Post-May 2025 CISA advisories** | `cisa.gov/news-events/cybersecurity-advisories` -- filter for DPRK / North Korea |
| **Post-Bybit cryptocurrency theft** | Chainalysis blog, TRM Labs, Elliptic, FBI statements -- any new major theft events |
| **New Microsoft Sleet reporting** | `microsoft.com/en-us/security/blog` -- search all Sleet groups |
| **New CVE exploitation** | CISA KEV catalog filtered for recent additions; Microsoft and Google TAG for new zero-days |
| **IT worker fraud evolution** | FBI IC3, DOJ press releases, OFAC -- scheme adaptation to detection measures |
| **DPRK response to Tornado Cash enforcement** | New mixing/laundering infrastructure adopted post-sanctions |
| **Bybit fund laundering trail** | Blockchain analysis of $1.5B fund movement through Feb-Oct 2025 |
| **CrowdStrike Global Threat Report** | Published annually (usually February) -- 2026 edition for updated DPRK data |
| **Mandiant M-Trends** | Annual report -- 2026 edition for DPRK intrusion statistics |
| **UN Panel of Experts** | Annual DPRK sanctions monitoring reports; cryptocurrency theft tallies |

### Priority Collection Requirements

1. **What is the total confirmed cryptocurrency theft for 2025, and which entities were compromised?** The Bybit theft ($1.5B) dominates, but additional smaller operations are likely unreported.
2. **Has DPRK IT worker fraud adapted to increased FBI/DOJ enforcement?** Laptop farm takedowns may have driven operational changes (e.g., shift to non-US jurisdictions, new identity techniques).
3. **Are DPRK groups exploiting new zero-days in the June 2025 -- Feb 2026 window?** Historically they maintain active zero-day programs, particularly for Chrome/Chromium and Windows.
4. **Has Moonstone Sleet's fake company technique been adopted by other DPRK clusters?** The fake company model (StarGlow Ventures, etc.) represents a novel social engineering approach.
5. **What new supply chain compromises have occurred?** Post-3CX/JumpCloud, DPRK groups likely maintained software supply chain operations.
6. **Has DPRK ransomware activity increased or shifted targets?** FakePenny represented an evolution; further ransomware development is expected.
7. **How has the Bybit theft impacted DPRK sanctions evasion infrastructure?** The scale of theft likely required new laundering channels.
8. **What is the current status of DPRK cryptocurrency laundering through DeFi protocols?** Protocol enforcement and KYC changes may have shifted patterns.

---

*This document is a living reference. Review and update quarterly at minimum, or immediately following major DPRK cryptocurrency theft events or new group disclosures. All content is derived from open-source intelligence. Validate IOCs against multiple independent sources before taking blocking actions. Cryptocurrency addresses should be verified through blockchain analytics platforms before inclusion in blocklists.*
