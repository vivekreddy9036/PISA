# FYP Project Documentation
# PISA — Portable IoT Security Assessment Platform
### End-to-End IoT Security: From Wireless Network Access to Device Exploitation

---

> **Version:** 3.0  
> **Date:** June 2026  
> **Author:** Vivek Reddy  
> **Target Publication:** IEEE Internet of Things Journal (IF 8.2)  
> **Hardware:** Raspberry Pi 4 (4GB/8GB) + Peripherals  
> **Cloud:** AWS (DynamoDB, Lambda, S3, EC2 Spot, API Gateway)  

---

## Table of Contents

0. [Current Implementation Status](#0-current-implementation-status)
1. [Project Identity](#1-project-identity)
2. [Problem Statement](#2-problem-statement)
3. [Research Objectives](#3-research-objectives)
4. [Research Questions & Hypotheses](#4-research-questions--hypotheses)
5. [5-Part Novelty Claim](#5-5-part-novelty-claim)
6. [System Architecture](#6-system-architecture)
7. [Project Scope](#7-project-scope)
8. [Module Breakdown](#8-module-breakdown)
9. [Hardware Specification & Bill of Materials](#9-hardware-specification--bill-of-materials)
10. [Software & Tech Stack](#10-software--tech-stack)
11. [AWS Cloud Architecture](#11-aws-cloud-architecture)
12. [Database Design](#12-database-design)
13. [CI/CD Pipeline](#13-cicd-pipeline)
14. [Ethics, Legal Constraints & Safety](#14-ethics-legal-constraints--safety)
15. [Project Timeline](#15-project-timeline)
16. [Related Work & Differentiation](#16-related-work--differentiation)
17. [Expected Outcomes & Deliverables](#17-expected-outcomes--deliverables)
18. [Publication Strategy](#18-publication-strategy)
19. [Extensions — If Time Permits](#19-extensions--if-time-permits)
20. [Budget](#20-budget)

---

## 0. Current Implementation Status

The rest of this document describes the full intended system. This section
states plainly what exists in code today, so it can be read on its own terms
rather than assumed to describe a finished system.

| Module | Status | Notes |
|---|---|---|
| M0 — Beacon capture | **Implemented** | Passive 802.11 beacon sniffing via Scapy; parses SSID/BSSID/channel/security/PMF/WPS |
| M0 — WSPS scoring | **Partial** | 7 of the originally-proposed 8 factors implemented (encryption, channel, signal, beacon interval, PMF, WPS, hidden SSID); cipher-suite and CVE-exposure factors deferred — see §8.0.2 |
| M0 — OUI→CVE correlation | **Implemented** | On-demand vendor lookup + live NVD 2.0 API query, triggered per-network from the dashboard |
| M0 — Handshake capture | Planned | Stub only |
| M1 — Network discovery | Planned | Stub only |
| M2 — Protocol fingerprinting | **Implemented** | On-demand MQTT/CoAP/HTTP/RTSP probing per device, fused into device_type + confidence, triggered from the dashboard |
| M3 — CVE correlation (beyond OUI-CVE) | **Implemented** | EPSS + CISA KEV correlation and a tri-metric ExploitScore (CVSS+EPSS+KEV) layered onto every NVD CVE lookup |
| M4 — Exploit pipeline | **Implemented** | RouterSploit-backed CVE verification (check-only or full exploit), gated by named operator authorization + mandatory 5s confirm, every attempt logged to `exploit_results` |
| M5 — Dashboard | **Implemented** | Session list, scan trigger (real + demo mode), session detail with WSPS grade badges, on-demand CVE lookup |
| AWS / Terraform | Planned | Terraform file is a placeholder; no Lambda/DynamoDB/S3 wiring exists |

**Why this matters:** sections below (system architecture, database design,
timeline) describe the target system this project is building toward. Where
a section's implementation has diverged from what's written (the WSPS
formula, §8.0.2; the database schema, §12), an inline note points back here
rather than the section silently overstating current state.

---

## 1. Project Identity

### Title
**PISA: Portable IoT Security Assessment Platform**  
*Automated End-to-End Security Assessment from Wireless Network Vulnerability Scoring to IoT Device Exploitation on Commodity Hardware*

### One-Line Description
A self-contained, field-deployable Raspberry Pi 4 device that autonomously assesses an environment's full IoT attack surface — from WiFi network vulnerabilities and router CVEs through to IoT device protocol fingerprinting, CVE correlation, and exploit delivery — in a single automated pipeline with cloud-backed intelligence.

### Tagline
*"Plug in. Walk in. Full attack surface — in minutes."*

### Project Type
- Hardware + Software Integration
- Cybersecurity / IoT Security
- Cloud-Connected Edge Device
- Authorized Penetration Testing Tool (Research)

### Professor Constraint Checklist
| Constraint | Status | How |
|---|---|---|
| AWS / Azure | ✓ AWS | DynamoDB, Lambda, S3, EC2 Spot, API Gateway, SNS, CloudWatch |
| CI/CD + DevOps | ✓ | GitHub Actions — OTA module deployment to RPi 4 |
| Raspberry Pi 4 + modules | ✓ | RPi 4 + WiFi adapter + GPS + touchscreen |
| IoT Security / Hardware Security | ✓ | Core domain |
| No ML/DL as core | ✓ | Rule-based protocol behavioral analysis throughout |
| No blockchain | ✓ | Not used |
| No dataset-based analysis | ✓ | Live active scanning only |

---

## 2. Problem Statement

The rapid proliferation of IoT devices across home, industrial, and enterprise environments has created a vast and poorly secured attack surface. This attack surface has two distinct layers that existing tools treat in complete isolation:

**Layer 1 — The Network Access Layer:** The WiFi networks that IoT devices connect to are themselves frequently misconfigured, running deprecated encryption (WPA2/TKIP instead of WPA3), with WPS enabled, and using router firmware containing publicly known and actively exploited CVEs. No portable tool autonomously assesses a wireless network's security posture, correlates the router hardware to applicable CVEs, and captures authentication credentials — all without active exploitation.

**Layer 2 — The Device Layer:** Once on a network, IoT devices communicate using application-layer protocols (MQTT, CoAP, Modbus, HTTP) that carry behavioral signatures specific to their manufacturer and firmware version. Existing security tools either rely on machine learning (requiring large training datasets and significant compute), identify only network service presence without deep protocol behavioral analysis, or require manual multi-tool workflows across Nmap, RouterSploit, Shodan, and Bettercap — none of which are integrated.

**The Gap:** No existing tool, product, or published research performs end-to-end, automated IoT security assessment spanning both layers — from passive wireless network vulnerability scoring through device fingerprinting, CVE correlation, and exploit delivery — on portable commodity hardware with cloud-backed intelligence. This leaves security practitioners and researchers without an efficient, field-deployable methodology for comprehensive IoT environment auditing.

**The Impact:** CISA's Known Exploited Vulnerabilities (KEV) catalog lists hundreds of IoT router and device CVEs that are actively exploited in the wild, yet the tooling to assess whether a given environment is exposed to these vulnerabilities in a unified, automated way does not exist.

---

## 3. Research Objectives

**Primary Objective**  
Design, implement, and evaluate a portable, self-contained IoT security assessment platform on Raspberry Pi 4 that performs automated two-layer security assessment: (1) WiFi network vulnerability scoring and router CVE correlation, and (2) IoT device protocol-aware behavioral fingerprinting with CVE correlation and exploit recommendation.

**Secondary Objectives**
1. Develop a WiFi Security Posture Scoring (WSPS) framework that derives a quantitative A–F security grade per network from passive beacon frame analysis alone — without active exploitation.
2. Implement protocol-aware behavioral fingerprinting for IoT devices across MQTT, CoAP, Modbus, and HTTP protocols that identifies device type, manufacturer, and firmware generation without machine learning.
3. Build an automated OUI-to-CVE and device-fingerprint-to-CVE correlation pipeline using NVD and CISA KEV data synchronized via AWS.
4. Demonstrate the complete Fingerprint → CVE → Exploit pipeline on at least 10 distinct IoT device types in a controlled lab environment.
5. Validate that the entire assessment pipeline executes end-to-end on commodity RPi 4 hardware within a field-practical time window (target: full assessment of a 10-device network in under 15 minutes).

---

## 4. Research Questions & Hypotheses

**RQ1 (Primary):**  
Can a portable, self-contained system perform end-to-end IoT security assessment — from wireless network vulnerability scoring to protocol-aware device fingerprinting and CVE-exploit correlation — without machine learning, on commodity hardware?

**RQ2 (Network Layer):**  
Can passive WiFi beacon frame analysis alone produce a reliable security posture score that accurately predicts network exploitability without active packet injection or authentication?

**RQ3 (Device Layer):**  
Do IoT devices of the same manufacturer and firmware generation exhibit sufficiently consistent protocol behavioral signatures (MQTT topic structure, CoAP response timing, HTTP header ordering) to enable deterministic device identification at accuracy rates comparable to ML-based approaches?

**RQ4 (Integration):**  
What is the accuracy, completeness, and time-to-assessment of the integrated two-layer pipeline compared to performing manual assessments using existing standalone tools (Nmap + Bettercap + RouterSploit + manual CVE lookup)?

**Hypotheses**
- H1: The WSPS framework will correctly classify network security posture with ≥90% agreement with manual expert assessment.
- H2: Protocol-aware behavioral fingerprinting will correctly identify IoT device type with ≥85% accuracy across tested devices.
- H3: The automated CVE correlation pipeline will surface all applicable Critical/High CVEs (CVSS ≥ 7.0) within 60 seconds of device identification.
- H4: End-to-end assessment time on the integrated platform will be ≤20% of the time required for equivalent manual multi-tool assessment.

---

## 5. 5-Part Novelty Claim

### Claim 1: WiFi Security Posture Scoring (WSPS) Framework
The first automated, real-time scoring system that derives a quantitative, unified A–F security grade per wireless network from passive beacon frame analysis alone. No active exploitation, no authentication, no packet injection required. Score is computed from a weighted combination of:
- Encryption protocol (WPA3-SAE = highest, WEP = lowest)
- Cipher suite strength (CCMP > TKIP)
- WPS status (enabled = critical penalty)
- Management Frame Protection (802.11w) support
- PMKID offline crack feasibility
- Router manufacturer CVE exposure (via OUI lookup)

**Differentiation from closest related work:** Existing wardriving tools (Kismet, WiGLE, airodump-ng) capture raw WiFi data but apply no security scoring. No published paper defines a passive-beacon-only posture scoring framework tied to CVE data.

---

### Claim 2: OUI-to-CVE Infrastructure Correlation
The first system to automatically correlate WiFi router hardware identity (derived from BSSID OUI + beacon Information Element fingerprinting) to applicable CVEs from NVD and CISA's KEV catalog in real-time on portable edge hardware. The pipeline:
1. Extract router manufacturer from beacon frame BSSID OUI
2. Optionally fingerprint firmware generation from beacon IE vendor extensions
3. Query AWS Lambda → NVD API + CISA KEV catalog
4. Return applicable CVEs with CVSS scores, exploit availability, and patch status
5. Integrate CVE exposure into the WSPS score for that network

**Differentiation:** No existing portable tool or published paper connects WiFi network discovery to router hardware CVE correlation. Shodan does passive CVE correlation on internet-facing devices — not local network router hardware via beacon analysis.

---

### Claim 3: Protocol-Aware Behavioral Fingerprinting with Cross-Protocol Confidence Fusion (Non-ML)
Fingerprints IoT devices by HOW they behave within application-layer protocols and by the STATE MACHINE TRANSITIONS they exhibit — not just which services they run. Specifically:
- **MQTT:** Topic hierarchy patterns, retained message presence, QoS levels, payload structure, CONNACK timing, keepalive negotiation sequence
- **CoAP:** Response option ordering, block transfer block-size negotiation behavior, observe notification interval patterns, DTLS handshake presence
- **HTTP/RTSP:** Admin panel DOM structure, header ordering, response timing, error message patterns, camera RTSP stream metadata, auth challenge format
- **Modbus:** Register address ranges, coil count patterns, function code sequences, exception response patterns

Each fingerprinter produces a per-protocol confidence score (0.0–1.0). When a device responds on multiple protocols, **Cross-Protocol Confidence Fusion** merges them:

```
combined_confidence = 1 − ∏(1 − cᵢ)   for each protocol i
```

This probabilistic AND formulation means two moderate-confidence signals (c₁=0.75, c₂=0.80) produce a fused confidence of 0.95, dramatically improving accuracy on multi-protocol devices (smart hubs, IP cameras, industrial gateways).

Additionally, PISA implements **Behavioral Drift Detection**: on repeated assessments of the same network, changes in a device's behavioral signature are flagged as potential firmware updates or compromise indicators — converting PISA from a point-in-time tool to a longitudinal monitoring platform.

**Differentiation from "From Flows to Functions" (Dec 2025, closest paper):** That work identifies IoT device types by tracking which network services are present over extended periods. PISA goes two levels deeper: (1) it analyzes behavioral patterns *within* those protocols to identify specific device models and firmware generations, and (2) it fuses evidence across multiple protocols to increase identification confidence.

---

### Claim 4: Two-Layer Integrated Assessment Pipeline on Portable Hardware with Parallel Priority-Queue Scheduling
The first system to chain WiFi network vulnerability assessment (Layer 1) with IoT device fingerprinting and exploitation (Layer 2) in a single automated pipeline on a portable Raspberry Pi 4 commodity device. The pipeline runs on a **parallel priority queue**: discovered devices are sorted by CVE risk exposure (known-bad OUI manufacturers first) and fingerprinted concurrently across multiple threads, reducing assessment time for a 10-device network from 20+ minutes (manual multi-tool) to under 8 minutes. This eliminates the fragmented multi-tool workflow (Nmap → Bettercap → RouterSploit → manual CVE lookup → manual exploit selection) with a single field-deployable device requiring no laptop, no internet connectivity for core operation, and no specialist operator knowledge.

---

### Claim 5: Tri-Metric CVE Exploitability Scoring (CVSS + EPSS + KEV) on Edge Hardware
The first portable IoT assessment tool to compute contextual exploitability using all three authoritative vulnerability signals:
- **CVSS v3.1** — severity and attack characteristics (NVD)
- **EPSS** (Exploit Prediction Scoring System, FIRST.org) — probability of exploitation in the next 30 days (updated daily)
- **CISA KEV** — confirmed active exploitation in the wild

Combined formula:
```
ExploitScore = CVSS_normalized(0–1) × (1 + 1.5×EPSS) × KEV_multiplier × Access_factor

where:
  CVSS_normalized = CVSS_score / 10.0
  EPSS            = FIRST.org daily probability (0.0–1.0)
  KEV_multiplier  = 2.0 if CISA KEV listed, else 1.0
  Access_factor   = 1.5 if service confirmed reachable, else 1.0
```

This produces a ranked exploitability index that is demonstrably more accurate than CVSS alone for prioritizing which CVEs an attacker would actually exploit first. No existing portable IoT assessment tool uses EPSS. The 2026 SBOM triage paper (Paper 34 in library) validates this as the current research frontier for CVE prioritization; PISA brings it to edge hardware for the first time.

---

## 6. System Architecture

### High-Level Two-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PISA — FIELD DEVICE (RPi 4)                  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              MODULE 0: WiFi Assessment Layer (WiSentinel)    │   │
│  │                                                             │   │
│  │  Beacon Capture → WSPS Scoring → OUI-CVE Lookup → Report   │   │
│  │  Handshake Capture (PMKID/EAPOL) → Hash Upload → AWS Crack  │   │
│  │  Deauth/EvilTwin Detection → Alert                         │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│                              │  Network joined / assessed           │
│  ┌───────────────────────────▼─────────────────────────────────┐   │
│  │              MODULE 1: Network Discovery                     │   │
│  │         Nmap scan → ARP sweep → Device inventory            │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│                              │                                      │
│  ┌───────────────────────────▼─────────────────────────────────┐   │
│  │              MODULE 2: Protocol-Aware Fingerprinting         │   │
│  │     MQTT / CoAP / Modbus / HTTP behavioral analysis         │   │
│  │     → Device type, manufacturer, firmware generation        │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│                              │                                      │
│  ┌───────────────────────────▼─────────────────────────────────┐   │
│  │              MODULE 3: CVE Correlation Engine                │   │
│  │     Device fingerprint → AWS Lambda → NVD + CISA KEV        │   │
│  │     → Ranked CVE list with CVSS + exploitability score      │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│                              │                                      │
│  ┌───────────────────────────▼─────────────────────────────────┐   │
│  │              MODULE 4: Exploit Pipeline                      │   │
│  │     RouterSploit / Metasploit → Exploit selection           │   │
│  │     → Execution → Result logging                            │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│                              │                                      │
│  ┌───────────────────────────▼─────────────────────────────────┐   │
│  │              MODULE 5: Reporting & Dashboard                 │   │
│  │     SQLite local DB → AWS S3 → PDF report + Web dashboard   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  7" Touch-   │  │  GPS Module  │  │  WiFi Adapter 1 (Monitor)│  │
│  │  screen UI   │  │  (Geotag)    │  │  WiFi Adapter 2 (Managed)│  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   AWS CLOUD       │
                    │                   │
                    │ DynamoDB          │
                    │ Lambda            │
                    │ S3                │
                    │ EC2 Spot          │
                    │ API Gateway       │
                    │ SNS               │
                    │ CloudWatch        │
                    └───────────────────┘
```

### Complete Assessment Flow (Parallel Priority-Queue Architecture)

```
START
  │
  ▼
[M0] Scan WiFi environment (monitor mode) — CONTINUOUS BACKGROUND THREAD
  │   ├── Capture beacon frames from all visible networks
  │   ├── Compute WSPS score (A–F) per network
  │   ├── OUI → Lambda → NVD → Router CVEs
  │   ├── Behavioral drift check: compare vs previous session data
  │   └── Flag target network for assessment
  │
  ▼
[M0] Passive handshake capture attempt (PMKID)
  │   ├── If PMKID captured → upload hash to S3 → Lambda → EC2 Spot (Hashcat)
  │   └── Log: network assessed, hash status, CVEs found
  │
  ▼
[M1] Join target network → ARP sweep + Nmap scan
  │   ├── Build device inventory (IP, MAC, OUI, open ports, services)
  │   └── Sort devices by CVE risk proxy:
  │         Tier 1: Known-bad OUI manufacturers (Hikvision, D-Link, Netgear...)
  │         Tier 2: Devices with known vulnerable ports (1883, 5683, 502, 554)
  │         Tier 3: All other devices
  │
  ▼
[M2+M3] PARALLEL PIPELINE — one thread per device, Tier 1 launched first
  │
  │   ┌──── Device A thread ──────────────────────────────────────────┐
  │   │ M2: MQTT fingerprint → HTTP fingerprint → Cross-Protocol Fusion│
  │   │ M3: device fingerprint → EPSS + CVSS + KEV → ExploitScore     │
  │   │ M4: top CVE → RouterSploit module → await authorization        │
  │   └───────────────────────────────────────────────────────────────┘
  │   ┌──── Device B thread ──────────────────────────────────────────┐
  │   │ M2: CoAP fingerprint → RTSP fingerprint → Cross-Protocol Fusion│
  │   │ M3: fingerprint → EPSS + CVSS + KEV → ExploitScore            │
  │   │ M4: top CVE → RouterSploit module → await authorization        │
  │   └───────────────────────────────────────────────────────────────┘
  │   ... (N threads for N devices, bounded by RPi thread pool = 4)
  │
  ▼
[M3] Unified CVE Ranking across all devices
  │   ├── Merge all device ExploitScores into session risk matrix
  │   ├── CISA KEV match → immediate SNS alert (critical finding)
  │   └── Present prioritized exploit queue to operator
  │
  ▼
[M4] Exploit Pipeline (authorized mode, manual approval per exploit)
  │   ├── Top CVE → RouterSploit/Metasploit module selection
  │   ├── Execute exploit → capture result
  │   └── Log: exploited? credential captured? shell obtained?
  │
  ▼
[M5] Generate Report
      ├── Upload all findings to AWS S3
      ├── Lambda generates PDF audit report
      ├── Push to web dashboard (API Gateway + Flask)
      └── SNS notification: "Assessment complete — N devices, X critical CVEs"

END
```

### Continuous Monitoring Mode (New in v2.0)
PISA can be left running passively — Module 0 runs indefinitely, alerting on:
- **New device** appearing on network not in previous inventory
- **WSPS score degradation** (network encryption downgraded, WPS re-enabled)
- **New CVE published** matching a previously fingerprinted device (via daily Lambda sync)
- **Behavioral drift**: device fingerprint signature changes → possible firmware update or compromise
This converts PISA from a point-in-time audit tool into an ongoing network security monitor.

---

## 7. Project Scope

### In-Scope (Core — Must Deliver)

| # | Feature | Module |
|---|---|---|
| 1 | Passive WiFi beacon frame capture and parsing | M0 |
| 2 | WiFi Security Posture Score (A–F) per network | M0 |
| 3 | OUI extraction + router manufacturer identification | M0 |
| 4 | OUI-to-CVE correlation via AWS Lambda + NVD | M0 |
| 5 | PMKID passive handshake capture | M0 |
| 6 | EAPOL 4-way handshake capture (authorized deauth) | M0 |
| 7 | Deauth flood detection (defensive sensor) | M0 |
| 8 | Network device discovery (Nmap + ARP sweep) | M1 |
| 9 | Service identification per device | M1 |
| 10 | MQTT behavioral fingerprinting (state machine + topic analysis) | M2 |
| 11 | CoAP behavioral fingerprinting (option ordering + block transfer) | M2 |
| 12 | HTTP admin panel fingerprinting (DOM + header + timing) | M2 |
| 13 | RTSP camera behavioral fingerprinting (Hikvision, Dahua, Reolink, Axis) | M2 |
| 14 | Cross-protocol confidence fusion (`1 − ∏(1−cᵢ)`) | M2 |
| 15 | Device type + manufacturer identification (non-ML, deterministic) | M2 |
| 16 | Behavioral drift detection (fingerprint delta across sessions) | M0/M2 |
| 17 | Device fingerprint → CVE lookup (NVD v2.0 API) | M3 |
| 18 | Tri-metric exploitability score (CVSS × EPSS × KEV) | M3 |
| 19 | CISA KEV real-time alerting via SNS | M3 |
| 20 | RouterSploit exploit recommendation + execution | M4 |
| 21 | Exploit result logging | M4 |
| 22 | SQLite local database (full schema — 9 tables) | M5 |
| 23 | Flask touchscreen UI | M5 |
| 24 | AWS S3 report upload + PDF report generation (Lambda) | M5 |
| 25 | AWS DynamoDB (network profiles + CVE sync + KEV catalog + EPSS cache) | Cloud |
| 26 | GitHub Actions CI/CD (OTA module deployment + Lambda deploy + Terraform) | DevOps |
| 27 | Parallel priority-queue pipeline scheduling | Core |
| 28 | Continuous monitoring mode (background sensor mode) | Core |

### Out-of-Scope (Will NOT be built)

| Feature | Reason |
|---|---|
| ML/DL-based device classification | Violates professor constraint |
| Blockchain audit logging | Violates professor constraint |
| Attacks on networks without authorization | Ethics — only authorized testing |
| Internet-scale scanning (Shodan-style) | Out of scope for portable local assessment |
| Full Metasploit integration (all modules) | RouterSploit sufficient for IoT scope |
| Mobile app | UI is touchscreen on device — no separate app needed |
| Multi-device concurrent assessment fleet | Single device — fleet is an extension |
| Deep packet inspection of encrypted traffic | TLS decryption out of scope |
| RF jamming / signal interference | Illegal — not included |

### Conditionally In-Scope (Implement if time permits — see Section 19)

| Feature | Priority | Module |
|---|---|---|
| GPS warwalking + security heatmap | High | M0 |
| AWS EC2 Spot GPU hash cracking pipeline | High | M0 |
| Modbus behavioral fingerprinting | Medium | M2 |
| ~~Evil twin / rogue AP detection~~ | ~~Medium~~ | **Moved to confirmed M0** |
| WPA3 downgrade attack detection | Medium | M0 |
| Enterprise WiFi (EAP/PEAP) analysis | Low | M0 |
| BLE device scanning + fingerprinting | Low | M2 |
| Zigbee network detection | Low | M2 |
| Remote web dashboard (API Gateway) | Medium | M5 |

---

## 8. Module Breakdown

### Module 0: WiSentinel — WiFi Assessment Layer

**Purpose:** Assess the wireless network before joining it. Provides Layer 1 security intelligence and feeds the WSPS score and router CVEs into the final audit report.

**Sub-features:**

#### 0.1 Beacon Frame Capture Engine
```
WiFi Adapter (Monitor Mode)
  → Scapy raw socket capture
  → Filter: 802.11 Management Frames (type=0, subtype=8)
  → Parse: SSID, BSSID, RSN IE, WPS IE, Vendor IE, signal strength
  → Store: SQLite network_profiles table
```
- Captures passively — zero network interaction
- Runs continuously in background thread
- Deduplicates by BSSID

#### 0.2 WiFi Security Posture Score (WSPS) Framework
Computed per network from passive beacon data alone — zero network interaction required.

> **Implementation status (v1, current):** the formula below reflects what is actually implemented in `pisa/m0/wsps.py` today — 7 additive factors, each contributing a fixed point value rather than a percentage weight of a 0–100 sub-score. This differs from the original 8-factor design proposed earlier in the project; see the note at the end of this subsection for what's deferred and why.

**Implemented factors (`pisa/m0/wsps.py`, weights in `config.WSPS_WEIGHTS`):**

| Factor | Points | Scoring Logic |
|---|---|---|
| Encryption type | up to 35 | WPA3=35, WPA2=25, WPA=10, Open=0 |
| Channel | up to 15 | Non-overlapping channel (1/6/11)=15, other channel=5, none=0 |
| Signal strength | up to 20 | >−50 dBm=20, >−70 dBm=12, >−85 dBm=6, weaker=0 |
| Beacon interval | up to 12 | Standard 100 TU=12, non-standard=5 |
| Management Frame Protection (802.11w) | +15 | PMF capability bit set in RSN IE=+15, else 0 |
| WPS status | −15 | WPS vendor-specific IE (00:50:F2, type 04) present=−15 penalty, absent=0 |
| Hidden SSID | −10 | Empty SSID in beacon=−10 penalty, else 0 |

Score is the sum of the above, clamped to [0, 100].

**Grade mapping (`config.WSPS_GRADES`):** A (≥90), B (≥75), C (≥60), D (≥45), E (≥30), F (<30)

**Deferred to a later phase (not yet implemented):**
- **Cipher suite** (CCMP vs TKIP distinction) — the RSN IE parsing already extracts the AKM suite for WPA2/WPA3 detection; extracting the pairwise cipher suite from the same structure is a natural next addition.
- **Router CVE exposure as a scoring input** — OUI→CVE correlation is implemented (`pisa/m0/oui_cve.py`) and surfaced in the dashboard, but is *not* folded into the WSPS score itself, because doing so would make `score_network()` depend on a live network call (NVD lookup) rather than being a pure function of packet-derived data — this would break offline scoring and make the existing unit tests dependent on mocking an external API.
- **PMKID offline crack feasibility** — requires active association/EAPOL interaction, not passive beacon sniffing; out of scope for the current passive-only capture architecture.
- **SSID hygiene** and **temporal stability (drift)** factors, and the planned ablation study (Cohen's κ across factor subsets) — deferred until the above are implemented and a labeled dataset for expert-agreement comparison exists.

#### 0.3 OUI-to-CVE Correlation
```
BSSID → first 3 octets (OUI)
  → Local OUI database lookup (IEEE OUI list, updated via CI/CD)
  → Manufacturer name + model family
  → AWS Lambda triggered
  → Lambda queries NVD API: vendor=<manufacturer> + product=router
  → Filter: CVEs with CVSS ≥ 7.0
  → Cross-reference CISA KEV catalog
  → Return: CVE IDs, CVSS scores, exploit status, patch availability
  → Store: DynamoDB + SQLite
```

#### 0.4 Handshake Capture
- **Passive PMKID:** Capture RSN PMKID from EAPOL message 1 — no deauth required
- **Active EAPOL (authorized mode only):** Send targeted 802.11 deauth frame → capture 4-way handshake on reconnection
- Extract hash → save `.hc22000` file → upload to S3

#### 0.5 Defensive Sensors
- **Deauth Flood Detection:** Count deauth frames per BSSID per second → alert if >10/sec
- **Evil Twin / Rogue AP Detection (Confirmed):** Detect duplicate SSID with different BSSID → flag as potential rogue AP. Also detects sudden encryption downgrade on same SSID.
- **WPA3 Downgrade Detection:** Alert if a network that previously broadcast WPA3 is now WPA2-only (Dragonblood downgrade attack indicator)

#### 0.6 Password Vulnerability Demo (Module 0.1)
Demonstrates that the captured handshake can be used to recover the WiFi password — proves the vulnerability is exploitable, not just theoretical.

```
Captured PMKID/EAPOL hash
  → aircrack-ng with RockYou wordlist (on RPi 4 CPU — light wordlists only)
  → [Optional] Upload hash to AWS EC2 Spot (Hashcat GPU cracking — full RockYou)
  → Result: "Password recovered in X minutes" OR "Strong password — not cracked"
  → Log result + crack time → include in WSPS report
```

- Only runs when operator explicitly triggers from touchscreen
- Authorization gate: operator must confirm "I own this network / have written authorization"
- Result is logged as evidence of vulnerability severity
- Never auto-runs — always manual trigger

#### 0.6 Behavioral Drift Detection
```
On every assessment session:
  → Load previous session's network + device fingerprints (from SQLite / DynamoDB)
  → Compare current WSPS score vs previous WSPS score per SSID
  → Compare current device fingerprint signatures vs previous per device (MAC)

Drift types:
  NETWORK_WSPS_DROP   → WSPS score decreased: log reason + alert (WPS re-enabled? encryption downgraded?)
  NEW_DEVICE          → Device not seen in previous session: alert (unauthorized device?)
  DEVICE_GONE         → Previously seen device no longer present: log
  FINGERPRINT_CHANGE  → Device's behavioral signature changed: flag as 'Possible firmware update or compromise'
  CVE_NEW             → CVE published since last session matches a known device fingerprint: alert

All drift events stored in: SQLite alerts table + DynamoDB + SNS notification
```
This is what converts PISA from a point-in-time audit tool into a longitudinal monitoring platform.

---

### Module 1: Network Discovery

**Purpose:** Build a complete inventory of all active devices on the network after joining.

**Sub-features:**

#### 1.1 ARP Sweep
```python
# arp-scan (shelled out to, like the Nmap step below) — discovers all devices on subnet
# Returns: IP, MAC, OUI (manufacturer) per device
```
- Faster than Nmap for initial host discovery
- Identifies manufacturer from MAC OUI
- Uses `arp-scan` rather than a hand-rolled Scapy sweep: on a large, busy
  subnet (verified on a real ~8k-address campus `/19`), Scapy's Python-level
  reply matching couldn't keep pace with the reply volume and silently missed
  most hosts, while `arp-scan` swept the same subnet completely in ~30s

#### 1.2 Nmap Service Scan
```
Target: all discovered hosts
Scan type: -sV (service version detection) + -O (OS detection)
Port range: common IoT ports
  → 1883 (MQTT)
  → 5683 (CoAP/UDP)
  → 502 (Modbus)
  → 80, 443, 8080, 8443 (HTTP/HTTPS admin)
  → 23 (Telnet)
  → 22 (SSH)
  → 554 (RTSP — cameras)
  → 5555 (ADB — Android IoT)
Output: per-device service map → feeds Module 2 routing
```

#### 1.3 Device Inventory Table
```
SQLite: devices
  - id, session_id, ip, mac, oui, manufacturer, hostname
  - open_ports (JSON), services (JSON)
  - fingerprint_result (FK), cve_count, exploit_status
  - discovery_timestamp, geolocation (lat/lng if GPS available)
```

---

### Module 2: Protocol-Aware Behavioral Fingerprinting

**Purpose:** Identify the specific device type, manufacturer, and firmware generation of each discovered IoT device by analyzing HOW it behaves within its application protocols — not just which protocols it runs.

**Routing logic:**
```
Device has port 1883 open → Run MQTT fingerprinter
Device has port 5683 open → Run CoAP fingerprinter
Device has port 502 open  → Run Modbus fingerprinter
Device has port 80/443    → Run HTTP fingerprinter
Multiple ports            → Run all applicable, merge results
```

#### 2.1 MQTT Behavioral Fingerprinter
```
Connect to broker (anonymous or with test credentials)
  → Capture: CONNACK response flags, max QoS advertised
  → Subscribe to wildcard '#' → observe topic hierarchy
  → Analyze: topic depth, naming conventions, payload structure
  → Measure: retain flag usage, LWT presence, keepalive enforcement

Fingerprint patterns:
  Tuya Smart Plug: topics follow 'tyDevice/{id}/dp/...' pattern, JSON payloads
  Shelly devices: topics follow 'shellies/{model}/...' pattern
  Tasmota: 'tele/{hostname}/STATE' topics present
  Mosquitto broker: specific CONNACK timing + protocol version support
```

#### 2.2 CoAP Behavioral Fingerprinter
```
Send GET /.well-known/core → parse resource directory
  → Analyze: resource path naming, content format IDs
Send observe request → measure notification intervals
Send block transfer → analyze block size negotiation
Measure response option ordering (device-specific)

Fingerprint patterns:
  Nordic Semiconductor IoT SDK: specific resource paths
  Contiki-NG: characteristic option ordering in responses
  RIOT OS: specific timing patterns in observe notifications
```

#### 2.3 HTTP Admin Panel Fingerprinter
```
GET / → capture full HTTP response
  → Headers: Server header value, X-Powered-By, Set-Cookie format
  → HTML: title tag, meta generator, admin panel DOM structure
  → Response timing: server processing latency
  → Error behavior: send invalid request, analyze error response format
  → Auth: login page structure, form field names, CSRF token presence

Fingerprint patterns:
  TP-Link Archer: specific title + form field names
  D-Link DIR: characteristic header combination
  Hikvision cameras: /doc/page/login.asp endpoint present
  Dahua cameras: /RPC2 endpoint + specific JSON RPC format
```

#### 2.4 RTSP Camera Behavioral Fingerprinter
IP cameras are the single most compromised IoT device class (Hikvision, Dahua — combined 500M+ deployed globally, hundreds of CISA KEV-listed CVEs).
```
Connect to port 554 (RTSP)
  → Send OPTIONS request → capture response headers
    Analyze: Server header value, Public methods list, session ID format
  → Send DESCRIBE request for /
    Analyze: SDP format, stream naming conventions, media type declarations
  → Probe /doc/page/login.asp (Hikvision), /RPC2 (Dahua), /web/index.html (Reolink)
  → Measure: auth challenge type (Digest vs Basic vs None), realm value format
  → Probe ONVIF endpoint /onvif/device_service → parse DeviceInformation response

Fingerprint patterns:
  Hikvision:   Server: App-webs/  + /doc/page/login.asp exists + ISAPI endpoint
  Dahua:       Server: Dahua + /RPC2 JSON-RPC endpoint + DH-SD auth format
  Reolink:     cgi-bin/api.cgi endpoint + specific CGI parameter format
  Axis:        Server: Apache + vapix endpoint + specific VAPIX API paths
  Generic:     ONVIF DeviceInformation → manufacturer/model from XML
```

#### 2.5 Cross-Protocol Confidence Fusion Engine
When a device responds on multiple protocols, merge individual fingerprint results:
```python
def fuse_confidence(results: list[dict]) -> dict:
    """
    results: [{device_type, manufacturer, model, confidence, protocol}, ...]
    Returns: merged fingerprint with fused confidence
    
    Uses probabilistic complement fusion:
      combined = 1 - prod(1 - c_i for each result_i matching same manufacturer)
    
    Example: MQTT c=0.75, HTTP c=0.80 → combined = 1-(0.25×0.20) = 0.95
    Conflict resolution: if top candidates differ across protocols, return both
                         with lower individual confidence (ambiguous device)
    """
```
- Multi-protocol devices (smart hubs, IP cameras with RTSP+HTTP+RTSP, routers) get dramatically higher confidence
- A device identified by one protocol only returns confidence as-is
- Cross-protocol conflicts are themselves diagnostic (possible device impersonation)

#### 2.6 Fingerprint Matching Engine
```
Each fingerprinter produces a feature vector + per-protocol confidence
  → Cross-Protocol Fusion (2.5) merges if multi-protocol
  → Compare fused fingerprint against signature database (SQLite: fingerprint_signatures)
  → Deterministic rule matching (no ML)
  → Final output: {device_type, manufacturer, model, firmware_gen, fused_confidence}
  → Compare vs previous session fingerprint → detect behavioral drift (0.6)

Signature database updated via CI/CD (GitHub Actions → S3 → RPi pull)
```

---

### Module 3: CVE Correlation Engine

**Purpose:** Map each identified device to its applicable CVEs, ranked by exploitability in the current field context.

#### 3.1 CVE Query Pipeline
```
Input: {manufacturer, model, firmware_gen} from Module 2

Step 1: Local SQLite check (cached CVEs from last sync)
Step 2 (if not cached): AWS Lambda invoked
  → Lambda queries NVD API v2.0: cpeName=cpe:2.3:h:{vendor}:{model}:*
  → Lambda cross-references CISA KEV catalog
  → Lambda returns: CVE list with CVSS v3.1 scores + exploit data
Step 3: Store results in DynamoDB + SQLite
Step 4: Compute exploitability score per CVE
```

#### 3.2 Tri-Metric Contextual Exploitability Scoring (CVSS + EPSS + KEV)
```
ExploitScore = CVSS_normalized × (1 + 1.5×EPSS) × KEV_multiplier × Access_factor

where:
  CVSS_normalized = CVSS_v3.1_score / 10.0               (NVD)
  EPSS            = FIRST.org daily exploitation probability (0.0–1.0)
                    fetched via: https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY
                    cached in DynamoDB with 24h TTL
  KEV_multiplier  = 2.0 if listed in CISA KEV catalog, else 1.0
  Access_factor   = 1.5 if service port confirmed open on this device (from M1), else 1.0

Examples:
  CVE-2021-36260 (Hikvision RCE):
    CVSS=9.8, EPSS=0.976, KEV=yes, Access=confirmed
    ExploitScore = 0.98 × (1 + 1.5×0.976) × 2.0 × 1.5 = 8.65  ← TOP PRIORITY

  CVE-2023-12345 (obscure low-EPSS):
    CVSS=8.1, EPSS=0.003, KEV=no, Access=confirmed
    ExploitScore = 0.81 × (1 + 1.5×0.003) × 1.0 × 1.5 = 1.22  ← deprioritized

Final ranking: sort all CVEs by ExploitScore descending
  ExploitScore ≥ 5.0  → CRITICAL (immediate operator alert)
  2.0–4.9             → HIGH
  0.5–1.9             → MEDIUM
  < 0.5               → LOW (informational only)
```

Academic value: EPSS is validated in the 2026 SBOM triage paper (Paper 34 in library) as superior to CVSS alone for exploit prioritization. PISA is the first portable IoT assessment tool to implement EPSS at the edge.

#### 3.3 CVE-to-Exploit Mapping
```
For each CVE with ExploitScore > 2.0:
  → Search RouterSploit module database (routersploit/modules/**)
  → Search Metasploit module index (/usr/share/metasploit-framework/modules/)
  → If module found: flag as 'exploitable with available tool'
  → Map: CVE-XXXX-YYYY → module path + expected outcome (shell/credentials/DoS)
```

#### 3.4 CISA KEV Real-Time Alerting (Core Feature)
```
During any CVE correlation result:
  IF any returned CVE is in CISA KEV catalog:
    → Immediately trigger SNS: "CRITICAL: Active exploitation CVE found on [device] at [IP]"
    → Log to alerts table with severity=CRITICAL
    → Highlight in touchscreen UI with red badge
    → Include in real-time dashboard alert feed

CISA KEV catalog synced daily via Lambda → stored in DynamoDB:
  Table: KnownExploitedVulnerabilities
    PK: cveID
    Attrs: vendorProject, productName, vulnerabilityName, dateAdded, dueDate
```

---

### Module 4: Exploit Pipeline

**Purpose:** Execute or recommend exploits against vulnerable devices in authorized assessment mode.

**Authorization Gate:**  
All exploitation requires explicit operator confirmation on the touchscreen. The system will NEVER auto-exploit without manual approval.

#### 4.1 Exploit Recommendation
```
Input: Ranked CVE list + CVE-to-exploit map from Module 3
Output: Ordered list of recommended exploits with:
  - CVE ID + CVSS score
  - Vulnerability description (2 lines)
  - RouterSploit/Metasploit module path
  - Expected outcome (credentials? shell? DoS?)
  - Risk level (will this crash the device?)
  - One-tap launch button (authorization required)
```

#### 4.2 RouterSploit Integration
```python
from routersploit.core.exploit import exploits

# Load module by path
# Set target IP + port
# Execute
# Capture: success/fail, credentials obtained, shell established
# Log to SQLite: exploit_results table
```

#### 4.3 Result Logging
```
Per exploit attempt:
  - Target device (FK to devices table)
  - CVE attempted
  - Module used
  - Result: SUCCESS / FAIL / ERROR
  - Evidence: credentials captured (hashed for storage), shell command output
  - Timestamp
```

---

### Module 5: Reporting & Dashboard

**Purpose:** Aggregate all findings into a structured, actionable audit report.

#### 5.1 Local SQLite Aggregation
All assessment data is persisted locally first — device-independent, works offline.

#### 5.2 AWS Upload Pipeline
```
Session complete → compress SQLite snapshot → upload to S3
Upload PCAP captures (handshakes) → S3
Upload fingerprint results → DynamoDB
Trigger Lambda: generate_report(session_id)
```

#### 5.3 PDF Report Generation (Lambda)
```
Lambda generates per-session PDF report:
  Executive Summary
    - Environment: X networks detected, Y devices found
    - Critical findings: Z CVEs (CVSS ≥ 9.0), W exploitable devices
    - Network security grades: [table of SSIDs + WSPS scores]
    - Devices with active exploits available: [count]

  Network Assessment (Layer 1)
    - Per-network WSPS scorecard
    - Router CVEs with CVSS scores
    - Handshake capture status
    - Recommendations (enable WPA3, disable WPS, update firmware)

  Device Assessment (Layer 2)
    - Per-device fingerprint results
    - CVE list (Critical/High only in executive view)
    - Exploit results (if authorized assessment performed)
    - Recommendations (update firmware, disable unused services)

  Appendix
    - Full CVE list with CVSS scores
    - Raw fingerprint data
    - Assessment methodology
    - Tool versions + signature database version
```

#### 5.4 Touchscreen Flask UI
```
Pages:
  / Home          → Session status, quick stats
  /networks       → WiFi network list with WSPS scores + CVE counts
  /devices        → Device inventory with fingerprint + CVE data
  /exploits       → Exploit recommendations + one-tap launch
  /report         → View/download current report
  /settings       → AWS config, assessment mode (passive/active), authorization
```

#### 5.5 Remote Web Dashboard (if extended)
```
AWS API Gateway → Flask on EC2 or Lambda
Accessible from any browser while device is in field
Same views as touchscreen UI
```

---

## 9. Hardware Specification & Bill of Materials

> **Note:** RPi 4 has built-in WiFi (BCM43455) — used for managed mode (joining target network). Only ONE external USB WiFi adapter is needed for monitor mode. TP-Link second adapter NOT required.

### What We Already Have

| Component | Status |
|---|---|
| Raspberry Pi 4 (4GB) | ✅ Already owned |
| 5V 3A USB-C Power Supply | ✅ Already owned |

### What We Are Buying

| # | Component | Specification | Est. Price (INR) | Purpose |
|---|---|---|---|---|
| 1 | **Alfa AWUS036ACM** | 802.11ac dual-band, MT7612U chip | ₹7,000 | Monitor mode — WiSentinel, beacon capture, PMKID, evil twin detection |
| 2 | **Official RPi 7" Touchscreen** | 800×480 capacitive DSI | ₹6,599 | Flask touchscreen UI |
| 3 | **Powered USB Hub** | 4-port USB 3.0, self-powered | ~₹800 | Connect Alfa + GPS + UART without RPi power issues |
| 4 | **NEO-6M GPS Module** | UART output | ~₹500 | GPS warwalking / geolocation tagging |
| 5 | **USB-to-UART Adapter** | FT232RL or similar | ~₹300 | GPS UART connection + Modbus RTU serial probing |
| | **Total to Buy** | | **~₹15,199** | |

> ⚠ **USB Hub must be self-powered (has its own DC power adapter).** The Alfa AWUS036ACM draws significant current — a bus-powered hub will cause the adapter to drop or behave unstably. Look for Anker, Ugreen, or Orico 4-port USB 3.0 powered hubs.

> **Why Alfa AWUS036ACM is required — not optional:**
> The RPi 4's built-in WiFi (BCM43455) does NOT expose monitor mode through its Linux driver — it can only be used to join networks (managed mode). You need an external USB adapter for all passive capture. The Alfa AWUS036ACM is dual-band (2.4GHz + 5GHz, 802.11ac), which means:
> - It captures beacons from ALL modern networks (most WPA3 networks are 5GHz)
> - A 2.4GHz-only adapter misses every 5GHz network — your WSPS assessment is incomplete
> - The MT7612U chip has a native Linux kernel driver (mt76) — zero driver headaches on RPi OS
> - Higher TX power → better PMKID capture success rate in the field
> - It is the standard adapter cited in WiFi security research — reviewers recognise it

### Extensions — Buy Only If Implementing Those Features

| Component | Purpose | Est. Price (INR) |
|---|---|---|
| RTL-SDR v3 dongle | RF spectrum analysis / 5G NB-IoT detection | ~₹1,500 |
| CC2531 Zigbee USB dongle | Zigbee network scanning extension | ~₹800 |
| BLE 5.0 USB dongle | BLE device scanning extension | ~₹400 |

### Hardware Architecture
```
┌─────────────────────────────────────────┐
│       Raspberry Pi 4 (4GB/8GB)          │
│                                         │
│  Built-in WiFi (BCM43455)               │
│    └──► Managed Mode only               │  ← joins target network
│         (no monitor mode on this chip)  │
│                                         │
│  USB 3.0 ──► Powered USB Hub            │
│               ├── Alfa AWUS036ACM       │  ← monitor mode, 2.4+5GHz dual-band
│               │   (MT7612U, 802.11ac)   │    beacon capture, PMKID, evil twin
│               ├── GPS NEO-6M            │  ← via USB-to-UART adapter
│               └── USB-to-UART           │  ← Modbus RTU serial probing
│                                         │
│  DSI ──► 7" Touchscreen                 │
│  USB-C ──► 5V 3A Wall PSU               │
│  microSD ──► 64GB (OS + SQLite)         │
└─────────────────────────────────────────┘
```

---

## 10. Software & Tech Stack

### Core Language
**Python 3.12** — entire project in Python for consistency and RPi compatibility

### Network & Protocol Libraries

| Library | Version | Use |
|---|---|---|
| Scapy | 2.5+ | Raw packet crafting, beacon capture, EAPOL handling |
| arp-scan | (system) | Shelled out to for ARP-based live host discovery (M1) |
| python-nmap | 1.6+ | Nmap wrapper for service discovery |
| paho-mqtt | 2.0+ | MQTT client for behavioral fingerprinting |
| aiocoap | 0.4+ | CoAP client for behavioral fingerprinting |
| pymodbus | 3.5+ | Modbus TCP/RTU client for fingerprinting |
| requests | 2.31+ | HTTP fingerprinting, NVD API calls, EPSS API calls |
| rtsp | 0.0.4+ | RTSP client for camera fingerprinting (port 554) |
| pyserial | 3.5+ | UART GPS communication |
| gpsd-py3 | 0.3+ | GPS data parsing |
| deepdiff | 7.0+ | Behavioral drift detection (fingerprint delta comparison) |
| concurrent.futures | stdlib | Thread pool executor for parallel M2/M3 pipeline |

### Framework & UI

| Library | Use |
|---|---|
| Flask 3.0 | Touchscreen web UI + API endpoints |
| Jinja2 | HTML templating for UI |
| SQLite3 (stdlib) | Local database |
| ReportLab / WeasyPrint | PDF report generation |

### Security Tools

| Tool | Use |
|---|---|
| RouterSploit | IoT exploit framework (Python — importable) |
| Hashcat (binary) | Local hash cracking (limited) |
| aircrack-ng suite | Handshake capture support |
| hcxdumptool | PMKID capture |
| hcxtools | Hash extraction + conversion |

### AWS SDK

| Library | Use |
|---|---|
| boto3 | DynamoDB, S3, Lambda invocation, SNS |
| AWS Lambda (Python 3.12) | CVE queries, report generation, hash cracking trigger |

### Testing & DevOps

| Tool | Use |
|---|---|
| pytest | Unit tests for all modules |
| pytest-cov | Coverage reporting |
| GitHub Actions | CI/CD pipeline — test + Lambda deploy + OTA RPi deploy |
| Docker | Containerized Lambda functions + local dev environment |
| Terraform | Infrastructure-as-Code for all AWS resources (IaC best practice) |
| Ansible (optional) | RPi provisioning automation |

### Operating System
**Raspberry Pi OS Lite (64-bit, Bookworm)** — headless base + manually installed packages
- Reason: full control, no unnecessary GUI overhead, monitor mode WiFi support

---

## 11. AWS Cloud Architecture

### Services Used

| AWS Service | Purpose | Tier |
|---|---|---|
| DynamoDB | Store network profiles, device profiles, CVE cache, session data | On-demand |
| S3 | Store PCAP files, PDF reports, fingerprint signature database | Standard |
| Lambda (Python 3.12) | CVE lookup, report generation, hash cracking trigger, OTA push | Serverless |
| EC2 Spot (p3.2xlarge or g4dn.xlarge) | GPU-accelerated Hashcat cracking | Spot (on-demand) |
| API Gateway | Remote web dashboard REST API | HTTP API |
| SNS | Push notifications (assessment complete, critical CVE found) | Topic |
| CloudWatch | Device health monitoring, Lambda logs, error alerts | Logs + Alarms |
| IAM | Role-based access control for device → AWS communication | Core |
| Secrets Manager | Store NVD API key, device credentials securely | Core |

### DynamoDB Tables

```
Table: NetworkProfiles
  PK: session_id
  SK: bssid
  Attrs: ssid, wsps_score, wsps_grade, encryption_type, wps_enabled,
         pmf_status, router_manufacturer, oui, cve_count, handshake_captured,
         geolat, geolng, timestamp

Table: DeviceProfiles
  PK: session_id
  SK: device_ip
  Attrs: mac, manufacturer, device_type, model, firmware_gen, confidence,
         open_ports, protocols, fingerprint_vector, cve_count

Table: CVECache
  PK: cpe_string
  SK: cve_id
  Attrs: cvss_score, cvss_vector, description, exploit_available,
         cisa_kev, epss_score, epss_percentile, patch_available,
         last_updated, ttl (24h expiry for EPSS — changes daily)

Table: EPSSCache
  PK: cve_id
  Attrs: epss_score, epss_percentile, model_version, score_date, ttl

Table: KnownExploitedVulnerabilities
  PK: cve_id
  Attrs: vendorProject, productName, vulnerabilityName,
         dateAdded, dueDate, requiredAction
  (Synced daily from CISA KEV catalog via Lambda)

Table: Sessions
  PK: session_id
  Attrs: start_time, end_time, operator, network_ssid, devices_found,
         critical_cves, exploits_attempted, drift_events, report_s3_path, status

Table: ExploitResults
  PK: session_id
  SK: exploit_id
  Attrs: target_ip, cve_id, module_used, result, evidence_hash, timestamp

Table: Alerts
  PK: session_id
  SK: alert_id
  Attrs: alert_type (KEV_MATCH|NEW_DEVICE|WSPS_DROP|FINGERPRINT_DRIFT|CVE_NEW),
         severity (CRITICAL|HIGH|MEDIUM|INFO),
         device_ip, cve_id, description, acknowledged, timestamp
```

### Lambda Functions

```
fn_cve_lookup
  Trigger: DynamoDB stream (new DeviceProfile) OR direct invoke from RPi
  Input: {manufacturer, model, firmware_gen}
  Action: Query NVD API v2.0 → fetch EPSS score (api.first.org) →
          cross-ref CISA KEV → compute ExploitScore → store in CVECache
  Output: CVE list with CVSS + EPSS + KEV + ExploitScore

fn_kev_sync
  Trigger: CloudWatch scheduled event (daily 00:00 UTC)
  Input: None
  Action: Fetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
          → Upsert all entries to KnownExploitedVulnerabilities table
          → For each known device fingerprint in DeviceProfiles → cross-reference new KEV entries
          → If match found → publish to SNS: "New KEV matches device on network [session]"
  Output: KEV sync count + alert count

fn_generate_report
  Trigger: S3 event (new session data upload) OR direct invoke
  Input: session_id
  Action: Aggregate all session data → generate PDF with WSPS scorecards +
          tri-metric CVE rankings + drift events → upload to S3 → send SNS
  Output: PDF S3 URL

fn_trigger_crack
  Trigger: S3 event (new .hc22000 file uploaded)
  Input: S3 path to hash file
  Action: Launch EC2 Spot instance with Hashcat + wordlist → store result in DynamoDB
  Output: Cracking job ID

fn_signature_update
  Trigger: Scheduled (daily) OR GitHub Actions deploy
  Input: New fingerprint signatures package
  Action: Update S3 signature database → notify connected RPi devices via SNS OTA topic
  Output: Update confirmation
```

### IAM Policy (RPi Device Role)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem", 
     "dynamodb:Query", "dynamodb:UpdateItem"], "Resource": "arn:aws:dynamodb:*:*:table/pisa-*"},
    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], 
     "Resource": "arn:aws:s3:::pisa-data/*"},
    {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], 
     "Resource": "arn:aws:lambda:*:*:function:pisa-*"},
    {"Effect": "Allow", "Action": ["sns:Publish"], 
     "Resource": "arn:aws:sns:*:*:pisa-*"}
  ]
}
```

---

## 12. Database Design

### SQLite Schema (Local — On Device)

> **Note:** this schema is generated from the actual implementation (`pisa/db/models.py`), not an aspirational design — it intentionally uses simpler `INTEGER PRIMARY KEY AUTOINCREMENT` session ids and no `CHECK` constraints, since SQLite doesn't need them for v1's usage pattern and every constraint here is enforced in application code (`pisa/db/queries.py`) instead. All 9 tables are created on startup; only `sessions`, `networks`, and `network_cves` are actively populated by v1 (M0 + dashboard). `devices` onward are defined and ready for M1–M4 but not yet written to by any code path, since those modules are still stubs.

```sql
-- Assessment sessions
CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    ended_at        TEXT,
    target_network  TEXT,
    status          TEXT    DEFAULT 'active',
    notes           TEXT
);

-- WiFi networks discovered (M0 — implemented)
CREATE TABLE networks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       INTEGER REFERENCES sessions(id),
    bssid            TEXT    NOT NULL,
    ssid             TEXT,
    channel          INTEGER,
    signal_dbm       INTEGER,
    security         TEXT,
    encryption       TEXT,
    beacon_interval  INTEGER,
    pmf_enabled      INTEGER DEFAULT 0,
    wps_enabled      INTEGER DEFAULT 0,
    hidden           INTEGER DEFAULT 0,
    wsps_score       INTEGER,
    wsps_grade       TEXT,
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    UNIQUE(bssid, session_id)
);

-- CVEs for networks, populated on-demand from OUI→NVD lookup (M0 — implemented)
CREATE TABLE network_cves (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id     INTEGER REFERENCES networks(id),
    cve_id         TEXT    NOT NULL,
    cvss_score     REAL,
    epss_score     REAL,
    kev_listed     INTEGER DEFAULT 0,
    exploit_score  REAL,
    description    TEXT,
    fetched_at     TEXT    NOT NULL
);

-- Devices discovered on network (M1 — planned, table ready but unused)
CREATE TABLE devices (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id             INTEGER REFERENCES sessions(id),
    network_id             INTEGER REFERENCES networks(id),
    ip_address             TEXT    NOT NULL,
    mac_address            TEXT,
    vendor                 TEXT,
    open_ports             TEXT,
    os_guess               TEXT,
    device_type            TEXT,
    fingerprint_confidence REAL,
    first_seen             TEXT    NOT NULL,
    last_seen              TEXT    NOT NULL
);

-- CVEs for devices, tri-metric scoring (M3 — planned, table ready but unused)
CREATE TABLE device_cves (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      INTEGER REFERENCES devices(id),
    cve_id         TEXT    NOT NULL,
    cvss_score     REAL,
    epss_score     REAL,
    kev_listed     INTEGER DEFAULT 0,
    exploit_score  REAL,
    description    TEXT,
    fetched_at     TEXT    NOT NULL
);

-- Exploit execution results (M4 — planned, table ready but unused)
CREATE TABLE exploit_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      INTEGER REFERENCES devices(id),
    cve_id         TEXT,
    module_path    TEXT    NOT NULL,
    authorized_by  TEXT    NOT NULL,
    authorized_at  TEXT    NOT NULL,
    result         TEXT,
    success        INTEGER DEFAULT 0,
    executed_at    TEXT    NOT NULL
);

-- Protocol fingerprint signatures (M2 — planned, table ready but unused)
CREATE TABLE fingerprint_signatures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER REFERENCES devices(id),
    protocol      TEXT    NOT NULL,
    feature_key   TEXT    NOT NULL,
    feature_value TEXT,
    confidence    REAL,
    captured_at   TEXT    NOT NULL
);

-- Behavioral drift log across sessions (M2 — planned, table ready but unused)
CREATE TABLE behavioral_drift (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id        INTEGER REFERENCES devices(id),
    protocol         TEXT    NOT NULL,
    baseline_value   TEXT,
    observed_value   TEXT,
    drift_score      REAL,
    flagged          INTEGER DEFAULT 0,
    detected_at      TEXT    NOT NULL
);

-- Unified alert log (used today for scan-failure alerts; broader use planned with M1-M4)
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER REFERENCES sessions(id),
    severity      TEXT    NOT NULL,
    category      TEXT    NOT NULL,
    message       TEXT    NOT NULL,
    related_id    INTEGER,
    related_type  TEXT,
    acknowledged  INTEGER DEFAULT 0,
    created_at    TEXT    NOT NULL
);
```

---

## 13. CI/CD Pipeline

### GitHub Repository Structure
```
pisa-platform/
  ├── core/
  │   ├── module0_wisentinel/
  │   │   ├── beacon_capture.py
  │   │   ├── wsps_scorer.py          # WSPS 8-factor formula
  │   │   ├── oui_cve_pipeline.py
  │   │   ├── handshake_capture.py
  │   │   └── drift_detector.py       # Behavioral drift detection
  │   ├── module1_discovery/
  │   ├── module2_fingerprinting/
  │   │   ├── mqtt_fingerprinter.py
  │   │   ├── coap_fingerprinter.py
  │   │   ├── http_fingerprinter.py
  │   │   ├── rtsp_fingerprinter.py   # Camera fingerprinting (M2.4)
  │   │   └── fusion_engine.py        # Cross-protocol confidence fusion (M2.5)
  │   ├── module3_cve/
  │   │   ├── cve_pipeline.py
  │   │   ├── epss_client.py          # FIRST.org EPSS API client
  │   │   ├── kev_matcher.py          # CISA KEV real-time alerting
  │   │   └── exploit_scorer.py       # Tri-metric ExploitScore
  │   ├── module4_exploit/
  │   ├── module5_reporting/
  │   └── pipeline/
  │       └── parallel_scheduler.py   # Priority-queue parallel pipeline
  ├── aws/
  │   ├── lambda/
  │   │   ├── fn_cve_lookup/
  │   │   ├── fn_kev_sync/            # Daily CISA KEV catalog sync
  │   │   ├── fn_generate_report/
  │   │   ├── fn_trigger_crack/
  │   │   └── fn_signature_update/
  │   └── terraform/
  │       ├── main.tf                 # DynamoDB, S3, Lambda, API GW, SNS, CloudWatch
  │       ├── variables.tf
  │       └── outputs.tf
  ├── signatures/
  │   └── fingerprint_db.json         # IoT device signatures (versioned)
  ├── tests/
  │   ├── unit/
  │   │   ├── test_wsps.py            # Ablation tests per WSPS factor
  │   │   ├── test_fusion_engine.py
  │   │   ├── test_epss_scoring.py
  │   │   └── test_drift_detector.py
  │   └── integration/
  ├── ui/
  │   └── flask_app/
  ├── .github/
  │   └── workflows/
  │       ├── test.yml
  │       ├── deploy_lambda.yml
  │       ├── deploy_terraform.yml    # Terraform plan + apply on infra changes
  │       └── deploy_device.yml
  └── requirements.txt
```

### GitHub Actions Workflows

#### workflow: test.yml (on every push)
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.12'}
      - run: pip install -r requirements.txt
      - run: pytest tests/unit/ --cov=core --cov-report=xml
      - run: pytest tests/integration/ (mock AWS)
      - uses: codecov/codecov-action@v4
```

#### workflow: deploy_lambda.yml (on push to main)
```yaml
name: Deploy Lambda Functions
on:
  push:
    branches: [main]
    paths: ['aws/lambda/**']
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
      - run: |
          for fn in aws/lambda/*/; do
            zip -r function.zip $fn
            aws lambda update-function-code \
              --function-name pisa-$(basename $fn) \
              --zip-file fileb://function.zip
          done
```

#### workflow: deploy_device.yml (on push to main — OTA to RPi)
```yaml
name: Deploy to RPi 5 (OTA)
on:
  push:
    branches: [main]
    paths: ['core/**', 'signatures/**', 'ui/**']
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Package release
        run: tar -czf pisa-release.tar.gz core/ signatures/ ui/
      - name: Upload to S3
        run: aws s3 cp pisa-release.tar.gz s3://pisa-data/releases/latest.tar.gz
      - name: Notify device (Lambda)
        run: aws lambda invoke --function-name pisa-fn_signature_update /dev/null
      # RPi polls S3 on notification and self-updates via systemd service
```

#### workflow: deploy_terraform.yml (on changes to aws/terraform/)
```yaml
name: Terraform Infrastructure Deploy
on:
  push:
    branches: [main]
    paths: ['aws/terraform/**']
jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: aws-actions/configure-aws-credentials@v4
      - run: terraform -chdir=aws/terraform init
      - run: terraform -chdir=aws/terraform plan -out=tfplan
      - run: terraform -chdir=aws/terraform apply tfplan
```
This ensures all AWS infrastructure (DynamoDB tables, Lambda functions, S3 buckets, SNS topics, IAM roles) is defined in code and reproducible from scratch — critical for DevSecOps story.

### Device OTA Update Service (systemd)
```ini
# /etc/systemd/system/pisa-updater.service
[Unit]
Description=PISA OTA Update Service

[Service]
Type=simple
ExecStart=/usr/local/bin/pisa-check-update.sh
Restart=always
RestartSec=3600  # Check every hour

[Install]
WantedBy=multi-user.target
```

---

## 14. Ethics, Legal Constraints & Safety

### Authorized Use Only
PISA is designed exclusively for **authorized security assessment** of networks and devices. The system includes the following enforcement mechanisms:

1. **Authorization Gate:** The touchscreen UI requires the operator to explicitly confirm:
   - "I own this network / have written authorization to test it"
   - Assessment mode selection: Passive (no traffic injection) / Active (authorized deauth/exploit)
   
2. **Audit Logging:** Every action (network scanned, handshake captured, exploit attempted) is timestamped, logged to SQLite, and uploaded to AWS. This creates an immutable record for authorization verification.

3. **No Auto-Exploitation:** Module 4 will never auto-execute exploits. Every exploit attempt requires a manual touchscreen tap with a 5-second confirmation countdown.

4. **Scope Limitation:** The system only assesses the currently joined network — it cannot scan networks it is not connected to (except for passive beacon analysis, which is legal in all jurisdictions studied).

### Legal Framework (India)
- **IT Act 2000, Section 43:** Unauthorized computer access is a civil offense
- **IT Act 2000, Section 66:** Unauthorized access with dishonest intent is criminal
- PISA is designed for use by network owners and authorized penetration testers only
- Academic use: testing on lab networks / personal networks is legal
- Include authorization letter template in project documentation

### Ethical Safeguards
- No plaintext credentials are stored — only SHA256 hashes of any captured credentials
- PCAP files containing handshakes are encrypted at rest on the device
- AWS S3 bucket for PCAPs is private with server-side encryption (SSE-S3)
- Deauth attacks (Module 0.4) are disabled in Passive mode
- Report PDFs are watermarked with "AUTHORIZED ASSESSMENT ONLY"

### Research Ethics
- All device testing conducted on personally owned devices in a controlled lab
- No testing on public networks, neighbors' networks, or university networks without explicit written permission
- Data from any testing is anonymized before inclusion in the research paper

---

## 15. Project Timeline

### Semester Plan (24 Weeks)

#### Phase 1: Foundation (Weeks 1–4)
| Week | Milestone |
|---|---|
| 1 | Hardware assembly + RPi OS setup + WiFi adapter monitor mode verification |
| 2 | Module 0: Beacon capture engine + basic WSPS scoring (encryption + WPS) |
| 3 | Module 0: OUI database integration + WSPS full scoring formula |
| 4 | AWS setup: DynamoDB tables + S3 buckets + IAM roles + Lambda skeleton |

**Phase 1 Deliverable:** RPi captures beacons, scores networks, OUI identified, AWS connected.

#### Phase 2: Network Layer (Weeks 5–8)
| Week | Milestone |
|---|---|
| 5 | Module 0: PMKID passive capture (hcxdumptool integration) |
| 6 | Module 0: Lambda fn_cve_lookup — NVD API integration, OUI-to-CVE pipeline |
| 7 | Module 0: EAPOL active capture + hash upload to S3 |
| 8 | Module 1: ARP sweep + Nmap integration + device inventory |

**Phase 2 Deliverable:** Full Layer 1 (WiFi) assessment working end-to-end with CVE correlation.

#### Phase 3: Device Fingerprinting (Weeks 9–15)
| Week | Milestone |
|---|---|
| 9 | Module 2: MQTT fingerprinting engine + state machine analysis + 3 device signatures |
| 10 | Module 2: HTTP admin panel fingerprinting + 5 device signatures |
| 11 | Module 2: CoAP fingerprinting engine + 2 device signatures |
| 12 | Module 2: RTSP camera fingerprinting (Hikvision, Dahua, Axis, Reolink) |
| 13 | Module 2: Cross-Protocol Confidence Fusion engine + multi-protocol devices |
| 14 | Module 2: Fingerprint signature database (SQLite) + routing logic + drift detection |
| 15 | Module 2: Integration test — accuracy evaluation on ≥10 lab devices (ablation study data collection) |

**Phase 3 Deliverable:** ≥85% accurate device fingerprinting across 10+ device types including IP cameras; cross-protocol fusion validated.

#### Phase 4: CVE & Exploit Pipeline (Weeks 16–19)
| Week | Milestone |
|---|---|
| 16 | Module 3: Device fingerprint → CVE correlation (NVD v2.0 + Lambda) |
| 17 | Module 3: EPSS API integration + Tri-Metric ExploitScore formula + CISA KEV alerting |
| 18 | Module 4: RouterSploit integration + exploit recommendation engine |
| 19 | Module 4: End-to-end test — full parallel pipeline on 5 known-vulnerable lab devices |

**Phase 4 Deliverable:** Full Fingerprint → CVSS+EPSS+KEV → Exploit pipeline working. CISA KEV alerts operational.

#### Phase 5: Reporting, CI/CD & Polish (Weeks 20–22)
| Week | Milestone |
|---|---|
| 20 | Module 5: Flask UI (all pages, alerts feed, drift view) + SQLite aggregation |
| 21 | Module 5: Lambda fn_generate_report + PDF + S3 + fn_kev_sync (daily KEV update) |
| 22 | GitHub Actions CI/CD: test suite + Lambda deploy + Terraform apply + OTA RPi deploy |

**Phase 5 Deliverable:** Complete working system with full CI/CD (4 workflows), Terraform IaC, and automated reporting.

#### Phase 6: Evaluation & Documentation (Weeks 23–24)
| Week | Milestone |
|---|---|
| 23 | Formal evaluation: WSPS ablation study, fingerprinting accuracy (per-protocol + fused), EPSS vs CVSS ranking comparison, end-to-end time vs manual baseline on 10-device network |
| 24 | Research paper draft (Paper A: WSPS/OUI-CVE short; Paper B: Full PISA system) + FYP final report |

**Phase 6 Deliverable:** Two paper drafts + FYP submission + public GitHub release.

---

## 16. Related Work & Differentiation

| Tool / Paper | Year | What It Does | PISA Difference |
|---|---|---|---|
| Pwnagotchi | 2019 | Passive PMKID capture + warwalking on RPi Zero | No CVE, no scoring, no device assessment, no cloud, not academic |
| Kismet | 2002–present | Passive WiFi logging, all protocols | Logs raw data only — no scoring, no CVE, no device fingerprinting |
| WiGLE | 2001–present | Crowdsourced SSID + encryption mapping | Cloud-only, no security scoring, no CVE, no device layer |
| WiFi Pineapple (Hak5) | Commercial | Active WiFi auditing platform | Proprietary $100+ hardware, no CVE correlation, not academic |
| Bettercap | 2018–present | Network attack toolkit | Manual operation, no CVE, no fingerprinting, not portable standalone |
| RouterSploit | 2016–present | IoT exploitation framework | No discovery, no fingerprinting, no CVE auto-lookup, not portable |
| Nmap + NSE scripts | 2000–present | Network scanning + service detection | No protocol behavioral analysis, no CVE pipeline, not integrated |
| Shodan | 2009–present | Internet-facing device indexing | Cloud-only, passive, no local assessment, no exploit pipeline |
| "From Flows to Functions" | Dec 2025 | Non-ML IoT device fingerprinting by service presence (UNSW Sydney) | Only checks WHICH services run — not HOW devices behave within protocols. No RTSP, no cross-protocol fusion, no CVE, no exploit, no hardware |
| DeviceRadar | 2024 | Packet fingerprinting on ISP switches | ISP-scale infrastructure, no CVE pipeline, no portable hardware, no WiFi layer |
| DeepFinger | 2023 | IoT protocol fingerprinting | Uses ML clustering, no CVE pipeline, no exploit, not portable |
| IoT Sentinel | 2017 | ML-based IoT device classification | Requires ML + training data, no CVE/exploit pipeline, not portable |
| SAFER (CERN) | 2022 | Fingerprinting + CVE assessment on org network | Requires enterprise infrastructure, no WiFi layer, no portable hardware, no EPSS |
| IoTective (Aston) | 2025 | Automated smart home pentest (WiFi+BLE+Zigbee) | No CVE correlation, no behavioral fingerprinting, no cloud backend, not edge-hardware |
| PISA (This Project) | 2026 | 5-part novelty: WiFi scoring (WSPS) + OUI-CVE + protocol behavioral fingerprinting (MQTT/CoAP/HTTP/RTSP) + cross-protocol fusion + CVSS×EPSS×KEV scoring + behavioral drift detection — all on RPi 5 | First system: both layers, non-ML, portable, EPSS-integrated, longitudinal monitoring capable |

---

## 17. Expected Outcomes & Deliverables

### Research Outcomes
1. A validated WiFi Security Posture Scoring (WSPS) framework with defined methodology
2. A protocol-aware behavioral fingerprinting technique for IoT devices (non-ML) — shown to achieve ≥85% accuracy
3. An automated OUI-to-CVE and fingerprint-to-CVE correlation pipeline — shown to surface all CVSS ≥ 7.0 CVEs within 60 seconds
4. Quantitative comparison: PISA vs manual multi-tool assessment (accuracy, completeness, time)
5. Full open-source release of platform + signature database

### Tangible Deliverables
| Deliverable | Target Date |
|---|---|
| Working hardware prototype | End of Week 4 |
| WiFi assessment layer (M0) | End of Week 8 |
| Device fingerprinting (M2) with 10 devices | End of Week 14 |
| Full pipeline (M0–M4) | End of Week 18 |
| Complete system with CI/CD + reports | End of Week 22 |
| Research paper draft | End of Week 24 |
| FYP final report | FYP submission deadline |
| GitHub repository (public) | On submission |
| IEEE IoT Journal paper submission | 4 weeks post-FYP |

### Key Metrics to Report in Paper

**Section VIII-A — WSPS Ablation Study**
- Evaluate WSPS with all 8 factors vs progressive subsets (2→4→6→8 factors)
- Metric: Cohen's κ agreement with 3 independent security expert ground-truth scores
- Goal: prove each added factor increases κ (justify the formula to reviewers)
- Expected result: 2-factor κ≈0.61, 8-factor κ≈0.88

**Section VIII-B — Fingerprinting Accuracy**
- Precision, Recall, F1 per protocol (MQTT / CoAP / HTTP / RTSP) individually
- Fused confidence vs single-protocol confidence for multi-protocol devices
- Confidence calibration curve: does a 0.90 confidence prediction match 90% accuracy?
- Test across ≥10 distinct device types, repeated 3× per device

**Section VIII-C — CVE Correlation Quality**
- Completeness: % of known CVEs (ground truth from vendor advisory) surfaced by PISA
- EPSS vs CVSS-only ranking: compare top-5 CVEs by each method against actual exploitation data
- Time to CVE result: seconds from fingerprint match to ranked CVE list
- Goal: PISA surfaces all CVSS≥7.0 CVEs within 60s; EPSS ranking matches historical exploit order better than CVSS alone

**Section VIII-D — End-to-End Timing**
- Per-module time breakdown: M0 (30s), M1 (45s), M2 per device (90s), M3 per device (15s), M4 (30s)
- Total time for N=10 device network: parallel pipeline vs sequential
- Comparison: PISA total vs manual multi-tool workflow (Nmap + Bettercap + RouterSploit + NVD search)
- Target: PISA ≤8min vs manual ≥45min (≥5× speedup)

**Section VIII-E — Behavioral Drift Detection**
- Simulate firmware update on lab device → verify PISA flags behavioral change
- Simulate device impersonation (MAC spoof of known device with different OS) → verify drift detected
- False positive rate: benign behavioral variation (reboots, traffic load) NOT flagged as drift

---

## 18. Publication Strategy

### Two-Paper Strategy (Maximizes Academic Output from One FYP)

#### Paper A — Short/Workshop Paper (Submit first, ~Week 24)
**Title:** "WSPS: A Passive WiFi Security Posture Scoring Framework via Beacon Frame Analysis and OUI-CVE Correlation"  
**Target:** ACM WiSec 2027 (workshop track) OR IEEE CNS 2027  
**Scope:** Module 0 only — WSPS framework, OUI-to-CVE pipeline, WSPS ablation study  
**Length:** 6 pages  
**Timeline:** Submit at Week 24 (FYP submission), decision ~3 months later  
**Value:** Earlier publication, proves WSPS novelty independently of the full system

#### Paper B — Full System Paper (Submit ~4 weeks post-FYP)
**Title:** "PISA: Portable IoT Security Assessment via Protocol-Aware Behavioral Fingerprinting and Tri-Metric CVE Exploitability Scoring on Commodity Hardware"  
**Target:** IEEE Internet of Things Journal (IF 8.2, Q1)  
**Scope:** Full system — all 5 novelty claims, full evaluation (ablation + fingerprinting + EPSS + timing + drift)  
**Length:** 12–14 pages  
**Timeline:** Submit 4 weeks post-FYP; decision ~4 months  
**Fallback:** Computers & Security (Elsevier, IF 5.6) if IoT Journal rejects

### arXiv Preprint
Submit Paper B to arXiv on the same day as journal submission — establishes timestamp priority, gets indexed by Google Scholar immediately, allows community feedback during review period.

### Conference Demo (Optional — High Visibility)
**ACM CCS 2027 Demo Track** or **NDSS 2027 Demo Track**  
Submit a 2-page demo paper with a video showing PISA running a full assessment  
Demo papers are accepted at much higher rates than full papers but appear in proceedings  
This gives a third publication line on the CV and direct community exposure

### Paper B Structure (IEEE IoT Journal)
```
I.    Introduction + Motivation (CISA KEV stats, IoT proliferation, tool fragmentation)
II.   Background & Related Work (table with 12 closest tools/papers)
III.  PISA System Architecture (two-layer, parallel pipeline overview)
IV.   WiFi Security Posture Scoring Framework (Novelty 1: WSPS, Novelty 2: OUI-CVE)
V.    Protocol-Aware Behavioral Fingerprinting (Novelty 3: protocols + RTSP + cross-protocol fusion)
VI.   Tri-Metric CVE Exploitability Scoring (Novelty 5: CVSS × EPSS × KEV)
VII.  Two-Layer Integrated Pipeline + Behavioral Drift Detection (Novelty 4)
VIII. Implementation (RPi 4 hardware, Python stack, AWS cloud, Terraform IaC, CI/CD)
IX.   Evaluation
       A. WSPS ablation study (Cohen's κ per factor subset)
       B. Fingerprinting accuracy (per protocol + cross-protocol fusion gain)
       C. EPSS vs CVSS-only CVE ranking comparison
       D. End-to-end timing (parallel vs sequential, PISA vs manual)
       E. Behavioral drift detection accuracy
X.    Ethics & Legal Considerations
XI.   Conclusion + Future Work (Federated signatures, 5G, multi-fleet)
```

---

## 19. Extensions — If Time Permits

Ranked by: (1) academic value, (2) implementation effort, (3) paper contribution

### Priority 1 — HIGH VALUE, MODERATE EFFORT

#### EXT-1: AWS EC2 Spot GPU Hash Cracking Pipeline
**What:** Upload captured PMKID/EAPOL hash → Lambda triggers EC2 Spot (p3.2xlarge) → Hashcat with RockYou + custom wordlist → result returned to device in minutes  
**Value:** Demonstrates end-to-end credential recovery without dedicated cracking hardware  
**Effort:** 1–2 weeks (Lambda + EC2 launch script + result polling)  
**Paper contribution:** Demonstrates practicality of the attack vector for the security posture argument

#### EXT-2: GPS Warwalking + Security Heatmap
**What:** GPS-tag every network with WSPS score + CVE count → generate GeoJSON → visualize as color-coded heatmap on web dashboard  
**Value:** Visual demonstration of how insecure networks are geographically distributed — strong paper figure  
**Effort:** 1 week (GPS data already flowing — just add geotag to network records + Leaflet.js map)  
**Paper contribution:** Adds "field deployment" dimension; enables large-scale study data

#### EXT-3: Remote Web Dashboard (API Gateway)
**What:** Flask dashboard accessible via browser from any location while device is in field — same views as touchscreen  
**Value:** Enables operator to monitor assessment remotely without standing next to the device  
**Effort:** 1 week (API Gateway in front of existing Flask routes + authentication)  
**Paper contribution:** Demonstrates cloud integration depth

---

### Priority 2 — HIGH VALUE, HIGHER EFFORT

#### EXT-4: Modbus Behavioral Fingerprinting
**What:** Add Modbus TCP/RTU fingerprinting — analyze register address patterns, coil counts, function code sequences to identify industrial IoT devices (PLCs, sensors, SCADA endpoints)  
**Value:** Extends system to ICS/OT (industrial) security — significantly widens paper scope and novelty  
**Effort:** 2–3 weeks (pymodbus + signature development for 5 ICS devices)  
**Paper contribution:** Adds industrial IoT angle — IEEE Industrial Informatics territory

#### ~~EXT-5: Evil Twin & Rogue AP Detection~~ ✅ MOVED TO CONFIRMED MODULE 0
This feature has been promoted to a confirmed core feature in Module 0.5. See Section 8 Module 0.

#### EXT-6: WPA3 Downgrade Detection
**What:** Detect when a network that previously broadcast WPA3 transitions to WPA2-only — indicator of a downgrade attack in progress  
**Value:** WPA3 security analysis is a growing research area — novel angle  
**Effort:** 1 week (compare historical beacon data against current)  
**Paper contribution:** New sub-contribution to WSPS framework

---

### Priority 3 — MODERATE VALUE, LOWER EFFORT

#### EXT-7: BLE Device Scanning + Fingerprinting
**What:** Use BLE USB adapter to scan for Bluetooth Low Energy devices — identify smart locks, health monitors, beacons — fingerprint by advertisement data patterns  
**Value:** Extends beyond WiFi to cover full wireless IoT attack surface  
**Effort:** 1–2 weeks (bleak or bluepy library)  
**Paper contribution:** "Cross-protocol" wireless assessment — additional novelty dimension

#### EXT-8: Zigbee Network Detection
**What:** Use CC2531 USB dongle to detect and log Zigbee networks, identify coordinator vs end devices  
**Value:** Zigbee is widely used in smart home IoT (Philips Hue, IKEA, etc.)  
**Effort:** 2 weeks (Zigbee2MQTT or custom sniffer)  
**Paper contribution:** Multi-protocol wireless coverage

#### EXT-9: MQTT Fuzzing (Lightweight)
**What:** Send malformed CONNECT, PUBLISH, and SUBSCRIBE packets to MQTT brokers and observe crash/hang behavior. Even basic fuzzing surfaces unhandled edge cases.  
**Value:** Extends PISA from "known CVE detection" to "zero-day surface discovery" — significant paper expansion  
**Effort:** 1–2 weeks (Scapy for raw MQTT packet crafting; no external fuzzer needed)  
**Paper contribution:** "Active vulnerability discovery beyond CVE databases" — new contribution angle

---

### Priority 4 — FUTURE WORK (Mention in Paper, Don't Implement)

- **Multi-device fleet:** Multiple PISA devices reporting to one cloud dashboard — enables large-scale environment assessment. Each device contributes new fingerprints to shared signature database.
- **Federated signature learning:** Multiple deployments contribute new device signatures to shared DynamoDB without sharing raw network traffic (privacy-preserving). Cite as future work in Paper B.
- **5G/LTE-M assessment:** RTL-SDR + gr-lte to detect NB-IoT/LTE-M devices in the environment — extends PISA to cellular IoT.
- **Automated firmware version detection:** Query router vendor update APIs to check if detected firmware is latest — extends CVE analysis with patch-gap measurement.
- **Attack path visualization:** Given N vulnerable devices, compute the minimal-effort path from WiFi access to critical device compromise (simplified attack graph, not full MIRAGE-style).

---

## 20. Budget

### Hardware — What We Have vs What We Buy

#### Already Owned (₹0 additional cost)

| Item | Notes |
|---|---|
| Raspberry Pi 4 (4GB) | Core compute platform |
| 5V 3A USB-C Power Supply | Wall power — lab use |

#### To Purchase

| Item | Actual Price (INR) | Notes |
|---|---|---|
| **Alfa AWUS036ACM** | ₹7,000 | Dual-band 2.4+5GHz, MT7612U, 802.11ac — monitor mode adapter |
| **Official RPi 7" Touchscreen** | ₹6,599 | 800×480 capacitive, DSI connector |
| **Powered USB Hub (4-port USB 3.0)** | ~₹800 | Must be self-powered — Anker/Ugreen/Orico recommended |
| **NEO-6M GPS Module** | ~₹500 | GPS warwalking + geolocation tagging |
| **USB-to-UART Adapter** | ~₹300 | GPS UART connection + Modbus RTU serial probing |
| **Total to Purchase** | **~₹15,199** | |

> **TP-Link TL-WN722N removed:** RPi 4 built-in WiFi (BCM43455) handles managed mode (joining target network for device discovery). Alfa handles monitor mode. No second USB adapter needed.
>
> **Power bank removed:** Using wall power supply (already owned). If field portability is needed later, a USB-C power bank can be added.

| Build Config | What's Included | Total to Spend (INR) |
|---|---|---|
| **Current build** | Alfa + Touchscreen + Hub + GPS + UART | **~₹15,199** |

### AWS Monthly Cost Estimate (During Development)

| Service | Usage | Est. Monthly Cost (INR) |
|---|---|---|
| DynamoDB | On-demand, low volume | ₹0 (free tier) |
| S3 | 5GB storage | ~₹30 |
| Lambda | ~200K invocations (CVE + EPSS + KEV daily sync) | ₹0 (free tier covers 1M/month) |
| API Gateway | Low volume dashboard | ₹0 (free tier) |
| EC2 Spot (g4dn.xlarge, ~10 hash crack jobs) | ~1–2hr total per month | ~₹300 |
| CloudWatch | Logs + alarms | ₹0 (free tier) |
| **AWS Monthly Total** | | **~₹330/month** |

### Full Project Budget

| Category | Cost (INR) |
|---|---|
| Hardware (recommended portable, no touchscreen) | ₹25,730 |
| 7" Touchscreen (optional — add for demo) | ₹3,500 |
| Extension hardware (RTL-SDR + BLE + Zigbee — optional) | ~₹2,700 |
| AWS (6 months development) | ~₹2,000 |
| Lab IoT devices for testing (3–5 cheap devices: smart plugs, IP cameras) | ~₹3,000 |
| Miscellaneous (cables, spare microSD) | ~₹500 |
| **Total without touchscreen** | **~₹35,430** |
| **Total with touchscreen** | **~₹38,930 (~$465 USD)** |

---

---

## Appendix A — 5-Part Novelty Summary (for Paper Abstract)

| # | Claim | Technical Contribution | First in Literature? |
|---|---|---|---|
| 1 | WSPS Framework | 8-factor passive beacon-only WiFi posture scoring with temporal drift tracking | Yes — no prior passive-only scoring framework tied to CVE data |
| 2 | OUI-to-CVE Correlation | Beacon BSSID OUI → router manufacturer → real-time NVD + KEV CVE lookup on edge | Yes — no tool connects WiFi network discovery to router CVE correlation locally |
| 3 | Protocol Behavioral Fingerprinting + Cross-Protocol Fusion | HOW devices behave within MQTT/CoAP/HTTP/RTSP protocols; confidence fusion via `1−∏(1−cᵢ)` | Yes — closest work (Paper 26) only checks service presence, not intra-protocol behavior |
| 4 | Two-Layer Integrated Pipeline + Behavioral Drift | WiFi layer feeds device layer in single pipeline; repeated assessments detect firmware changes | Yes — no tool chains both layers + drift detection on portable hardware |
| 5 | Tri-Metric CVE Scoring | CVSS × EPSS × KEV exploitability formula on edge hardware | Yes — EPSS never applied in portable IoT assessment context |

---

*Document Version 2.0 — June 2026*  
*Last updated: After comprehensive project sculpting pass*  
*Next update: After Zeroth Review feedback / after hardware assembly*
