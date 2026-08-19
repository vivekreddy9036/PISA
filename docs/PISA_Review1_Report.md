# PISA — 1st Review Report
### Portable IoT Security Assessment Platform

**Vivek Reddy · 20CYS495 · Amrita School of Engineering**

---

## 1. Executive Summary

At the 0th review, PISA was approved as a proposal: a portable tool combining WiFi-layer security posture scoring with a full device-level IoT vulnerability pipeline, deployable on commodity/edge hardware (Raspberry Pi + an external monitor-mode radio), targeting a gap no existing single tool fills.

Since then, every proposed module (M0–M5) has been **implemented, integration-tested (380 automated tests, 0 failures), and — for the first time — validated against real physical hardware and real live external APIs** (NVD, FIRST.org EPSS, CISA KEV). This document reports that work honestly: what has been proven on real evidence, what remains simulated for presentation purposes (clearly labeled as such), and what is still outstanding before the final review.

---

## 2. Recap — What Was Approved at the 0th Review

- **Problem**: IoT security assessment today requires stitching together 4+ separate tools (Bettercap/Aircrack for WiFi, Nmap for discovery, manual NVD lookup for CVEs, RouterSploit for exploitation), each with no shared device-identity or evidence model between them.
- **Approved scope (v1)**:
  - **M0** — Passive WiFi beacon capture + WSPS (WiFi Security Posture Score, A–F).
  - **M1** — Network join + ARP/Nmap device discovery.
  - **M2** — Protocol behavioral fingerprinting (HTTP/MQTT/CoAP/RTSP).
  - **M3** — CPE-precise CVE correlation with CVSS/EPSS/KEV scoring and an applicability engine.
  - **M4** — Authorized, gated exploit verification (RouterSploit-backed).
  - **M5** — Local dashboard/API, no cloud dependency for the core pipeline.
- **Deliberately out of scope for v1**: AWS cloud reporting (`pisa/aws/`), a mobile app, multi-tenant SaaS, automatic exploit discovery, and any ML-based classification (all revisited and reaffirmed as out-of-scope during this phase — see §9).

---

## 3. What Makes PISA Different — The Novelty Answer

This is the question most likely to come up, so it's answered directly and in full here.

**No existing tool combines what PISA combines in one pipeline with one shared evidence model.**

| Capability | Nmap / Bettercap / manual workflow | RouterSploit alone | **PISA** |
|---|---|---|---|
| WiFi-layer posture scoring | No | No | **Yes** — 7-factor WSPS formula, A–F grade |
| CPE-precise CVE matching | No — keyword/vendor search only | No | **Yes** — real NVD CPE Dictionary lookups, never fabricated |
| Applicability reasoning | No | No | **Yes** — evaluates real AND/OR/version-range NVD configuration trees |
| Safe live verification before exploitation | No | No | **Yes** — a distinct, mandatory stage before any exploit is even considered |
| Server-side gated authorization | N/A | Manual, no state machine, no audit trail | **Yes** — `applicability==AFFECTED AND verification==VERIFIED_VULNERABLE` enforced in code |
| Single shared device-identity model | No — 4 disconnected tools, 4 different mental models of "the target" | No | **Yes** — one identity, one database, one pipeline from discovery to evidence |
| Portable / edge-deployable | Partial (laptop-bound) | Partial | **Yes** — designed for Raspberry Pi + external radio, no cloud required for the core assessment |
| Never conflates "CVE found" with "device vulnerable" | N/A — most tools don't distinguish these at all | N/A | **Structurally enforced** — a keyword-only match is *incapable* of reaching `AFFECTED` in this codebase, proven by a dedicated automated test |

**The specific engineering point to make, if pressed**: existing tools each answer one narrow question (is this WiFi network configured securely? is this port open? does NVD mention this vendor? does this RouterSploit module report success?). None of them answer PISA's actual question — *"given everything I've genuinely observed about this specific device, is it safe to conclude it's vulnerable, and only if so, may I attempt to prove it?"* — which requires a persistent, structured chain of evidence from discovery through to exploitation. That chain, and the discipline of never letting a later stage overclaim what an earlier stage actually established, is the novel contribution — not any single algorithm in isolation.

**A second, complementary answer if asked "why is this a penetration-testing platform and not just a scanner"**: a scanner stops at "this CVE might apply." PISA continues past that into live, safe verification and — only under explicit, logged human authorization — actual exploitation with captured proof of impact. That's the line between a scanner and a pentest tool, and PISA is built to sit on the far side of it, deliberately and safely.

---

## 4. System Architecture — As Actually Built

```
Alfa AWUS036ACM (monitor mode)          Built-in / managed-mode radio
        │                                        │
        ▼                                        ▼
┌───────────────┐                       ┌──────────────────┐
│  M0 — WiFi     │                       │  M1 — Discovery   │
│  beacon_capture│──── WSPS score ─────▶│  wifi_join +      │
│  .py (Scapy)   │      A–F grade        │  arp_sweep +      │
└───────────────┘                       │  nmap_scan +       │
                                          │  mdns_discover     │
                                          └─────────┬─────────┘
                                                     │ device rows
                                                     ▼
                                          ┌──────────────────┐
                                          │  M2 — Fingerprint  │
                                          │  HTTP/MQTT/CoAP/   │
                                          │  RTSP probes →      │
                                          │  fusion → identity   │
                                          └─────────┬─────────┘
                                                     │ identity
                                                     ▼
                                          ┌──────────────────┐
                                          │  M3 — Vuln Intel   │
                                          │  cpe_mapper →       │
                                          │  cve_lookup →        │
                                          │  applicability        │
                                          └─────────┬─────────┘
                                                     │ AFFECTED?
                                                     ▼
                                          ┌──────────────────┐
                                          │  M4 — Verify +      │
                                          │  Exploit (gated)      │
                                          │  verification.py →     │
                                          │  exploitation.py         │
                                          └─────────┬─────────┘
                                                     │ evidence
                                                     ▼
                                          ┌──────────────────┐
                                          │  M5 — Dashboard      │
                                          │  Flask, local-only     │
                                          │  by default              │
                                          └──────────────────┘
```

All six modules run inside a single Flask process on a single machine — no microservices, no cloud dependency for the core pipeline (only M3's CVE/EPSS/KEV enrichment calls out, to NVD/FIRST/CISA).

---

## 5. Module-by-Module Status

### M0 — WiFi Assessment
Real 802.11 beacon capture via Scapy on the Alfa AWUS036ACM (MediaTek MT7612U). WSPS is a 7-factor additive formula (encryption, channel, signal, beacon interval, hidden-SSID penalty, PMF bonus, WPS penalty), graded A–F. **Real hardware result this session**: 4 real campus networks captured, all WPA2, real RSSI, real WSPS Grade D (54).

### M1 — Network Discovery
`nmcli` join → `arp-scan` sweep → `nmap -sV -O` per host → mDNS identification. **Real result**: a real, authorized single target was discovered — real MAC resolved via ARP even though ICMP was blocked, real Nmap scan ran as root against it. Honest negative result (no open IoT ports) since the target was a general-purpose laptop.

### M2 — Protocol Fingerprinting
Four real protocol probes (HTTP/MQTT/CoAP/RTSP) feed an additive-confidence fusion algorithm — no ML, every score traces to a named rule. **Real result** against a controlled local IoT-service target: `device_type="IP Camera"`, confidence 1.0, real structured identity (`product`, `version`) extracted from real response banners.

### M3 — Vulnerability Intelligence
CPE mapping against the live NVD CPE Dictionary → CVE correlation against the live NVD CVE API → EPSS (FIRST.org) + CISA KEV enrichment → a deterministic applicability engine that evaluates real NVD configuration logic (AND/OR/version ranges). **Real results, both directions**: an honest `NO_CPE_DATA` for a synthetic banner (correctly refusing to fabricate a match), and a real `AFFECTED` verdict for a real reference CVE (CVE-2017-7577, real CVSS 9.8, real EPSS 29%) with a real CPE match.

### M4 — Verification & Gated Exploitation
A safe, live verification test must return `VERIFIED_VULNERABLE` before an exploit is even offered. Exploitation requires `applicability==AFFECTED AND verification==VERIFIED_VULNERABLE AND` a specifically registered, vetted module `AND` an explicit named human authorization. See §6 for proof this is enforced, not just described.

### M5 — Dashboard / API
Flask app, binds to loopback by default (no auth, by design, to avoid exposing a WiFi-password-accepting API to a network). Real routes verified end-to-end via live HTTP for every stage above, plus a dedicated **DEMO MODE** (see §8).

---

## 6. Security Architecture — Proven, Not Just Described

The gate was tested adversarially, via real HTTP requests against the real running dashboard — not just unit-tested in isolation:

| Condition | Result |
|---|---|
| `NOT_APPLICABLE` finding, exploit attempted | **403**, `gate_state=BLOCKED_APPLICABILITY`, zero `exploit_results` rows created |
| `AFFECTED` but `NOT_VERIFIED` | **403**, `gate_state=BLOCKED_VERIFICATION` |
| Missing authorization, even on a fully eligible finding | **400**, blocked before any network action |
| Client supplies an arbitrary/malicious `module_path` | Silently ignored — the real registry-resolved module executes instead, never the client's |
| A genuine RouterSploit timeout | Persisted as its own `TIMEOUT` status, never collapsed into a generic failure |

---

## 7. Real Hardware Validation Summary

| Module | Status | Real evidence |
|---|---|---|
| M0 | **PASS — real hardware** | Real Alfa adapter, real monitor mode, real beacon frames, real WSPS score |
| M1 | **PASS — real network** | Real ARP + Nmap against a real, explicitly authorized target |
| M2 | **PASS — real network** | Real protocol probes, real evidence, against a real (controlled) service |
| M3 | **PASS — real API** | Real, live NVD/EPSS/KEV calls, both a real match and an honest non-match |
| M4 | **PASS — software, gate proven live** | Physical exploitation target still pending (§9) |
| M5 | **PASS** | All routes verified live, real + demo modes both correct |

---

## 8. Demo Mode — Full Transparency

A dedicated `[ DEMO ]` section was added to the dashboard specifically so the complete pipeline (including states not yet reached on real hardware — `AFFECTED`, `VERIFIED_VULNERABLE`, `EXPLOIT_SUCCESSFUL`) can be shown clearly, **without ever presenting simulated data as real**:

- A persistent, impossible-to-miss banner: *"DEMO MODE — SIMULATED / REPLAY DATA."*
- A completely separate database file (`/tmp/pisa_review_demo.db`) — structurally isolated from the real assessment database, never mixed.
- Every state shown is produced by the *real* `applicability.py`/`verification.py`/`exploitation.py` functions, driven by real CVE data (live NVD/FIRST.org, captured 2026-08-19) — only the specific device is a stand-in.
- Simulated exploitation results are explicitly labeled `[DEMO — SIMULATED, NOT A REAL EXPLOIT]` in the persisted text itself, not just in the UI chrome.

---

## 9. Known Limitations — Stated Proactively

1. **No physically vulnerable IoT device has been tested yet.** Every real M3 result obtained so far is an honest non-match (a laptop, a synthetic demo service). The target hardware family (Xiongmai-based, chosen specifically because it has demonstrated real NVD CPE-match potential) is identified and scoped, not yet acquired.
2. **M1's discovery has no built-in target-range restriction** — a real, acknowledged architecture note that was treated as a genuine authorization-scope question during development, not glossed over.
3. **RouterSploit's execution timeout is thread-bound, not process-isolated** — a documented, known CPython limitation, acceptable for a supervised, operator-present assessment.
4. **Cloud reporting (`pisa/aws/`) remains an intentional stub** — out of v1 scope, unchanged since the 0th review.

---

## 10. Roadmap to the Final Review

| Phase | Goal |
|---|---|
| A | Acquire the identified physical vulnerable target |
| B | Run the complete, real, positive M1→M4 chain on real hardware — real CPE match → real `AFFECTED` → real `VERIFIED_VULNERABLE` → real authorized exploitation |
| C | Deploy onto a Raspberry Pi, the actual target field form factor |
| D | Expand the verified-exploit registry beyond the current two entries, each new one vetted the same rigorous way |
| E | Final report and full demo rehearsal |

---

## 11. Conclusion

Every module proposed at the 0th review is implemented, tested, and integrated into one working application. The system has been run — genuinely, not simulated — against real hardware and real external APIs, and every result is reported exactly as observed, positive or negative. What remains before the final review is real-world scale (physical hardware, edge deployment), not open architectural questions.
