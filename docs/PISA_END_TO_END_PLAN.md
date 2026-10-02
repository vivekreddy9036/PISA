# PISA — Project Idea & End-to-End Plan (Consolidated)

A single-file summary of what PISA is, how it works end to end, where it
currently stands, and what's left. Pulled together from
`docs/FYP_PROJECT_DOCUMENTATION.md` (full research doc), `docs/PISA_SRS.md`
(requirements, implementation status per requirement), and
`docs/PISA_Review1_Report.md` (what's been proven on real hardware so far) —
written so it can be read on its own, e.g. on the RPi, without pulling in
all three.

---

## 1. The idea, in one paragraph

PISA (Portable IoT Security Assessment) is a Raspberry Pi 4-based,
field-deployable security assessment tool, built in the spirit of Hak5 gear
(WiFi Pineapple, LAN Turtle) — a standalone pentest *gadget*, not a laptop
app. It assesses a target environment's full IoT attack surface in one
automated pipeline, across two layers existing tools treat separately:
**Layer 1 — the WiFi network itself** (encryption, router CVEs, handshake
capture) and **Layer 2 — the IoT devices on that network** (protocol
fingerprinting, device-specific CVE correlation, and — only under explicit
human authorization — live exploit verification). Tagline: *"Plug in. Walk
in. Full attack surface — in minutes."*

## 2. The gap it fills

Today that requires stitching together 4+ separate tools by hand — Bettercap/
Aircrack for WiFi, Nmap for discovery, manual NVD lookups for CVEs,
RouterSploit for exploitation — none of which share a device-identity or
evidence model. A scanner alone stops at "this CVE might apply"; PISA's
differentiator is carrying a structured chain of evidence all the way from
*discovery* through *CPE-precise CVE matching* through *live safety
verification* to *authorized exploitation*, never letting a later stage
overclaim what an earlier one actually established (e.g. a keyword-only CVE
match can never reach an `AFFECTED` verdict in this codebase — enforced in
code, proven by a dedicated test).

## 3. Architecture — the six modules (M0–M5)

```
Alfa AWUS036ACM (monitor mode)          RPi built-in radio (managed mode)
        │                                        │
        ▼                                        ▼
┌────────────────┐                      ┌───────────────────┐
│ M0 — WiFi       │                      │ M1 — Discovery      │
│ beacon capture  │──── WSPS score ────▶│ join + arp-scan +    │
│ (Scapy)         │      A–F grade       │ nmap + mDNS           │
└────────────────┘                      └──────────┬─────────┘
                                                      │ device rows
                                                      ▼
                                          ┌───────────────────┐
                                          │ M2 — Fingerprint     │
                                          │ HTTP/MQTT/CoAP/RTSP    │
                                          │ probes → fusion         │
                                          └──────────┬─────────┘
                                                      │ identity
                                                      ▼
                                          ┌───────────────────┐
                                          │ M3 — Vuln Intel       │
                                          │ CPE map → CVE lookup →  │
                                          │ applicability engine     │
                                          └──────────┬─────────┘
                                                      │ AFFECTED?
                                                      ▼
                                          ┌───────────────────┐
                                          │ M4 — Verify + Exploit  │
                                          │ (gated, authorized-only) │
                                          └──────────┬─────────┘
                                                      │ evidence
                                                      ▼
                                          ┌───────────────────┐
                                          │ M5 — Dashboard          │
                                          │ Flask, local-only by     │
                                          │ default                    │
                                          └───────────────────┘
```

All six modules run in a single Flask process on one machine — no
microservices. Only M3's CVE/EPSS/KEV enrichment reaches out to the
internet (NVD, FIRST.org, CISA); everything else works offline.

### Module detail

| Module | What it does | Key files |
|---|---|---|
| **M0 — WiFi Assessment** | Passive 802.11 beacon capture (Scapy) on a monitor-mode adapter; 7-factor WiFi Security Posture Score (encryption, channel, signal, beacon interval, hidden-SSID, PMF, WPS) → A–F grade; OUI→vendor→CVE lookup via live NVD; PMKID/handshake capture (passive by default) | `pisa/m0/` |
| **M1 — Network Discovery** | Joins a scored network (`nmcli`, second managed-mode radio) → `arp-scan` sweep → `nmap -sV -O` (parallel, thread pool) on IoT-relevant ports → mDNS device-name resolution | `pisa/m1/` |
| **M2 — Protocol Fingerprinting** | Probes HTTP/MQTT/CoAP/RTSP behavior per device, fuses per-protocol evidence (+ mDNS baseline) into a device-type + confidence score — rule-based, no ML | `pisa/m2/` |
| **M3 — Vulnerability Intelligence** | CPE-precise matching against the live NVD CPE Dictionary → CVE correlation → EPSS (FIRST.org) + CISA KEV enrichment → deterministic applicability engine evaluating real AND/OR/version-range NVD configuration trees → tri-metric 0–100 `exploit_score` | `pisa/m3/` |
| **M4 — Verify & Gated Exploitation** | A live, safe verification check must return `VERIFIED_VULNERABLE` before exploitation is even offered. Exploitation requires `applicability==AFFECTED AND verification==VERIFIED_VULNERABLE AND` a vetted RouterSploit module match `AND` named human authorization + mandatory 5s confirm. Every attempt (success or failure) is an append-only audit row. | `pisa/m4/` |
| **M5 — Dashboard/API** | Local Flask app, binds to loopback by default (no auth, by design — avoids exposing a WiFi-password-accepting API to a network); session list, scan trigger, per-network CVE lookup, device discovery/fingerprinting/exploit UI, plus a clearly-labeled Demo Mode (separate DB, `[DEMO]` banner, never mixed with real data) | `pisa/m5/`, `pisa/db/` |

## 4. Current implementation status (most current source: SRS v1.8 + Review1 report)

| Module | Status | Real-hardware validation |
|---|---|---|
| M0 — Beacon capture + WSPS | **Implemented** (7/8 scoring factors; cipher-suite + CVE-as-score-factor deferred by design, see SRS §FR-2) | **Pass** — real Alfa adapter, 4 real campus networks captured, real WSPS Grade D |
| M0 — OUI→CVE | **Implemented** | live NVD queries working |
| M0 — PMKID/handshake capture | **Implemented**, passive mode only (active/deauth mode exists but gated, not exposed in UI yet) | — |
| M1 — Network join + discovery | **Implemented** | **Pass** — real ARP+Nmap against a real authorized target |
| M2 — Protocol fingerprinting | **Implemented** | **Pass** — real HTTP/MQTT/CoAP/RTSP probes against a controlled IoT-service target, `device_type="IP Camera"`, confidence 1.0 |
| M3 — CVE correlation + CPE + applicability + EPSS/KEV | **Implemented** | **Pass** — real NVD/EPSS/KEV calls, both a real `AFFECTED` match (CVE-2017-7577) and an honest `NO_CPE_DATA` non-match |
| M4 — Authorized exploit verification | **Implemented** | **Pass (software)** — gate proven live via adversarial HTTP tests (see below); physical exploitation target still pending |
| M5 — Dashboard | **Implemented** | **Pass** — all routes verified live, real + demo modes both correct |
| AWS cloud reporting (`pisa/aws/`) | **Planned**, intentionally out of v1 scope | — |

**M4 gate proven adversarially** (real HTTP requests against the real running dashboard, not just unit tests):

| Condition | Result |
|---|---|
| `NOT_APPLICABLE` finding, exploit attempted | 403, zero `exploit_results` rows created |
| `AFFECTED` but not yet verified | 403, `gate_state=BLOCKED_VERIFICATION` |
| Missing authorization | 400, blocked before any network action |
| Client supplies a malicious `module_path` | silently ignored — real registry-resolved module runs instead |
| Genuine RouterSploit timeout | persisted as its own `TIMEOUT` status, not collapsed into generic failure |

380 automated tests, 0 failures, CI on every push to `main`.

## 5. Hardware

**Target end-state (Hak5-style standalone gadget, not a laptop app):**

| Component | Status | Purpose |
|---|---|---|
| Raspberry Pi 4 (4GB) | Owned | main compute |
| Alfa AWUS036ACM (MT7612U, 802.11ac dual-band) | Owned, in use | monitor-mode capture (RPi's own BCM43455 can't do monitor mode) |
| RPi built-in WiFi | — | managed-mode join (M1) |
| 7" official RPi touchscreen | Planned | field UI (DSI, 800×480) |
| Powered USB hub (self-powered, not bus-powered) | Planned | Alfa + GPS + UART without RPi power issues |
| NEO-6M → upgraded to **NEO-M9N** GPS module | **In progress** — see §6 | GPS warwalking / geolocation tagging, review-1 demo |
| USB-to-UART adapter | Planned | GPS over USB-UART + Modbus RTU probing |

**Key constraint driving UX decisions:** must run headless-friendly on RPi 4-class hardware — no heavy JS framework, no external CDN dependency, dashboard binds to loopback by default specifically so it can be viewed from a laptop while running headless on a field Pi.

**No ML/DL, no blockchain, no dataset-trained components** — a stated project constraint; all scoring/fingerprinting/fusion logic is rule-based and traceable to a named rule.

## 6. Current side-quest: ESP32 + GPS demo target (for review-1)

The review-1 panel asked for an IoT camera + GPS + ESP32 demo, plus a
justification of how the pipeline uses "many tools" once a vulnerability is
found. Rather than add a second board, a GPS module was wired into the
*existing* ESP32 (`firmware/esp32-iot-target/esp32-iot-target.ino`), which
already simulates a vulnerable IoT camera for M2/M3 testing (it answers just
enough HTTP/MQTT/CoAP/RTSP to be detected by the real M2 probes, standing in
for the Alfa-adapter-dependent live-camera case).

**Demo narrative:** M1 (nmap) finds the host → M2 fingerprints it as a
camera via HTTP/CoAP/RTSP banners → M3 flags the unauthenticated
`GET /cgi-bin/status.cgi` endpoint as an info-disclosure finding → hitting it
returns a real GPS fix (lat/lon/alt/sats). This is **deliberately not
claimed as a specific CVE** (unlike `scripts/demo_iot_target.py`, which
reproduces CVE-2019-16920 byte-for-byte because it has to satisfy
RouterSploit's real `check()` for M4) — the ESP32 target is only ever
exercised through M2/M3, never M4, so it's framed honestly as a
realistic-pattern demo finding, not a fake CVE ID.

**Status as of this session:**
- Swapped the module from NEO-6M to a 7Semi NEO-M9N breakout.
- Wiring confirmed correct and working (TX/MISO→GPIO16, RX/MOSI→GPIO17,
  5V/GND) — verified by capturing real NMEA sentences via a standalone test
  sketch.
- Firmware updated: `GPS_BAUD` 9600 → 38400 (NEO-M9N's actual default),
  comments/log strings updated NEO-6M → NEO-M9N.
- Hit a brownout/reset-loop issue powering the module directly off the
  ESP32's own USB-derived 5V rail (GPS current draw + WiFi TX bursts
  together sagging the rail). **Fix in progress:** power the GPS module from
  the RPi's 5V pin instead (RPi fed by a direct USB-C wall connection, not a
  laptop/hub), keeping GPS data lines (TX/RX) on the ESP32, with RPi GND
  tied to ESP32 GND for a shared reference. Not yet verified end-to-end.
- Full wiring/troubleshooting detail: `firmware/esp32-iot-target/GPS_WIRING_NOTES.md`.

## 7. Known limitations (stated proactively, per Review1 report)

1. No physically vulnerable IoT device has been tested yet — every real M3
   `AFFECTED` result so far is against a reference CVE, not a live owned
   device. Target hardware family (Xiongmai-based) identified, not yet
   acquired.
2. M1's discovery has no built-in target-range restriction — a real,
   acknowledged authorization-scope question, not glossed over.
3. RouterSploit's execution timeout is thread-bound, not process-isolated —
   acceptable for a supervised, operator-present assessment.
4. AWS cloud reporting remains an intentional stub, unchanged since the 0th
   review.

## 8. Roadmap to final review

| Phase | Goal |
|---|---|
| A | Acquire the identified physical vulnerable target (Xiongmai-based) |
| B | Run the complete, real, positive M1→M4 chain on real hardware — real CPE match → real `AFFECTED` → real `VERIFIED_VULNERABLE` → real authorized exploitation |
| C | Deploy onto the Raspberry Pi — the actual target field form factor |
| D | Expand the verified-exploit registry beyond the current two entries, each vetted the same rigorous way |
| E | Final report and full demo rehearsal |

## 9. Ethics / authorization posture

Authorized-use only throughout. M0 beacon capture is passive-only (no
injection/deauth by default). M1 network join is the one deliberate,
explicit, user-initiated active step (joins with a supplied password — never
deauth). M4 exploitation requires explicit, named, logged human
authorization plus a mandatory 5-second confirmation pause before any
run/check action becomes clickable — enforced in code, not just UI, and
proven adversarially (see §4 table).
