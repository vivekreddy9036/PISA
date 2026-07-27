# Software Requirements Specification

## PISA — Portable IoT Security Assessment Platform

**Version:** 1.0
**Date:** 2026-07-20
**Author:** Vivek Reddy
**Conforms to:** IEEE 830-1998 SRS structure

---

## 1. Introduction

### 1.1 Purpose

This document specifies the software requirements for PISA (Portable IoT
Security Assessment), a field-deployable tool for assessing the security
posture of a WiFi network and, in later phases, the IoT devices on it. It is
intended for the academic review panel, and as a reference for continued
development, distinct from `docs/FYP_PROJECT_DOCUMENTATION.md`, which covers
the full research motivation, novelty claims, and long-term system design.
This SRS specifies *requirements* — what the system must do — and states
plainly, per requirement, whether it is implemented in the current release
(v1) or planned for a later one.

### 1.2 Scope

PISA runs on a Raspberry Pi 4 (or any Linux host for development/demo
purposes) and provides:

- **In scope for v1 (implemented):** passive WiFi beacon capture, WiFi
  Security Posture Scoring (WSPS), OUI-based router vendor identification
  with on-demand CVE correlation via the NVD API, session persistence in
  SQLite, a browser-based dashboard to trigger scans and view results, M1
  network join + device discovery (join a scored network with its
  password, then ARP-sweep and Nmap-scan the joined subnet for live
  devices), M3 device CVE correlation via NVD with EPSS + CISA KEV
  correlation and a tri-metric ExploitScore, and M2 protocol behavioral
  fingerprinting (MQTT/CoAP/HTTP/RTSP probing fused into a device-type +
  confidence), and M4 authorized exploit verification via RouterSploit
  (operator-confirmed check/exploit against a device's already-surfaced
  CVEs, with a mandatory 5-second confirmation and a full audit log).
- **Out of scope for v1 (planned, not in this release):** AWS cloud
  reporting/storage integration.

### 1.3 Definitions, Acronyms, Abbreviations

| Term | Meaning |
|---|---|
| WSPS | WiFi Security Posture Score — a 0–100 score (and A–F grade) computed from passive beacon analysis |
| BSSID | Basic Service Set Identifier — the MAC address of a WiFi access point |
| OUI | Organizationally Unique Identifier — the vendor-specific first 3 octets of a MAC address |
| PMF | Protected Management Frames (802.11w) |
| CVE | Common Vulnerabilities and Exposures |
| NVD | National Vulnerability Database (NIST) |

### 1.4 References

- `docs/FYP_PROJECT_DOCUMENTATION.md` — full research documentation, novelty claims, long-term architecture
- IEEE 802.11-2020 — WiFi beacon frame and RSN information element format
- NVD API 2.0 documentation (`https://nvd.nist.gov/developers/vulnerabilities`)

### 1.5 Overview

Section 2 describes the product at a high level. Section 3 lists specific
functional and non-functional requirements, each tagged **[Implemented]** or
**[Planned]**. Section 4 covers use cases for the v1 WiFi assessment flow.

---

## 2. Overall Description

### 2.1 Product Perspective

PISA v1 is a standalone Flask web application backed by a local SQLite
database. It is not part of a larger existing product; it is the first
release of a system intended to grow into a full IoT security assessment
pipeline (see §7 "Project Scope" in the FYP documentation for the target
end-state).

### 2.2 Product Functions (summary)

1. Capture WiFi beacon frames from a monitor-mode interface.
2. Score each discovered network's security posture (WSPS) and assign a
   letter grade.
3. Identify a network's access-point vendor from its BSSID and, on request,
   look up known CVEs for that vendor.
4. Persist scan sessions and results, and present them in a dashboard.
5. On request, join a scored network with its WiFi password and discover
   devices on it (ARP sweep + Nmap port/OS scan), recording IP, MAC,
   vendor, open ports, and OS guess per device.
6. On request, look up known CVEs for a discovered device from its Nmap OS
   guess (or OUI vendor as fallback).
7. On request, fingerprint a discovered device's MQTT/CoAP/HTTP/RTSP
   behavior and fuse the signals into a device-type + confidence.
8. On request, and only under explicit, logged operator authorization,
   verify a device's already-found CVE against RouterSploit (check-only
   or full exploit), gated by a mandatory 5-second confirmation.

### 2.3 User Characteristics

The primary user is an authorized security assessor (e.g. a student
demonstrating the tool, or a professional running a sanctioned WiFi
assessment) with basic familiarity with WiFi security concepts (encryption
types, WPS) but not necessarily with packet-level protocol details.

### 2.4 Constraints

- WiFi beacon capture (M0) is passive-only — no active association or
  packet injection. M1 network join is the one deliberate, explicit,
  user-initiated exception: it actively associates to a target network
  with a supplied password to enable device discovery. It still never
  performs packet injection or deauthentication.
- No ML/DL, blockchain, or dataset-trained components (project constraint).
- Must run on Raspberry Pi 4 class hardware — lightweight, no heavy JS
  frontend framework, no external CDN dependency (field deployment may lack
  internet access for the dashboard itself, though live NVD/CVE lookups do
  require connectivity).
- Authorized-use only; see §14 "Ethics, Legal Constraints & Safety" in the
  FYP documentation.

### 2.5 Assumptions and Dependencies

- A monitor-mode-capable WiFi adapter is required for beacon capture (M0).
- M1 network join assumes a second, managed-mode WiFi radio distinct from
  the monitor-mode adapter (dual-radio hardware — e.g. a Raspberry Pi's
  built-in adapter for joining, plus an external adapter for capture).
- Live CVE lookups depend on the NVD 2.0 REST API being reachable and its
  (currently generous but rate-limited) unauthenticated request quota.

---

## 3. Specific Requirements

### 3.1 Functional Requirements

#### FR-1: WiFi Beacon Capture — **[Implemented]**

The system shall capture 802.11 beacon frames from a specified monitor-mode
interface for a configurable duration and extract, per network: BSSID, SSID
(or hidden-network indicator), channel, signal strength, beacon interval,
encryption type (Open/WPA/WPA2/WPA3), PMF capability, and WPS status.

*Implementation:* `pisa/m0/beacon_capture.py`

#### FR-2: WiFi Security Posture Scoring (WSPS) — **[Implemented, partial factor set]**

The system shall compute a 0–100 score and A–F grade for each captured
network from encryption type, channel (overlapping vs. non-overlapping),
signal strength, beacon interval regularity, PMF capability, WPS status, and
hidden-SSID status.

Cipher-suite detail and CVE-exposure-as-a-scoring-factor are **[Planned]** —
deferred because folding a live CVE lookup into the score would make scoring
depend on network connectivity and break the property that scoring is a pure
function of captured packet data. See FYP documentation §8.0.2 for full
rationale.

*Implementation:* `pisa/m0/wsps.py`, weights in `config.py`

#### FR-3: OUI-to-Vendor and Vendor-to-CVE Lookup — **[Implemented]**

The system shall derive an access point's vendor from its BSSID's OUI
(IEEE OUI database) and, on user request (not automatically), query the NVD
2.0 API for CVEs associated with that vendor, storing results against the
network.

*Implementation:* `pisa/m0/oui_cve.py`, `pisa/m5/routes/api.py`

#### FR-4: Scan Session Management — **[Implemented]**

The system shall create a session record when a scan starts, track its
status (`active`/`running`/`done`/`error`), and persist all networks
discovered during that session, associated with the session.

*Implementation:* `pisa/db/models.py`, `pisa/db/queries.py`, `pisa/m0/scan_runner.py`

#### FR-5: Demo Mode — **[Removed, v1.2]**

Originally provided a mode that generated synthetic network data through
the same scoring/persistence path as a real capture, for development
without monitor-mode hardware. Removed in v1.2: PISA is a real-time
assessment tool operating against live hardware and live networks only, and
a synthetic-data path risked being mistaken for a live capture. Test
coverage for the scan/CVE code paths now mocks the real capture/lookup
functions directly (see `tests/m5/test_routes.py`) instead of relying on a
product-facing demo feature.

#### FR-6: Dashboard — **[Implemented]**

The system shall provide a web dashboard that: lists past scan sessions;
allows starting a new scan (interface, duration); shows per-session network
results with WSPS grade badges; allows triggering an on-demand CVE lookup
per network; and, per network, allows joining it with its WiFi password and
viewing the devices discovered on it (FR-7).

*Implementation:* `pisa/m5/`

#### FR-12: PMKID / EAPOL Handshake Capture — **[Implemented, passive mode]**

The system shall capture WPA PMKID and 4-way-handshake material from a
monitor-mode interface by orchestrating `hcxdumptool`/`hcxpcapngtool` (not a
from-scratch 802.11i EAPOL-Key parser — scapy 2.5's EAPOL layer only decodes
the 4-byte header). Passive mode (default) transmits nothing — it only
captures a handshake if the AP or a client generates one on its own, and may
legitimately capture zero hashes in a short window. Active mode (deauth-based
forced capture) requires an explicit `authorized=True` argument from the
caller and is gated the same way FYP documentation §14 requires for any
active/authorized-mode action; it is not exposed anywhere in the dashboard UI
yet, so in practice only passive mode is reachable today. Successful captures
are written as `.hc22000` hash files and linked to the matching `networks`
row (`handshake_captured`, `handshake_type`, `handshake_path`,
`handshake_captured_at` — added to the schema in Sprint 2, migrated
in-place for pre-existing databases).

*Implementation:* `pisa/m0/handshake.py`, `pisa/db/models.py`
(`_migrate_handshake_columns`), `pisa/db/queries.py`
(`mark_handshake_captured`, `find_network_by_bssid`)

#### FR-7: IoT Device Discovery — **[Implemented]**

The system shall join a scored network on request, given its WiFi password,
via a managed-mode interface distinct from the monitor-mode capture
interface (`config.JOIN_IFACE`), then discover devices on the joined subnet:
an `arp-scan` sweep (shelled out to; a Scapy-based sweep was tried first but
couldn't keep up with reply volume on a large, busy subnet — verified on a
real ~8k-address campus `/19`, where it surfaced a handful of hosts against
`arp-scan`'s complete sweep in ~30s) for live hosts, followed by an Nmap
`-sV -O` scan restricted to
common IoT-relevant ports (MQTT 1883, CoAP 5683, Modbus 502, RTSP 554, plus
common web/mgmt/remote-access ports) for open ports, service names, and an
OS guess per host. Vendor is resolved from each host's MAC OUI (same lookup
path as FR-3). Each host is also queried over mDNS (DNS-SD,
`224.0.0.251:5353`) for a self-announced friendly instance name and
advertised service types, mapped to a human-readable device-type label —
added after reverse DNS was tried and confirmed non-functional on the
actual target network, while mDNS was confirmed to work (resolves real
device names independent of the network's own DNS infrastructure). Results
are recorded per device (IP, MAC, vendor, open ports, OS guess, mDNS name,
device type) against the joined network and session.

The Nmap stage runs concurrently across hosts (`config.NMAP_MAX_WORKERS`, a
`ThreadPoolExecutor`) rather than one host at a time — sequential scanning at
up to `config.NMAP_HOST_TIMEOUT` per host was a multi-hour bottleneck once
the `arp-scan` fix above started surfacing hundreds of live hosts instead of
a handful. One host's scan raising (nmap crash, vendor-lookup error, etc.)
is isolated and recorded as a `warning`-severity alert rather than aborting
devices already scanned successfully by the rest of the pool.

Protocol-level behavioral fingerprinting beyond Nmap's OS/service guess is
FR-8/M2; device-specific CVE correlation is FR-9.

*Implementation:* `pisa/m1/wifi_join.py`, `pisa/m1/arp_sweep.py`,
`pisa/m1/nmap_scan.py`, `pisa/m1/mdns_discover.py`,
`pisa/m1/discovery_runner.py`

#### FR-8: Protocol Behavioral Fingerprinting — **[Implemented]**

The system shall fingerprint discovered devices by probing MQTT, CoAP, HTTP,
and RTSP protocol behavior and fuse per-protocol confidence into a combined
device-type confidence score.

On user request (matching FR-3/FR-9's rule), the system probes each open
port on a discovered device against the protocol it's associated with
(MQTT 1883, HTTP 80/443/8080/8443, RTSP 554), plus CoAP (5683) probed
unconditionally since it's UDP and never appears in Nmap's TCP-only
open-port list from FR-7. Each protocol probe fails soft (empty result on
any timeout/error) and returns zero or more evidence features
(`fingerprint_signatures`), each optionally suggesting a device-type. The
existing mDNS-derived device type from FR-7 is included as a candidate at
a fixed baseline weight; fusion sums confidence per candidate device-type
(capped at 1.0) and the highest-scoring one, with its confidence, is
written back to `devices.device_type`/`devices.fingerprint_confidence`.

Devices can be fingerprinted individually (`fingerprint_device`) or in bulk
for a whole network (`fingerprint_network`, `run_fingerprint_network`),
which fans out across a thread pool (`config.M2_MAX_WORKERS`) the same way
FR-7's Nmap stage does — each device's mandatory CoAP probe alone costs up
to `config.M2_PROBE_TIMEOUT`, making a sequential sweep impractical at the
device counts FR-7 now surfaces. One device's probe raising is isolated and
recorded as a `warning`-severity alert rather than aborting the batch.

*Implementation:* `pisa/m2/mqtt_probe.py`, `coap_probe.py`, `http_probe.py`,
`rtsp_probe.py`, `fusion.py`, `fingerprint_runner.py`,
`pisa/m5/routes/api.py` (`fingerprint_device`, `fingerprint_network`,
`fingerprint_network_status`)

#### FR-9: Device CVE Correlation — **[Implemented]**

The system shall correlate discovered devices against known CVEs, on user
request (not automatically, matching FR-3's rule). The search keyword
prefers the device's Nmap `os_guess`, simplified to drop version-specific
detail (`_simplify_os_guess`: e.g. "Cisco Nexus switch (NX-OS 6.0(2))" ->
"Cisco Nexus switch" — NVD's `keywordSearch` ANDs every token, so a literal
version string zeroes out otherwise-relevant results). There is no
vendor-only fallback when no OS guess is available (`lookup_device_cves`
returns `None`, distinct from `[]`) — verified in practice that a
vendor-only search is too generic to mean anything, returning the same
decade-old CVEs for unrelated devices. Reuses the same NVD 2.0 query path
as FR-3 (`_query_nvd`, extracted as a shared helper).

Every CVE returned by FR-3/FR-9's NVD lookup is additionally enriched
(`pisa/m3/exploit_score.py::enrich_cves`) with its FIRST.org EPSS score
(probability of real-world exploitation within 30 days,
`pisa/m3/epss_client.py`) and CISA KEV listing (confirmed real-world
exploitation, cached catalog download), then combined with CVSS into a
single 0–100 `exploit_score` (`compute_exploit_score`: CVSS and EPSS
weighted equally at 0.4 each, KEV listing a flat +0.2 bonus; a missing
CVSS or EPSS value contributes 0 to its term rather than being excluded/
renormalized).

*Implementation:* `pisa/m0/oui_cve.py` (`lookup_device_cves`,
`_simplify_os_guess`, `_query_nvd`), `pisa/m3/epss_client.py`,
`pisa/m3/exploit_score.py`, `pisa/db/queries.py` (`insert_device_cve`,
`get_device_cves`), `pisa/m5/routes/api.py` (`check_device_cves`,
`check_cves`)

#### FR-10: Authorized Exploit Verification — **[Implemented]**

The system shall, only under explicit operator authorization, attempt
verification of specific CVEs against discovered devices via RouterSploit
modules, logging authorization metadata and results.

Given a device and a CVE already surfaced by FR-9 (the action is scoped
to CVEs the tool has already found for that device, not arbitrary CVE
strings), the system searches RouterSploit's ~358-module index for a
match by CVE ID (`find_modules_for_cve`) — coverage is inherently partial
(only ~24 modules cite an explicit CVE), so no match is a normal, honest
result. If a module matches, the dashboard requires: a named operator
("authorized by"), an explicit "I have authorization to test this
device" confirmation, and a 5-second mandatory pause before the
run/check action becomes clickable (NFR-7). "Check only" (the module's
non-destructive `check()`) is the default; "Full exploit" (`run()`) is a
separate, explicitly-selected mode. Every attempt — check or run,
success or failure — is logged as its own row in `exploit_results` with
the authorizing operator and timestamps (append-only audit log, not a
cached lookup, unlike the CVE tables).

*Implementation:* `pisa/m4/routersploit_gate.py`, `pisa/db/queries.py`
(`insert_exploit_result`, `get_exploit_results`), `pisa/m5/routes/api.py`
(`exploit_modules_for_cve`, `run_device_exploit`)

#### FR-11: Cloud Reporting — **[Planned]**

The system shall optionally sync session data to AWS (DynamoDB) and generate
PDF reports (S3 + Lambda).

*Target implementation:* `pisa/aws/`

### 3.2 External Interface Requirements

#### 3.2.1 Hardware Interfaces

- WiFi adapter supporting monitor mode, for beacon capture (FR-1).
- A second WiFi radio in managed mode, for M1 network join (FR-7).
- *(Planned, future hardware phase)* GPS module, touchscreen display.

#### 3.2.2 Software Interfaces

- Python 3.12+, Flask 3.x, Scapy 2.5.x (see `requirements.txt`).
- SQLite 3 (bundled with Python) for local persistence.
- NVD 2.0 REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) —
  optional API key via `NVD_API_KEY` environment variable for higher rate
  limits.
- IEEE OUI database (`https://standards-oui.ieee.org/oui/oui.txt`),
  downloaded on first use.

#### 3.2.3 User Interfaces

- Browser-based dashboard served by the Flask app (`pisa/m5/`), self-styled
  with no external CDN dependency.
- CLI flags on `run.py` (`--scan`, `--duration`, `--iface`,
  `--join-network`, `--password`, `--join-iface`) for headless operation.

### 3.3 Non-Functional Requirements

| ID | Requirement | Status |
|---|---|---|
| NFR-1 | A scan of typical duration (30s) shall not block the dashboard from serving other requests (scans run in a background thread). | Implemented |
| NFR-2 | Scoring (`score_network`) shall be a pure function of packet-derived data, with no network I/O, so it can be unit tested offline. | Implemented |
| NFR-3 | A failed real capture (e.g. interface not in monitor mode) shall mark the session as errored with a logged alert, not crash the server process. | Implemented |
| NFR-4 | The dashboard shall render without any external CDN or internet-hosted asset, to support offline field deployment. | Implemented |
| NFR-5 | All SQLite writes shall go through a connection with foreign-key enforcement enabled. | Implemented |
| NFR-6 | Test suite shall run in CI on every push/PR to `main` (GitHub Actions). | Implemented |
| NFR-7 | *(Planned)* Exploit-verification actions (M4) shall require explicit operator authorization recorded with a timestamp before execution. | Planned |

### 3.4 Use Cases

**UC-1: Run a real WiFi assessment**
1. User places a monitor-mode-capable adapter into monitor mode.
2. User starts a scan from the dashboard (interface name set) or via
   `python run.py --scan --iface <iface> --duration 30`.
3. System sweeps `config.SCAN_CHANNELS`, capturing beacons per channel for
   the configured duration, scores each network, and persists results.
4. User reviews graded networks and, per network of interest, triggers a
   live NVD CVE lookup for the access point's vendor.

**UC-2: Join a network and discover its devices**
1. Following UC-1, user enters a scored network's real WiFi password and
   clicks "Join & Discover Devices" (or runs
   `python run.py --join-network <ssid> --password <pw>` headlessly).
2. System joins the network via `nmcli` on `config.JOIN_IFACE`, ARP-sweeps
   the joined subnet, and Nmap-scans each live host for open ports/OS.
3. User reviews the discovered devices (IP, MAC, vendor, open ports, OS
   guess) on the session detail page.

**UC-3 *(Planned)*: Full network + device assessment**
1. Following UC-2, the system additionally fingerprints devices' protocols
   and correlates device-specific CVEs.
2. Under explicit authorization, the system verifies exploitability for a
   selected high-priority CVE and logs the outcome.

---

## 4. Appendix

### 4.1 Traceability to Modules

| Requirement | Module | Status |
|---|---|---|
| FR-1, FR-2 | M0 | Implemented |
| FR-3 | M0 | Implemented |
| FR-4 | DB / M0 | Implemented |
| FR-5 | — | Removed, v1.2 |
| FR-6 | M5 | Implemented |
| FR-12 | M0 | Implemented, passive mode |
| FR-7 | M1 | Implemented |
| FR-8 | M2 | Implemented |
| FR-9 | M0 / M3 | Implemented |
| FR-10 | M4 | Implemented |
| FR-11 | AWS | Planned |

### 4.2 Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-07-20 | Initial SRS, aligned to v1 (M0 + DB + M5) implementation |
| 1.1 | 2026-07-23 | Added FR-12 (PMKID/EAPOL handshake capture, Sprint 2) |
| 1.2 | 2026-07-26 | FR-7 (M1 network join + device discovery) implemented; removed Demo Mode |
| 1.3 | 2026-07-26 | FR-9 (M3 device CVE correlation, NVD only) implemented |
| 1.4 | 2026-07-26 | FR-7 extended with mDNS device identification |
| 1.5 | 2026-07-27 | FR-8 (M2 protocol behavioral fingerprinting) implemented |
| 1.6 | 2026-07-27 | FR-9 extended with EPSS + CISA KEV correlation and a tri-metric ExploitScore (M3) |
| 1.7 | 2026-07-27 | FR-10 (M4 authorized RouterSploit exploit verification) implemented |
