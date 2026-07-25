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
  SQLite, and a browser-based dashboard to trigger scans and view results.
- **Out of scope for v1 (planned, not in this release):** IoT device
  discovery on the network (M1), protocol-level behavioral fingerprinting
  (M2), CVE correlation for discovered devices (M3), an authorized exploit
  pipeline (M4), and AWS cloud reporting/storage integration.

### 1.3 Definitions, Acronyms, Abbreviations

| Term | Meaning |
|---|---|
| WSPS | WiFi Security Posture Score — a 0–100 score (and A–F grade) computed from passive beacon analysis |
| BSSID | Basic Service Set Identifier — the MAC address of a WiFi access point |
| OUI | Organizationally Unique Identifier — the vendor-specific first 3 octets of a MAC address |
| PMF | Protected Management Frames (802.11w) |
| CVE | Common Vulnerabilities and Exposures |
| NVD | National Vulnerability Database (NIST) |
| Demo Mode | A local-only mode that generates synthetic scan data so the dashboard can be exercised without monitor-mode WiFi hardware |

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

1. Capture WiFi beacon frames from a monitor-mode interface (or generate
   synthetic data in Demo Mode).
2. Score each discovered network's security posture (WSPS) and assign a
   letter grade.
3. Identify a network's access-point vendor from its BSSID and, on request,
   look up known CVEs for that vendor.
4. Persist scan sessions and results, and present them in a dashboard.
5. *(Planned)* Discover IoT devices on the assessed network, fingerprint
   their protocols, correlate device-specific CVEs, and offer an authorized
   exploit-verification pipeline.

### 2.3 User Characteristics

The primary user is an authorized security assessor (e.g. a student
demonstrating the tool, or a professional running a sanctioned WiFi
assessment) with basic familiarity with WiFi security concepts (encryption
types, WPS) but not necessarily with packet-level protocol details.

### 2.4 Constraints

- Passive-only capture in v1 — no active association or packet injection.
- No ML/DL, blockchain, or dataset-trained components (project constraint).
- Must run on Raspberry Pi 4 class hardware — lightweight, no heavy JS
  frontend framework, no external CDN dependency (field deployment may lack
  internet access for the dashboard itself, though live NVD/CVE lookups do
  require connectivity).
- Authorized-use only; see §14 "Ethics, Legal Constraints & Safety" in the
  FYP documentation.

### 2.5 Assumptions and Dependencies

- A monitor-mode-capable WiFi adapter is assumed for real captures; Demo
  Mode removes this dependency for development and demonstration.
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

#### FR-5: Demo Mode — **[Implemented]**

The system shall provide a mode that generates synthetic, realistic network
data through the same scoring and persistence path as a real capture, for
development and demonstration without requiring monitor-mode hardware. This
mode is for local development/testing use, not for presenting synthetic
results as live captures.

*Implementation:* `pisa/m0/demo_data.py`, `pisa/m0/scan_runner.py`

#### FR-6: Dashboard — **[Implemented]**

The system shall provide a web dashboard that: lists past scan sessions;
allows starting a new scan (interface, duration, demo toggle); shows
per-session network results with WSPS grade badges; and allows triggering an
on-demand CVE lookup per network.

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

#### FR-7: IoT Device Discovery — **[Planned]**

The system shall discover devices on the assessed network (ARP sweep, port
scan) and record IP, MAC, vendor, open ports, and OS guess.

*Target implementation:* `pisa/m1/`

#### FR-8: Protocol Behavioral Fingerprinting — **[Planned]**

The system shall fingerprint discovered devices by probing MQTT, CoAP, HTTP,
and RTSP protocol behavior and fuse per-protocol confidence into a combined
device-type confidence score.

*Target implementation:* `pisa/m2/`

#### FR-9: Device CVE Correlation — **[Planned]**

The system shall correlate fingerprinted devices against CVE, EPSS, and
CISA KEV data to produce a prioritized exploitability score.

*Target implementation:* `pisa/m3/`

#### FR-10: Authorized Exploit Verification — **[Planned]**

The system shall, only under explicit operator authorization, attempt
verification of specific CVEs against discovered devices via RouterSploit
modules, logging authorization metadata and results.

*Target implementation:* `pisa/m4/`

#### FR-11: Cloud Reporting — **[Planned]**

The system shall optionally sync session data to AWS (DynamoDB) and generate
PDF reports (S3 + Lambda).

*Target implementation:* `pisa/aws/`

### 3.2 External Interface Requirements

#### 3.2.1 Hardware Interfaces

- WiFi adapter supporting monitor mode (real capture; not required in Demo
  Mode).
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
- CLI flags on `run.py` (`--scan`, `--demo`, `--duration`, `--iface`) for
  headless operation.

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

**UC-1: Run a demo scan (no hardware)**
1. User opens the dashboard, checks "Demo Mode," sets a duration, clicks
   "Start Scan."
2. System creates a session, generates synthetic networks scored through
   the real WSPS pipeline, and marks the session `done`.
3. User is taken to the session detail page and sees graded networks.
4. User clicks "Check CVEs" on a network row and sees canned CVE data.

**UC-2: Run a real WiFi assessment**
1. User places a monitor-mode-capable adapter into monitor mode.
2. User starts a scan from the dashboard (Demo Mode unchecked, interface
   name set) or via `python run.py --scan --iface <iface> --duration 30`.
3. System captures beacons for the configured duration, scores each network,
   and persists results.
4. User reviews graded networks and, per network of interest, triggers a
   live NVD CVE lookup for the access point's vendor.

**UC-3 *(Planned)*: Full network + device assessment**
1. Following UC-2, the system additionally discovers devices on the
   network, fingerprints their protocols, and correlates device CVEs.
2. Under explicit authorization, the system verifies exploitability for a
   selected high-priority CVE and logs the outcome.

---

## 4. Appendix

### 4.1 Traceability to Modules

| Requirement | Module | Status |
|---|---|---|
| FR-1, FR-2 | M0 | Implemented |
| FR-3 | M0 | Implemented |
| FR-4, FR-5 | DB / M0 | Implemented |
| FR-6 | M5 | Implemented |
| FR-12 | M0 | Implemented, passive mode |
| FR-7 | M1 | Planned |
| FR-8 | M2 | Planned |
| FR-9 | M3 | Planned |
| FR-10 | M4 | Planned |
| FR-11 | AWS | Planned |

### 4.2 Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-07-20 | Initial SRS, aligned to v1 (M0 + DB + M5) implementation |
| 1.1 | 2026-07-23 | Added FR-12 (PMKID/EAPOL handshake capture, Sprint 2) |
