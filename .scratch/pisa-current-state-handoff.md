# PISA — Complete Current-State Handoff Report

**Audit date:** 2026-08-19
**Audit method:** Read-only inspection of source, tests, live SQLite database, config, and documentation. No source code was modified. Findings are evidence-based (file:line/function cited); where a claim could not be directly verified from code in this pass, it is marked as such. Prior `.scratch/pisa-*.md` phase-audit logs were used only as a map of what to go re-verify in current code — never cited as evidence of current state.

**Headline finding, stated up front because it governs almost every section below:**
PISA has two parallel vulnerability-intelligence implementations. **Phases 3–6 (CPE mapping, CPE-based CVE correlation, applicability engine, verification engine) and the gated-exploitation orchestration layer of Phase 7 are fully implemented and unit-tested — but are not imported or called anywhere in the live Flask app, the CLI, or each other's non-test callers.** The running dashboard/API still performs CVE lookups via the older keyword-search path (`pisa/m0/oui_cve.py`) and calls RouterSploit directly with no applicability/verification gate. This is confirmed independently by (a) a full import-graph grep across `pisa/m0`, `pisa/m1`, `pisa/m5`, `run.py` and (b) the real production `pisa.db` on this machine, where every one of 70 real `device_cves` rows has `applicability_status='UNKNOWN'`, `verification_status='NOT_ATTEMPTED'`, `correlation_method` NULL, and `cpe_candidates`/`verification_attempts`/`assessments` all have **0 rows**.

---

## 1. Project Overview

**What PISA is today:** A Python/Flask application, run as root on a Raspberry Pi 4 or a Linux laptop with two WiFi radios, that (a) passively captures 802.11 beacon frames and scores the network's security posture (WSPS, A–F), (b) can join a target network and enumerate devices on it via ARP/Nmap/mDNS, (c) can behaviorally fingerprint discovered devices over HTTP/MQTT/CoAP/RTSP, (d) can look up CVEs for a network's vendor or a device's OS guess via a keyword search against NVD, enriched with EPSS and CISA KEV into a single ExploitScore, and (e) can run a RouterSploit module against a device on operator request, logging the outcome. All of this is driven from a browser dashboard on `127.0.0.1:5000` or via CLI flags.

**Problem it solves:** Combines WiFi-layer security assessment and device-layer vulnerability assessment for IoT networks in one portable tool, instead of separately running Bettercap/Aircrack + Nmap + manual CVE lookup + RouterSploit.

**Genuinely working today (reachable from the live app):** beacon capture + WSPS scoring, OUI vendor lookup, keyword-based CVE lookup + EPSS/KEV/ExploitScore enrichment, PMKID/EAPOL handshake capture, network join, ARP/Nmap/mDNS device discovery, MQTT/CoAP/HTTP/RTSP fingerprinting with device-type + structured-identity fusion, direct (ungated) RouterSploit check/run execution with authorization logging.

**Built and unit-tested but NOT reachable from the live app:** CPE mapping (`cpe_mapper.py`), CPE-based CVE correlation (`cve_lookup.py`, `nvd_client.py`), the applicability engine (`applicability.py`), the verification engine (`verification.py`), the gated exploitation orchestrator with its 2-CVE registry, proof-of-impact checks, and redaction (`exploitation.py`).

**Only planned/documented, not implemented:** AWS cloud reporting (`pisa/aws/*.py` are one-line comment stubs; `terraform/main.tf` has zero `resource` blocks).

**Mocked in tests but real in production code:** all of M0–M4's automated tests mock the network/subprocess/RouterSploit boundary — this is a CI-safety property, not a sign the underlying code is fake. Every module's live-network capability was independently confirmed by fork inspection (real `requests`/`socket`/`paho-mqtt`/`aiocoap`/subprocess calls in the source).

**Requires physical hardware (not validated in this environment):** a monitor-mode-capable WiFi adapter for M0 beacon capture; a real vulnerable IoT device for the positive (actually-exploitable) case of M4. Only the negative/non-vulnerable case has been exercised against live infrastructure.

**Requires Internet/API access:** OUI/IEEE registry download (one-time, cached to `pisa/m0/oui.txt`), NVD CPE/CVE APIs, FIRST.org EPSS, CISA KEV catalog download (cached, no expiry).

---

## 2. Complete Architecture (as implemented, not as documented)

```
Hardware (2× WiFi radio, root)
   ↓
M0  pisa/m0/  — beacon_capture.py, wsps.py, oui_cve.py, handshake.py, scan_runner.py
   ↓ (session/network rows in SQLite)
M1  pisa/m1/  — wifi_join.py, arp_sweep.py, nmap_scan.py, mdns_discover.py, discovery_runner.py
   ↓ (device rows)
M2  pisa/m2/  — http/mqtt/coap/rtsp_probe.py, fusion.py, fingerprint_runner.py
   ↓ (device_type, confidence, identity_* columns)
M3  pisa/m3/  — TWO PARALLEL PATHS, only one is live-wired:
      LIVE:  oui_cve.py (M0, keyword search) → exploit_score.py (EPSS+KEV+ExploitScore)
      DEAD:  cpe_mapper.py → cve_lookup.py/nvd_client.py → applicability.py → verification.py
   ↓
M4  pisa/m4/routersploit_gate.py — called DIRECTLY by M5, bypassing pisa/m3/exploitation.py's gate
   ↓
M5  pisa/m5/  — app.py, routes/{api,dashboard,sessions}.py, templates/ — Flask dashboard, no auth
```

Per-module detail (purpose, files, I/O, deps, DB tables, tests, limitations) is in §5–§10.

---

## 3. File-by-File Implementation Map

| Component | File | Purpose | Implemented? | Tested? | Reachable from live app? |
|---|---|---|---|---|---|
| Beacon capture | `pisa/m0/beacon_capture.py` | Scapy raw 802.11 sniff, RSN/security parsing | Yes | Yes (9) | Yes |
| WSPS scoring | `pisa/m0/wsps.py` | 7-factor additive score → A–F | Yes (7/8 factors) | Yes (6) | Yes |
| OUI + keyword CVE | `pisa/m0/oui_cve.py` | Vendor lookup + NVD keyword search | Yes | Yes (9) | **Yes — this is the live CVE path** |
| Handshake/PMKID | `pisa/m0/handshake.py` | hcxdumptool/hcxpcapngtool wrapper | Yes (passive default) | Yes (10, all mocked) | Yes |
| Scan orchestration | `pisa/m0/scan_runner.py` | Thin orchestrator | Yes | Indirect only | Yes |
| WiFi join | `pisa/m1/wifi_join.py` | `nmcli` subprocess | Yes | Yes (6) | Yes |
| ARP sweep | `pisa/m1/arp_sweep.py` | `arp-scan` subprocess | Yes | Yes (7) | Yes |
| Nmap scan | `pisa/m1/nmap_scan.py` | `-sV -O` on IoT port list | Yes | Yes (5) | Yes |
| mDNS discovery | `pisa/m1/mdns_discover.py` | Raw UDP DNS-SD | Yes | Yes (8) | Yes |
| Discovery orchestration | `pisa/m1/discovery_runner.py` | Join→ARP→mDNS→Nmap, threaded | Yes | Yes (5) | Yes |
| HTTP probe | `pisa/m2/http_probe.py` | `GET /`, Server header + keywords | Yes | Yes (mocked) | Yes |
| MQTT probe | `pisa/m2/mqtt_probe.py` | Anonymous CONNACK | Yes | Yes (mocked) | Yes |
| CoAP probe | `pisa/m2/coap_probe.py` | `.well-known/core` GET | Yes | Yes (mocked) | Yes |
| RTSP probe | `pisa/m2/rtsp_probe.py` | Raw `OPTIONS` over TCP | Yes | Yes (mocked) | Yes |
| Fusion | `pisa/m2/fusion.py` | Additive-sum device-type fusion + identity parsing | Yes | Yes (18) | Yes |
| Fingerprint orchestration | `pisa/m2/fingerprint_runner.py` | Per-device + network-wide, threaded | Yes | Yes (10) | Yes |
| CPE mapping | `pisa/m3/cpe_mapper.py` | Identity → NVD CPE API → candidates | Yes | Yes (19+1 skipped-live) | **No — zero callers outside its own tests** |
| CVE (CPE-based) | `pisa/m3/cve_lookup.py`, `nvd_client.py` | CPE → NVD CVE API, pagination/retry | Yes | Yes (26+9) | **No — zero live callers** |
| EPSS client | `pisa/m3/epss_client.py` | FIRST.org EPSS | Yes | Yes (3) | Yes (via `exploit_score.py`'s legacy path) |
| ExploitScore/KEV | `pisa/m3/exploit_score.py` | CVSS+EPSS+KEV weighted score | Yes | Yes (3) | Yes |
| Applicability | `pisa/m3/applicability.py` | CPE version/AND-OR-negate matching | Yes | Yes (41) | **No — zero live callers** |
| Verification | `pisa/m3/verification.py` | 2 real HTTP verification tests | Yes | Yes (23) | **No — zero live callers** |
| Exploitation orchestrator | `pisa/m3/exploitation.py` | Gated registry, proof-of-impact, redaction | Yes | Yes (26) | **No — zero live callers** |
| RouterSploit adapter | `pisa/m4/routersploit_gate.py` | Tri-state check(), timeout, interactive-shell detection | Yes | Yes (17) | **Yes — called directly by M5, bypassing the M3 gate** |
| Flask app | `pisa/m5/app.py`, `routes/*.py` | Dashboard + API | Yes | Yes (20, real temp-DB test client) | — |
| Templates | `pisa/m5/templates/*.html` | UI | Yes (partial data surfaced) | N/A | — |
| DB schema/queries | `pisa/db/models.py`, `queries.py`, `connection.py` | 12 tables, 10 idempotent migrations | Yes | Yes (42) | Yes |
| AWS | `pisa/aws/{dynamo,lambda_client,s3_report}.py` | Cloud reporting | **No — 1-line comment stubs** | No | No |
| Terraform | `terraform/main.tf` | IaC | **No — provider block only, 0 resources** | N/A | No |
| CLI | `run.py` | `--scan`/`--join-network`/`--host` | Yes | Indirect (M5 route tests) | Yes |

---

## 4. End-to-End Data Flow (actual, not aspirational)

```
WiFi beacon
   ↓ beacon_capture.start_capture()                              [IMPLEMENTED]
device discovery (ARP+Nmap+mDNS)
   ↓ discovery_runner.run_discovery() → queries.insert_device()  [IMPLEMENTED]
fingerprint (HTTP/MQTT/CoAP/RTSP)
   ↓ fingerprint_runner.run_fingerprint() → fusion.fuse()         [IMPLEMENTED]
structured identity
   ↓ fusion.fuse_identity() → queries.update_device_identity()    [IMPLEMENTED — but 0/2105 real devices
                                                                    have identity_vendor/product populated
                                                                    in the live DB]
CPE
   ↓ cpe_mapper.map_device_to_cpe()                                [IMPLEMENTED, TESTED — NOT CALLED
                                                                     by any route/CLI → NOT REACHED live]
CVE (CPE-based)
   ↓ cve_lookup.correlate_device_cves()                            [IMPLEMENTED, TESTED — NOT REACHED live]
CVE (actual live path)
   ↓ oui_cve.lookup_device_cves(os_guess) + exploit_score.enrich_cves()  [IMPLEMENTED, REACHED live —
                                                                           this is what really runs]
EPSS / KEV / CVSS
   ↓ exploit_score.compute_exploit_score()                         [IMPLEMENTED, REACHED live]
applicability
   ↓ applicability.determine_applicability()                       [IMPLEMENTED, TESTED — NOT REACHED live;
                                                                      live device_cves.applicability_status
                                                                      is 'UNKNOWN' for 100% of real rows]
verification
   ↓ verification.run_verification()                               [IMPLEMENTED, TESTED — NOT REACHED live;
                                                                      verification_attempts table has 0 rows]
exploitation authorization
   ↓ exploitation.attempt_exploitation() / check_gate()             [IMPLEMENTED, TESTED — NOT REACHED live]
   ↓ (live path instead:) pisa/m5/routes/api.py:run_device_exploit  [REACHED live — calls routersploit_gate
                                                                      directly, gate on applicability/
                                                                      verification status is NOT ENFORCED here]
RouterSploit
   ↓ routersploit_gate.run_exploit()                                [IMPLEMENTED, REACHED live]
evidence
   ↓ queries.record_exploit_outcome()                               [IMPLEMENTED, REACHED live — but without
                                                                      exploitation.py's redaction or
                                                                      proof-of-impact check, and with
                                                                      `timed_out` never passed, so a real
                                                                      timeout is misrecorded as EXPLOIT_FAILED]
```

---

## 5. M0 — WiFi Assessment

**Beacon capture** (`beacon_capture.py:126` `start_capture()`): iterates `config.SCAN_CHANNELS` (2.4GHz 1/6/11 + 5GHz 36–165), sets channel via `iw dev <iface> set channel` subprocess per channel, then `scapy.sniff(..., timeout=dwell)` sequentially per channel (not a background hopping thread — deliberate, since a mid-socket band switch silently kills Scapy's socket). Requires the interface to already be in monitor mode (README documents the manual `nmcli/iw` sequence).

**WSPS formula** — exact, from `wsps.py` + `config.py:73-86`, additive, clamped to [0,100]:
- Encryption: WPA3 +35, WPA2 +25, WPA +10, Open +0
- Channel: non-overlapping {1,6,11} +15; other known channel +5; unknown +0
- Signal: >−50dBm +20; >−70 +12; >−85 +6; weaker/missing +0
- Beacon interval: ==100ms +12; other known +5; missing +0
- Hidden SSID: −10
- PMF (802.11w) enabled: +15
- WPS enabled: −15
- Grade thresholds: A≥90, B≥75, C≥60, D≥45, E≥30, else F

7 of the originally-proposed 8 factors implemented. **Cipher-suite strength and CVE-exposure factors: NOT IMPLEMENTED.** **Beacon drift/temporal-stability detection: NOT IMPLEMENTED** (zero hits for "drift" anywhere in `pisa/m0/`).

**Hidden SSID detection**: `len(ssid)==0` after IE-0 decode → `hidden=True`.

**Security/PMF parsing** (`_detect_security`): hand-rolled RSN IE (ID 48) byte-layout walk — detects WPA2 vs WPA3 (AKM suite type 8 = SAE), PMF via MFPR capability bit 0x0040, vendor IEs for WPA/WPS. Wrapped in a bare `except Exception: pass` — fails safe (falls back to defaults) rather than crashing on a malformed frame.

**OUI/CVE**: `oui_cve.py` downloads the real IEEE OUI registry once (`pisa/m0/oui.txt`, confirmed on disk, real data not a fixture), then does on-demand keyword search against `https://services.nvd.nist.gov/rest/json/cves/2.0` per dashboard click — not cached/scheduled.

**Handshake capture** (`handshake.py`): shells to `hcxdumptool`/`hcxpcapngtool` (system binaries, not in `requirements.txt`, existence not checked before invoking — an uncaught `FileNotFoundError` risk if absent). Passive by default (`authorized=False` disables deauth/probe/association frames); active/forced-handshake mode requires explicit `authorized=True`, no default path to it.

**Tests**: 39 across 4 files, all mock the capture/subprocess boundary — no live-hardware test exists in the automated suite (consistent with a CI-safe design).

**Live/physical validation status**: `run.py --scan` was exercised in a prior session against nonexistent hardware (graceful error path confirmed); no monitor-mode adapter has been used against a real beacon in the environment this audit ran in.

---

## 6. M1 — Network Discovery / Join

- **Join** (`wifi_join.py`): `nmcli connection delete <ssid>` (clear stale profile) → `nmcli device wifi rescan` → 2s sleep → `nmcli device wifi connect <ssid> password <pw> ifname <iface>`. List-args subprocess (no `shell=True`, no injection risk), but the WiFi password is a literal CLI argument — visible via `ps`/`/proc/<pid>/cmdline` for the process's lifetime (minor local-exposure risk, not persisted to DB/logs).
- **ARP sweep** (`arp_sweep.py`): shells to `arp-scan --interface <iface> --plain --quiet --ignoredups <cidr>` (chosen over Scapy per README — verified reasoning: Scapy's Python-level reply matching couldn't keep up on a real ~8k-address subnet).
- **Nmap** (`nmap_scan.py`): `nmap -sV -O --host-timeout 30s -p <IOT_SCAN_PORTS> -oX -`, restricted to `config.IOT_SCAN_PORTS` (22,23,80,443,502,554,1883,5555,5683,8080,8443). XML parsed via stdlib `ElementTree`, `ParseError` caught (empty result, not a crash).
- **mDNS** (`mdns_discover.py`): real two-phase DNS-SD over raw UDP multicast to `224.0.0.251:5353`, scoped to the ARP-sweep result set (not whole-broadcast-domain).
- **Persistence/orchestration** (`discovery_runner.py`): join → ARP → mDNS → per-host Nmap, threaded (`ThreadPoolExecutor(max_workers=30)`), per-host failures isolated (one bad host doesn't abort the batch), self-host explicitly appended (ARP sweeps never see themselves), join failure → `mark_discovery_error` + alert, no partial state.

**Tests**: 30 across 5 files, all subprocess/socket-mocked. **Dead/duplicate code**: none found.

---

## 7. M2 — Device Fingerprinting

| Probe | Mechanism | Evidence | device_type_hint | Confidence (hardcoded literal) |
|---|---|---|---|---|
| HTTP | `GET /` (https if port∈{443,8443}) | `Server` header; keyword match against `{server} {body[:2000]}` for camera/nvr/router/gateway/printer/hub | Server header alone → None; keyword hit → mapped label | 0.5 (header) / 0.7 (keyword) |
| MQTT | Anonymous CONNACK via paho-mqtt v2 | CONNACK reason code | Always "MQTT Broker" if any code received | 0.9 (accepted) / 0.5 (rejected) |
| CoAP | `GET .well-known/core` via aiocoap | Raw payload, `<` char count as pseudo-resource-count | Always "CoAP Device" | 0.85 / 0.4 |
| RTSP | Raw `OPTIONS` over TCP socket | Status line + `Server:` header | Status line → "IP Camera" always; banner → None | 0.9 / 0.5 |

**Fusion algorithm** (`fusion.fuse()`, exact code):
```python
scores = {}
if existing_device_type: scores[existing_device_type] = 0.5   # mDNS baseline
for feature in probe_results:
    hint = feature.get("device_type_hint")
    if not hint: continue
    scores[hint] = min(1.0, scores.get(hint, 0.0) + feature.get("confidence", 0.0))
best = max(scores, key=scores.get) if scores else (existing_device_type, 0.0)
```
Additive-sum-per-label-then-argmax, capped at 1.0. No evidence → returns `(existing_device_type, 0.0)`. Ties resolve to first-inserted key (undocumented, incidental Python-dict behavior, not a designed tie-break rule).

**Structured identity** (`fuse_identity()`): `vendor` only ever comes from the M1 OUI guess (synthesized in-memory, not a DB-backed evidence row). `product`/`version` only from `http.server`/`rtsp.server` banner text, parsed by a regex (`_parse_banner`) that splits `Product/Version` or `Product Version`, falling back to whole-string-as-product with no version rather than guessing. **`model` and `firmware` are hardcoded `None` always** — no probe anywhere populates either field (confirmed by dedicated test + code inspection).

**What M2 does NOT collect**: no TLS/mTLS certificate inspection (`verify=False`, cert discarded), no UPnP/SSDP, no Nmap `-sV` product/version fields (only `service.name` extracted in M1), only a single `GET /` for HTTP (no crawling/auth attempts), no CoAP resource enumeration beyond `.well-known/core` byte-count, no MQTT topic subscription, no RTSP `DESCRIBE`/stream probing, no retry logic on any probe.

**Tests**: 41 across 6 files, 100% mock-based (monkeypatched networking seam functions) — zero live-network M2 test exists.

---

## 8. M3 — Vulnerability Intelligence

### CPE (`cpe_mapper.py`) — implemented, tested, **not live-reachable**

Pipeline: identity (vendor/product/version) → `_build_keyword()` → NVD CPE API 2.0 `keywordSearch` → `_score_candidate()` → persisted via `replace_cpe_candidates`. Status constants and exact trigger conditions:
- `CPE_CONFIRMED`: hardware-part (`h`) CPE, vendor+product+version all match, not deprecated → confidence floored 0.9.
- `CPE_CANDIDATE`: default pre-override status.
- `CPE_AMBIGUOUS`: >1 scored candidate — overrides individual statuses regardless of confidence.
- `NO_CPE_DATA`: no vendor/product, unbuildable keyword, zero NVD matches, or >5 matches (`_MAX_AMBIGUOUS_CANDIDATES=5`).
- `NVD_UNAVAILABLE`: request exception (distinct from a confirmed-empty result).

**Known recall gap, live in the code today**: `_build_keyword` only uses `vendor.split()[0]` — "Hangzhou Xiongmai Technology Co.,Ltd" → "Hangzhou" (a city). Live-verified during Phase 3: this specific case resolves to `NO_CPE_DATA` even though "Xiongmai" alone finds real matches.

Caching: per-device, explicit-refresh only (`force_refresh`), no TTL — but this entire layer is moot in production since nothing calls it (see §12).

### CVE (`nvd_client.py`, `cve_lookup.py`) — implemented, tested, **not live-reachable**

`query_cves_by_cpe()`: NVD CVE API 2.0, `cpeName` param, `resultsPerPage=100`, pagination via `startIndex` bounded to 5 pages max. Retry: 3 attempts, exponential backoff `2*2**attempt` (2/4/8s) on 429/5xx. CVSS extraction prioritizes v3.1→v4.0→v3.0→v2; the v2 `baseSeverity`-is-a-sibling-not-nested quirk was live-verified and is anchored by a dedicated test. `configurations` JSON stored verbatim, no flattening.

**Keyword fallback** (`_add_keyword_fallback_findings`): reuses `oui_cve.lookup_device_cves` unmodified, produces `correlation_method="KEYWORD"`, hard-codes `source_cpe=[]`/`configurations=None` — structurally cannot carry an applicability claim, and never overwrites a CPE-sourced finding.

**Not cache-gated**: every call re-queries NVD's CVE API regardless of `force_refresh` — only the CPE layer (Phase 3) has a cache.

### EPSS / KEV / ExploitScore — implemented, tested, **partially live-reachable**

- EPSS (`epss_client.py`): FIRST.org `/data/v1/epss`, `cve=<comma-list>`. Missing CVE stays absent from the dict, never defaulted to 0.
- KEV (`exploit_score.py`): downloaded once to `pisa/m3/kev_catalog.json`, **never re-downloaded once present — no TTL/staleness check at all**, a real risk for a "currently exploited" signal that's supposed to be current.
- ExploitScore formula (exact, `compute_exploit_score`):
  ```
  score = round(100 * (0.4*(cvss/10) + 0.4*epss + 0.2*(1.0 if kev_listed else 0.0)), 1)
  ```
  Missing metric contributes 0, not excluded/renormalized.
- **This path (EPSS+KEV+ExploitScore) IS wired into the live app**, but only enriching the old keyword-search findings, not the CPE-based ones.

Two independent EPSS/KEV-merge code paths exist (`exploit_score.enrich_cves()` for the legacy flat shape vs. `cve_lookup._enrich_with_epss_and_kev()` for the new finding shape) — the underlying HTTP fetch is shared, but the merge logic is duplicated.

### Applicability (`applicability.py`) — implemented, tested, **not live-reachable**

Real CPE 2.3 component-wise wildcard matching (`*`/None always match, `-` matches only literal `-`, else case-insensitive equality). Version checked separately, always against `device.identity_version`, via plain-equality or range comparison (`versionStartIncluding` etc., segment-by-segment numeric-or-lexicographic heuristic, not full semver). AND/OR/negate via three-valued Kleene logic. Exact status set: `UNKNOWN`, `NO_CPE_DATA`, `POTENTIALLY_AFFECTED`, `AFFECTED`, `NOT_APPLICABLE`.
- `AFFECTED`: combined result True AND ≥1 contributing match has `vulnerable:true`.
- `NOT_APPLICABLE`: combined True with no vulnerable match, or combined False.
- `UNKNOWN`: combined None (missing version evidence) — also the hardcoded outcome for any `KEYWORD`-correlated finding.
- `POTENTIALLY_AFFECTED`: a post-hoc downgrade when exactly one contributing CPE candidate's own Phase-3 status was `CPE_CANDIDATE` (not `CPE_CONFIRMED`).

Real, live-discovered integration fix: `source_cpe` (Phase 4) only contains NVD's `vulnerable:true`-flagged CPEs for a given CVE, so a required-but-non-vulnerable AND-branch (e.g. the hardware CPE in a hardware+firmware AND config) was missing. Fixed by supplementing `source_cpe` with the device's full `cpe_candidates` set before evaluating — implemented entirely inside `applicability.py`, no Phase 3/4 code touched.

### Verification (`verification.py`) — implemented, tested, **not live-reachable**

Eligibility gate (`_is_eligible`): `applicability_status=="AFFECTED"` always eligible; `"POTENTIALLY_AFFECTED"` eligible only per-test (`supports_potentially_affected`); everything else never eligible.

**Exactly two CVEs have a real verification test, full registry, nothing else exists:**
- `HTTP-CREDS-DISCLOSURE-001` (CVE-2018-9995): GET `/device.rsp?opt=user&cmd=list`, cookie `uid=admin`. `VERIFIED_VULNERABLE` requires HTTP 200 + JSON with a `list` array containing an entry with both `uid` and `pwd` keys.
- `HTTP-PATH-TRAVERSAL-001` (CVE-2017-7577): GET `/../../../../../etc/passwd`. `VERIFIED_VULNERABLE` requires HTTP 200 + body containing both `"root:"` and `":0:0:"`.

CVE-2017-16725 (this project's own primary applicability test case) deliberately has **no** verification test — a stack overflow can't be confirmed without triggering it, which the project correctly classifies as exploitation, not verification. Timeout: `config.VERIFICATION_TIMEOUT = 5.0`s.

### Exploitation orchestration (`exploitation.py`) — implemented, tested, **built correctly, unreachable in production**

Registry (`_REGISTRY`), **exactly two entries, `supported=True`, nothing else**:
- `CVE-2018-9995` → `cameras.multi.dvr_creds_disclosure`
- `CVE-2017-7577` → `cameras.xiongmai.uc_httpd_path_traversal`

Gate (`check_gate`), in order: `device_cves` row exists → registry entry with `supported=True` exists → `applicability_status=="AFFECTED"` → `verification_status=="VERIFIED_VULNERABLE"` → the module path is still present in the real installed RouterSploit package. Authorization (`attempt_exploitation`) requires non-empty `authorized_by`. **No timed confirm-delay exists in this module** — the 5-second countdown is purely a UI-layer control (confirmed in §10). `EXPLOIT_TIMEOUT=20.0`s used inside `routersploit_gate.run_exploit`.

Proof-of-impact: CVE-2018-9995 requires `"username"`+`"password"` in captured output; CVE-2017-7577 requires `"root:"`+`":0:0:"`. `final_success` = RouterSploit's own bool AND (mode=="check" OR proof_confirmed) — a `run`-mode "success" with no proof is not counted as success.

Redaction: CVE-2018-9995's redactor replaces the entire result with a fixed confirmation string (coarse, whole-result, not field-level) if creds markers are detected; CVE-2017-7577's is a no-op (justified as not credential secrets).

**This module is airtight in isolation and completely unreachable from the live system** — see §9/§12 for what actually runs instead.

---

## 9. M4 — Exploitation (RouterSploit Adapter)

**Do not read this as "PISA supports RouterSploit generally."** `pisa/m4/routersploit_gate.py` can technically execute *any* of the 358 installed RouterSploit modules if handed a `module_path` string — allowlisting to a specific, vetted set is the job of `pisa/m3/exploitation.py`'s 2-entry registry, and (critical finding) **the live app does not use that registry** (§12).

**Public interface**: `find_modules_for_cve(cve_id)` — literal case-insensitive substring match of the CVE ID against each module's name/description/references (only 24 of 358 installed modules reference an explicit CVE ID at all — an empty result is the common case, not a bug). `run_exploit(device_ip, module_path, mode, port=None)` — the single orchestration entrypoint, never raises.

**Tri-state check() classification** (`_classify_check_result`): uses `is True`/`is False` identity checks — confirmed the historical `bool(None)==False` collapse bug is genuinely fixed, no remaining bare-bool coercion anywhere in the file. Constants: `CONFIRMED_VULNERABLE` / `CONFIRMED_NOT_VULNERABLE` / `INCONCLUSIVE`.

**Interactive shell() detection**: static bytecode inspection — `"shell" in run.__code__.co_names`. Only gates `mode="run"`; refuses such a module outright rather than hanging. Verified against the real installed package: correctly flags `netgear.dgn2200_ping_cgi_rce` as interactive, correctly clears both of `exploitation.py`'s registered (non-interactive) modules.

**Timeout mechanism**: `ThreadPoolExecutor(max_workers=4).submit(...).result(timeout=)`. **Confirmed NOT true process isolation** — a hung thread is not killed, only abandoned; it continues running and holding a worker slot. The pool is module-global and **never shut down**; repeated timeouts under sustained use will progressively starve the 4-worker pool (not covered by any existing test, which only exercises a single isolated timeout).

**Module registered/supported today**: CVE-2018-9995 (`cameras.multi.dvr_creds_disclosure`), CVE-2017-7577 (`cameras.xiongmai.uc_httpd_path_traversal`) — **only via `exploitation.py`'s registry, which the live app does not call.** Via the live app's actual path (`pisa/m5/routes/api.py`), there is no registry restriction at all — any `module_path` the client sends is attempted.

**Output flow**: RouterSploit's printer-thread stdout is captured into a string buffer and returned as opaque free text (`result`) — no structured field extraction (no separate credentials/shell-transcript keys), and **this adapter itself performs zero redaction** — sanitization is exploitation.py's job, which is unreachable live.

**Tests**: 17 test functions (not the "8" figure carried in a prior phase log — stale). 15 use a fully faked module index; 2 exercise the real installed `routersploit` package (interactive-shell detection against real `netgear.dgn2200_ping_cgi_rce`, `dvr_creds_disclosure`, `uc_httpd_path_traversal`). No test runs a real module's `check()`/`run()` against a live target from within this file's own suite.

---

## 10. M5 — API / Dashboard

| Route | Method | Purpose | Reaches CPE/applicability/verification/gated-exploitation? |
|---|---|---|---|
| `/` | GET | Session list | — |
| `/sessions/<id>` | GET | Session + networks + CVEs | — |
| `/api/scan` (+status) | POST/GET | Beacon scan | M0 only |
| `/api/networks/<id>/cves` | POST | "Check CVEs" (network) | **No — `oui_cve.lookup_cves()` (keyword) + `exploit_score.enrich_cves()`** |
| `/api/networks/<id>/join` (+devices/status) | POST/GET | Join + discover | M1 only |
| `/api/devices/<id>/cves` | POST | "Check CVEs" (device) | **No — `oui_cve.lookup_device_cves(os_guess)` (keyword) + `exploit_score.enrich_cves()`. Never calls `cpe_mapper`/`cve_lookup`/`applicability`/`verification`.** |
| `/api/devices/<id>/fingerprint`, `/api/networks/<id>/fingerprint` | POST/GET | Fingerprinting | M2 only (identity fusion IS reached here) |
| `/api/devices/<id>/cves/<cve>/exploit-modules` | GET | Find RouterSploit modules | Calls `routersploit_gate.find_modules_for_cve` directly — **not** `exploitation.py`'s registry |
| `/api/devices/<id>/exploit` | POST | Run/check exploit | **Calls `routersploit_gate.run_exploit()` directly. `pisa/m3/exploitation.py` (`attempt_exploitation`, the applicability/verification gate, proof-of-impact, redaction) is never imported anywhere in `pisa/m5`.** |

**Auth**: none anywhere — no API key, session, login, or CSRF protection. By design, mitigated only by binding to `127.0.0.1` by default (`config.FLASK_HOST`, overridable via `--host`/`PISA_HOST`, prints a warning but does not block a non-loopback bind).

**Server-side gate reality on `/api/devices/<id>/exploit`** (`api.py:198-232`): the only checks are `authorized_by` non-empty, `mode in ("check","run")`, `module_path` non-empty, and that a `device_cves` row links the device to that CVE. **No applicability_status check, no verification_status check, no restriction of `module_path` to the 2-entry registry.** A direct `curl` POST with any `module_path` executes immediately — the dashboard's 5-second countdown is a client-side JavaScript `setInterval`/button-disable pattern only (`session_detail.html`), not enforced server-side. Authorization is still durably logged before the call (NFR-7's audit trail holds), and `record_exploit_outcome` is called — but without `timed_out=` ever passed (a real timeout is misrecorded as `EXPLOIT_FAILED`) and without any redaction (a real disclosed-credentials result is persisted to `exploit_results.result` verbatim).

**Templates**: `session_detail.html` shows networks/CVEs/devices/fingerprint-trigger/exploit-authorization form. **`applicability_status`, `verification_status`, `exploitation_status` are not rendered anywhere** (grepped, zero matches) — not hidden by choice, simply because the feature that would populate them meaningfully is never invoked live.

**Tests**: `tests/m5/test_routes.py`, 20 tests, real Flask test client against a real temp SQLite DB (not fully mocked at the DB layer), with only the network/hardware/RouterSploit boundary monkeypatched per test.

**run.py**: `--scan`, `--join-network`/`--password`/`--join-iface`, `--host`. No root-privilege check in Python itself — relies on underlying `iw`/scapy/arp-scan calls failing with OS permission errors if not root.

---

## 11. Database

12 tables (`pisa/db/models.py`), all base tables via `CREATE TABLE IF NOT EXISTS`, 10 idempotent `ALTER TABLE`-based migration functions run unconditionally on every `create_tables()` call (verified idempotent by dedicated tests). `PRAGMA foreign_keys = ON` is set on every connection (`connection.py:11`) and **actually enforced** — `PRAGMA foreign_key_check` against the live `pisa.db` returned zero violations. Live schema matches `models.py` column-for-column, no drift.

Key tables: `assessments`, `sessions` (nullable `assessment_id` FK), `networks`, `network_cves`, `devices` (`vendor` = OUI guess, `identity_*` = fused identity — deliberately kept separate), `device_cves` (16 NVD/EPSS/KEV columns + `applicability_status`/`verification_status`/`applicability_reason`), `cpe_candidates`, `verification_attempts`, `exploit_results` (`exploitation_status`), `fingerprint_signatures`, `behavioral_drift`, `alerts`.

**State-machine columns — single-writer discipline is real, not aspirational:**
- `applicability_status`: only writer `set_device_cve_applicability`, only caller `pisa/m3/applicability.py`. Default `'UNKNOWN'`.
- `verification_status`: only writer `set_device_cve_verification`, only caller `pisa/m3/verification.py`. Default `'NOT_ATTEMPTED'`.
- `exploitation_status`: writers are the one-time historical backfill migration and `record_exploit_outcome` — called from both the live M5 route and (in isolation) `exploitation.py`, but both go through the same function, so no split-brain risk at the DB layer. Values: `NOT_ATTEMPTED` (default), `EXPLOIT_SUCCESSFUL`, `EXPLOIT_FAILED`, `TIMEOUT`.

`exploit_results.cve_id` and `verification_attempts.cve_id` are bare TEXT, not FKs — this join has no referential-integrity enforcement (convention only).

**Live database evidence (this machine's real `pisa.db`) — the single most important piece of ground truth in this report:**

| Table | Rows |
|---|---|
| sessions | 50 |
| networks | 59 |
| devices | 2105 |
| network_cves | 30 |
| device_cves | 70 |
| **cpe_candidates** | **0** |
| **verification_attempts** | **0** |
| **assessments** | **0** |
| exploit_results | 1 |
| fingerprint_signatures | 14 |
| behavioral_drift | 0 |
| alerts | 35 |

- `device_cves.applicability_status`: `UNKNOWN` for 70/70 rows.
- `device_cves.verification_status`: `NOT_ATTEMPTED` for 70/70 rows.
- `device_cves.correlation_method`: NULL/empty for 70/70 rows (i.e. every real CVE finding on this machine came from the keyword path, not the CPE pipeline).
- `exploit_results.exploitation_status`: `EXPLOIT_SUCCESSFUL` for the 1 real row (run via the live, ungated `/exploit` route).
- `devices.identity_vendor`/`identity_product` populated: **0 of 2105.**
- `sessions.assessment_id` set: **0 of 50** (`create_assessment` is never called from any route or CLI path).

This independently confirms, from data rather than code reading alone, that Phases 3–6 have never executed against this machine's real usage — not because they don't work (they're unit-tested and were live-API-verified in isolation during development), but because nothing in the live call graph reaches them.

---

## 12. State Machine

```
                 ┌───────────────┐
   CVE finding → │ applicability │  writer: applicability.py only
                 │  UNKNOWN(default) → NO_CPE_DATA / AFFECTED / NOT_APPLICABLE / POTENTIALLY_AFFECTED
                 └───────┬───────┘
                         │ gate: AFFECTED (always) or POTENTIALLY_AFFECTED (per-test flag)
                         ▼
                 ┌───────────────┐
                 │ verification  │  writer: verification.py only
                 │  NOT_ATTEMPTED(default) → VERIFIED_VULNERABLE / NOT_VERIFIED / INCONCLUSIVE
                 └───────┬───────┘
                         │ gate: VERIFIED_VULNERABLE required (check_gate, exploitation.py)
                         ▼
                 ┌───────────────┐
                 │ exploitation  │  writer: record_exploit_outcome (via exploitation.py OR direct M5 route)
                 │  NOT_ATTEMPTED(default) → EXPLOIT_SUCCESSFUL / EXPLOIT_FAILED / TIMEOUT
                 └───────────────┘
```

**This state machine is real and enforced — but only inside `pisa/m3/exploitation.py`, which nothing in the live app calls.** The live exploitation path (`pisa/m5/routes/api.py:run_device_exploit`) writes `exploitation_status` **without ever checking `applicability_status` or `verification_status` at all** — it is a structurally separate, ungated write path to the same column. This is not a bug a caller could theoretically trigger; it is the actual, only, currently-shipping way a user runs an exploit through the dashboard. The gate exists in code and passes 26 tests in isolation; it does not exist in the running product.

---

## 13. External Services / Data Sources

| Service | Purpose | API/Library | Live in prod path? | Required? | Failure handling |
|---|---|---|---|---|---|
| NVD CPE API 2.0 | CPE candidates | `cpe_mapper.py` via `requests` | No (unreachable module) | N/A live | Retry/backoff exists in code, unused live |
| NVD CVE API 2.0 (CPE-based) | CVE correlation | `nvd_client.py` | No (unreachable module) | N/A live | 3 retries, exp. backoff 2/4/8s, 5-page pagination cap |
| NVD CVE API 2.0 (keyword) | CVE correlation | `oui_cve.py` | **Yes** | Optional (on-demand click) | Degrades to no results, not fabricated |
| FIRST.org EPSS | Exploit probability | `epss_client.py` | Yes (legacy merge path) | Optional (enrichment) | Missing CVE → absent, never defaulted to 0 |
| CISA KEV | Known-exploited flag | `exploit_score.py`, cached JSON, **no TTL** | Yes | Optional (enrichment) | Downloaded once, never refreshed automatically |
| RouterSploit | Exploit modules | `routersploit==3.4.7`, `routersploit_gate.py` | Yes | Required for M4 | Needs `setuptools<81` + `standard-telnetlib` shims for Py3.13 |
| Scapy | Beacon/handshake capture | `scapy==2.5.0` | Yes | Required for M0 | — |
| Nmap | Port/OS scan | `python-nmap==0.7.1` + system `nmap` | Yes | Required for M1 | XML parse errors caught, empty result |
| arp-scan | Host discovery | subprocess | Yes | Required for M1 | — |
| nmcli | WiFi join | subprocess | Yes | Required for M1 join | — |
| paho-mqtt, aiocoap | M2 probes | Python libs | Yes | Required for M2 MQTT/CoAP | Bounded 3s timeout |
| hcxdumptool/hcxpcapngtool | Handshake capture | system binaries, not in requirements.txt | Yes | Required for M0 handshake | Not checked for existence before invoking |
| boto3, AWS | Cloud reporting | pinned in requirements.txt | **No** | Unused — dead dependency | N/A |

All network-touching stages have an explicit bounded timeout (`config.py`: `ARP_SWEEP_TIMEOUT=60`, `NMAP_HOST_TIMEOUT=30`, `MDNS_QUERY_TIMEOUT=2.0`, `M2_PROBE_TIMEOUT=3.0`, `VERIFICATION_TIMEOUT=5.0`, `EXPLOIT_TIMEOUT=20.0`) — no unbounded external call found anywhere in scope.

---

## 14. Test Coverage

Full suite: **356 passed, 1 skipped, 4 warnings** (pre-existing dependency deprecation notices, unrelated to project code). Skip = the one deliberately-marked live-NVD-CPE-API integration test.

Category breakdown (by `def test_` count per directory):

| Category | Tests |
|---|---|
| db | 42 |
| M0 | 39 |
| M1 | 30 |
| M2 | 41 |
| M3 | 167 |
| M4 | 18 |
| M5 | 20 |
| **Total** | **357** (356 run + 1 skipped) |

No dedicated "integration" or "security/NFR" test directory exists — NFR-7 (exploit-authorization audit logging) is covered by assertions embedded in `tests/m5/test_routes.py` and `tests/m3/test_exploitation.py`, not a separate suite. M3's 167 tests dwarf every other module — reflecting that it's both the largest and, per §12, the least production-reachable module.

---

## 15. Real-World Validation

### A. Unit-tested
Every module in the codebase — 357 tests total, all runnable offline/CI-safe.

### B. Integration-tested
DB migration tests against synthetic pre-Phase-1 schemas and the real production `pisa.db` (per prior implementation-log entries, re-confirmed structurally sound by this audit's live schema check). M5 route tests use a real (temp) SQLite DB through a real Flask test client.

### C. Live API tested
NVD CPE/CVE APIs, FIRST EPSS, CISA KEV were called live during development (per prior implementation-log narrative — e.g. real Xiongmai CPE/CVE resolution) — but this happened as manual/ad hoc verification, not as part of the automated pytest suite (only 1 test is live-marked, and it's skipped by default).

### D. Live network tested
RouterSploit `check()` for both registered CVEs was run against real resolved internet IPs during development (`CONFIRMED_NOT_VULNERABLE` both times, no hang/crash) — again, manual verification outside the automated suite.

### E. Physical hardware tested
**None.** No monitor-mode beacon capture against a real access point, no real vulnerable IoT device has been fingerprinted/CVE-matched/verified/exploited in this environment. This is the single largest gap between "software complete" and "field validated."

### F. Actually demonstrated end-to-end
`scripts/demo_iot_target.py` (145 lines, real operational tooling, not dead code) runs a local HTTP/CoAP/RTSP target on 127.0.0.1 reproducing a real D-Link double-decode CVE (CVE-2019-16920) pattern, usable for demonstrating M2+M4 without physical hardware — this is the closest thing to an end-to-end live demo available. **No evidence found that the full Phase 3–7 pipeline (CPE→applicability→verification→gated exploitation) has ever been run end-to-end through the live application against any target, physical or simulated** — because, per §12, the live application never calls it.

---

## 16. Current Hardware

- **Already available/assumed** (hardcoded in `config.py` on the dev machine): `WIFI_IFACE="wlx00c0cab96bf1"` (monitor-mode adapter), `JOIN_IFACE="wlp0s20f3"` (managed-mode). Both overridable via CLI/dashboard.
- **Required**: two WiFi radios (one monitor-capable), root/`CAP_NET_ADMIN`/`CAP_NET_RAW`, `nmcli`/`arp-scan`/`nmap` on the host.
- **Optional**: `hcxdumptool`/`hcxpcapngtool` (only for handshake capture).
- **Required but absent in this audit environment**: any real vulnerable IoT device for M4 positive-case validation.
- **Unknown**: whether `hcxdumptool`/`hcxpcapngtool` are actually installed on this machine — not verified by any fork (no existence check exists in code either).

---

## 17. Security / Engineering Risks (ranked)

**CRITICAL**
1. **The applicability/verification gate on live exploitation is not enforced.** `pisa/m5/routes/api.py:run_device_exploit` calls `routersploit_gate.run_exploit()` directly, bypassing `pisa/m3/exploitation.py`'s `check_gate` entirely — no `applicability_status`/`verification_status` check, and `module_path` is taken verbatim from the client request, not restricted to the 2-entry supported registry. Any authenticated-to-the-dashboard user (there is no auth) can run any of RouterSploit's 358 modules against any device with a `device_cves` row, regardless of whether the CVE was ever shown to be applicable or verified.

**HIGH**
2. Real disclosed credentials (CVE-2018-9995's output) are persisted **unredacted** to `exploit_results.result` via the live route — `exploitation.py`'s redaction logic is never invoked on this path.
3. No authentication/authorization anywhere in the dashboard/API (`pisa/m5`) — mitigated only by default loopback binding, which is a single flag (`--host`) away from being disabled.
4. `ThreadPoolExecutor(max_workers=4)` in `routersploit_gate.py` never shuts down and leaks a worker slot on every timeout (threads aren't killable in CPython) — repeated timeouts under sustained/adversarial use will starve the pool for all future exploit attempts.

**MEDIUM**
5. A genuine RouterSploit timeout via the live route is recorded as `EXPLOIT_FAILED`, not `TIMEOUT` (`timed_out=` never passed to `record_exploit_outcome` from `api.py`), losing the distinction Phase 7 specifically added the enum value for.
6. CISA KEV catalog cache has no TTL/staleness check — a deployment can silently run on a stale "currently exploited" signal indefinitely.
7. `cpe_mapper._build_keyword`'s single-token vendor extraction is a live, known recall gap (multi-word vendors under-resolve to `NO_CPE_DATA`) — moot in production today since the module isn't called, but would matter immediately if wired up.
8. `handshake.py` invokes `hcxdumptool` without checking it's installed — an unguarded `FileNotFoundError` if the binary is missing.
9. WiFi password passed as a literal `nmcli` CLI argument — visible in local process listings for the connect call's duration (not logged/persisted).

**LOW**
10. Two independent EPSS/KEV-merge implementations (`exploit_score.enrich_cves` vs. `cve_lookup._enrich_with_epss_and_kev`) — duplicate merge logic sharing only the underlying HTTP fetch.
11. `exploit_results.cve_id`/`verification_attempts.cve_id` are unenforced TEXT joins, not real FKs.
12. No CSRF protection framework-wide — currently low-impact since there's no session/auth to forge, but becomes a real gap the moment auth is added.
13. `fusion.fuse()`'s tie-break on equal scores is incidental Python dict-iteration order, not a documented policy.

---

## 18. Documentation Drift

- `docs/FYP_PROJECT_DOCUMENTATION.md` §0 status table is **substantially stale**:
  - Line 53 `"M0 — Handshake capture: Planned, Stub only"` — **false**, 165-line real implementation + 10 tests exist.
  - Line 54 `"M1 — Network discovery: Planned, Stub only"` — **false**, 5 real modules + 30 tests exist.
  - M5 note claims "scan trigger (real + **demo mode**)" — **false**, zero Demo Mode code remains anywhere (confirmed removed, git commit `864e6b7`).
  - Deeper schema section (lines ~1171–1224) labels `devices`/`device_cves`/`exploit_results`/`fingerprint_signatures` as "planned, table ready but unused" — **false**, these are actively written by the live M1–M4 pipeline.
- `docs/PISA_SRS.md`'s FR status table is accurate and current against this audit's findings, including correctly marking FR-11 (Cloud reporting) "Planned."
- **No existing document (README, FYP doc, or SRS) states the central finding of this audit** — that Phases 3–6 and the M3 exploitation gate, despite being "Implemented" per the SRS, are not reachable from the live application. The SRS's "Implemented" labels for FR-9 (Device CVE Correlation) and FR-10 (Authorized Exploit Verification) are true of the *code*, but overstate what a user of the running app actually gets — worth a documentation correction distinguishing "implemented" from "wired into the product."
- `README.md` makes no over-claiming statements — its "Current scope (v1)" list matches the SRS, not the stale FYP doc.

---

## 19. Dead / Duplicate / Unused Code

- **`pisa/aws/{dynamo,lambda_client,s3_report}.py`** — one-line comment stubs, zero functions/classes, zero callers anywhere in the repo. `boto3` is a pinned-but-unused runtime dependency.
- **`terraform/main.tf`** — 16 lines, `terraform`/`provider` blocks only, zero `resource` blocks.
- **`pisa/m3/{cpe_mapper,cve_lookup,nvd_client's CVE-by-CPE path,applicability,verification,exploitation}.py`** — not "dead" in the traditional sense (fully implemented, fully tested, internally correct), but **functionally unreachable from production** — the most consequential finding of this whole audit, covered in depth above.
- **Duplicate EPSS/KEV merge logic** — `exploit_score.enrich_cves()` vs `cve_lookup._enrich_with_epss_and_kev()` (§17.10).
- `pisa/db/models.py`'s `_migrate_exploit_status_column` backfill and `record_exploit_outcome` are the only two writers of `exploitation_status` — not duplicate, but worth noting as the sole legitimate multi-writer case in the schema.
- `scripts/demo_iot_target.py`, `generate_ppt.py`, `gen_arch_diagram.py` — legitimate ancillary tooling (not application code, not tested, not imported by `pisa/`), correctly outside the runtime/test surface, not dead code.
- CI (`.github/workflows/test.yml`) pins Python 3.12 while local dev runs 3.13 (per other forks' venv paths) — a version mismatch worth flagging, not verified further in this pass.

---

## 20. Current Product Capability

### WORKING
Passive WiFi beacon capture + WSPS A–F scoring; OUI vendor lookup; keyword-based CVE search enriched with real EPSS+KEV+ExploitScore; PMKID/EAPOL passive handshake capture; network join; ARP/Nmap/mDNS device discovery; MQTT/CoAP/HTTP/RTSP behavioral fingerprinting with device-type fusion and (mostly-empty-in-practice) structured identity; direct, authorization-logged RouterSploit check/run execution against two supported exploit modules (or, in principle, any of 358 installed modules, since nothing restricts `module_path` on the live route).

### PARTIALLY WORKING
Structured device identity (vendor/product/version) — implemented and wired, but 0 of 2105 real devices on this machine have it populated, meaning either fingerprinting hasn't been run against real devices with usable banners, or the evidence sources (HTTP/RTSP banners only) are too narrow in practice. WSPS scoring — 7 of 8 originally-proposed factors.

### NOT YET WORKING (built but not reachable)
The entire CPE-based CVE correlation → applicability → verification → gated-exploitation pipeline. This is real, tested code sitting one import statement away from being live, but as of this audit it is not part of the product a user experiences.

### REQUIRES HARDWARE (cannot be validated in this environment)
Real beacon capture against a live AP; the positive (actually-vulnerable) case for both M4 exploits; any end-to-end run of the Phase 3–7 pipeline against a real device (even if it were wired up, it's never been exercised against real hardware).

---

## 21. Professor Demo Readiness

*"If I give PISA an authorized vulnerable IoT device, can it..."*

| # | Step | Verdict | Why |
|---|---|---|---|
| 1 | Discover it | **YES** | M1 ARP/Nmap/mDNS is real and reachable. |
| 2 | Identify it | **PARTIAL** | OUI vendor guess works; structured identity (Phase 2) is wired but empirically thin (0/2105 real devices populated). |
| 3 | Fingerprint it | **YES** | M2 is real and reachable, if the device speaks HTTP/MQTT/CoAP/RTSP. |
| 4 | Map it to CPE | **NO** | `cpe_mapper.py` is never called by anything reachable from the dashboard/CLI. |
| 5 | Find relevant CVEs | **PARTIAL** | Keyword-search CVE lookup works and is live; the more precise CPE-based lookup does not run. |
| 6 | Determine applicability | **NO** | `applicability.py` is never called live; `applicability_status` is `UNKNOWN` for every real row in the DB. |
| 7 | Verify the vulnerability | **NO** | `verification.py` is never called live; `verification_attempts` has 0 rows. |
| 8 | Ask for explicit authorization | **PARTIAL** | The live `/exploit` route does require a non-empty operator name and logs it — but the 5-second confirm is UI-only, not server-enforced, and there's no applicability/verification precondition. |
| 9 | Execute a supported exploit | **YES, but unrestricted** | `routersploit_gate.run_exploit` works and is reachable; it is not limited to the "supported" 2-module registry on this path. |
| 10 | Prove impact | **NO** | The live route has no proof-of-impact check; "success" is whatever RouterSploit's own bool says. |
| 11 | Record evidence | **PARTIAL** | Outcome and authorization are logged (`exploit_results`), but without redaction and without the `TIMEOUT` distinction. |
| 12 | Generate a meaningful result | **PARTIAL** | A raw RouterSploit result and an ExploitScore are shown; the richer applicability/verification narrative the architecture promises never appears. |

**Bottom line for a demo**: steps 1, 3, 9 work cleanly today. Steps 4, 6, 7, 10 — the parts of the architecture that make this project's "5-part novelty claim" distinctive (CPE-precision correlation, applicability, verification, proof-of-impact) — do not run in the product as currently wired, despite being fully built and tested in isolation. Wiring them in is an integration task (import + route changes), not a research/engineering-from-scratch task — the hard parts are done.

---

## 22. Product Readiness

**Classification: Research prototype — with a functional-FYP-quality core and a materially incomplete integration layer.**

Reasoning: the individual engineering (WSPS math, CPE matching, NVD pagination/retry, tri-state RouterSploit adapter, DB migration discipline, 357 passing tests) is well above "rough prototype" quality — closer to "functional FYP" or "early product" in isolation. But a product is defined by what a user experiences end-to-end, and the single most architecturally important capability this project claims (CVE→CPE→applicability→verification→gated exploitation, its actual novelty claim per the FYP doc) is not reachable by any user action today. That gap — real, tested code that the application doesn't call — is characteristic of a research prototype where individual components were validated independently but final integration wasn't completed, not of a functional product.

---

## 23. Top 10 Remaining Problems (ranked by impact × likelihood × demo importance)

1. **The gated-exploitation safety machinery is bypassed by the only live exploit route.** (§17.1) Highest severity: this is a live safety control, not a feature gap.
2. **The entire CPE→applicability→verification pipeline is unreachable from the product.** Blocks the project's core novelty claim from ever being demonstrated live.
3. **Zero physical-hardware validation** for M0 beacon capture or M4's positive exploit case — everything is validated against non-vulnerable/simulated targets.
4. **Structured device identity is empirically thin** (0/2105 real devices populated) — undermines the CPE pipeline's input quality even if wired up.
5. **RouterSploit exploit output is unredacted and persisted verbatim on the live path** — real credentials could land in the DB.
6. **No authentication on the dashboard/API** — acceptable only under the current "trusted operator, loopback-only" assumption, which is one flag away from being violated.
7. **`ThreadPoolExecutor` leak in `routersploit_gate.py`** — a slow-drip resource exhaustion risk under repeated timeouts, with no shutdown/recycling.
8. **`cpe_mapper._build_keyword`'s single-token vendor tokenization** — a known, live recall gap that would immediately hurt the CPE pipeline's precision the moment it's wired up.
9. **CISA KEV cache has no staleness policy** — a "currently exploited" signal that can silently go stale forever.
10. **FYP documentation drift** — the project's own primary write-up misrepresents M0/M1 as unimplemented and references removed features (Demo Mode), which would embarrass a demo if read alongside the live system.

---

## 24. Top 10 Next Engineering Tasks

1. **Wire `pisa/m3/exploitation.py` into `pisa/m5/routes/api.py`'s `/exploit` route**, replacing the direct `routersploit_gate.run_exploit()` call with `attempt_exploitation()`. *Why:* closes the CRITICAL safety gap (§17.1) and is the single highest-leverage change in the codebase. *Files:* `pisa/m5/routes/api.py`. *Complexity:* Medium (route + response-shape changes, existing tests will need updates). *Dependency:* none — `exploitation.py` is ready today. *Outcome:* live exploitation becomes gated on applicability=AFFECTED + verification=VERIFIED_VULNERABLE, restricted to the 2-module registry, with proof-of-impact and redaction applied.
2. **Wire `cpe_mapper.map_device_to_cpe` + `cve_lookup.correlate_device_cves` into the `/api/devices/<id>/cves` route**, either replacing or running alongside the keyword path. *Why:* this is the project's actual novelty claim; today it's invisible to any user. *Files:* `pisa/m5/routes/api.py`, `pisa/m5/templates/session_detail.html`. *Complexity:* Medium-High (needs a UI decision on how to present CPE-sourced vs keyword-sourced findings side by side). *Dependency:* none. *Outcome:* real CVE findings gain `correlation_method`, `source_cpe`, and become eligible for applicability/verification.
3. **Wire `applicability.determine_applicability` to run automatically after step 2's CVE correlation**, and surface `applicability_status` in the template. *Why:* required before verification/exploitation gating can mean anything to a user. *Files:* `pisa/m3/cve_lookup.py` or the M5 route, `session_detail.html`. *Complexity:* Low-Medium. *Dependency:* task 2.
4. **Add a "Verify" button/route calling `verification.run_verification`**, gated on `applicability_status`, surfaced in the UI. *Why:* completes the visible pipeline; only 2 CVEs supported today but that's honest and demoable. *Files:* new/extended route in `api.py`, template. *Complexity:* Low-Medium. *Dependency:* task 3.
5. **Add a server-side minimum-elapsed-time enforcement for the exploit confirm gate** (not just client-side JS), and pass `timed_out=` from the route into `record_exploit_outcome`. *Why:* closes §17.5 and makes the "mandatory 5-second confirm" claim true. *Files:* `pisa/m5/routes/api.py`, possibly `pisa/db/queries.py` call site. *Complexity:* Low. *Dependency:* task 1 (do together).
6. **Give the RouterSploit `ThreadPoolExecutor` a bounded lifecycle** — recycle/replace the executor after N timeouts, or move to a process-based isolation model as the Phase 7 log already flagged. *Why:* closes a real resource-exhaustion risk (§17.4/§23.7). *Files:* `pisa/m4/routersploit_gate.py`. *Complexity:* Medium-High if moving to process isolation (RouterSploit's in-process module-loading model resists this, per the Phase 7 log's own note); Low if just adding executor recycling. *Dependency:* none.
7. **Acquire the two identified real target devices** (TBK-clone DVR for CVE-2018-9995, Xiongmai-family device for CVE-2017-7577/CVE-2017-16725) and run the full wired-up pipeline (post tasks 1–4) against them. *Why:* the single largest credibility gap for a professor demo — nothing has been validated against real hardware. *Files:* none (validation exercise). *Complexity:* Low engineering, but external/logistics-dependent (procurement). *Dependency:* tasks 1–4 for a meaningful end-to-end run.
8. **Improve `cpe_mapper._build_keyword`'s vendor tokenization** beyond "first word only" (e.g. try full vendor string, then progressively shorter prefixes, or a small brand-alias table). *Why:* directly improves CPE recall the moment the pipeline goes live (task 2). *Files:* `pisa/m3/cpe_mapper.py`. *Complexity:* Low-Medium. *Dependency:* none, but low value until task 2 lands.
9. **Add a KEV catalog staleness/refresh policy** (e.g. re-download if the cached file is older than N days). *Why:* keeps a security-critical "currently exploited" signal actually current. *Files:* `pisa/m3/exploit_score.py`. *Complexity:* Low. *Dependency:* none.
10. **Correct `docs/FYP_PROJECT_DOCUMENTATION.md`'s §0 status table and schema-status notes**, and add an explicit "implemented vs. wired-into-product" column to whichever status table a professor will actually read. *Why:* prevents an avoidable credibility gap in the primary written deliverable. *Files:* `docs/FYP_PROJECT_DOCUMENTATION.md`. *Complexity:* Low (documentation only). *Dependency:* ideally after tasks 1–4, so the corrected doc reflects the newly-wired reality rather than needing a second correction.

---

## 25. Final Architecture Diagram

```
Hardware (2× WiFi radio, root)
   │
   ▼
[IMPLEMENTED] M0 — beacon_capture.py, wsps.py, oui_cve.py, handshake.py
   │  WSPS score, keyword-CVE lookup, passive PMKID/EAPOL capture
   ▼
[IMPLEMENTED] M1 — wifi_join.py, arp_sweep.py, nmap_scan.py, mdns_discover.py
   │  device rows: ip, mac, vendor(OUI), open_ports, os_guess
   ▼
[IMPLEMENTED] M2 — http/mqtt/coap/rtsp_probe.py, fusion.py
   │  device_type, confidence, identity_{vendor,product,version} (model/firmware always None)
   │
   ├──────────────────────────────┬─────────────────────────────────────┐
   ▼ (LIVE PATH)                  ▼ (BUILT, NOT WIRED — [PARTIAL])       │
[IMPLEMENTED]                  [IMPLEMENTED, TESTED, UNREACHABLE]        │
oui_cve.py (keyword CVE)       cpe_mapper.py → cve_lookup.py             │
   │                              → applicability.py → verification.py  │
   ▼                                            │                       │
exploit_score.py (EPSS+KEV+ExploitScore)        ▼                       │
   │                           [IMPLEMENTED, TESTED, UNREACHABLE]        │
   │                           exploitation.py (gated registry,          │
   │                           proof-of-impact, redaction)               │
   │                                            │                       │
   └───────────────┬────────────────────────────┘                       │
                    ▼                                                   │
[IMPLEMENTED] M4 — routersploit_gate.py                                 │
   │  called DIRECTLY by M5 [CRITICAL: bypasses exploitation.py's gate] │
   ▼                                                                    │
[IMPLEMENTED] M5 — Flask dashboard/API, no auth, binds 127.0.0.1        │
                                                                         │
[NOT IMPLEMENTED] AWS/Terraform (pisa/aws/*.py = 1-line stubs, ─────────┘
                   terraform/main.tf = provider block only)
```

---

## 26. Final Handoff File

This document: `.scratch/pisa-current-state-handoff.md`

Category legend used throughout this report: **IMPLEMENTED** (real code exists and does what it claims) / **TESTED** (covered by automated tests, distinguish mocked vs. live within each section) / **LIVE-VALIDATED** (exercised against real external APIs/network during development, generally manual not automated) / **PHYSICALLY-VALIDATED** (exercised against real target hardware — true for nothing in this codebase today) / **PLANNED** (documented intent, no code — true only for AWS/Terraform).
