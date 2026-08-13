# PISA — Phase 0 Baseline

Audit performed against working tree state (repo root `/home/vivek/PISA`, branch `main`, HEAD `02f37a6`, with 5 uncommitted files — see §10). No source was modified to produce this document.

---

## 1. Current architecture

```
run.py (CLI entry point: --scan / --join-network / dashboard server)
  └── pisa/m5/app.py (Flask app factory, registers 3 blueprints)
        ├── pisa/m5/routes/dashboard.py   (GET / — session list + new-scan form)
        ├── pisa/m5/routes/sessions.py    (GET /sessions/<id> — session detail page)
        └── pisa/m5/routes/api.py         (14 JSON routes, see §5)

pisa/db/
  ├── connection.py   — sqlite3 connection factory (FK enforcement on)
  ├── models.py       — CREATE TABLE + 4 in-place migration functions
  └── queries.py       — all SQL, hand-written (no ORM)

pisa/m0/  WiFi layer
  ├── beacon_capture.py  — Scapy monitor-mode 802.11 beacon sniff
  ├── wsps.py            — pure-function 0-100 score + A-F grade
  ├── oui_cve.py         — OUI→vendor lookup + NVD keywordSearch (BOTH network-vendor AND device-CVE lookups live here)
  ├── handshake.py       — PMKID/EAPOL capture via hcxdumptool (passive by default)
  ├── scan_runner.py     — orchestrates one beacon-capture session
  └── wsps.py / oui.txt  — IEEE OUI database (downloaded on first use)

pisa/m1/  Network join + discovery
  ├── wifi_join.py        — nmcli-based join to a target SSID
  ├── arp_sweep.py        — shells out to `arp-scan`
  ├── nmap_scan.py        — shells out to `nmap -sV -O`, thread-pooled
  ├── mdns_discover.py    — DNS-SD query per host
  └── discovery_runner.py — orchestrates join → arp-scan → nmap → mdns

pisa/m2/  Protocol behavioral fingerprinting
  ├── http_probe.py, mqtt_probe.py, coap_probe.py, rtsp_probe.py — one probe module each
  ├── fusion.py            — pure function: confidence-sum fusion → (device_type, confidence)
  └── fingerprint_runner.py — orchestrates probes per device / per network (thread pool)

pisa/m3/  Vulnerability intelligence
  ├── nvd_client.py   — DEAD STUB (1 line, unused; real NVD client is in m0/oui_cve.py)
  ├── epss_client.py  — FIRST.org EPSS API client
  ├── exploit_score.py — CISA KEV catalog load + tri-metric ExploitScore
  └── kev_catalog.json — downloaded-once, checked into git (stale-forever in practice)

pisa/m4/  Exploitation
  └── routersploit_gate.py — module discovery, check()/run() adapter, output capture

pisa/aws/  Placeholder only — dynamo.py/lambda_client.py/s3_report.py are unimplemented stubs, matches "Planned" status everywhere else in the docs. terraform/main.tf is a placeholder.

config.py — all tunables (interfaces, timeouts, worker-pool sizes, WSPS weights, port lists)
```

No ORM, no migration framework (raw `ALTER TABLE ... IF NOT EXISTS`-style guards in `models.py`), no background job queue (raw `threading.Thread(daemon=True)` per long operation), no auth layer, no cloud dependency at runtime.

---

## 2. Working components

Verified by direct source read (not by trusting docstrings) across this and prior review sessions, plus a fresh full test run (§10):

| Component | Status |
|---|---|
| M0 beacon capture + WSPS scoring | Real, pure-function scoring, offline-testable |
| M0 OUI→vendor / OUI→CVE (network-level) | Real, live NVD `keywordSearch` |
| M1 join + ARP sweep + Nmap + mDNS | Real, thread-pooled, per-host failure isolated as a `warning` alert |
| M2 four protocol probes + fusion | Real; MQTT only detects broker presence/anon-access (no product ID); HTTP captures `Server` header + keyword table |
| M3 EPSS client | Real, correct current FIRST.org endpoint (`api.first.org/data/v1/epss`), batches CVE IDs |
| M3 CISA KEV + ExploitScore | Real; KEV catalog downloaded once and **checked into git** (`pisa/m3/kev_catalog.json`) — never refreshes |
| M4 RouterSploit adapter | Real — reverse-engineers RouterSploit's non-public module index and printer-thread output capture; module-discovery-by-CVE-substring confirmed correct against the installed 3.4.7 package |
| M5 dashboard + API | Real, no external CDN, no server-side auth (documented, loopback-bind default) |
| Test suite | 159/159 passing; 17/21 test files mock network I/O at the boundary while exercising real logic (not placeholder theater) |
| NFR-7 fix (uncommitted) | Complete and tested — see §10 |

---

## 3. Broken / missing components

These are gaps, not bugs in what exists — nothing above is broken in the sense of "doesn't do what it claims." The following either don't exist or are actively wrong:

1. **No CPE anywhere in the codebase** (confirmed by repo-wide grep). `oui_cve.py::_query_nvd` uses NVD's free-text `keywordSearch` against a vendor name or a simplified Nmap OS-guess string — no version-range matching, no applicability determination.
2. **`pisa/m3/nvd_client.py` is a dead 1-line stub.** The real NVD client lives in `pisa/m0/oui_cve.py`, contradicting the module boundary implied by FR-9/M3.
3. **No structured device identity.** `m2/fusion.py`'s output is `(device_type: str, confidence: float)` — a label, not `(vendor, product, model, version)`. This blocks CPE mapping regardless of what NVD integration looks like.
4. **No applicability/verification/exploitation state machine.** `device_cves`/`network_cves` store a CVE + scores with no status field at all. `exploit_results` is a flat append-only log, disconnected from the CVE row it verifies.
5. **RouterSploit `check()` tri-state collapsed incorrectly.** `routersploit_gate.run_exploit` does `bool(success)` on a value that can legitimately be `True`/`False`/`None` (e.g. `misfortune_cookie.py`'s `check()` returns `None` for "could not verify") — `None` silently becomes `False` ("not vulnerable"), which is wrong.
6. **No exploit timeout.** `run_exploit()` calls `instance.check()`/`instance.run()` synchronously in the Flask request thread with no timeout. Confirmed via direct inspection of the installed RouterSploit package: 53 of its exploit modules call `shell()` (`routersploit/core/exploit/shell.py:48`, `while True: cmd = input(...)`), which will hang that thread indefinitely if such a module is ever invoked through `run()`.
7. **No structured evidence.** `exploit_results.result` is a single text blob (captured stdout), not request/response pairs, hashes, or tool-version metadata.
8. **Behavioral drift** — `behavioral_drift` table exists in the schema; zero code anywhere reads or writes it.
9. **Modbus fingerprinting** — referenced only as a port number in `nmap_scan.py`; no probe module exists.
10. **KEV catalog has no provenance/refresh** — frozen at whatever date the committed JSON file was last updated, no stored catalog date.

None of items 1-10 are pre-existing bugs that need root-causing; they're the actual scope of Phases 1-8. Nothing here contradicts prior review findings — this section is a restatement for the implementation record, not a new discovery.

---

## 4. Existing database schema

9 tables, SQLite, no ORM (`pisa/db/models.py`):

- **`sessions`** — id, started_at, ended_at, target_network, status, notes
- **`networks`** — id, session_id FK, bssid, ssid, channel, signal_dbm, security, encryption, beacon_interval, pmf_enabled, wps_enabled, hidden, wsps_score, wsps_grade, first_seen, last_seen, handshake_* (4 cols), discovery_* (4 cols) — `UNIQUE(bssid, session_id)`
- **`network_cves`** — id, network_id FK, cve_id, cvss_score, epss_score, kev_listed, exploit_score, description, fetched_at — `UNIQUE(network_id, cve_id)` (upsert-enforced via a migration that rebuilds the table)
- **`devices`** — id, session_id FK, network_id FK, ip_address, mac_address, vendor, open_ports (JSON text), os_guess, device_type, mdns_name, fingerprint_confidence, first_seen, last_seen — **no vendor/product/version structured columns, no CPE column**
- **`device_cves`** — same shape as `network_cves`, keyed on device_id — **no applicability/verification/exploitation status columns**
- **`exploit_results`** — id, device_id FK, cve_id, module_path, authorized_by, authorized_at, result, success, executed_at — flat audit log, one row per attempt
- **`fingerprint_signatures`** — id, device_id FK, protocol, feature_key, feature_value, confidence, captured_at — per-probe raw evidence, already exists and already close to what an evidence table needs
- **`behavioral_drift`** — schema exists, unused (see §3.8)
- **`alerts`** — id, session_id FK, severity, category, message, related_id, related_type, acknowledged, created_at — generic warning/error log already used by M1/M2's per-host failure isolation

Migration pattern already established (`_migrate_*` functions in `models.py`, run unconditionally on every `create_tables()` call, guarded by `PRAGMA table_info`/`PRAGMA index_list` checks) — Phase 1's schema changes should follow this exact pattern, not introduce a new migration framework.

---

## 5. Existing API flow

Single blueprint, `pisa/m5/routes/api.py`, 14 routes, all synchronous Flask handlers, long operations backgrounded via raw `threading.Thread(daemon=True)`:

```
POST /api/scan                                    → starts M0 beacon capture (backgrounded)
GET  /api/scan/<session_id>/status
POST /api/networks/<id>/cves                       → M0/M3 NVD+EPSS+KEV lookup (synchronous)
POST /api/networks/<id>/join                       → starts M1 discovery (backgrounded)
GET  /api/networks/<id>/discovery/status
GET  /api/networks/<id>/devices
POST /api/devices/<id>/cves                        → same NVD+EPSS+KEV lookup, device-scoped (synchronous)
POST /api/devices/<id>/fingerprint                 → M2 single-device fingerprint (synchronous)
POST /api/networks/<id>/fingerprint                → M2 whole-network fingerprint (backgrounded)
GET  /api/networks/<id>/fingerprint/status
GET  /api/devices/<id>/cves/<cve_id>/exploit-modules → M4 find_modules_for_cve (synchronous)
POST /api/devices/<id>/exploit                     → M4 run_exploit (synchronous, in-request, no timeout)
```

No authentication/authorization middleware anywhere. Target IP for exploitation is read server-side from the device's DB row (`device["ip_address"]`), never taken from the client request body — a real, load-bearing safety property already in place. The 5-second confirmation gate (NFR-7) is client-side JS only, not enforced server-side.

---

## 6. Existing RouterSploit flow

`pisa/m4/routersploit_gate.py`, reverse-engineers RouterSploit 3.4.7 internals (confirmed against the exact package installed in `venv/lib/python3.13/site-packages/routersploit`):

1. `_load_module_index()` — `index_modules()` + `import_exploit()` over every module, caches `{module_path: Exploit class}`, one-time.
2. `find_modules_for_cve(cve_id)` — literal lowercase substring match of the CVE ID against each module's `name`/`description`/`references` (no structured CVE metadata exists in RouterSploit itself — confirmed by direct inspection: only 25 of 194 installed exploit modules mention a CVE string at all).
3. `run_exploit(device_ip, module_path, mode, port)` — instantiates the module, sets `.target`/`.port`, calls `.check()` (output captured via RouterSploit's own `PrinterThread`/`thread_output_stream` redirection mechanism), then `.run()` only if `mode == "run"` and `check()` was truthy.
4. Never raises to the caller — all failures become `{"success": False, "result": "error: ..."}`.

Confirmed gaps (from this session's direct read of the installed package, not assumption): `check()` can return `True`/`False`/`None`, collapsed via `bool()`; `run()` has no timeout; 53 of the installed exploit modules call `shell()`, an interactive `input()`-loop that will hang indefinitely if reached through this adapter with no attached TTY.

---

## 7. Existing CVE flow

Two call sites, one shared implementation, both in `pisa/m0/oui_cve.py`:

- **Network-level**: `lookup_cves(bssid)` → `bssid_to_vendor(bssid)` (OUI database lookup) → `_query_nvd(vendor_name)`.
- **Device-level**: `lookup_device_cves(os_guess)` → `_simplify_os_guess(os_guess)` (strips parenthetical version detail because NVD's `keywordSearch` ANDs every token) → `_query_nvd(simplified_guess)`. Returns `None` (not `[]`) when there's no OS guess — deliberately no vendor-only fallback (documented reasoning in the docstring: vendor-only search was tested and found too generic).
- **`_query_nvd(keyword)`** — GET `https://services.nvd.nist.gov/rest/json/cves/2.0` with `keywordSearch` param, optional `apiKey` header from `config.NVD_API_KEY`. Extracts CVSS via v3.1 → v3.0 → v2 fallback (correct priority order).
- **Enrichment**: every result list is passed through `pisa/m3/exploit_score.py::enrich_cves()`, which batches an EPSS lookup and checks local KEV catalog membership, then computes `exploit_score = 100 * (0.4 * cvss/10 + 0.4 * epss + 0.2 * kev_bonus)`.
- **Persistence**: `queries.insert_network_cve` / `insert_device_cve` — upsert on `(network_id|device_id, cve_id)`, no status/applicability field exists to write to.

No CPE at any point in this flow. No caching beyond "already-fetched rows stay in the DB until the same on-demand check is triggered again" — every "Check CVEs" click is a live synchronous call. This is the flow Phase 4/5 replace as primary (keeping keyword search as a documented fallback per prior review guidance, not deleting it).

---

## 8. Files that must change

| Phase | Files |
|---|---|
| 1 (data model) | `pisa/db/models.py` (new tables/columns + migration functions), `pisa/db/queries.py` (new query functions) |
| 2 (structured identity) | `pisa/m2/fusion.py` (output contract change, keep the confidence-sum algorithm), `pisa/m2/fingerprint_runner.py` (persist new fields), each `m2/*_probe.py` only if a probe needs to emit a new evidence field it doesn't already capture (e.g. HTTP already captures `Server` header — likely additive only) |
| 3 (CPE mapping) | New module, likely `pisa/m3/cpe_mapper.py` |
| 4 (NVD vuln intel) | `pisa/m0/oui_cve.py` (extend, don't replace — keyword search stays as documented fallback for the "no CPE data" case), delete-or-repurpose `pisa/m3/nvd_client.py` (currently dead) |
| 5 (applicability) | New module, likely `pisa/m3/applicability.py` |
| 6 (verification) | New module, likely `pisa/m3/verification.py` or a new `pisa/m3/checks/` package |
| 7 (RouterSploit reliability) | `pisa/m4/routersploit_gate.py` only (tri-state fix, timeout wrapper, shell()-module detection/rejection) |
| 8 (evidence) | `pisa/db/models.py`/`queries.py` (extend `fingerprint_signatures` or add an `evidence` table — the former already has the right shape), `pisa/m5/routes/api.py` (persist evidence at each relevant call site) |
| 9-10 (orchestration, reporting) | New orchestration module; `pisa/m5/routes/`, `pisa/m5/templates/` for report rendering |

---

## 9. Files that should NOT change

Per the explicit instruction to preserve working components and only touch what a concrete integration/correctness problem requires:

- `pisa/m0/beacon_capture.py`, `pisa/m0/wsps.py`, `pisa/m0/scan_runner.py`, `pisa/m0/handshake.py` — WiFi layer, no identified defect.
- `pisa/m1/*` (arp_sweep, nmap_scan, wifi_join, mdns_discover, discovery_runner) — discovery layer, no identified defect.
- `pisa/m2/http_probe.py`, `mqtt_probe.py`, `coap_probe.py`, `rtsp_probe.py` — probe logic itself is sound; only the caller (`fingerprint_runner.py`) and fusion's output contract change.
- `pisa/m3/epss_client.py` — correct as-is.
- `pisa/db/connection.py` — correct as-is.
- `pisa/m5/routes/dashboard.py`, `sessions.py`, templates, static CSS — UI layer stays; only `api.py` gains routes/response fields as new engines land.
- `config.py` — extend with new tunables additively; don't restructure existing keys.
- Existing tests — all 159 must keep passing; extend, don't rewrite.

---

## 10. Baseline test results

```
159 passed, 4 warnings in 1.26s
```

Warnings are pre-existing dependency deprecation notices (scapy's TripleDES, RouterSploit's `pkg_resources`/`telnetlib` shims already documented in `README.md`), not test failures — no action needed.

**Working tree has 5 uncommitted files**, verified by diff to be a complete, tested, already-integrated fix (not WIP to fix or avoid touching carelessly):
- `pisa/db/queries.py`, `pisa/m5/routes/api.py`, `tests/m5/test_routes.py`, `docs/PISA_SRS.md` — implements NFR-7 (commit the exploit-authorization audit row *before* calling `run_exploit()`, not after, so a crash/hang mid-run still leaves a durable record). Includes a new passing test (`test_run_device_exploit_authorization_persists_even_if_run_crashes`) exercising exactly that case.
- `.claude/settings.local.json` — unrelated tool-permission entries from prior sessions, not application code.

Recommendation: commit this NFR-7 work as its own commit before starting Phase 1, so Phase 1's diff is clean and doesn't bundle unrelated changes (see §18 of the plan — "prefer additive changes," clean checkpoints).

---

## 11. Phase 1 implementation plan

Scope: data model + assessment state only. No behavior change to existing scan/discovery/fingerprint/CVE/exploit flows in this phase — purely additive schema and a new `Assessment` concept that existing flows don't yet populate (that wiring is Phase 9).

1. **New table `assessments`**: id, scope (free text or JSON — target SSID/CIDR/notes), started_at, ended_at, status, operator, notes. A `sessions` row will optionally reference an `assessment_id` (nullable FK, additive) rather than replacing `sessions` — session already carries most of what "scope" needs for the current WiFi-scan-first workflow, and the plan explicitly says preserve working components.
2. **Extend `devices`**: add nullable columns `identity_vendor`, `identity_product`, `identity_model`, `identity_version`, `identity_confidence` — additive, `device_type`/`fingerprint_confidence` stay as-is (existing UI and fusion output keep working unmodified until Phase 2 lands).
3. **Extend `device_cves` / `network_cves`**: add `applicability_status` (`UNKNOWN` / `NO_CPE_DATA` / `POTENTIALLY_AFFECTED` / `AFFECTED` / `NOT_APPLICABLE`, default `UNKNOWN`), `verification_status` (`NOT_ATTEMPTED` / `VERIFICATION_AVAILABLE` / `VERIFIED_VULNERABLE` / `NOT_VERIFIED` / `INCONCLUSIVE`, default `NOT_ATTEMPTED`) as separate columns — no change to existing `cvss_score`/`epss_score`/`kev_listed`/`exploit_score` columns.
4. **`exploit_results`**: add `exploitation_status` (`NOT_ATTEMPTED` / `EXPLOIT_UNAVAILABLE` / `EXPLOIT_AVAILABLE` / `EXPLOIT_SUCCESSFUL` / `EXPLOIT_FAILED` / `TIMEOUT`) alongside the existing `success` boolean (keep `success` for backward compatibility with existing queries/tests; derive it from the new status field going forward rather than dropping it).
5. **Migration functions**: follow the existing `_migrate_*` pattern in `pisa/db/models.py` exactly (idempotent, `PRAGMA table_info` guarded, called unconditionally from `create_tables()`).
6. **New query functions** in `pisa/db/queries.py`: `create_assessment`, `get_assessment`, `update_device_identity`, `set_cve_applicability`, `set_cve_verification`, `set_exploit_status` — additive, existing query functions untouched.
7. **Tests**: new `tests/db/test_models.py` cases for each migration (fresh DB has the columns; a pre-migration DB fixture gets them added); new `tests/db/test_queries.py` cases for each new query function, including enum-boundary cases (invalid status value rejected or defaulted — decide and test one behavior explicitly).
8. **Definition of done for Phase 1**: `pytest tests/` still 159+N passing, `python run.py --scan ...` still works unmodified end-to-end (new columns are nullable/defaulted, nothing reads them yet), schema change reviewable as a single diff to `models.py` + `queries.py` + tests only — no route/UI files touched in this phase.

---

**Status: Phase 0 complete. No source code was modified. Awaiting approval to begin Phase 1.**
