# PISA Phase 8 Integration Investigation

**Read-only. No source code was modified, no files created except this report, no bugs fixed, no refactoring performed.** All findings below are traced from the actual current source (re-read directly for this investigation, not recalled from the earlier audit) with exact file:line/function references.

---

## 1. Current Live Call Graph

**Scan (M0):**
```
run.py (--scan flag, or POST /api/scan via pisa/m5/routes/api.py:start_scan)
   ↓
pisa/m0/scan_runner.py:run_scan(session_id, iface, timeout, db_path)
   ↓
pisa/m0/beacon_capture.py:start_capture(...)
   ↓
queries.close_session() / queries.fail_session()
```

**Join + discovery (M1):**
```
run.py (--join-network, or POST /api/networks/<id>/join via api.py:join_network)
   ↓
pisa/m1/discovery_runner.py:run_discovery(network_id, session_id, iface, ssid, password, db_path)
   ↓
wifi_join.join_network() → arp_sweep.scan_subnet() → mdns_discover.identify_hosts()
   ↓ (per host, threaded)
_scan_host() → oui_cve.bssid_to_vendor() + nmap_scan.scan_host()
   ↓
queries.insert_device(conn, session_id, network_id, device)
```

**Fingerprint (M2), reachable from `api.py:fingerprint_device` / `fingerprint_network`:**
```
pisa/m2/fingerprint_runner.py:run_fingerprint(device_id, db_path)
   ↓
_PROBES[protocol](ip, port, timeout)   # http/mqtt/coap/rtsp_probe.probe()
   ↓
fusion.fuse(device_type, features) → (device_type, confidence)
fusion.fuse_identity(vendor, features, device_type, confidence) → DeviceIdentity
   ↓
queries.insert_fingerprint_signature() [per feature]
queries.update_device_fingerprint(device_id, device_type, confidence)
queries.update_device_identity(device_id, vendor, product, model, firmware, version)
```
This chain is fully connected and live — confirmed by direct re-read of `fingerprint_runner.py:21-81`. `devices.identity_vendor/product/model/firmware/version` **are** written here.

**CVE lookup — the actual live path, network-level:**
```
POST /api/networks/<id>/cves → api.py:check_cves() [api.py:48-63]
   ↓
cves = exploit_score.enrich_cves(oui_cve.lookup_cves(network["bssid"]))
   ↓
queries.insert_network_cve(conn, network_id, cve)  [loop, one call per CVE]
```

**CVE lookup — the actual live path, device-level:**
```
POST /api/devices/<id>/cves → api.py:check_device_cves() [api.py:113-131]
   ↓
cves = oui_cve.lookup_device_cves(device["os_guess"])
if cves is None: return {"reason": "no_os_fingerprint"}
cves = exploit_score.enrich_cves(cves)
   ↓
queries.insert_device_cve(conn, device_id, cve)  [loop, one call per CVE]
```
**This is the entire live CVE path. It stops here.** `applicability.py`, `verification.py` are never imported by `api.py` at all — confirmed by the full file read (imports at `api.py:1-13` are: `threading`, `flask`, `config`, `queries`, `get_connection`, `oui_cve`, `run_scan`, `discovery_runner`, `fingerprint_runner`, `exploit_score`, `routersploit_gate`. **No `cpe_mapper`, `cve_lookup`, `applicability`, `verification`, or `exploitation` import exists in this file.**)

**Exploitation — the actual live path:**
```
POST /api/devices/<id>/exploit → api.py:run_device_exploit() [api.py:198-232]
   ↓
validate authorized_by / mode / module_path (client-supplied, unrestricted)
   ↓
queries.record_exploit_authorization(conn, device_id, cve_id, module_path, authorized_by)
   ↓
outcome = routersploit_gate.run_exploit(device["ip_address"], module_path, mode, port=port)
   ↓
queries.record_exploit_outcome(conn, result_id, outcome["result"], outcome["success"])
```

---

## 2. Current CVE Path — Exact Trace

**Network-level** — caller `api.py:check_cves` (line 48), function `oui_cve.lookup_cves(bssid)`. Input: a BSSID string (resolved to vendor via OUI, then NVD keyword search). Output: list of `{cve_id, cvss_score, description, ...}` dicts (flat legacy shape). DB write: `queries.insert_network_cve` per CVE, into `network_cves`. Downstream consumers: none beyond the JSON response — no applicability/verification exists for networks at all (correctly so: there is no CPE-mapping input for a network, only for devices with identity columns).

**Device-level** — caller `api.py:check_device_cves` (line 113), function `oui_cve.lookup_device_cves(os_guess)`. Input: `device["os_guess"]` (Nmap's OS-detection string, **not** the Phase-2 `identity_*` columns — the live device CVE path does not consume structured identity at all). Output: `None` (no OS guess available) or a list of flat CVE dicts, then enriched by `exploit_score.enrich_cves()` (adds `epss_score`, `kev_listed`, `exploit_score`). DB write: `queries.insert_device_cve` per CVE, into `device_cves` — sets `cvss_score, epss_score, kev_listed, exploit_score, description, fetched_at` only (confirmed by reading `queries.py:163-191`; this INSERT statement's column list does **not** include `correlation_method`, `source_cpe`, `applicability_status`, or `verification_status` — those columns are simply left at their schema defaults / whatever a prior write left them). Downstream consumers: only the dashboard template's CVE list and the exploit route's `_get_device_cve_or_none` existence check.

---

## 3. New M3 Pipeline — Actual Entry Points

| Function | File:line | Inputs | Outputs | DB writes | Callers today |
|---|---|---|---|---|---|
| `map_device_to_cpe(conn, device_id, force_refresh=False)` | `cpe_mapper.py:237` | `device_id`; reads `device.identity_vendor/identity_product/identity_version` internally | `list[dict]` of CPE candidates (`cpe, confidence, status, source, identity_basis, nvd_cpe_name_id`) | `queries.replace_cpe_candidates` → `cpe_candidates` table | `cve_lookup.correlate_device_cves` (internal, see below) only |
| `correlate_device_cves(conn, device_id, force_refresh=False, include_keyword_fallback=True)` | `cve_lookup.py:164` | `device_id` | `{"status": ..., "findings": [...]}` — each finding has `cve_id, source_cpe, correlation_method, cvss_*, epss_*, kev_*, weaknesses, cve_references, configurations` | `queries.upsert_device_cve_intelligence` per finding → `device_cves` (does **not** write `applicability_status`/`verification_status`, by design) | **Nothing — zero callers outside `tests/m3/test_cve_lookup.py`** |
| `determine_applicability(conn, device_id, cve_id)` | `applicability.py:332` | `device_id, cve_id`; re-reads the persisted `device_cves` row + `devices.identity_version` + `cpe_candidates` internally | `dict` with `status` (`AFFECTED`/`NOT_APPLICABLE`/`UNKNOWN`/`NO_CPE_DATA`/`POTENTIALLY_AFFECTED`) + reasoning fields | `queries.set_device_cve_applicability` → `device_cves.applicability_status/applicability_reason` | **Nothing — zero callers outside `tests/m3/test_applicability.py`** |
| `verification_availability(conn, device_id, cve_id)` / `run_verification(conn, device_id, cve_id)` | `verification.py:281` / `301` | `device_id, cve_id`; re-reads `device_cves.applicability_status` + `devices.ip_address/open_ports` internally | availability dict / `{"status": ..., "test_id", "execution_state", "reason", "evidence", "duration_ms"}` | `queries.record_verification_attempt` → `verification_attempts`; `queries.set_device_cve_verification` → `device_cves.verification_status` | **Nothing — zero callers outside `tests/m3/test_verification.py`** |
| `check_gate(conn, device_id, cve_id)` (read-only) / `attempt_exploitation(conn, device_id, cve_id, mode, authorized_by)` | `exploitation.py:142` / `188` | `device_id, cve_id, mode, authorized_by`; re-reads `device_cves.applicability_status/verification_status` internally, looks up `module_path` from its own 2-entry `_REGISTRY` (never from the caller) | gate dict / `{"status": ..., "result_id", "check_state", "proof_confirmed", ...}` | `queries.record_exploit_authorization` + `queries.record_exploit_outcome(..., timed_out=...)` → `exploit_results` | **Nothing — zero callers outside `tests/m3/test_exploitation.py`** |

Confirmed independently: `grep -rn "cpe_mapper\|cve_lookup\|applicability\|verification\b\|exploitation" pisa/m5/ run.py pisa/m0/ pisa/m1/ pisa/m2/` (excluding the M3 modules' own internal cross-imports and their test files) returns no hits. This matches, and is now confirmed at the exact-function level, what the earlier full-codebase audit found.

---

## 4. Call-Graph Comparison

**CURRENT LIVE PIPELINE (device CVE → exploit)**
```
POST /api/devices/<id>/cves
   ↓
oui_cve.lookup_device_cves(os_guess)          CONNECTED
   ↓
exploit_score.enrich_cves(cves)                CONNECTED
   ↓
queries.insert_device_cve(...)                 CONNECTED
   ↓
[dashboard shows CVE list]                     CONNECTED
   ↓
POST /api/devices/<id>/exploit
   ↓
routersploit_gate.run_exploit(ip, module_path, mode)   CONNECTED (but ungated)
   ↓
queries.record_exploit_outcome(...)            CONNECTED (timed_out never passed)
```

**INTENDED PIPELINE (traced against what actually exists in code today — nothing hypothetical)**
```
POST /api/devices/<id>/cves  (existing route, would need its body changed)
   ↓
cve_lookup.correlate_device_cves(conn, device_id)   DISCONNECTED — function exists, route doesn't call it
   ↓  (internally already calls cpe_mapper.map_device_to_cpe + oui_cve fallback — see §9)
[findings persisted to device_cves]                 DISCONNECTED (as a live path; the function that would do this is never invoked)
   ↓
applicability.determine_applicability(conn, device_id, cve_id)  [once per finding]  DISCONNECTED — no call site anywhere live
   ↓
[no route exists to trigger this at all]
verification.run_verification(conn, device_id, cve_id)          DISCONNECTED — no call site, AND no route exists
   ↓
POST /api/devices/<id>/exploit  (existing route, would need its body changed)
   ↓
exploitation.check_gate(conn, device_id, cve_id)                 DISCONNECTED — function exists, route doesn't call it
exploitation.attempt_exploitation(conn, device_id, cve_id, mode, authorized_by)  DISCONNECTED — route calls routersploit_gate directly instead
```

No edge in the intended pipeline is `UNKNOWN` — every function referenced above was read directly for this investigation and its exact signature/behavior is known (§3). The only genuinely open question is *where* the `applicability.determine_applicability` loop should be triggered from (see §7) — that is a design decision, not an unknown.

---

## 5. Database Flow

| Table | Populated by live scan today? | Populated by tests only? |
|---|---|---|
| `devices` | Yes (`discovery_runner` → `insert_device`) | — |
| `devices.identity_*` | **Yes** — `fingerprint_runner.run_fingerprint` → `update_device_identity` is live-wired (confirmed §1). Empirically sparse on this machine (0/2105 in the earlier full-repo audit) but the *code path* is connected, unlike the M3 pipeline below. | Also tested |
| `device_cves` (legacy columns: `cvss_score`, `epss_score`, `kev_listed`, `exploit_score`, `description`) | Yes, via `insert_device_cve` (old keyword path) | — |
| `device_cves` (Phase-4 columns: `correlation_method`, `source_cpe`, `nvd_status`, `configurations`, etc.) | **No** — only `upsert_device_cve_intelligence` writes these, and its only caller is `cve_lookup.correlate_device_cves`, which nothing live calls. | Tests only |
| `device_cves.applicability_status`/`applicability_reason` | **No** — only `set_device_cve_applicability`, only caller `applicability.determine_applicability`, never called live. | Tests only |
| `device_cves.verification_status` | **No** — only `set_device_cve_verification`, only caller `verification.run_verification`, never called live. | Tests only |
| `cpe_candidates` | **No** — only `replace_cpe_candidates`, only caller `cpe_mapper.map_device_to_cpe`, never called live. | Tests only |
| `verification_attempts` | **No** — only `record_verification_attempt`, only caller `verification.run_verification`, never called live. | Tests only |
| `exploit_results` | Yes — but via the direct `routersploit_gate.run_exploit()` call in `api.py:run_device_exploit`, not via `exploitation.attempt_exploitation` | Also tested (both paths) |

This matches and refines the earlier full-repo audit's live-DB evidence (70/70 `device_cves` rows at `applicability_status='UNKNOWN'`, `cpe_candidates`/`verification_attempts` at 0 rows) — now with the exact function-level reason confirmed by direct code re-read rather than DB inspection alone.

---

## 6. M5 Route Analysis

**`/api/devices/<id>/cves`** (`api.py:113-131`, `check_device_cves`): calls `oui_cve.lookup_device_cves(device["os_guess"])` then `exploit_score.enrich_cves(cves)`, loops `queries.insert_device_cve`. Does not read or use `device["identity_vendor"/"identity_product"/"identity_version"]` at all, even though those columns exist and may be populated on the same `device` dict already fetched via `queries.get_device_by_id` two lines earlier.

**`/api/devices/<id>/exploit`** (`api.py:198-232`, `run_device_exploit`) — read exactly as written, no interpretation:
```python
cve_id = body.get("cve_id") or ""
module_path = body.get("module_path") or ""          # client-supplied, no allowlist
mode = body.get("mode") or ""
authorized_by = (body.get("authorized_by") or "").strip()
port = body.get("port")

if not authorized_by: 400
if mode not in ("check", "run"): 400
if not module_path: 400
# device exists; cve_id is associated with device (queries.get_device_cves lookup) — that's it.

result_id = queries.record_exploit_authorization(conn, device_id, cve_id, module_path, authorized_by)
outcome = routersploit_gate.run_exploit(device["ip_address"], module_path, mode, port=port)
queries.record_exploit_outcome(conn, result_id, outcome["result"], outcome["success"])
```
- **What it currently calls**: `routersploit_gate.run_exploit` directly. `pisa/m3/exploitation.py` is not imported in this file at all (confirmed by the full import list in §1) — so yes, it bypasses `exploitation.py` completely, not partially.
- **What parameters it accepts**: `cve_id`, `module_path` (arbitrary string, not validated against `exploitation._REGISTRY`), `mode`, `authorized_by`, `port` — all from the raw request JSON body.
- **Arbitrary module paths**: yes — nothing constrains `module_path` to the two supported entries; `routersploit_gate.run_exploit` will attempt to load and run whatever string is given if RouterSploit's index resolves it.
- **Where authorization is checked**: only `authorized_by` non-empty (line 208-209). No server-side timer/delay of any kind exists in this function.
- **Where applicability is checked**: nowhere in this function.
- **Where verification is checked**: nowhere in this function.
- **Where exploit result is recorded**: `queries.record_exploit_outcome(conn, result_id, outcome["result"], outcome["success"])` — note only 3 positional args; `record_exploit_outcome`'s `timed_out` parameter (which exists — confirmed via `exploitation.py:243`'s call `queries.record_exploit_outcome(conn, result_id, persisted_result, final_success, timed_out=timed_out)`) is never supplied here, so a real RouterSploit timeout is recorded indistinguishably from a plain failure.

No changes made to this file — reported as-is per the strict stop condition.

---

## 7. Minimum Integration Point

The engines already read/write through the database, not through in-memory object passing between modules — this means the "minimum" integration is unusually small: **each M3 entry point can be called with only `(conn, device_id, cve_id_or_nothing)`, and each one independently re-reads whatever state it needs from the DB.** No new plumbing/adapter code is needed to connect them to each other — they're already connected to each other. Only `pisa/m5/routes/api.py` needs new call sites.

| File | Function | Current responsibility | Required change | Why |
|---|---|---|---|---|
| `pisa/m5/routes/api.py` | `check_device_cves` (line 113) | Keyword-only CVE lookup + flat enrichment, `insert_device_cve` | Replace body with a call to `cve_lookup.correlate_device_cves(conn, device_id, force_refresh=...)`; loop `applicability.determine_applicability(conn, device_id, finding["cve_id"])` over the returned findings | `correlate_device_cves` already does CPE-first + keyword-fallback + EPSS/KEV internally (§9) — this single call replaces the entire current body's logic, then applicability needs an explicit follow-up call since it isn't invoked internally by `cve_lookup.py` (by design — Phase 4/5 are deliberately decoupled modules) |
| `pisa/m5/routes/api.py` | *(no existing function — new route needed)* | — | Add a route (e.g. `POST /api/devices/<id>/cves/<cve>/verify`) calling `verification.run_verification(conn, device_id, cve_id)` | No route anywhere today can ever populate `verification_status` live — this is a genuine gap, not a rewire; without it, `exploitation.check_gate`'s `VERIFIED_VULNERABLE` requirement can never be satisfied live no matter what else is wired |
| `pisa/m5/routes/api.py` | `run_device_exploit` (line 198) | Accepts client `module_path`, calls `routersploit_gate.run_exploit` directly, records outcome without `timed_out` | Replace the gate/call/record block with a single call to `exploitation.attempt_exploitation(conn, device_id, cve_id, mode, authorized_by)`; drop the client-supplied `module_path` parameter entirely (the module path should come from `exploitation._REGISTRY`, not the request body) | Closes the CRITICAL gate-bypass and arbitrary-module-path issues as a direct consequence of using the existing gated function instead of the raw adapter |
| `pisa/m5/routes/api.py` | `exploit_modules_for_cve` (line 184) | Calls `routersploit_gate.find_modules_for_cve(cve_id)` directly (informational RouterSploit search) | No change strictly required for the gate to close (the exploit route itself no longer trusts client-supplied module paths after the change above) — but this route's output could mislead an operator into supplying a module path the new `run_device_exploit` will now ignore; worth a decision, not a code change per se | Consistency of operator-facing UI once the above lands |
| `pisa/m3/exploit_score.py` or `pisa/m3/cve_lookup.py` | `enrich_cves` / `_enrich_with_epss_and_kev` | `enrich_cves` computes `exploit_score` (via `compute_exploit_score`); `_enrich_with_epss_and_kev` (used by `correlate_device_cves`) does **not** | Either add an `exploit_score` computation+field to `cve_lookup.py`'s enrichment, or compute it in the route after `correlate_device_cves` returns, before/alongside persistence | **New finding, not previously flagged**: `device_cves.exploit_score` (a real schema column) would go permanently unpopulated for any row created via the new path if `check_device_cves` is switched to `correlate_device_cves` as-is — see §8 |
| `pisa/m5/templates/session_detail.html` | — | Renders CVE list, exploit-auth form; does not render `applicability_status`/`verification_status`/`exploitation_status` at all | Add fields/controls to surface applicability, a "Verify" trigger, verification result | Not required for the backend gate to function, but required for a human operator (or a professor demo) to see the pipeline is real |

**This is the complete minimum set.** No changes are needed inside `pisa/m3/*.py` themselves — every engine's public entry point already has the exact signature a caller needs (§3, §8). The network-level `/api/networks/<id>/cves` route (`check_cves`, line 48) is **correctly excluded** from this list — see §9.

---

## 8. Data Contract Check

Traced against the actual current function signatures re-read in this investigation (not assumed):

| Link | Match? | Detail |
|---|---|---|
| fingerprint output → `DeviceIdentity` | **Match** | `fingerprint_runner.py:49` calls `fusion.fuse_identity(...)` directly and gets a `DeviceIdentity` object with `.vendor/.product/.model/.firmware/.version` — used immediately at line 61-65 to call `queries.update_device_identity`. No mismatch. |
| `DeviceIdentity` → CPE mapper | **Match, DB-mediated, not object-mediated** | `cpe_mapper.map_device_to_cpe(conn, device_id, ...)` does **not** take a `DeviceIdentity` object as a parameter — it re-reads `identity_vendor/identity_product/identity_version` from the `devices` row via `queries.get_device_by_id` (`cpe_mapper.py:251-258`). This works correctly *as long as* `update_device_identity` was called and committed first. Not a mismatch, but a real **ordering dependency**: if a caller ran `cpe_mapper.map_device_to_cpe` before fingerprinting ever ran (or before its DB write committed), it would silently see `identity_vendor=None` and fall into `NO_CPE_DATA`, not an error. |
| CPE mapper → CVE lookup | **Match, and already wired internally** | `cve_lookup.correlate_device_cves` calls `cpe_mapper.map_device_to_cpe(conn, device_id, force_refresh=force_refresh)` directly at `cve_lookup.py:188` — this link is **not** part of the Phase 8 gap; it already works today, just unreached because nothing calls `correlate_device_cves` itself. |
| CVE lookup → applicability | **Match, but requires an explicit second call — not automatic** | `correlate_device_cves` returns `{"status", "findings": [...]}` and persists each finding via `upsert_device_cve_intelligence`, but does **not** call `determine_applicability` itself (deliberate module boundary per `cve_lookup.py`'s own docstring: "This module never decides whether a CVE actually applies... applicability_status... never written here"). A caller must loop over the returned `findings` list and call `applicability.determine_applicability(conn, device_id, finding["cve_id"])` once per finding, after the `correlate_device_cves` call has committed. This is the one place in the whole chain that needs an explicit orchestration decision (§7). |
| applicability → verification | **Match, DB-mediated** | `determine_applicability` persists via `set_device_cve_applicability`; `run_verification` re-reads `applicability_status` fresh via `queries.get_device_cve` (`verification.py:317`). No object is passed between them — correct and consistent with the rest of the chain. |
| verification → exploitation | **Match, DB-mediated** | `run_verification` persists via `set_device_cve_verification`; `exploitation.check_gate` re-reads `verification_status` fresh via `queries.get_device_cve` (`exploitation.py:167`). Same pattern, no mismatch. |
| **New finding**: `device_cves.exploit_score` column vs. new-path finding shape | **Mismatch** | `insert_device_cve` (old path) explicitly sets `exploit_score` (computed by `exploit_score.enrich_cves` → `compute_exploit_score`). `upsert_device_cve_intelligence` (new path, used by `correlate_device_cves`) has **no `exploit_score` in its INSERT column list at all** (confirmed by direct read of `queries.py:194-267`) — its `ON CONFLICT` clause doesn't touch that column either, so switching `check_device_cves` to the new path would leave `device_cves.exploit_score` NULL forever for any row only ever touched by the new path. This is a genuine, previously-unflagged data-contract gap that must be resolved as part of Phase 8 (see §7's row for it), not merely a rewire. |

**Overall conclusion for this section**: the CPE→CVE→applicability→verification→exploitation chain itself has **no real data-contract mismatch** — every handoff is DB-row-mediated and already consistent, which is a good sign for how small Phase 8's implementation risk actually is. The one concrete gap found is the `exploit_score` column, which sits *outside* the core M3 chain (it's a Phase-4-adjacent enrichment convenience field, not a Phase 5/6/7 gating field), so it does not block applicability/verification/exploitation from working correctly even if left unresolved initially — it would just mean `device_cves.exploit_score` reads NULL for new-path rows until addressed.

---

## 9. Old Keyword Fallback — Recommendation

Based on the actual code, not a policy decision:

- **Can it remain?** Yes, and it already does, safely, *inside* the new pipeline: `cve_lookup._add_keyword_fallback_findings` (`cve_lookup.py:126-140`) already calls `oui_cve.lookup_device_cves` as a fallback whenever the CPE path yields no real candidates, and explicitly never overwrites a CPE-sourced finding for the same CVE ID. The `include_keyword_fallback=True` default parameter on `correlate_device_cves` means switching `check_device_cves` to call it (§7) **automatically keeps keyword-search coverage** — there's no separate decision needed to "keep the old path," it's already folded in.
- **Where should it run?** Exactly where it already runs — inside `correlate_device_cves`, after the CPE-based query, only for CVE IDs the CPE path didn't already find. No route-level duplication needed.
- **Under what condition?** Automatic, per the existing code: any CVE ID not already present in `findings_by_cve` after the CPE-based NVD query.
- **Can keyword findings reach AFFECTED?** **No — structurally impossible**, confirmed directly: `applicability.determine_applicability` (`applicability.py:364-374`) has a hardcoded branch — `if row.get("correlation_method") == "KEYWORD"`, it returns `STATUS_UNKNOWN` unconditionally with an explicit reason string ("keyword evidence alone can never establish AFFECTED (mandatory invariant...)") and never even reaches the CPE-evaluation logic below it.
- **Can keyword findings reach verification?** **No.** `verification._is_eligible` (`verification.py:251-256`) requires `applicability_status in ("AFFECTED",)` or `"POTENTIALLY_AFFECTED"` — a KEYWORD finding is permanently `UNKNOWN`, so `run_verification` will always return `NOT_ATTEMPTED` for it (line 319-323).
- **Can keyword findings reach exploitation?** **No**, for the same reason one level further down: `exploitation.check_gate` (`exploitation.py:160-165`) requires `applicability_status == "AFFECTED"`, which a KEYWORD finding can never have.

**Recommendation**: no change needed to the keyword-fallback mechanism itself for Phase 8 — it is already correctly and permanently subordinate to the CPE path by construction. The only action item is making sure the *network-level* CVE route (`check_cves`, `api.py:48`) is **left exactly as-is** — `oui_cve.lookup_cves` there is not a "fallback" awaiting an upgrade, it is the *only possible* CVE mechanism for networks, since networks have no `identity_vendor/product/version` columns for a CPE mapper to consume (only `devices` rows do). Migrating the network route to anything CPE-based is not just unnecessary but not physically possible with the current schema.

---

## 10. Exploit-Route Bypass Analysis

Confirmed by direct code re-read (§6), stated precisely:

`client → POST /api/devices/<id>/exploit → api.py:run_device_exploit → routersploit_gate.run_exploit(...)` **is the entire path.** `pisa/m3/exploitation.py` is not imported by `pisa/m5/routes/api.py` (verified via the file's complete import list, §1) — there is no partial use of `exploitation.py`; it is a full bypass, not a degraded one.

**Exact bypass mechanics:**
1. No `applicability_status` read anywhere in `run_device_exploit`.
2. No `verification_status` read anywhere in `run_device_exploit`.
3. `module_path` comes verbatim from `request.get_json()["module_path"]` (line 203) with only an empty-string check (line 212-213) — **not** cross-checked against `exploitation._REGISTRY`'s two supported entries. Any RouterSploit module path resolvable by `routersploit_gate.find_modules_for_cve`'s underlying index (in principle, any of the 358 installed modules, per the earlier full audit's M4 findings) can be attempted.
4. The only precondition beyond `authorized_by`/`mode` is that a `device_cves` row exists linking `(device_id, cve_id)` — i.e. *some* CVE was ever recorded for that device by *any* means, including the old keyword path, which per §9 can never legitimately reach `AFFECTED`/`VERIFIED_VULNERABLE` in the first place.
5. `record_exploit_outcome` is called with only 3 args (`result_id, result, success`) — the `timed_out` kwarg that exists on the function (confirmed via `exploitation.py:243`'s own call site, which does pass it) is never supplied from this route, so RouterSploit timeouts are indistinguishable from ordinary failures in this table for anything run through the live route.

No fix proposed or implied here per the stop condition — reported exactly as it stands.

---

## 11. Minimum Integration Test Plan (described, not written)

**Positive chain — live scan → identity → CPE → CVE → applicability:**
1. Seed a device row with `identity_vendor`/`identity_product`/`identity_version` matching a real, previously-verified NVD CPE (the project's own Xiongmai fixture is the natural choice — it was already used as the live-verification target in Phases 3-5).
2. Call the (post-Phase-8) `check_device_cves`-equivalent route/function and assert: (a) a `cpe_candidates` row now exists for the device, (b) a `device_cves` row exists with `correlation_method` in `("CPE", "CPE_AMBIGUOUS")`, not NULL/KEYWORD, (c) `applicability_status` is no longer the default `UNKNOWN` — for the known Xiongmai fixture with an observed firmware version, specifically `AFFECTED`.
3. A second variant of the same test with **no** `identity_version` set should assert `applicability_status == UNKNOWN` with a reason mentioning missing version evidence — proving the negative/undetermined path is also reachable, not just the positive one.

**Positive chain — verification → authorization → exploitation gate:**
4. Starting from a device_cves row already at `applicability_status=AFFECTED` (seeded or produced by test 2), call the (post-Phase-8) verify route/function against a local mock HTTP server that returns the exact vulnerable-shape response `HTTP_CREDS_DISCLOSURE_001` expects; assert `verification_status == VERIFIED_VULNERABLE` and a `verification_attempts` row was written.
5. Call the exploit route with `mode="check"` and a valid `authorized_by`; assert `exploitation.check_gate`'s conditions are what actually gated the call (i.e. the route no longer accepts a client-supplied `module_path` — assert the request body no longer needs/accepts one, or that if still accepted, it's ignored in favor of the registry).

**Negative test — the one the user specifically asked for:**
6. Seed a device_cves row at `applicability_status=NOT_APPLICABLE` (or `verification_status=NOT_VERIFIED`) and assert the exploit route/`exploitation.check_gate` returns `eligible: False` with `gate_state` = `BLOCKED_APPLICABILITY` (or `BLOCKED_VERIFICATION`) — and, critically, assert **no** `exploit_results` row was written as a side effect of the attempt (per `attempt_exploitation`'s own documented behavior: "a blocked attempt... is not persisted at all"). This is the test that would have caught the current bypass had it existed before Phase 7 shipped — it exercises the route, not just the isolated `exploitation.py` module (`tests/m3/test_exploitation.py` already proves the gate works in isolation; what's missing is a `tests/m5/test_routes.py` case proving the *route* enforces it too).

All six are describable today because every function they'd call already exists with a known, stable signature (§3) — no speculative API design is needed to write this test plan for real.

---

## 12. Physical Validation — Software Blockers

Per the stop condition, no physical testing was performed or planned here. The question asked is narrower: **would the current integration, once wired, be *capable* of supporting the already-planned physical lab test?**

Answer: **yes, structurally — with one blocker that must land first, not several.**

- The verification tests (`HTTP-CREDS-DISCLOSURE-001`, `HTTP-PATH-TRAVERSAL-001`) and the two registered exploits are already written against the *exact* real target hardware families identified in the Phase 6/7 logs (TBK-clone DVR, Xiongmai uc-httpd family) — no new engineering is needed in `pisa/m3/verification.py` or `exploitation.py` themselves for those two CVEs.
- **The one hard blocker**: none of §7's minimum integration changes exist yet. Today, plugging in real hardware and clicking through the live dashboard would run the old keyword CVE path and the ungated exploit route — it would **not** exercise `cpe_mapper`/`applicability`/`verification`/the gated `exploitation` module at all, regardless of how vulnerable the real device is, because nothing live calls them. Physical hardware cannot validate code paths the running application never reaches.
- Once §7's changes land, physical validation becomes purely a hardware-acquisition and manual-testing exercise (already scoped in the Phase 6/7 logs) — no further software work is implied by this investigation beyond what §7 already lists.

---

## 13. Recommended Implementation Order (for the user's future decision — not started here)

1. Wire `check_device_cves` → `cve_lookup.correlate_device_cves` + a `determine_applicability` loop (closes the largest visibility gap; lowest risk, since `correlate_device_cves` was already independently live-API-verified during Phase 4 development).
2. Resolve the `exploit_score` column gap (§8) alongside step 1, so the switch doesn't silently regress an existing displayed field.
3. Add the missing verification route/trigger (no equivalent exists today — this is additive, not a rewire).
4. Wire `run_device_exploit` → `exploitation.attempt_exploitation`, dropping the client-supplied `module_path` (closes the CRITICAL gate bypass — highest safety value, but touches the one route with real authorization/audit implications, so sequence it after 1-3 are proven working in a lower-stakes path first).
5. Template updates to surface `applicability_status`/`verification_status` and the new verify control.
6. The integration tests described in §11, written against the newly-wired routes specifically (not just the already-existing isolated `pisa/m3/test_*.py` suites).

This ordering is a suggestion based on what this investigation found to be lowest-risk-first; it is not a commitment and nothing here has been implemented.

---

## 14. Risks

- **Sequencing risk**: if step 4 (exploit route) is wired before step 3 (verification route) exists, the gate will simply always block (`verification_status` can never reach `VERIFIED_VULNERABLE` with no way to trigger it) — functionally safe (fails closed) but would look like a regression/bug to whoever tests it next, worth flagging in whatever implementation plan follows.
- **The `exploit_score` gap (§8)** is easy to miss because it sits outside the applicability/verification/exploitation gating chain entirely — a naive rewire of `check_device_cves` alone would silently stop populating a column the dashboard may already display, without breaking any test (no current test exercises `check_device_cves`'s live column population against the new path, since no test calls the new path through that route).
- **`insert_device_cve` vs `upsert_device_cve_intelligence` coexistence**: confirmed safe at the schema level (same `(device_id, cve_id)` unique key, neither function's `ON CONFLICT` clause touches columns the other owns exclusively) — but if both paths are ever left active simultaneously for the same device (e.g. only the network-level route still uses the old path, which is correct per §9, while the device-level route is switched), a developer reading `device_cves` rows without checking `correlation_method` could still be misled about a given row's provenance. Not a data-corruption risk, a readability one.
- **No route-level test currently proves the gate** (§11, point 6) — `tests/m3/test_exploitation.py`'s 26 tests only prove `exploitation.py` is correct in isolation; they provide no evidence about whether a *route* wired to call it would actually enforce it correctly (e.g. a wiring bug that calls `check_gate` but ignores its result). This is the single highest-value test to add alongside step 4.
