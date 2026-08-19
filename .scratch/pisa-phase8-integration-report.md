# PISA Phase 8 Integration Report

Connects the existing, already-tested M3 vulnerability-intelligence pipeline (CPE mapping → CVE correlation → applicability → verification → gated exploitation) into the live Flask/CLI application. **No new engine was written.** Every function called by the new code below already existed, was already unit-tested, and its signature was independently confirmed by direct source read during the Phase 8 investigation before any edit was made.

---

## 1. Files Changed

| File | Lines changed |
|---|---|
| `pisa/m5/routes/api.py` | rewired 3 routes, added 1 new route |
| `pisa/m3/cve_lookup.py` | +10 lines |
| `pisa/db/queries.py` | +6/-4 lines |
| `pisa/m5/templates/session_detail.html` | rewrote the device-CVE rendering/exploit-panel JS |
| `tests/m5/test_routes.py` | updated 4 existing tests, added 10 new route-level integration tests + fixtures |
| `tests/m3/test_cve_lookup.py` | +1 regression test |
| `tests/db/test_queries.py` | +1 regression test |

No files under `pisa/m0/`, `pisa/m1/`, `pisa/m2/`, or `pisa/m4/` were touched. No new module was created. `pisa/m3/{cpe_mapper,applicability,verification,exploitation}.py` are byte-for-byte unmodified — only `cve_lookup.py` changed, and only to add the missing `exploit_score` computation (§10), not to alter its CPE/CVE/keyword-fallback logic.

(`.claude/settings.local.json` shows as modified in `git status` — pre-existing local tool-permission config, not touched intentionally by this work, consistent with prior phases' practice of leaving it out of feature commits.)

## 2. Why Each File Changed

- **`pisa/m5/routes/api.py`** — this was the entire gap the Phase 8 investigation identified: the only file in the live call graph that needed new call sites. Four routes changed/added (§4).
- **`pisa/m3/cve_lookup.py`** — the one genuine data-contract gap the investigation found: `_enrich_with_epss_and_kev` never computed `exploit_score`, so switching the live route to this path would have silently dropped that field. Fixed by calling the *existing* `exploit_score.compute_exploit_score()` — no new formula.
- **`pisa/db/queries.py`** — `upsert_device_cve_intelligence` needed `exploit_score` added to its column list so the value computed above actually reaches the database (schema column already existed).
- **`pisa/m5/templates/session_detail.html`** — the backend changes are invisible without a UI that can display `correlation_method`, `applicability_status`, `verification_status`, and drive the new `/verify` route — required to actually demonstrate the pipeline, not just wire it silently.
- **Test files** — existing tests encoded the *old* architecture's contract (arbitrary `module_path` accepted, `{"cves": [...]}` response shape, direct `routersploit_gate` calls) and had to be updated to encode the *new*, intended contract; new tests prove the live routes — not just the isolated M3 modules — enforce the gate.

## 3. Old Call Graph

```
POST /api/devices/<id>/cves    -> oui_cve.lookup_device_cves(os_guess) -> exploit_score.enrich_cves() -> insert_device_cve()
POST /api/devices/<id>/exploit -> [client-supplied module_path] -> routersploit_gate.run_exploit() -> record_exploit_outcome()
(no verification route existed)
```

## 4. New Call Graph (as implemented, verified in §9 and §12)

```
POST /api/devices/<id>/cves
   -> cve_lookup.correlate_device_cves(conn, device_id, force_refresh)
        -> cpe_mapper.map_device_to_cpe(conn, device_id)     [CPE, unchanged, now reached live]
        -> nvd_client.query_cves_by_cpe(cpe)                 [unchanged, now reached live]
        -> oui_cve.lookup_device_cves(os_guess)               [keyword fallback, still runs when no CPE data]
        -> epss_client.get_epss_records / exploit_score.get_kev_record / exploit_score.compute_exploit_score
        -> queries.upsert_device_cve_intelligence()
   -> [per finding] applicability.determine_applicability(conn, device_id, cve_id)
        -> queries.set_device_cve_applicability()

POST /api/devices/<id>/cves/<cve_id>/verify        [NEW ROUTE]
   -> verification.run_verification(conn, device_id, cve_id)
        -> queries.record_verification_attempt() / queries.set_device_cve_verification()

POST /api/devices/<id>/exploit
   -> exploitation.attempt_exploitation(conn, device_id, cve_id, mode, authorized_by)
        -> exploitation.check_gate()  [applicability==AFFECTED AND verification==VERIFIED_VULNERABLE
                                        AND a supported registry entry exists]
        -> routersploit_gate.run_exploit(ip, REGISTRY_module_path, mode)   [module path from _REGISTRY only]
        -> exploitation's own proof_check() + redact_result()
        -> queries.record_exploit_outcome(..., timed_out=...)

GET /api/devices/<id>/cves/<cve_id>/exploit-modules   [unchanged route, response extended]
   -> routersploit_gate.find_modules_for_cve()  [informational — annotated with pisa_supported, not an allowlist]
```

## 5. CPE Integration

`check_device_cves` no longer calls `oui_cve`/`exploit_score` directly — it calls `cve_lookup.correlate_device_cves`, whose first action is `cpe_mapper.map_device_to_cpe(conn, device_id, force_refresh=force_refresh)` (unchanged code, `pisa/m3/cpe_mapper.py`, not touched by this phase). This was already true of `correlate_device_cves` before Phase 8 — the CPE step was never missing logic, it was missing a caller. Live-verified in §9: a device seeded with `identity_vendor="Xiongmai"`, `identity_product="AHB7008F8-H"`, `identity_version="4.02.r11.3070"` produced a real `cpe_candidates` row (`cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*`) through the live route.

## 6. CVE Integration

Same route, same call — `correlate_device_cves` internally queries `nvd_client.query_cves_by_cpe` per real CPE candidate, normalizes CVSS/weaknesses/references/configurations, and falls back to the *existing* `oui_cve.lookup_device_cves` keyword path only for CVE IDs the CPE path didn't already find (`_add_keyword_fallback_findings`, unmodified). No duplicate CVE-fetching logic was added anywhere — `check_device_cves` contains zero NVD-calling code of its own, by design (per the task's explicit instruction not to duplicate the pipeline). Live-verified in §9: `device_cves.correlation_method == "CPE"` for the CPE-sourced finding; `test_check_device_cves` (rewritten) proves the keyword fallback still fires correctly for a device with no structured identity, tagging the resulting row `correlation_method == "KEYWORD"`.

## 7. Applicability Integration

`check_device_cves` adds exactly one new loop after `correlate_device_cves` returns: `for finding in result["findings"]: applicability.determine_applicability(conn, device_id, finding["cve_id"])`. `applicability.py` itself is unmodified — this is the one cross-module orchestration decision the Phase 8 investigation flagged as needed (§8 of the investigation report), and it is now made at the route layer, not inside either M3 module (preserving `cve_lookup.py`'s and `applicability.py`'s own documented module boundaries). Live-verified in §9: the seeded device's finding resolved to `POTENTIALLY_AFFECTED` (a real, honest verdict — the single CPE candidate's Phase-3 status was `CPE_CANDIDATE`, not `CPE_CONFIRMED`, so `applicability.py`'s own conservative single-candidate cap applied — exactly the behavior its test suite already covers).

## 8. Verification Integration

New route, `POST /api/devices/<device_id>/cves/<cve_id>/verify` (`pisa/m5/routes/api.py`), a thin wrapper: existence checks (device found, CVE associated with device — same pattern as every other route in the file) then a single call to `verification.run_verification(conn, device_id, cve_id)`, returning its result unmodified. All logic — eligibility gating on `applicability_status`, test selection (`find_tests_for_cve`), the 5-second timeout (`config.VERIFICATION_TIMEOUT`), evidence redaction, persistence — remains entirely inside `verification.py`, untouched. Live-verified in §9: a mocked HTTP response matching `HTTP-CREDS-DISCLOSURE-001`'s vulnerable shape produced `status: VERIFIED_VULNERABLE`, a real `verification_attempts` row, and `device_cves.verification_status` updated to match — through the actual HTTP route, not a direct module call.

## 9. Exploitation Integration

`run_device_exploit` no longer reads or uses a client-supplied `module_path` at all — the field is not read from the request body. The route validates only `authorized_by`, `mode`, and that the CVE is associated with the device (all pre-existing HTTP-level checks, unchanged in spirit), then calls `exploitation.attempt_exploitation(conn, device_id, cve_id, mode, authorized_by)` — exactly the signature specified, and the same function whose gate (`check_gate`) and registry (`_REGISTRY`) are entirely unmodified by this phase.

**Live-verified in §9's demo, this is the single most important piece of evidence in this report**: a request was sent with `module_path: "exploits.routers.netgear.dgn2200_ping_cgi_rce"` (a real, different, interactive RouterSploit module) alongside a valid `cve_id`/`mode`/`authorized_by`. The mocked `routersploit_gate.run_exploit` call captured the module path it actually received: `exploits.cameras.multi.dvr_creds_disclosure` — the CVE-2018-9995 registry entry, not the attacker-supplied path. The malicious field was silently ignored, exactly as intended, because the route never reads it. A second call against the same device with `applicability_status` forced to `NOT_APPLICABLE` returned HTTP 403 with `gate_state: BLOCKED_APPLICABILITY`, and the `exploit_results` table still had exactly 1 row afterward (not 2) — confirming a blocked attempt is never persisted, matching `exploitation.py`'s own documented behavior.

## 10. ExploitScore Preservation

`pisa/m3/cve_lookup.py::_enrich_with_epss_and_kev` gained one call: `finding["exploit_score"] = exploit_score.compute_exploit_score(finding.get("cvss_score"), finding["epss_score"], finding["kev_listed"])` — the exact existing function from `pisa/m3/exploit_score.py`, unmodified, same weights (CVSS 0.4 / EPSS 0.4 / KEV 0.2), no new scoring formula. `pisa/db/queries.py::upsert_device_cve_intelligence` gained `exploit_score` in its `INSERT` column list and `ON CONFLICT ... DO UPDATE` clause. Regression tests: `tests/m3/test_cve_lookup.py::test_24_exploit_score_regression_computed_via_existing_formula` (asserts the persisted value equals `exploit_score.compute_exploit_score(...)` called directly — proving no second formula was introduced) and `tests/db/test_queries.py::test_upsert_device_cve_intelligence_persists_exploit_score` (proves the column round-trips through the DB layer, including on a refresh/update). Live-verified in §9: `device_cves.exploit_score == 55.2` for the demo CVE (CVSS 9.8, EPSS 0.4, no KEV — matches `100 * (0.4*0.98 + 0.4*0.4 + 0.2*0) = 55.2` by hand).

## 11. UI Changes

`pisa/m5/templates/session_detail.html`'s device-CVE rendering was rewritten (network-level CVE rendering, `formatCve`/`renderNetworkCves`, is untouched — network rows have no CPE path, per the investigation's §9 finding, and correctly still use the old keyword-only shape). Each device finding now shows: CVE ID, CVSS, EPSS%, KEV badge, ExploitScore, correlation method + CPE source (or an explicit "keyword match only, no confirmed CPE" label), an `Applicability: <STATE>` badge, a `Verification: <STATE>` badge with a **Verify** button shown only when applicability makes verification meaningful, and either an **Authorize Exploit** control (shown only when `applicability_status == AFFECTED && verification_status == VERIFIED_VULNERABLE`) or an explicit `"Exploitation unavailable — requires AFFECTED + VERIFIED VULNERABLE (enforced server-side)"` note. State labels are the backend's own enum strings with underscores replaced by spaces (`VERIFIED_VULNERABLE` → `VERIFIED VULNERABLE`, etc.) — never re-derived or invented client-side. The exploit-confirmation form no longer sends `module_path` in its request body at all. Every place the UI decides whether to show an action is commented in the source as **not the security boundary** — the server-side gate is unconditional regardless of what the UI renders (demonstrated concretely in §9's malicious-module-path test).

This was verified by rendering the template through a real Flask test client (`test_scan_and_session_detail_flow` and the full Phase 8.7 suite all exercise `GET /sessions/<id>`) and by `python -m py_compile`/import-time checks on every changed Python file. **Not visually verified in a browser** — no browser is available in this environment; this is stated plainly rather than claimed, per §17.

## 12. Route-Level Tests

Ten new tests were added to `tests/m5/test_routes.py`, all going through the real Flask test client against a real temporary SQLite DB (`tests/conftest.py`'s existing fixtures, unmodified) — never by calling an M3 module function directly, since that would only prove the module works in isolation (already proven by the pre-existing 167 M3 unit tests) and would say nothing about whether the *route* actually invokes it:

| Test | Proves |
|---|---|
| `test_1_device_cve_route_reaches_cpe_and_applicability` | Live route → real `cpe_candidates` row, `correlation_method` CPE/CPE_AMBIGUOUS, applicability populated (AFFECTED/POTENTIALLY_AFFECTED), `exploit_score` not lost |
| `test_2_device_cve_route_missing_version_stays_unknown` | No `identity_version` → `applicability_status == UNKNOWN`, never `AFFECTED` merely because a CVE exists |
| `test_3_verify_route_persists_attempt_and_status` | Live `/verify` route → real `verification_attempts` row + `verification_status` update |
| `test_4_exploit_route_reaches_exploitation_attempt` | Live `/exploit` route calls `exploitation.attempt_exploitation` with exactly `(device_id, cve_id, mode, authorized_by)` — spied directly |
| `test_5_not_applicable_blocks_exploitation` | `NOT_APPLICABLE` → 403, zero RouterSploit calls, zero `exploit_results` rows |
| `test_6_not_verified_blocks_exploitation` | `AFFECTED` + `NOT_VERIFIED` → 403, zero `exploit_results` rows |
| `test_7_missing_authorization_fails_closed_even_when_eligible` | Fully eligible device, no `authorized_by` → 400, zero RouterSploit calls |
| `test_8_arbitrary_module_path_cannot_control_execution` | Malicious `module_path` in request body → actually-executed path is the registry path, not the client's |
| `test_9_timeout_persists_as_timeout_not_generic_failure` | RouterSploit timeout → `exploitation_status == "TIMEOUT"` in the DB, not `EXPLOIT_FAILED` |
| `test_10_keyword_finding_cannot_reach_verification_or_exploitation` | Keyword-only finding → `UNKNOWN` applicability, `/verify` returns `NOT_ATTEMPTED`, `/exploit` returns 403 `BLOCKED_APPLICABILITY`, zero `exploit_results` rows |

## 13. Negative Security Tests

Tests 5, 6, 7, 8, and 10 above are the negative/fail-closed tests specifically. Every one of them asserts **both** the HTTP-level outcome (403/400, correct `gate_state`) **and** the absence of a side effect (`queries.get_exploit_results(conn, device_id) == []`, or that a mocked `routersploit_gate.run_exploit` was never called) — proving the block is real, not just a misleading response with the exploit having quietly run anyway.

## 14. Database Validation

A temporary, disposable SQLite DB (`/tmp/pisa_phase8_demo.db`, created fresh via `create_tables`) was used for the live end-to-end demonstration in this report — never the real `pisa.db`. Confirmed populated through the live route chain, in order: `devices.identity_*` (seeded directly, as fingerprinting would), `cpe_candidates` (1 real row), `device_cves.correlation_method`/`source_cpe` (`"CPE"`, the real CPE string), `device_cves.applicability_status`/`applicability_reason` (`"POTENTIALLY_AFFECTED"` with a full reason payload), `verification_attempts` (1 row) + `device_cves.verification_status` (`"VERIFIED_VULNERABLE"`), and `exploit_results` (1 row, `exploitation_status = "EXPLOIT_SUCCESSFUL"`, module path from the registry, redacted result text). The real production `pisa.db` was not opened, written, or otherwise touched anywhere in this phase's work — confirmed via `md5sum pisa.db` before/after and `git status` showing it untracked/unchanged.

## 15. Full Test Result

| | Total | Passed | Skipped | Failed |
|---|---|---|---|---|
| Baseline (start of Phase 8) | 357 | 356 | 1 | 0 |
| New tests added | 12 | — | — | — |
| **Final** | **369** | **368** | **1** | **0** |

```
368 passed, 1 skipped, 4 warnings in 3.25s
```

The 1 skip is the pre-existing, deliberately-marked live-NVD-CPE-API integration test (unrelated to Phase 8, unchanged). The 4 warnings are the same pre-existing dependency-deprecation notices (scapy TripleDES, RouterSploit's `pkg_resources`/`telnetlib` shims) present before this phase. Zero pre-existing tests were deleted; 4 were rewritten because they encoded the old, now-intentionally-replaced contract (arbitrary `module_path`, `{"cves": [...]}` response shape) — each rewrite is documented in §12/§9 above and in the tests' own updated docstrings, not silently weakened.

## 16. Remaining Limitations

1. **No UI visual verification.** The template renders and passes its Flask-level tests, but no browser was available to click through the new Verify/Authorize Exploit controls visually.
2. **Structured identity is still empirically sparse in real usage** (per the prior full-repo audit: 0/2105 real devices on this machine had `identity_vendor`/`identity_product` populated before Phase 8) — Phase 8 makes the CPE pipeline *reachable*, it does not improve M2's fingerprinting coverage, which was explicitly out of scope.
3. **`cpe_mapper._build_keyword`'s single-token vendor tokenization** (flagged in the original full audit) is unchanged — a real, live recall gap that now matters in production for the first time, since the CPE path is finally reachable. Not touched here per the explicit "do not create another CPE engine" / minimal-change-set instruction.
4. **The exploit-modules route (`exploit_modules_for_cve`) still reports every RouterSploit module whose metadata merely mentions a CVE ID** — clearly labeled informational (`pisa_supported`, `supported_module_path`, an explanatory `note` field) per Phase 8.5's instructions, but it is still, by design, a wider list than what can execute.
5. **No physical hardware validation of any kind was performed or claimed** — see §17.
6. **`.claude/settings.local.json`** shows as modified in `git status`; this is local tool-permission config unrelated to Phase 8 and was not intentionally edited.

## 17. Exact Statement of Physical Validation Status

**No physical testing was performed in Phase 8, and none is claimed.** Every demonstration in this report (§9, §12, §14) runs against mocked HTTP/RouterSploit boundaries and a disposable temporary SQLite database — the same class of evidence the project's own M3 unit test suite already relies on, extended one layer up to prove the *routes* (not just the isolated modules) invoke the real pipeline correctly. Per the Phase 8 investigation's own §12 finding: this integration removes the one hard *software* blocker to physical validation (the live app previously couldn't reach the CPE/applicability/verification/gated-exploitation pipeline at all, regardless of how vulnerable a real device might be) — but acquiring and testing against real hardware (the TBK-clone DVR and Xiongmai-family device identified in earlier phases) remains entirely undone and is not represented as done anywhere in this report.

---

# PISA PHASE 8 COMPLETE

- [x] device CVE route reaches cve_lookup — `check_device_cves` → `cve_lookup.correlate_device_cves` (§6, live-verified §9)
- [x] cve_lookup reaches CPE mapping — unmodified internal call to `cpe_mapper.map_device_to_cpe`, now live-reachable (§5, live-verified §9)
- [x] applicability is actually invoked — `check_device_cves`'s new loop calls `applicability.determine_applicability` per finding (§7, live-verified §9)
- [x] verification has a live route — `POST /api/devices/<id>/cves/<cve_id>/verify` (§8, live-verified §9)
- [x] exploit route reaches exploitation.py — `run_device_exploit` → `exploitation.attempt_exploitation` (§9, live-verified §9 with a spy test and an end-to-end demo)
- [x] client cannot select arbitrary exploit module — `module_path` is never read from the request body; demonstrated concretely with a malicious module path being ignored (§9, `test_8`)
- [x] applicability + verification gate is server-side — enforced entirely inside `exploitation.check_gate` (unmodified); demonstrated blocking on `NOT_APPLICABLE` and `NOT_VERIFIED` with zero side effects (`test_5`, `test_6`, live demo §9)
- [x] timeout is preserved — `record_exploit_outcome(..., timed_out=...)` now reached from the live route; `test_9` proves `exploitation_status == "TIMEOUT"` in the DB, not `EXPLOIT_FAILED`
- [x] route-level negative tests exist — `test_5`, `test_6`, `test_7`, `test_8`, `test_10` (§13)
- [x] full test suite passes — 368 passed, 1 skipped, 0 failed (§15)
- [x] no fake physical exploitation claim is made — §17 states plainly that no physical validation occurred

All checkboxes are true. Phase 8 integration is complete: the live product now runs identity → CPE → CVE → applicability → verification → authorization → gated exploitation → proof/redaction → dashboard, with the previous critical bypass closed and proven closed by an executable test suite, not just by inspection.
