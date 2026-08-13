# PISA — Phase 6 Verification Engine Audit

## 1. Architecture

```
device_cves row (Phase 4/5: correlation_method, applicability_status)
        ↓
verification_availability() / run_verification()  — gate check, no side effects yet
        ↓
find_tests_for_cve(cve_id) — small static registry, keyed by explicit CVE ID
        ↓
_is_eligible(applicability_status, test) — the gate (§2)
        ↓
test.check(ip, port, timeout) — the one test that ran, bounded timeout
        ↓
VerificationOutcome (execution_state, vulnerable, reason, evidence)
        ↓
map to public result (VERIFIED_VULNERABLE / NOT_VERIFIED / INCONCLUSIVE)
        ↓
persist: verification_attempts (append-only, full provenance)
       + device_cves.verification_status (current-conclusion summary)
```

New module: `pisa/m3/verification.py`. Placed in `pisa/m3/` for consistency with this project's own established pattern in this multi-phase build (Phases 3-5's new modules — `cpe_mapper.py`, `cve_lookup.py`, `nvd_client.py`, `applicability.py` — all live there too, even though the original FYP's M-numbering would put verification closer to "M4"); noted here as a placement decision, not an accident.

`pisa/m4/routersploit_gate.py` is completely untouched — confirmed by `test_20_successful_verification_does_not_trigger_exploitation`, which patches it and asserts it's never called.

## 2. Eligibility rules

| `applicability_status` | Eligible? |
|---|---|
| `AFFECTED` | Yes, always (if a test exists for the CVE) |
| `POTENTIALLY_AFFECTED` | Only if the specific test explicitly declares `supports_potentially_affected=True` |
| `NOT_APPLICABLE` / `UNKNOWN` / `NO_CPE_DATA` | Never — `NOT_ATTEMPTED`, no test runs, no network request is made |

Both implemented tests set `supports_potentially_affected=True` — their hypotheses (an unauthenticated endpoint exposing credentials; a path-traversal-vulnerable web server) are OEM-firmware-family conditions, not narrowly version-gated, so a `POTENTIALLY_AFFECTED` device (weak CPE identity, per Phase 5) is still a legitimate candidate to actually test — verification is exactly the mechanism that can *resolve* that uncertainty on the real target, which is the whole point of having it as a separate step from applicability. `AFFECTED` never means `VERIFIED_VULNERABLE` — no code path treats them as equivalent; a real `test.check()` call is mandatory to reach `VERIFIED_VULNERABLE`, enforced structurally (tests 8-13 exercise this directly).

## 3. Verification tests implemented

Both hypotheses are drawn from the **real RouterSploit module source** examined during this project's earlier target-selection review, not invented:

### HTTP-CREDS-DISCLOSURE-001 (CVE-2018-9995)
**Hypothesis**: the target's embedded DVR/NVR web interface exposes an unauthenticated endpoint (`GET /device.rsp?opt=user&cmd=list` with a `uid=admin` cookie) that discloses user credentials in JSON — the exact condition `routersploit/modules/exploits/cameras/multi/dvr_creds_disclosure.py`'s real `check()` tests for.
**Vulnerable**: HTTP 200, JSON with a `list` array containing `uid`/`pwd` entries.
**Not vulnerable**: non-200, or 200 without that structure.
**Safety**: `SAFE_ACTIVE` — a single unauthenticated GET, no state change, matches RouterSploit's own module's non-destructive `check()`.

### HTTP-PATH-TRAVERSAL-001 (CVE-2017-7577)
**Hypothesis**: the target's `uc-httpd` embedded web server fails to sanitize `../` sequences, allowing unauthenticated file read outside the web root — the exact condition `routersploit/modules/exploits/cameras/xiongmai/uc_httpd_path_traversal.py`'s real `check()` tests for.
**Vulnerable**: HTTP 200 with a body matching the `/etc/passwd` structure (`root:` + `:0:0:`).
**Not vulnerable**: non-200, or 200 without that signature.
**Safety**: `SAFE_ACTIVE` — read-only, no state change.

**CVE-2017-16725 (this project's own real applicability-testbed CVE) deliberately has no verification test** — it's a stack buffer overflow; confirming it requires triggering it, which is exploitation, not verification. Documented explicitly per instruction 18 rather than silently omitted or forced into the framework — `find_tests_for_cve("CVE-2017-16725") == []`, tested directly.

## 4. Safety classification

`PASSIVE` and `SAFE_ACTIVE` only — no `DESTRUCTIVE` class exists in this module at all (not even as an unused enum value), so there's no code path that could accidentally run one. Both implemented tests are `SAFE_ACTIVE` (a real, single, read-only HTTP request); neither modifies device state, obtains a shell, uploads anything, or creates persistent state.

## 5. Timeout / error handling

`config.VERIFICATION_TIMEOUT` (5.0s default, matching `M2_PROBE_TIMEOUT`'s established convention) bounds every request. Internal execution states (richer than the public enum, per instruction 22): `OK`, `TIMEOUT`, `TARGET_UNREACHABLE`, `MALFORMED_RESPONSE`, `TEST_UNAVAILABLE` (no matching open port recorded for the test's protocol). Every non-`OK` state maps to the public `INCONCLUSIVE` — never `VERIFIED_VULNERABLE`, never `NOT_APPLICABLE` — and the detailed state is preserved verbatim in `verification_attempts.execution_state`, never discarded. All five states independently tested (10-13, plus the no-open-port case).

## 6. Evidence / provenance

New table `verification_attempts` (mirrors the existing, already-proven `exploit_results` audit-log pattern — not a new architecture): one row per attempt, `device_id`/`cve_id`/`test_id`/`result`/`execution_state`/`reason`/`evidence` (JSON)/`duration_ms`/`started_at`/`completed_at`. `device_cves.verification_status` (Phase 1's existing column, reused as-is) holds only the *latest* conclusion — multiple attempts accumulate in `verification_attempts` without overwriting history (tested: `test_17_multiple_verification_attempts_preserved`).

**Redaction (instruction 23)**: a test's raw evidence dict may include a `_sensitive_keys` list naming fields to mask; `_redact_evidence` (applied centrally, once, not trusted to each test) replaces those values with `"***REDACTED***"` before persistence. `HTTP-CREDS-DISCLOSURE-001` marks its `passwords` field this way — usernames and the fact that credentials were disclosed are preserved as proof, the actual password values are not. Tested directly (`test_15_evidence_persistence`).

## 7. Scope enforcement

Verification only ever operates on a `device_id` that already has a real `device_cves` row (created by Phase 4, itself only ever populated for devices discovered within a real M1 session) — there is no code path to specify an arbitrary IP or a device outside that chain. A nonexistent `device_id` returns `NOT_ATTEMPTED` immediately, no network request (`test_14`). This project's session→assessment relationship (Phase 1) exists but isn't yet wired into an explicit "is this IP in scope" check anywhere in the codebase (M4's RouterSploit gate has the same property — target IP comes from the trusted device row, never client input, but there's no separate scope-record check either) — Phase 6 matches that existing precedent rather than inventing a new, inconsistent authorization layer.

## 8. Database changes

One new table (`verification_attempts`) — added via `CREATE TABLE IF NOT EXISTS` (new table, no `ALTER` migration needed, same pattern as `assessments`/`cpe_candidates`). Zero changes to `device_cves.verification_status` (Phase 1, reused as-is) or `applicability_status`/`applicability_reason` (Phase 5, confirmed untouched by test `test_19`).

## 9. Real-target validation status

**Pending — no physical hardware in this environment**, per instruction 20's explicit allowance ("if physical hardware is not available... document physical validation as pending. Do not fake a successful physical verification result."). What *was* done instead, honestly:
- Full framework implemented and unit-tested (23 tests, all scenarios in the required matrix).
- A genuine **live network sanity check** against real (non-vulnerable) infrastructure: both `_check_http_creds_disclosure` and `_check_http_path_traversal` were run against `example.com` over the real network — both correctly returned `NOT_VERIFIED` (HTTP 404 on both crafted paths), confirming no false-positive against ordinary, non-vulnerable infrastructure. This is a real-network check, not a substitute for testing against an actual vulnerable DVR/camera, and is reported as exactly that.
- The earlier target-selection review already identified concrete, purchasable hardware (a generic TBK-clone DVR for CVE-2018-9995, a Xiongmai-family device for CVE-2017-7577) — real physical validation against those remains the next real-world step, not fabricated here.

## 10. Unsupported verification cases

- **CVE-2017-16725** — requires exploitation (memory corruption), not verifiable safely. Documented, not implemented.
- **MQTT/CoAP/RTSP verification tests** — deliberately not built in this phase. `pisa/m2/mqtt_probe.py` already has the anonymous-CONNECT logic that a hypothetical `MQTT-ANON-ACCESS` test could reuse, but no specific real CVE was identified (in this project's research to date) that this project could point the hypothesis at — building a "protocol security configuration check" without a concrete CVE backing it would have meant inventing a condition rather than verifying one, which this phase's own instruction 4 explicitly prohibits ("do not create a generic... test and call that vulnerability verification"). Left as a clearly-scoped, straightforward extension for a future phase once a specific real CVE justifies it, using the exact same `VerificationTest` registration pattern.

## 11. Known limitations

1. No real physical-hardware validation yet (§9) — the single biggest gap before this can be called production-validated.
2. Only 2 verification tests exist, both HTTP — MQTT/CoAP/RTSP verification is unbuilt (§10).
3. Scope enforcement is implicit (device must already exist in the DB via the real discovery chain) rather than an explicit "assessment scope" check against Phase 1's `assessments`/`sessions` relationship — matches this codebase's existing precedent (M4 has the same property) rather than a gap unique to this phase, but worth strengthening once Phase 1's `assessments` table gets real orchestration wiring.
4. `_pick_port` only checks the device's already-recorded `open_ports` (from M1's Nmap scan) — a device whose Nmap scan missed the relevant port (e.g. non-standard HTTP port) will get `TEST_UNAVAILABLE`/`INCONCLUSIVE` even if the real service is reachable elsewhere; no fallback port-probing exists in Phase 6 itself.
5. Redaction (§6) is opt-in per test (`_sensitive_keys`) — a future test author who forgets to mark a sensitive field would leak it; no automatic secret-shaped-string detection exists.
