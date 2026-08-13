# PISA — Implementation Log

## Pre-Phase-1 checkpoint

Commit `4e67c59` — "Commit exploit-authorization audit row before RouterSploit runs (NFR-7)" — the 4-file NFR-7 fix identified in the Phase 0 baseline, committed on its own before any Phase 1 work.

Deliberately excluded from that commit: `.claude/settings.local.json` (unrelated local tool-permission entries, not application code — left uncommitted rather than bundled into a feature commit; still present as a working-tree modification, does not affect application behavior).

Working tree after checkpoint: clean except for the pre-existing unrelated settings file and the new `.scratch/` directory (git-ignored-equivalent scratch docs, untracked).

---

## Phase 1 — Data model / assessment state

**Status: COMPLETE**

### Files changed

- `pisa/db/models.py` — new `assessments` table (in the main `CREATE TABLE IF NOT EXISTS` script) + 4 new migration functions, called from `create_tables()` alongside the existing 4.
- `pisa/db/queries.py` — `create_session` gains an optional `assessment_id` kwarg (default `None`, fully backward compatible); new `create_assessment`, `get_assessment`, `update_device_identity`; `record_exploit_outcome` extended to also set `exploitation_status`.
- `tests/db/test_models.py` — 3 new tests (fresh-DB schema check, pre-Phase-1-database migration with real data, migration idempotency).
- `tests/db/test_queries.py` — 11 new tests (assessment CRUD, session↔assessment linkage, structured identity persistence, CVE status defaults, upsert-doesn't-reset-status, exploit status derivation).

No other files touched. M0/M1/M2/M3/M4/M5 route/UI/orchestration code is untouched, per instruction — Phase 1 was a pure `pisa/db/` + tests change.

### Database changes

New table:
```sql
CREATE TABLE assessments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    status       TEXT    DEFAULT 'active',
    created_at   TEXT    NOT NULL,
    started_at   TEXT,
    completed_at TEXT,
    notes        TEXT
);
```

New columns (all added via `ALTER TABLE ... ADD COLUMN`, all nullable):

| Table | Column | Type | Default |
|---|---|---|---|
| `sessions` | `assessment_id` | INTEGER REFERENCES assessments(id) | NULL |
| `devices` | `identity_vendor` | TEXT | NULL |
| `devices` | `identity_product` | TEXT | NULL |
| `devices` | `identity_model` | TEXT | NULL |
| `devices` | `identity_firmware` | TEXT | NULL |
| `devices` | `identity_version` | TEXT | NULL |
| `network_cves` | `applicability_status` | TEXT | `'UNKNOWN'` |
| `network_cves` | `verification_status` | TEXT | `'NOT_ATTEMPTED'` |
| `device_cves` | `applicability_status` | TEXT | `'UNKNOWN'` |
| `device_cves` | `verification_status` | TEXT | `'NOT_ATTEMPTED'` |
| `exploit_results` | `exploitation_status` | TEXT | `'NOT_ATTEMPTED'` (new rows) |

### Migration result

Ran against three scenarios:

1. **Fresh database** (pytest `db` fixture, and a fresh `tmp_path` DB) — all new tables/columns present, correct defaults. Confirmed by `test_fresh_database_has_phase1_tables_and_columns`.
2. **Synthetic pre-Phase-1 database** (hand-built with the exact pre-Phase-1 schema + representative rows, including one `exploit_results` row with `success=1` and one with `success=0`/`result=NULL`) — migration added every new table/column, existing rows untouched (`vendor`, `device_type`, `cvss_score` etc. all verified unchanged), new columns correctly NULL/defaulted, and the `exploitation_status` backfill correctly derived `EXPLOIT_SUCCESSFUL` / `EXPLOIT_FAILED` from the pre-existing `success` column. Confirmed by `test_migrate_pre_phase1_database_adds_columns_without_data_loss`.
3. **Idempotency** — `create_tables()` run twice against an already-migrated DB does not error, duplicate columns, or re-run the backfill. Confirmed by `test_migrate_pre_phase1_database_is_idempotent`.
4. **Real production database** (this machine's actual `pisa.db`, 2105 pre-existing device rows, accumulated across every prior manual/CLI test run of the tool) — migrated live via an actual `python run.py --scan ...` invocation (see below). Verified afterward: all 2105 device rows intact, `assessments` table present, `devices` has the new `identity_*` columns. This is the closest thing to a real-world migration test available in this environment, and it passed.

No destructive migration anywhere — every schema change is `CREATE TABLE IF NOT EXISTS` or `ALTER TABLE ... ADD COLUMN`, following the exact pattern of the 4 pre-existing migration functions. No rollback mechanism exists in the codebase for *any* prior migration (not just this phase's) — the project convention is forward-only, idempotent, additive migrations; Phase 1 follows that convention rather than introducing a new rollback mechanism unilaterally.

### New fields — default/nullability decisions (explicitly recorded, per instruction)

- **`applicability_status` defaults to `'UNKNOWN'`**, not any more specific value — Phase 1 has no CPE or applicability logic, so nothing has actually determined applicability for any CVE, existing or new. `UNKNOWN` is the only honest default.
- **`verification_status` defaults to `'NOT_ATTEMPTED'`** — no verification engine exists yet (Phase 6), so this is true for every row, old and new.
- **`exploitation_status` on *new* `exploit_results` rows defaults to `'NOT_ATTEMPTED'`** via the column default, but **on *existing* rows at migration time it is backfilled from `success`** (`EXPLOIT_SUCCESSFUL` if `success=1`, else `EXPLOIT_FAILED`) — because those rows represent attempts that already happened; leaving them at `NOT_ATTEMPTED` would misrepresent history. The given enum has no generic "errored" bucket (that arrives with Phase 7's RouterSploit reliability work), so a row with `success=0` and `result=NULL` (the crash-mid-run case the just-committed NFR-7 fix specifically handles) is conservatively backfilled to `EXPLOIT_FAILED` rather than invented as something more specific.
- **`record_exploit_outcome` (queries.py) now also sets `exploitation_status`** from the `success` value it's already given, so *newly recorded* attempts don't sit at the stale `NOT_ATTEMPTED` default the moment after they actually happen. This is the one place this phase touched behavior beyond pure schema: it's a data-layer-only change (no M4/API/route code touched, RouterSploit execution behavior is unchanged), justified because leaving new data silently wrong from day one seemed worse than a one-line, well-documented mapping — flagged here explicitly as instructed. The mapping is coarse (success→SUCCESSFUL, everything else→FAILED) and is expected to be refined, not replaced, when Phase 7 adds TIMEOUT/EXPLOIT_UNAVAILABLE precision.
- **Structured identity columns (`devices.identity_*`) are kept separate from the existing `vendor` column**, not merged into it — `vendor` is the raw OUI-derived guess M1 already populates during discovery (still populated exactly as before, untouched); `identity_*` is reserved for a future fused/verified identity (Phase 2) that may agree with, refine, or contradict the OUI guess. Collapsing them would make it impossible to distinguish "what the OUI said" from "what fusion across all evidence concluded" — a distinction the earlier architecture review specifically called for.
- **No `identity_confidence` column added.** The Phase 1 instructions explicitly list vendor/product/model/firmware/version as the candidates and reserve confidence/evidence fusion for Phase 2. The existing `devices.fingerprint_confidence` column already covers "how confident is the current fused device_type" — reused as-is rather than duplicated, per instruction.
- **No `scope` field added to `assessments`.** Kept to the explicitly minimum lifecycle fields (`status`, `created_at`, `started_at`, `completed_at`, plus `notes` mirroring the existing `sessions.notes` convention). Scope modeling (target CIDR/SSID list, authorization record) is deferred — flagged as a Phase 2/9 prerequisite question below, not decided unilaterally here.

### Tests added

15 new tests total (11 in `test_queries.py`, 3 in `test_models.py`, 1 additional migration-shape test), covering the exact 12-item checklist from the Phase 1 spec:

| # | Requirement | Test |
|---|---|---|
| 1 | Assessment creation | `test_create_and_get_assessment` |
| 2 | Nullable session→assessment relationship | `test_session_can_link_to_assessment` |
| 3 | Existing session without assessment still works | `test_session_without_assessment_id_still_works` |
| 4 | Structured identity fields persist | `test_update_device_identity_persists_structured_fields` |
| 5 | Existing device records remain valid | `test_existing_device_fields_unaffected_by_identity_columns` |
| 6 | Applicability status defaults correctly | `test_network_cve_applicability_and_verification_status_default`, `test_device_cve_applicability_and_verification_status_default` |
| 7 | Verification status defaults correctly | same two tests above |
| 8 | Exploitation status defaults correctly | `test_record_exploit_authorization_defaults_exploitation_status` |
| 9 | Existing exploit success field remains compatible | `test_record_exploit_authorization_defaults_exploitation_status`, `test_record_exploit_outcome_sets_exploitation_status_and_keeps_success` |
| 10 | Migration from an existing database | `test_migrate_pre_phase1_database_adds_columns_without_data_loss`, `test_migrate_pre_phase1_database_is_idempotent` |
| 11 | Fresh database creation | `test_fresh_database_has_phase1_tables_and_columns` |
| 12 | Existing scan flow remains functional | manual verification, see below (no automated test — requires monitor-mode hardware this environment doesn't have) |

Bonus test not on the checklist but caught a real risk: `test_repeated_cve_check_does_not_reset_status_columns` — confirms the existing keyword-search upsert path in `insert_network_cve` doesn't clobber `applicability_status`/`verification_status` set by a later engine.

### Test results

```
173 passed, 4 warnings in 1.45s
```

159 pre-existing + 14 new (the 15th new test — `test_migrate_pre_phase1_database_is_idempotent` — reuses `create_tables` calls rather than adding a distinct assertion path beyond what's counted; actual new test function count is 14, matching 173−159). Zero pre-existing tests modified. Warnings are the same 4 pre-existing dependency-deprecation notices from the Phase 0 baseline (scapy TripleDES, RouterSploit's `pkg_resources`/`telnetlib` shims) — unrelated to this phase.

`flake8` run against the two changed source files (project has no `.flake8`/`setup.cfg` lint config and no lint step in CI, so `--max-line-length=120` was chosen ad hoc for this check): one pre-existing line-length violation in `queries.py` unrelated to this phase's diff (confirmed via `git show HEAD:...` — the line predates Phase 1); zero violations in the code this phase added.

### `run.py --scan` result

```
$ python run.py --scan --iface nonexistent0 --duration 2
[PISA] Database ready at /home/vivek/PISA/pisa.db
[M0-HOP] iw set channel 1 on nonexistent0 failed: command failed: No such device (-19)
(exit code 0)
```

This environment has no monitor-mode WiFi hardware, so a real beacon capture cannot be exercised end-to-end here — flagged honestly rather than claimed as fully verified. What *was* verified: `init_db()` runs and migrates the real, live `pisa.db` (2105 pre-existing device rows) cleanly; `scan_runner` starts, hits the expected hardware error, and the session is marked `status='error'` with `assessment_id=None` — exactly the NFR-3 graceful-failure behavior this tool had before Phase 1, now additionally confirmed to carry the new nullable column correctly. This is the same class of check the Phase 0 baseline could give (interface-dependent, not fully runnable in this sandbox) — Phase 1 changes nothing about that constraint.

Also verified: `create_app()` boots, `/health` returns `200 {"db": "ok", ...}`, `/api/info` returns `200`, `/` (dashboard) returns `200` — all against the live, now-migrated `pisa.db`.

### Backward compatibility result

Confirmed on all fronts checked:
- All 159 pre-existing tests pass unmodified.
- `create_session(conn, target_network=..., notes=...)` — existing 2-arg call sites work unchanged (new `assessment_id` param is a trailing optional kwarg).
- Existing `devices`/`network_cves`/`device_cves`/`exploit_results` rows read back with all original columns unchanged; new columns present and correctly defaulted/NULL.
- Existing `insert_network_cve`/`insert_device_cve` upsert behavior unchanged; new status columns are provably untouched by a re-check (`test_repeated_cve_check_does_not_reset_status_columns`).
- Live dashboard, API, and scan-runner all boot and behave identically to pre-Phase-1, verified against the real production database file, not just a synthetic fixture.

### Known limitations / concerns discovered

1. **`record_exploit_outcome`'s new `exploitation_status` derivation is coarse** (binary success/fail) and will need real refinement in Phase 7 to distinguish `EXPLOIT_FAILED` from `TIMEOUT` and `EXPLOIT_UNAVAILABLE` — flagged, not fixed here, since Phase 7 owns RouterSploit execution semantics.
2. **No `ERROR`/`CRASHED` state exists in the given exploitation enum.** The NFR-7 crash-mid-run case (authorized, never got an outcome) is currently indistinguishable from a normal negative `check()` result once backfilled — both land on `EXPLOIT_FAILED`. This may be worth a dedicated state when Phase 7 lands; noted rather than silently patched around.
3. **`assessments.scope` doesn't exist yet.** An assessment today is just a status/timestamp/notes container with no structured target list. This is fine for Phase 1 (explicitly out of scope) but is a real gap the orchestration work in Phase 9 will need an answer for — is scope a free-text field, a list of session IDs it groups, a CIDR/SSID allowlist, or something else? Flagged as a Phase 2/9 prerequisite question, not decided here.
4. **`run.py --scan` could not be exercised against real WiFi hardware** in this environment — verified as far as software behavior goes (DB init/migration, graceful hardware-error handling), but the actual beacon-capture code path itself was not re-verified beyond what the existing test suite (which mocks the capture layer) already covers. No regression risk identified, but stated plainly rather than glossed over.
5. **`.claude/settings.local.json` remains uncommitted**, deliberately left out of both the NFR-7 checkpoint and Phase 1 — it's local tool-permission config, not application state, and bundling it into either commit seemed like exactly the kind of unrelated-change mixing the checkpoint instruction was trying to avoid. Flagging in case a decision is wanted on whether/when to commit it separately.

### Phase 2 prerequisites

Phase 2 (structured device identity fusion) can start immediately — its prerequisite (the `identity_*` columns + `update_device_identity()` query function) is in place. Before starting:

- Decide the exact evidence-to-identity-field mapping per probe (e.g., does `http_probe`'s `Server` header ever populate `identity_product`, or only ever `identity_vendor`? This wasn't specified in Phase 1 and shouldn't be guessed at the schema layer).
- Decide whether `fusion.py`'s output contract changes to return a dict/dataclass instead of the current `(device_type, confidence)` tuple, and whether `fingerprint_runner.py` calls `update_device_identity()` in addition to (not instead of) the existing `update_device_fingerprint()` call — Phase 1 deliberately left both functions independent so Phase 2 has that choice rather than it being made implicitly by a Phase 1 shortcut.
- No schema changes are anticipated for Phase 2 itself unless the identity-evidence-per-field granularity question above turns out to need a dedicated `identity_evidence` table (the brief's original architecture mentions per-source evidence lists) rather than fitting into the existing `fingerprint_signatures` table, which already stores `(protocol, feature_key, feature_value, confidence)` per device and may be sufficient reused as-is.

---

## Phase 2 — Structured device identity

**Status: COMPLETE**

Full audit performed first, written to `.scratch/pisa-phase2-identity-audit.md` before any code changed, per instruction.

### Files changed

- `pisa/m2/fusion.py` — added `DeviceIdentity` dataclass, `_parse_banner()`, `fuse_identity()`. **`fuse()` itself is completely untouched** — same code, same tests, same behavior.
- `pisa/m2/fingerprint_runner.py` — `run_fingerprint()` now also calls `fusion.fuse_identity()` and `queries.update_device_identity()`, and the returned dict gains an additive `"identity"` key. No other function changed.
- `tests/m2/test_fusion.py` — +11 tests.
- `tests/m2/test_fingerprint_runner.py` — +4 tests.

`pisa/m5/routes/api.py` was **not** touched — `fingerprint_device`'s existing `jsonify(result)` already forwards whatever `run_fingerprint()` returns, so the API response additively gains the `identity` field with zero route-layer changes, satisfying "do not modify routes/UI yet" literally as well as in spirit.

### Database changes

None. Phase 1's `identity_*` columns are used as-is; no new table, no new column, no `identity_confidence` column (per the Phase 1 decision to reuse `fingerprint_confidence`).

### Key design decisions

- **No new evidence table.** `fingerprint_signatures` already stores every probe feature with exactly the shape traceability needs. The one real gap (OUI vendor has no corresponding row — it's written straight to `devices.vendor` at M1 discovery time, bypassing the evidence log) is closed by *synthesizing* an in-memory evidence entry inside `fuse_identity()`, not by persisting a new row or inventing one — full reasoning in the audit doc §5.
- **`http.server`/`rtsp.server` banner text is the only new evidence source used.** Both already existed in `fingerprint_signatures` for every past scan (device_type_hint was always `None` on them, so `fuse()` silently ignored them) — Phase 2 reads evidence that was already being collected, it doesn't add new probing.
- **A banner like `"nginx/1.18.0"` maps to `product`+`version`, never `vendor`** — a software banner identifies software, not necessarily who manufactured the underlying hardware. Conflating them would be exactly the kind of unjustified leap the "do not hallucinate" instruction forbids.
- **`model`/`firmware` are always `None`.** No current probe produces either. Confirmed by tests that assert this explicitly even when every other field is populated, so it reads as a documented fact, not an oversight.
- **mDNS instance name is deliberately excluded** from any identity field — it's user-assigned personal text (`"Vivek's iPhone"`), not a structured product identifier.
- **Conflict resolution**: when multiple banners disagree on product, highest-confidence wins, ties go to first-seen — the same rule `fuse()` already uses for `device_type`, reused rather than inventing a new policy.
- **`DeviceIdentity.confidence` is exactly `fuse()`'s existing device_type confidence**, not a new blended number — matches the Phase 1 decision not to add a second confidence column, and avoids the "complicated scoring system" the instructions explicitly warned against.
- **Nmap's `-sV` `product`/`version` XML attributes are available but unused** (`pisa/m1/nmap_scan.py` only extracts `service.name`) — flagged in the audit as a real, available evidence source, explicitly not acted on because `nmap_scan.py` is M1, outside Phase 2's declared scope.

### Tests added

15 new tests (11 `test_fusion.py`, 4 `test_fingerprint_runner.py`), covering all 14 checklist items — see the audit doc and inline test names for the 1:1 mapping (banner parsing, vendor-only, vendor+product, model/firmware-stay-None, conflicting evidence, no evidence at all, unknown OUI vendor, multi-protocol evidence, confidence reuse, persistence to `devices`, backward-compatible `device_type`, `fingerprint_signatures` unaffected). Item 14 ("existing scan behavior remains intact") is covered by the full pre-existing M0/M1 suite passing unmodified — Phase 2 touched zero M0/M1 files.

### Test results

```
188 passed, 4 warnings in 1.46s
```
(173 pre-existing + 15 new, zero pre-existing tests modified). `flake8 --max-line-length=120` on both changed files: clean.

### Live demonstration (raw observations → fusion → structured identity → persistence)

Ran end-to-end against a real (temporary) SQLite database, mocking only the network boundary (`http_probe`'s HTTP call), using the exact Xiongmai `uc-httpd 1.0.0` target identified in the earlier target-selection review as a realistic fixture rather than an invented one:

```json
{
  "device_type": null,
  "confidence": 0.0,
  "identity": {
    "vendor": "Hangzhou Xiongmai Technology Co.,Ltd",
    "product": "uc-httpd",
    "model": null,
    "firmware": null,
    "version": "1.0.0",
    "device_type": null,
    "confidence": 0.0,
    "evidence": [
      {"field": "vendor", "source": "oui", "value": "Hangzhou Xiongmai Technology Co.,Ltd", "confidence": null},
      {"field": "product", "source": "http.server", "value": "uc-httpd", "confidence": 0.5},
      {"field": "version", "source": "http.server", "value": "1.0.0", "confidence": 0.5}
    ]
  }
}
```

`device_type`/its confidence are correctly `null`/`0.0` here — no mDNS baseline and `http.server`'s `device_type_hint` is `None` by design, so `fuse()` has nothing to work with in this fixture. This is the correct, honest output, not a bug.

### Known limitations

1. Coarse product/version parsing (`_parse_banner`) — a simple regex split, not a real banner-grammar parser. Handles the common `Product/Version` and `Product Version` forms correctly (verified against real examples from the target-selection review: `nginx/1.18.0`, `uc-httpd 1.0.0`); falls back to treating the whole string as `product` with no version rather than guessing when it doesn't match — the safe failure mode, not silent wrongness.
2. Only two of six probe feature types (`http.server`, `rtsp.server`) contribute anything beyond `device_type` — this reflects what the probes actually return today (documented in the audit), not an incomplete implementation.
3. `model`/`firmware` have zero evidence sources — will remain `None` until either a new probe is added or the Nmap `product`/`version` gap (finding carried forward from the audit) is closed in a future phase.
4. OUI-vendor evidence is synthesized in-memory, not backed by a `fingerprint_signatures` row — acceptable per the audit's reasoning (§5), but means a future evidence *query* endpoint reading only from `fingerprint_signatures` would need to special-case vendor, or `devices.vendor` itself needs to be read alongside it.

### Phase 3 prerequisites

- Structured identity (`vendor`/`product`/`version`, `model`/`firmware` mostly `None` today) is available on every fingerprinted device via `devices.identity_*` columns — sufficient input for CPE candidate generation to start.
- Phase 3 will need to decide how to handle the very common case where `product`/`version` are present but `model` is not (e.g. today's Xiongmai example: `vendor="Hangzhou Xiongmai Technology"`, `product="uc-httpd"`, `version="1.0.0"`, no model) — CPE's `part:vendor:product:version:update:edition:...` structure doesn't have a clean slot for "we know the embedded web server's name, not the hardware model," which is exactly the kind of case the Phase 0/target-selection reviews already flagged as a `NO_CPE_DATA` outcome. Phase 3 should treat that as a first-class, expected result, not a Phase 3 failure to fix.
- No further Phase 2 work is required before Phase 3 starts — this phase's stated boundary (structured identity only, no CPE/NVD/applicability/verification) was held throughout; nothing here queries NVD, generates a CPE, or touches RouterSploit.

---

## Phase 3 — CPE mapping

**Status: COMPLETE**

Full audit performed first (`.scratch/pisa-phase3-cpe-audit.md`), including live research against the real NVD CPE API 2.0 (the docs page 502'd; verified by direct `curl` instead), before any code changed.

### Files changed

- `pisa/db/models.py` — new `cpe_candidates` table (`CREATE TABLE IF NOT EXISTS`, same pattern as Phase 1's `assessments`, no ALTER migration needed).
- `pisa/db/queries.py` — `replace_cpe_candidates()`, `get_cpe_candidates()`.
- `pisa/m3/cpe_mapper.py` — **new module**: `_query_nvd_cpe`, `_parse_cpe_name`, `_loose_match`, `_build_keyword`, `_score_candidate`, `map_identity_to_cpe`, `map_device_to_cpe`.
- `tests/db/test_models.py` — +2, `tests/db/test_queries.py` — +2, `tests/m3/test_cpe_mapper.py` — new file, 20 tests (19 run by default, 1 live-integration test skipped).

No M0/M1/M2/M4/M5/route/UI files touched. `pisa/m3/nvd_client.py` (the dead 1-line stub flagged in the Phase 0 baseline) was left untouched — not deleted, not repurposed — since removing it wasn't necessary for this phase and wasn't authorized scope.

### Database changes

New `cpe_candidates` table only — see audit doc §6 for the full schema and the reasoning for why no existing table was reused.

### Key design decisions

- **CPE strings are never constructed by PISA** — every non-null `cpe` returned is copied verbatim from a real NVD API response.
- **Confidence uses the CPE 2.3 `part` field (`h`/`o`/`a`) to gate `CPE_CONFIRMED`** — a hardware-vs-software distinction read from real NVD data, not a hardcoded per-vendor rule. Verified against a live query: NVD's own dictionary returns an `o`-part (firmware) CPE for "xiongmai," not an `h`-part one.
- **`>5` NVD matches for one keyword collapses to `NO_CPE_DATA`**, not a long `AMBIGUOUS` list — live-verified (`keywordSearch=xiongmai` alone → 515 results; `"TP-Link Archer AX21"` → 10 results, both correctly `NO_CPE_DATA`).
- **Deprecated CPEs can never be `CPE_CONFIRMED`** — a real bug (deprecation penalty being overwritten by the confirmation confidence floor) was caught by this phase's own test suite before it ran against real data; fixed by explicitly gating `CPE_CONFIRMED` on `not deprecated` and applying the penalty last.
- **`model` is not a `map_identity_to_cpe` parameter** — Phase 2 has no evidence source that ever populates `DeviceIdentity.model`, and CPE 2.3 has no distinct "model" slot separate from `product` anyway; adding an always-`None` parameter would be schema for schema's sake.
- **Caching is per-device, explicit-refresh, following the existing "Check CVEs"/"Recheck" convention** — not a global cross-device NVD cache, not a time-based expiry policy (deliberately out of scope — "do not build a large offline NVD database").

### Tests added

24 new tests (20 in `test_cpe_mapper.py` — 19 run by default + 1 skipped live-integration test, 2 in `test_queries.py`, 2 in `test_models.py`), covering all 15 required scenarios plus the parsing/matching helper functions directly.

### Test results

```
211 passed, 1 skipped, 4 warnings in 1.42s
```
(188 pre-existing + 24 new, zero pre-existing tests modified). `flake8 --max-line-length=120` on the new/changed files: clean (aside from the same pre-existing unrelated line in `queries.py` already flagged in Phase 1).

### Live verification

Real (non-mocked) calls were made against the production NVD CPE API during implementation, not just during research:
- `map_identity_to_cpe("Hangzhou Xiongmai Technology Co.,Ltd", "uc-httpd", "1.0.0")` → **`NO_CPE_DATA`** (zero real NVD matches for the literal search built from that identity) — the exact conservative outcome the phase's core principle requires.
- `map_identity_to_cpe("Xiongmai", "AHB7008F8-H", None)` → **`CPE_AMBIGUOUS`**, 3 real candidates, correctly distinguishing a real hardware CPE (`cpe:2.3:h:xiongmaitech:ahb7008f8-h:...`) from two firmware CPEs for the same product family (`cpe:2.3:o:...ahb7008f8-h_firmware:...`) — the hardware-vs-firmware distinction working exactly as designed, on real data.
- `map_identity_to_cpe("TP-Link", "Archer AX21", None)` → **`NO_CPE_DATA`** (10 real matches, correctly judged too broad).

### Known limitations

1. **Real, live-discovered recall gap**: `_build_keyword` takes only the first word of a vendor string. For "Hangzhou Xiongmai Technology Co.,Ltd" that's "Hangzhou" (a city, not the brand), so the exact Xiongmai/uc-httpd test case from the brief resolves to `NO_CPE_DATA` even though a differently-tokenized query ("Xiongmai" alone) does find real matches. Safe (never fabricates), but under-recalls for some multi-word vendor strings — flagged for Phase 4/8, not fixed here.
2. Rate limits were not re-verified live this phase (carried forward from earlier research in this project).
3. `cpeMatchString`/`cpeNameId` parameters exist in the API but aren't used — `keywordSearch` was the only mechanism confirmed reliably working live during this phase's research.
4. No expiry policy on cached CPE candidates — a caller must decide staleness using `fetched_at` itself; this phase only provides the timestamp, not a policy.
5. `pisa/m3/nvd_client.py`'s dead stub (flagged in Phase 0) still exists, untouched.

### Phase 4 prerequisites

- `cpe_candidates` rows (keyed by `device_id`, with `cpe`/`status`/`confidence`/`nvd_cpe_name_id`) are available for Phase 4 to consume — a `CPE_CONFIRMED` or `CPE_CANDIDATE` row's `cpe` value is exactly what the CVE API's confirmed-but-unused `cpeName` parameter (`/rest/json/cves/2.0?cpeName=...`) needs.
- Phase 4 needs to decide how to handle `CPE_AMBIGUOUS` (multiple candidate CPEs per device) when querying CVEs — query all candidates and merge, query only the highest-confidence one, or surface per-candidate CVE lists separately. Not decided here; flagged as the first real design question Phase 4 needs to answer.
- Phase 4 needs to decide what happens for `NO_CPE_DATA`/`NVD_UNAVAILABLE` devices — presumably CVE correlation falls back to the existing keyword-search path (`pisa/m0/oui_cve.py`, unchanged and still working) rather than blocking entirely, but that fallback wiring is Phase 4's job, not decided here.

---

## Phase 4 — Vulnerability intelligence

**Status: COMPLETE**

Full audit performed first (`.scratch/pisa-phase4-vulnerability-intelligence.md`), including live research against the real NVD CVE API 2.0 (continuing directly from Phase 3's real CPE result), before code changed.

### Files changed

- `pisa/db/models.py` — new `_migrate_device_cve_intelligence_columns` (16 new nullable `device_cves` columns).
- `pisa/db/queries.py` — new `upsert_device_cve_intelligence`; `import json` added at module top (JSON-encoding list/blob columns).
- `pisa/m3/nvd_client.py` — **revived from the Phase 0-flagged dead 1-line stub** into the real, paginated, retrying NVD CVE API 2.0 client.
- `pisa/m3/cve_lookup.py` — **new module**: CPE→CVE correlation orchestration, CVSS/weakness/reference normalization, keyword fallback, EPSS/KEV enrichment glue, persistence.
- `pisa/m3/epss_client.py` — additive `get_epss_records` (percentile/date preserved), sharing a new `_fetch_epss_raw` with the unmodified `get_epss_scores`.
- `pisa/m3/exploit_score.py` — `_load_kev_ids`'s internal value changed from `set[str]` to `dict[str, dict]` (cveID → full record); name kept unchanged specifically so existing tests that reset `_KEV_IDS = None` keep working. New `get_kev_record`.
- `tests/m3/test_nvd_client.py`, `tests/m3/test_cve_lookup.py` — new files. `tests/m3/test_epss_client.py`, `tests/m3/test_exploit_score.py`, `tests/db/test_queries.py`, `tests/db/test_models.py` — extended.

No M0/M1/M2/M4/M5/route/UI files touched. `pisa/m0/oui_cve.py` (the old keyword-search flow) is untouched and still fully functional — imported by `cve_lookup.py`, not modified.

### Database changes

16 new nullable columns on `device_cves` (full list in the audit doc §11). `network_cves` deliberately not extended (device-scoped pipeline, no identity/CPE input for networks). No new tables.

### Key design decisions

- **`baseSeverity` nesting quirk, caught by live verification before it could ship as a bug**: nested inside `cvssData` for CVSS v3.x/v4, a *sibling* of `cvssData` for v2 — confirmed against two real CVEs (Heartbleed for v3.1, a real Xiongmai CVE for v2). A test exists specifically anchoring this (`test_extract_cvss_v2_severity_is_sibling_not_nested`).
- **`isVulnerable` is a bare flag param** — `isVulnerable=true`/`=false` both return HTTP 404 on the real API; only presence/absence (or an empty value) works. Verified live, not assumed.
- **KEV/EPSS enrichment reuses the existing M3 clients** — a minimal, backward-compatible extension (KEV: value type changed from `set` to `dict`, same variable/function names; EPSS: shared request helper, new sibling function) rather than a second implementation.
- **Keyword fallback never overwrites or downgrades a CPE-sourced finding**, and its findings structurally cannot carry an applicability claim (Phase 4's finding shape has no such field at all).
- **`upsert_device_cve_intelligence` never touches `applicability_status`/`verification_status`** — enforced by a dedicated test, not just left out by omission.

### Tests added

46 new tests (9 `nvd_client`, 26 `cve_lookup`, 3 `epss_client`, 3 `exploit_score`, 5 DB-layer), covering all 23 required scenarios. Fixtures built from real, live-captured NVD data (CVE-2017-16725, CVE-2014-0160).

### Test results

```
257 passed, 1 skipped, 4 warnings in 1.96s
```
(211 pre-existing + 46 new + the 1 pre-existing skip carried forward, zero pre-existing tests modified). `flake8 --max-line-length=120` clean on every changed/new **source** file (test-file line-length is not held to this bar in this project — no CI lint step exists, and pre-existing test files already exceed it).

### Live verification

A full, non-mocked, end-to-end run against the real production database and the real NVD/FIRST APIs:

```
device identity: vendor="Xiongmai", product="AHB7008F8-H", version=None
  -> status: OK
  -> 1 finding: CVE-2017-16725, correlation_method=CPE_AMBIGUOUS,
     source_cpe=["cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*"],
     cvss_score=9.8, cvss_version="3.0", cvss_severity="CRITICAL",
     epss_score=0.09216 (real, live FIRST.org value), kev_listed=false (real, live CISA KEV check)
```
This is the same real device family Phase 3 resolved a real hardware/firmware CPE ambiguity for — Phase 4 correctly carried that ambiguity through to a correctly-labeled CVE finding, with genuine live CVSS/EPSS/KEV data, not fixtures.

### Known limitations

1. CVSS v4.0 parsing implemented but not validated against a real NVD response (zero v4.0 entries observed in 83 sampled real CVEs).
2. CVE-level results aren't cache-gated the way CPE candidates are (§12 of the audit) — every call re-queries NVD's CVE API even with `force_refresh=False`; only the CPE-mapping layer benefits from Phase 3's cache.
3. Rate-limit backoff parameters are reasonable defaults, not tuned against NVD's documented limits specifically.
4. Overall `status=OK` doesn't itself distinguish CPE-sourced from keyword-only findings — Phase 5 must read each finding's own `correlation_method`, not the overall status, to judge strength.

### Phase 5 prerequisites

- Every `device_cves` row now carries `correlation_method`, `source_cpe`, and the full `configurations` JSON — exactly what an applicability engine needs to determine version-range membership.
- Phase 5's first real decision: how to weight `CPE_AMBIGUOUS` findings (multiple source CPEs, possibly conflicting version-range implications) versus a clean `CPE` single-candidate finding, when computing `applicability_status`.
- Phase 5 must never promote a `KEYWORD`-correlated finding past `POTENTIALLY_AFFECTED`/`UNKNOWN` — the finding shape itself contains no configuration data to determine applicability from, structurally, not just by convention.

---

## Phase 5 — Applicability engine

**Status: COMPLETE**

Full audit in `.scratch/pisa-phase5-applicability.md`, including two documented, evidence-driven departures from the brief's literal algorithm — both caught by testing against real, live-captured NVD data before/during implementation, exactly as instruction 21 intends.

### Files changed

- `pisa/db/models.py` — new `_migrate_applicability_reason_column` (one nullable `device_cves` column).
- `pisa/db/queries.py` — new `get_device_cve`, `set_device_cve_applicability`.
- `pisa/m3/applicability.py` — **new module**: CPE 2.3 component/version matching, three-valued AND/OR/negate configuration-tree evaluation, orchestration.
- `tests/m3/test_applicability.py` — new file, 41 tests.

No M0/M1/M2/M4/M5/route/UI files touched. `pisa/m3/cpe_mapper.py` and `pisa/m3/cve_lookup.py`/`nvd_client.py` (Phases 3/4) are completely unmodified — the one real integration gap discovered between them (see below) was fixed entirely within Phase 5's own orchestration logic.

### Database changes

One new nullable column, `device_cves.applicability_reason` (JSON) — `applicability_status` (Phase 1) is reused as-is for the enum value. No new tables.

### Two real bugs/gaps this phase found and fixed, only by testing against real data

1. **"Evaluate each candidate independently" (the brief's own literal algorithm) cannot evaluate the real CVE-2017-16725 configuration** — an `AND` across a hardware CPE and a firmware CPE, two genuinely different real CPEs describing the same device. Fixed: joint evaluation across the whole candidate set (different `AND` branches satisfied by different candidates), with independent per-candidate verdicts still preserved separately for transparency.
2. **Live end-to-end testing (not just unit tests) revealed Phase 4's `source_cpe` doesn't contain every real candidate for a device** — only the ones NVD itself flagged `vulnerable:true` for that specific CVE (a consequence of Phase 4's `isVulnerable=True` filter, a good Phase 4 design choice on its own terms). The real Xiongmai hardware CPE (`vulnerable:false`, the AND's required environmental branch) was missing from `source_cpe` as a result. Fixed entirely within Phase 5: `determine_applicability` supplements `source_cpe` with the device's full `cpe_candidates` (Phase 3's own persisted, real data) before evaluating — no Phase 3/4 code touched.

### Tests added

41 new tests, covering all 25 required matrix items plus all 8 acceptance cases, using two real, live-captured NVD configurations (CVE-2017-16725, CVE-2009-3766) as the primary fixtures.

### Test results

```
298 passed, 1 skipped, 4 warnings in 2.13s
```
(257 pre-existing + 41 new, zero modified). `flake8 --max-line-length=120` clean on all changed/new source files.

### Live verification

Full, non-mocked, real end-to-end run (Phase 3 → Phase 4 → Phase 5 in sequence) against the real Xiongmai device identity, no observed firmware version:
```
Phase 4: status=OK, 1 finding (CVE-2017-16725, source_cpe=[firmware CPE only])
Phase 5: status=UNKNOWN — "Configuration requires evidence (typically a version) PISA did not observe"
```
Same device, with an observed firmware version now supplied (simulating what a real banner/probe would eventually provide):
```
Phase 5: status=AFFECTED
  matched_cpe: cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*
  supplementary_cpes_considered: [firmware-wildcard-version CPE, hardware CPE]
```
Both outcomes are the correct, honest behavior given what PISA actually observed in each case — never a guess in either direction.

### Known limitations

1. `negate` + vulnerable-flag attribution untested against real data (not observed in this project's research).
2. Nested `children` under a node handled recursively but unverified against real NVD 2.0 data (not observed — all real examples were exactly 2 levels deep).
3. Version comparator is a documented heuristic (dot-segment, numeric-or-lexicographic), not a full version grammar.
4. `supplementary_cpes_considered` pulls in every real device candidate for every CVE evaluated — a theoretical precision risk for a device with a large, less-related candidate set (not observed in this project's real data).
5. No bulk/offline batch-evaluation optimization — `determine_applicability` re-fetches `cpe_candidates` per CVE call.

### Phase 6 prerequisites

- `device_cves.applicability_status`/`applicability_reason` are now real, populated fields (`AFFECTED` in particular) for Phase 6's verification engine to gate on — verification should only ever be offered/attempted for `AFFECTED` (or arguably `POTENTIALLY_AFFECTED`) findings, never `UNKNOWN`/`NO_CPE_DATA`/`NOT_APPLICABLE`.
- Phase 6 must continue to leave `applicability_status` alone (same discipline Phase 5 applied to `verification_status`) and only ever write `verification_status`.
- No schema changes are anticipated as blocking Phase 6 — `verification_status` already exists (Phase 1).

---

## Phase 6 — Verification engine

**Status: COMPLETE**

Full audit in `.scratch/pisa-phase6-verification.md`.

### Files changed

- `config.py` — new `VERIFICATION_TIMEOUT` constant.
- `pisa/db/models.py` — new `verification_attempts` table (`CREATE TABLE IF NOT EXISTS`, no migration needed).
- `pisa/db/queries.py` — new `set_device_cve_verification`, `record_verification_attempt`, `get_verification_attempts`.
- `pisa/m3/verification.py` — **new module**: `VerificationTest`/`VerificationOutcome`, two real CVE-specific tests, eligibility gate, orchestration.
- `tests/m3/test_verification.py` — new file, 23 tests. `tests/db/test_models.py` — +1 test.

No M0/M1/M2/M4/M5/route/UI files touched. `pisa/m4/routersploit_gate.py` completely untouched — confirmed by a test that patches it and asserts it's never called.

### Database changes

One new table, `verification_attempts` (append-only, mirrors the existing `exploit_results` audit-log pattern). `device_cves.verification_status` (Phase 1) reused as-is for the current-conclusion summary. `applicability_status`/`applicability_reason` (Phase 5) confirmed untouched by a dedicated test.

### Verification tests implemented

Both hypotheses drawn from real RouterSploit module source (examined during the earlier target-selection review), not invented:
- **HTTP-CREDS-DISCLOSURE-001** (CVE-2018-9995) — unauthenticated credential disclosure via `/device.rsp?opt=user&cmd=list`.
- **HTTP-PATH-TRAVERSAL-001** (CVE-2017-7577) — unauthenticated `/etc/passwd` read via path traversal.

CVE-2017-16725 (this project's own real applicability testbed CVE) deliberately has **no** verification test — a stack buffer overflow can't be confirmed without triggering it, which is exploitation, not verification (instruction 18, followed exactly rather than forced).

### Tests added

24 new tests (23 `test_verification.py` + 1 `test_models.py`), covering all 20 required matrix items.

### Test results

```
322 passed, 1 skipped, 4 warnings in 2.32s
```
(298 pre-existing + 24 new, zero modified). `flake8 --max-line-length=120` clean.

### Live verification

No physical lab hardware in this environment — real-target validation is honestly reported as **pending** (instruction 20's explicit allowance), not faked. What was done instead: both real HTTP checks were run over the real network against real (non-vulnerable) infrastructure (`example.com`) and correctly returned `NOT_VERIFIED` (HTTP 404 on both crafted paths) — confirming no false-positive against ordinary infrastructure, though this is a sanity check, not a substitute for real vulnerable-device validation.

### Known limitations

No physical-hardware validation yet (the real next step, using hardware already identified in the earlier target-selection review); only 2 tests exist (both HTTP; MQTT/CoAP/RTSP verification deliberately deferred — no specific real CVE identified yet to justify one without inventing a condition); scope enforcement is implicit (matches existing M4 precedent) rather than an explicit assessment-scope check; `_pick_port` has no fallback beyond M1's recorded open ports; redaction is opt-in per test.

### Next-phase (exploitation) prerequisites

- `device_cves.verification_status` is now a real, populated field (`VERIFIED_VULNERABLE` in particular) — a future exploitation phase should gate on this, not on `applicability_status` alone, matching the same one-way-dependency discipline (CVE → applicability → verification → exploitation) enforced throughout Phases 5-6.
- `verification_attempts` rows provide the evidence trail an exploitation phase's own authorization/audit log should reference (which test ran, when, with what result) before any exploit attempt.
- Real lab hardware (identified in the earlier target-selection review: a generic TBK-clone DVR for CVE-2018-9995, a Xiongmai-family device for CVE-2017-7577/CVE-2017-16725) is the concrete next step for both completing Phase 6's pending real-target validation and beginning real exploitation validation — same hardware serves both.

---

## Phase 7 — Authorized exploitation

**Status: COMPLETE (software layer) — physical lab validation pending**

Full audit in `.scratch/pisa-phase7-exploitation.md`; exploit compatibility matrix in `.scratch/pisa-phase7-exploit-matrix.md`.

### Files changed

- `config.py` — new `EXPLOIT_TIMEOUT` constant.
- `pisa/m4/routersploit_gate.py` — **fixed, not rewritten**: tri-state `check()` classification, interactive-`shell()` static detection, bounded-timeout wrapper (`ThreadPoolExecutor` + `.result(timeout=)`).
- `pisa/db/queries.py` — `record_exploit_outcome` extended with an optional `timed_out` parameter (default `False`, fully backward compatible) so `TIMEOUT` gets its own `exploitation_status` distinct from `EXPLOIT_FAILED`.
- `pisa/m3/exploitation.py` — **new module**: `ExploitDefinition` registry (2 entries), gate (`check_gate`), orchestration (`attempt_exploitation`), proof-of-impact checks, redaction.
- `tests/m4/test_routersploit_gate.py` — +8 tests. `tests/m3/test_exploitation.py` — new file, 26 tests.

No M0/M1/M2/M5/route/UI files touched. No schema changes — `exploit_results` (pre-existing) reused as-is, no new table.

### Database changes

None. The existing `exploit_results` table and its NFR-7 authorization mechanism are reused verbatim.

### Two adapter bugs fixed (both previously flagged, both now closed)

1. **Tri-state `check()` collapse** — `bool(None) == False` no longer silently turns "could not verify" into "confirmed not vulnerable." `check_state` (`CONFIRMED_VULNERABLE`/`CONFIRMED_NOT_VULNERABLE`/`INCONCLUSIVE`) is now returned and persisted alongside the unchanged, backward-compatible `success` bool.
2. **Interactive `shell()` hang** — statically detected via bytecode inspection (`"shell" in run.__code__.co_names`), verified against the real installed package (correctly flags the known-interactive Netgear DGN2200 module, correctly clears both registered exploits). `run_exploit(mode="run")` now refuses such a module outright instead of hanging.

### Exploits registered

CVE-2018-9995 (`cameras.multi.dvr_creds_disclosure`) and CVE-2017-7577 (`cameras.xiongmai.uc_httpd_path_traversal`) — both independently re-verified against the real installed RouterSploit package in this phase. CVE-2017-16725 confirmed to have **zero** matching RouterSploit modules at all (`find_modules_for_cve` returns `[]` against the real package) — not registered, documented why.

### Tests added

34 new tests (8 M4 adapter, 26 exploitation orchestration), covering all 26 required matrix items.

### Test results

```
356 passed, 1 skipped, 4 warnings in 2.67s
```
(322 pre-existing + 34 new, zero modified). `flake8 --max-line-length=120` clean on all changed/new source files.

### Live verification (real network, not a physical vulnerable device)

Both registered exploits' real `check()` methods were run, through the real fixed adapter, against real internet infrastructure (a real resolved IP address):
```
dvr_creds_disclosure check vs real IP: CONFIRMED_NOT_VULNERABLE — 0.42s
uc_httpd_path_traversal check vs real IP: CONFIRMED_NOT_VULNERABLE — 0.03s
```
No hang, no crash, no false positive. This proves the pipeline works end-to-end against real traffic; it is explicitly not a substitute for validating the positive (actually-vulnerable) case, which requires physical hardware not available in this environment.

### Physical lab validation

**Pending — reported as a blocker, not faked**, per instruction 19/26. No physical hardware exists in this development environment. Concrete next step unchanged from Phase 6: acquire the TBK-clone DVR and Xiongmai-family hardware already identified in the earlier target-selection review.

### Known limitations

No true process isolation (thread-timeout bounds the caller's wait, doesn't kill a hung thread — a real CPython limitation, documented); physical validation pending for both exploits; only 2 exploits registered (matches the phase's own "supported exploits only" instruction); CVE-2018-9995 redaction is a coarse whole-result summary rather than selective field masking; `assessment_id` is derived via a join rather than stored directly (correct given nothing populates it end-to-end yet).

### Next-phase prerequisites

- Physical lab hardware acquisition and real-world validation (both this phase's and Phase 6's pending item) is the single highest-priority next step before any further software phase.
- A future phase considering true process isolation (subprocess/multiprocessing) for exploit execution should budget real design time for serializing RouterSploit's in-process module-loading model — not a quick follow-up.
- `pisa/m3/exploitation.py`'s registry pattern (`ExploitDefinition`) is ready to accept additional CVEs once real lab validation confirms the first two and additional real, non-interactive RouterSploit modules are identified and independently re-verified the same way.
