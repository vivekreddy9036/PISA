# PISA — Phase 5 Applicability Engine Audit

## 1. Applicability state machine

`UNKNOWN` / `NO_CPE_DATA` / `POTENTIALLY_AFFECTED` / `AFFECTED` / `NOT_APPLICABLE` — no new states added, per instruction. Written only by `pisa/m3/applicability.py`, never by Phase 4 (`cve_lookup.py`, unmodified) or Phase 1's schema defaults.

| Status | When |
|---|---|
| `AFFECTED` | The device's real CPE candidate set + observed version satisfies a vulnerable NVD configuration match criterion. |
| `POTENTIALLY_AFFECTED` | Same as AFFECTED, but the sole underlying CPE identity was only Phase 3's `CPE_CANDIDATE` (weak), not `CPE_CONFIRMED` — capped, never silently upgraded (instruction 12). |
| `NOT_APPLICABLE` | The candidate set structurally fails the configuration (a definite `False`, not a missing-evidence gap). |
| `UNKNOWN` | A required version (or other evidence) wasn't observed — genuinely undetermined, not guessed either way. Also the status for `KEYWORD`-only findings (see §4) and CVEs with no `configurations` data at all. |
| `NO_CPE_DATA` | Structurally defensive: a CPE-correlated row with an empty `source_cpe` — see §4. |

## 2. Configuration evaluation logic

```
device_cves row (Phase 4: source_cpe, configurations, correlation_method)
  + Phase 3's full cpe_candidates set (device_id)
  + Phase 2's identity_version
        ↓
evaluate_configurations(configurations, candidate_cpes, identity_version)
        ↓
  per top-level configuration object (OR'd together — documented NVD semantics):
    per node (AND/OR + negate over its cpeMatch list):
      per cpeMatch: does ANY candidate CPE's (part,vendor,product,...) match
                    the criteria, AND does identity_version satisfy the
                    version constraint (inline or versionStart/End range)?
        ↓
  Kleene three-valued AND/OR/negate combination (True/False/None)
        ↓
  if the whole configuration is True: does at least one *contributing*
  cpeMatch have vulnerable=true? -> AFFECTED. If none do -> NOT_APPLICABLE
  (structurally matched the required environment, but not the actually-
  vulnerable component). If None anywhere with no False -> UNKNOWN.
```

Full DDL/code in `pisa/m3/applicability.py`.

## 3. Version comparison

Segment-by-segment on `.`: numeric segments compare numerically, non-numeric segments compare lexicographically. Handles real OpenSSL-style suffixed versions correctly (`1.0.1a > 1.0.1`, verified as a unit test) as a deliberate, documented heuristic — not a full semver parser. `versionStartIncluding`/`versionStartExcluding`/`versionEndIncluding`/`versionEndExcluding` implemented as the four documented `>=`/`>`/`<=`/`<` operators; all four independently unit-tested. Missing target version → `UNKNOWN`, never guessed.

## 4. AND/OR/negate behavior, and two documented departures from the brief's literal wording

**Kleene (three-valued) logic** — `AND`: any `False` wins; else any `None` wins; else `True`. `OR`: any `True` wins; else any `None` wins; else `False`. `negate` inverts a non-`None` result. Standard, well-established (same as SQL `NULL` propagation), not invented for this project.

**Departure #1 — joint, not independent, candidate evaluation.** The brief's own CASE A/B/C/D example (§11) says "evaluate each candidate independently." Implemented that way first — and it failed on the real, live-captured CVE-2017-16725 configuration, which is an `AND` across two genuinely *different* real CPEs (a hardware CPE and a firmware CPE, both legitimately describing the same physical device). A single candidate string can never simultaneously equal two different CPEs, so no single independently-evaluated candidate could ever satisfy that `AND` — the engine would incorrectly conclude `NOT_APPLICABLE`/`UNKNOWN` for a CVE that demonstrably does apply. Fixed by evaluating the *whole* candidate set jointly (different `AND` branches can each be satisfied by a different member of the set), while still computing and preserving each candidate's own independent verdict separately, in `candidate_verdicts`, for the transparency instruction 11 also asks for. This is a real bug the "cross-check against real NVD data" instruction (§21) was specifically designed to catch, and it did.

**Departure #2 (found during live validation, after implementation) — supplement `source_cpe` with the device's full Phase 3 candidate set.** Running the complete pipeline live (Phase 3 → Phase 4 → Phase 5, non-mocked, against the real Xiongmai device) revealed that Phase 4's `correlation_device_cves` queries NVD's CVE API per-candidate with `isVulnerable=True` (a deliberate, good Phase 4 design choice — see the Phase 4 audit). The consequence: a CVE row's `source_cpe` only ever contains candidates NVD itself flagged `vulnerable: true` *for that specific CVE*. The real Xiongmai hardware CPE (`vulnerable: false` for CVE-2017-16725 — it's the required-but-not-itself-vulnerable environmental branch) never made it into `source_cpe`, even though it's a real Phase 3 candidate for the device and is exactly what the `AND` needs to be satisfiable at all. Fixed **entirely within Phase 5** (no Phase 3/4 code touched, per this phase's explicit constraints): `determine_applicability` unions `source_cpe` with the device's complete `cpe_candidates` table (Phase 3's own persisted data, already real/NVD-sourced), evaluates against that union, and separately records which CPEs were "supplementary" (in the union but not in the CVE row's own `source_cpe`) for full transparency. Verified live: with this fix, `CVE-2017-16725` on the real device correctly reaches `AFFECTED` once an observed firmware version is present, and correctly stays `UNKNOWN` when it isn't.

**Vulnerable-flag + negate interaction — a documented, unresolved ambiguity, per instruction 21's "stop and document" directive.** When `negate: true` flips a node's combined result from `False` to `True` *without* any individual `cpeMatch` having actually matched, there is no real `cpeMatch` to attribute the "vulnerable" signal to — `contributing` is deliberately left empty in that case. `negate` was not observed anywhere in this project's real captured NVD data (Phase 3/4's research), so this is untested against reality; a constructed, clearly-labeled illustrative fixture is used in tests instead. Flagged rather than silently resolved with an invented attribution rule.

## 5. CPE ambiguity handling

`CPE_AMBIGUOUS` (multiple Phase 3 candidates) — every candidate participates in the joint evaluation (§4). `ambiguity_existed: true` is recorded whenever `len(source_cpe) > 1`, and `candidate_verdicts` preserves each individual candidate's own independent verdict (matching instruction 11's CASE A/B/C/D framing), even though the *final* status comes from the joint evaluation. Verified against all four of the brief's own worked cases (tests 18-20, acceptance cases 6-7) plus the real live device.

## 6. Keyword safety invariant (mandatory)

`correlation_method == "KEYWORD"` → `applicability_status` is **hard-coded to `UNKNOWN`**, computed before any configuration data is even inspected — there is no code path from a `KEYWORD` row to `AFFECTED`, structurally, not just by a missing case. `test_22_keyword_finding_cannot_become_affected` and `test_acceptance_case5_keyword_only_never_affected` both assert this directly, using the brief's own Xiongmai/uc-httpd worked example.

**Reconciling an apparent contradiction between two of the brief's own instructions** (instruction 21 explicitly calls for this when semantics are ambiguous): §3's worked example says the Xiongmai/KEYWORD case gets `applicability_status = UNKNOWN`; §13's general rule says `NO_CPE_DATA` is the correct result "if cpe_status = NO_CPE_DATA." Read literally, a `KEYWORD` finding *is* a case where the underlying CPE mapping was `NO_CPE_DATA` — so which rule wins? Resolution implemented here: `NO_CPE_DATA` means "nothing to evaluate at all"; `UNKNOWN` means "some evidence exists but can't establish applicability." A `KEYWORD` row, by definition, only exists because keyword search found *something* — so it gets the more specific `UNKNOWN`, matching §3's explicit worked example, which is read as the more specific rule overriding §13's general default for this one case. `NO_CPE_DATA` is reserved for a `CPE`/`CPE_AMBIGUOUS`-correlated row with an empty `source_cpe` — a data-integrity edge case Phase 4's current design shouldn't produce, guarded against rather than assumed impossible.

## 7. NO_CPE_DATA semantics

Never conflated with `NOT_APPLICABLE` — a lack of identity is not evidence of safety (instruction 13, upheld structurally: the only code path to `NO_CPE_DATA` is the empty-`source_cpe` guard, entirely separate from the `NOT_APPLICABLE` code path, which requires an actual definite-`False` configuration evaluation).

## 8. NVD_UNAVAILABLE semantics

Phase 4's `NVD_UNAVAILABLE` devices never get a `device_cves` row written at all (`cve_lookup.py`, unmodified) — so there is structurally nothing for Phase 5 to evaluate for such a device/CVE pair. `determine_applicability` on a nonexistent row returns `UNKNOWN` (never a false `NOT_APPLICABLE`) — verified by `test_acceptance_case8_nvd_unavailable_upstream`.

## 9. Provenance / explanation model

One additional column, `device_cves.applicability_reason` (JSON), alongside the existing `applicability_status` — not a parallel status system, not a new table. Every evaluation's result includes `status`, `matched_cpe`, `matched_criteria_id`, `matched_criteria`, `version_evaluated`, `reason` (human-readable), `candidate_verdicts` (per-candidate breakdown for the ambiguous case), `ambiguity_existed`, and `supplementary_cpes_considered` (the departure #2 CPEs pulled in beyond the CVE row's own `source_cpe`). Verified persisted and round-tripped correctly by test (`test_24_applicability_explanation_provenance_persisted`).

`verification_status` and `exploitation_status` are never touched by this module — enforced by `set_device_cve_applicability`'s SQL only ever setting `applicability_status`/`applicability_reason`, and confirmed by the existing device_cves rows remaining valid without an applicability run (`test_25`).

## 10. Real CVE validation cases (instruction 21)

Two real, live-captured NVD configurations (not invented) were reasoned through manually before writing tests, per instruction:

- **CVE-2017-16725** (real Xiongmai stack buffer overflow) — `AND` of a `vulnerable:true` firmware branch (exact version `4.02.r11.3070`, no version range) and a `vulnerable:false` hardware branch (`version:"-"`). Manually reasoned expected result: a device confirmed to be this hardware model, running exactly this firmware version, is `AFFECTED`; the same device with an unknown or different firmware version is `UNKNOWN`/`NOT_APPLICABLE` respectively. Matches implementation exactly (tests 4, 4b, and the live end-to-end run in the implementation log).
- **CVE-2009-3766** (real mutt use-after-free) — simple `OR`/single-node, `versionStartIncluding: 1.5.16` / `versionEndExcluding: 1.5.19`. Manually reasoned: `1.5.16` and `1.5.18` in range (`AFFECTED`), `1.5.15` and `1.5.19` out of range (`NOT_APPLICABLE`) — boundary-exact, both ends. Matches implementation exactly (tests 9, 12, acceptance cases 1-3).

No ambiguity in NVD's documented semantics required stopping work entirely — the two departures in §4 were resolved with documented reasoning rather than blocking, since blocking on them would have meant the engine simply couldn't evaluate the one real CVE this whole phase was validated against.

## 11. Known limitations

1. `negate` + vulnerable-flag attribution is untested against real data (not observed in this project's research) — see §4's third point.
2. Nested `children` under a node is handled recursively but is **unverified against real NVD API 2.0 data** — not observed in any real captured configuration (all real examples found were exactly 2 levels: configuration → nodes → cpeMatch).
3. The version comparator (§3) is a documented heuristic, not a full CPE/product version grammar — could misorder unusual non-dot-delimited version schemes (none observed in this project's real data).
4. `supplementary_cpes_considered` (departure #2) pulls in *every* real CPE candidate the device has, for *every* CVE evaluated — for a device with many fingerprinted protocols and a large candidate set, this could occasionally pull in an unrelated CPE that happens to structurally match an unrelated node in a complex multi-product configuration. Not observed in this project's real data (the device tested has exactly 3 real candidates, all genuinely related), but worth flagging as a theoretical precision risk for a future phase to monitor.
5. Cross-CVE performance: `determine_applicability` is called once per CVE and re-fetches `cpe_candidates` from the database each time — fine at today's scale (a handful of devices/CVEs in a lab assessment), not optimized for bulk/offline batch evaluation across an entire session.
