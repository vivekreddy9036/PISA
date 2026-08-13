# PISA — Phase 3 CPE Mapping Audit

## 1. NVD CPE API 2.0 endpoints used

Researched live against the production API during this phase (direct `curl`, captured 2026-08-13) after `nvd.nist.gov/developers/products`' documentation page returned HTTP 502 (transient/blocked, retried once). Details below are from real, verified traffic — not assumed.

- **Base URL used**: `https://services.nvd.nist.gov/rest/json/cpes/2.0/`
- **Parameter used**: `keywordSearch` only. Confirmed live-working (`keywordSearch=xiongmai` → 515 real results, verbatim response captured). `cpeMatchString` (partial CPE 2.3 wildcard match) was tested live and returned `totalResults: 0` for plausible-looking wildcard strings — its exact matching semantics are **unverified**, so this phase does not rely on it as the primary mechanism. `cpeNameId`/`matchCriteriaId` (exact-record lookups) are not used — Phase 3 has no known CPE name to look up by ID yet; that becomes relevant once a candidate is already confirmed.
- **`resultsPerPage`**: used, capped at 20 in `_query_nvd_cpe` (PISA's own request size, not an NVD limit).
- **Auth**: `apiKey` header, sourced from `config.NVD_API_KEY` — same optional-key pattern already used by `pisa/m0/oui_cve.py::_query_nvd`. Confirmed the header name is correct (present in the live response's `access-control-allow-headers`).
- **Rate limits**: not independently re-verified this pass; carried forward from this project's earlier research (5 req/30s unauthenticated, 50 req/30s with a key, per NIST's own published limits) — not re-confirmed live in this phase, flagged as inherited rather than freshly verified.
- **Response shape** — confirmed verbatim from a real live call:
  ```json
  {"resultsPerPage":2,"startIndex":0,"totalResults":515,"format":"NVD_CPE","version":"2.0","timestamp":"...",
   "products":[{"cpe":{"deprecated":false,"cpeName":"cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:-:*:*:*:*:*:*:*",
   "cpeNameId":"007AB5F3-...","lastModified":"...","created":"...","titles":[{"title":"...","lang":"en"}],"refs":[...]}}]}
  ```
  Deprecated entries additionally carry `deprecatedBy`/`deprecates` arrays of `{cpeName, cpeNameId}` — confirmed live against a real deprecated Windows 10 CPE. `pisa/m3/cpe_mapper.py` reads `products[].cpe.{cpeName, cpeNameId, deprecated}` — nothing else from the response is currently used.
- **NVD API 1.0**: not used anywhere.

## 2. Identity → CPE mapping

```
DeviceIdentity (vendor, product, version)
      ↓
_build_keyword(vendor, product) — first word of vendor + product, joined
      ↓
_query_nvd_cpe(keyword) — real NVD keywordSearch, returns None on failure
      ↓
score each returned product against (vendor, product, version)
      ↓
rank + classify (CONFIRMED / CANDIDATE / AMBIGUOUS / NO_CPE_DATA / NVD_UNAVAILABLE)
```

No CPE string is ever constructed by PISA itself — every non-null `cpe` value returned is copied verbatim from an NVD API response (`cpe.cpeName`). This satisfies the core "never invent a CPE" principle structurally, not just by convention.

## 3. Confidence / ranking logic (deterministic, no ML)

Per-candidate score, built from three independently-checkable signals read off the real CPE 2.3 name (`_parse_cpe_name`):

| Signal | Weight | Basis |
|---|---|---|
| Vendor token loosely matches | +0.3 | `_loose_match` — case/punctuation-insensitive containment, since NVD's controlled vocabulary (`xiongmaitech`) rarely equals a human-readable string (`Hangzhou Xiongmai Technology Co.,Ltd`) verbatim |
| Product token loosely matches | +0.3 | same |
| Version token exactly matches (only if identity has a version *and* the CPE has a real, non-wildcarded one) | +0.3 | exact string equality — no fuzzy version comparison, since a wrong "close" version match would be worse than no claim at all |
| CPE `part` field | gate, not a score | `part == "h"` is required (alongside all three matches above) for `CPE_CONFIRMED` — a `part == "a"`/`"o"` match identifies software/OS, not hardware |
| `cpe.deprecated` | ×0.5, and blocks CONFIRMED outright | NVD itself flagging an entry as superseded is reason enough to require review, not an automatic confirmation |

`CPE_CONFIRMED` requires **all** of: vendor match, product match, version match, `part == "h"`, not deprecated. Anything short of that is `CPE_CANDIDATE` (or `CPE_AMBIGUOUS` if more than one plausible candidate came back). A candidate matching neither vendor nor product at all is capped at confidence ≤0.2 — present in the list (so ranking/evidence stays honest about what NVD actually returned) but never mistaken for a real signal.

**Why the `part` field, not a hardcoded vendor lookup table**: this is the direct answer to the Xiongmai/uc-httpd concern in the brief. Rather than special-casing "if vendor looks like Xiongmai, distrust the match" (an unmaintainable, unjustified rule), the CPE 2.3 specification's own `part` field already encodes exactly this distinction (hardware vs. OS vs. application) for every entry in the dictionary — using it is reading real, structured NVD data, not inventing a heuristic. Verified against real NVD data during this phase: a live `keywordSearch=xiongmai` query's top result is `cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:...` — an **`o`-part (OS/firmware) CPE**, exactly the "software, not hardware" case this design anticipates, confirmed from the real dictionary rather than assumed.

`device_type` is accepted as a parameter but not weighted — no NVD query meaningfully narrows on a label like "IP Camera" without risking false precision, and the instructions are explicit that device_type may only be supporting evidence, never primary. Kept in the signature for interface completeness rather than silently dropped.

## 4. CPE status model

| Status | Meaning | When |
|---|---|---|
| `CPE_CONFIRMED` | Single, strong, official hardware match | All scoring gates pass (§3) |
| `CPE_CANDIDATE` | A plausible but not fully-confirmed match | One NVD result, doesn't clear the CONFIRMED bar |
| `CPE_AMBIGUOUS` | Multiple (2–5) plausible matches, none arbitrarily chosen | >1 NVD result within the bounded range |
| `NO_CPE_DATA` | No defensible match — genuinely no evidence, zero NVD results, or too many (>5) to be a real candidate set | See §5 |
| `NVD_UNAVAILABLE` | The NVD request itself failed (network/HTTP error) | `_query_nvd_cpe` returns `None` |

`NO_CPE_DATA` and `NVD_UNAVAILABLE` are structurally distinct return values (`_query_nvd_cpe` returns `None` on failure vs. `[]` on a confirmed zero-match) — never conflated, and never confused with `NOT_APPLICABLE` (that status doesn't exist yet; it's Phase 5's applicability-engine concept, one layer downstream of CPE mapping and out of scope here).

## 5. The ">5 results = NO_CPE_DATA" conservatism, and what it looks like live

A bare vendor-only search (no product) realistically returns hundreds of results — confirmed live: `keywordSearch=xiongmai` alone returned **515** total results. That's not "ambiguous between a few plausible products," it's an unconstrained listing. `_MAX_AMBIGUOUS_CANDIDATES = 5` draws the line: more than that collapses to `NO_CPE_DATA` with an `identity_basis` explaining why (distinct wording from the true zero-match case, even though both share the same status literal — kept deliberately simple rather than adding a status enum value nobody asked for).

Live-verified during this phase: `map_identity_to_cpe("TP-Link", "Archer AX21", None)` → 10 real NVD matches → correctly classified `NO_CPE_DATA` ("10 NVD CPE entries matched keyword 'TP-Link Archer AX21' — too broad to be a defensible candidate set"), not forced into a 10-item `AMBIGUOUS` list.

## 6. Database

**Decision: one new table, `cpe_candidates`, no ALTER migration needed.**

Per instruction, the Phase 1/2 schema was inspected first for a suitable existing location. It doesn't have one: `fingerprint_signatures` is scoped to raw per-protocol probe features (wrong shape — a CPE candidate isn't a protocol feature, and needs a `status` field, an `nvd_cpe_name_id`, and the ability to hold *multiple* rows per device with individually-tracked confidence for the `AMBIGUOUS` case); `devices.identity_*` are scalar per-device columns and can't represent a candidate list at all. A new table is the minimum necessary structure the instructions asked me to justify, not skip:

```sql
CREATE TABLE cpe_candidates (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id        INTEGER REFERENCES devices(id),
    cpe              TEXT,              -- NULL for NO_CPE_DATA/NVD_UNAVAILABLE
    confidence       REAL,              -- NULL for the same
    status           TEXT    NOT NULL,
    source           TEXT,
    identity_basis   TEXT,
    nvd_cpe_name_id  TEXT,
    fetched_at       TEXT    NOT NULL
);
```

Added via `CREATE TABLE IF NOT EXISTS` in the main schema script (same as Phase 1's `assessments` table) — no `ALTER TABLE` migration function needed, since it's a wholly new table and this project's existing `create_tables()` already runs unconditionally on every startup.

No `UNIQUE` constraint on `(device_id, cpe)`: a fresh CPE mapping run is a full re-evaluation of a device's identity, not an incremental update to one CPE, so `replace_cpe_candidates()` deletes-then-inserts the whole set per device in one call — simpler than an upsert that would also have to handle multiple `NULL`-`cpe` status-only rows per device (SQLite treats `NULL` as always-distinct under `UNIQUE`, which would silently accumulate duplicate `NO_CPE_DATA` rows under an upsert approach instead of replacing them).

## 7. Caching

`map_device_to_cpe(conn, device_id, force_refresh=False)`:
- Checks `get_cpe_candidates()` first; if a cached set exists and its status isn't `NVD_UNAVAILABLE`, returns it without touching the network.
- `NVD_UNAVAILABLE` results are **never** served from cache — a transient failure shouldn't permanently block a retry.
- `fetched_at` is stamped on every row by `replace_cpe_candidates()`, so staleness is always determinable by a caller, even though this phase doesn't itself implement an expiry policy (deliberately — "do not build a large offline NVD database in this phase").
- `force_refresh=True` bypasses the cache and re-queries unconditionally.
- Live-verified with a call-counting monkeypatch: first call queries NVD once, a second call reuses the cache (zero additional queries), `force_refresh=True` queries again.

## 8. Test strategy

All 20 new tests in `tests/m3/test_cpe_mapper.py` are deterministic and network-independent — they monkeypatch `_query_nvd_cpe` with fixtures built from **real, live-captured NVD API 2.0 responses** (the actual Xiongmai firmware CPE entry returned during this phase's research), not invented shapes, per instruction. One additional test (`test_live_nvd_cpe_api_returns_real_data`) is `@pytest.mark.skip`-decorated and hits the real API — excluded from the default suite/CI, run manually.

## 9. A real bug this design caught, and a real limitation it exposed

- **Bug caught by the deprecated-CPE test**: the original scoring code applied the deprecated-confidence halving *before* the CONFIRMED-status confidence floor (`confidence = max(confidence, 0.9)`), so the floor silently overwrote the penalty and a deprecated entry could still be scored `CPE_CONFIRMED`. Fixed: deprecation now explicitly gates `CPE_CONFIRMED` out entirely, and the ×0.5 penalty is applied last so nothing after it can undo it. Caught by the test suite before this ever ran against real data.
- **Limitation found via a live call, not hidden**: `_build_keyword` takes only the *first* word of the vendor string (mirroring `oui_cve.py`'s existing rationale for stripping detail that would zero out an ANDed keyword search). For "Hangzhou Xiongmai Technology Co.,Ltd," the first word is "Hangzhou" — a city name, not the brand "Xiongmai" — and a live query on "Hangzhou uc-httpd" correctly but unhelpfully returned zero NVD matches, when a query on "Xiongmai" (the second word) does find real matches. This is a real recall gap: PISA will under-match some multi-word vendor strings where the brand isn't the first token. It is not a *safety* gap — the system still never fabricates a match, it just sometimes misses a real one and correctly falls back to `NO_CPE_DATA` — but it's flagged plainly here rather than glossed over, and is a reasonable Phase 4/8 refinement (e.g., trying each vendor word individually, or preferring the OUI database's own shorter canonical name field if one exists).
