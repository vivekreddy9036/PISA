"""Applicability engine (Phase 5): does a CVE discovered by Phase 4
actually apply to this specific device?

Operates entirely on data Phase 4 already persisted (source_cpe,
configurations, correlation_method) plus Phase 2's device identity — no
NVD request is made here (instruction 23: deterministic, local,
offline-capable after vulnerability intelligence has been retrieved).

Core distinction this module exists to enforce, in both code and
database: "CVE discovered" != "applicable" != "verified" != "exploited".
This module only ever writes applicability_status/applicability_reason —
never verification_status (Phase 6) or exploitation_status (Phase 7).

See .scratch/pisa-phase5-applicability.md for the full state machine and
two documented, deliberate departures from this phase's brief, made
because testing against real, live-captured NVD data (CVE-2017-16725)
proved the literal instructions couldn't correctly evaluate it:

1. "Evaluate each candidate independently" (per the CASE A/B/C/D example)
   cannot express an AND across two genuinely *different* real CPEs
   (a hardware CPE AND a firmware CPE — the actual, real shape of
   CVE-2017-16725's configuration). A single candidate string can never
   simultaneously equal two different CPEs. This module evaluates the
   *whole* candidate CPE set jointly against the configuration tree (so
   different AND-branches can each be satisfied by a different member of
   the set), while still computing and preserving each candidate's own
   independent verdict for provenance/transparency.
2. The Xiongmai/KEYWORD worked example (§3: UNKNOWN) and the general
   NO_CPE_DATA rule (§13) are reconciled explicitly — see
   determine_applicability's docstring.
"""
import json

from pisa.db import queries

STATUS_UNKNOWN = "UNKNOWN"
STATUS_NO_CPE_DATA = "NO_CPE_DATA"
STATUS_POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
STATUS_AFFECTED = "AFFECTED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

_RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
_CPE_FIELDS = (
    "part", "vendor", "product", "version", "update", "edition",
    "language", "sw_edition", "target_sw", "target_hw", "other",
)


# ---------------------------------------------------------------------------
# CPE 2.3 component matching (wildcard-aware — never plain substring/equality)
# ---------------------------------------------------------------------------

def _parse_cpe(cpe_name: str) -> dict | None:
    """Full CPE 2.3 component split (part/vendor/product/version/update/
    edition/language/sw_edition/target_sw/target_hw/other) — deliberately
    separate from pisa/m3/cpe_mapper.py::_parse_cpe_name (which only
    extracts part/vendor/product/version) rather than modifying that
    module, per this phase's explicit "do not rewrite CPE mapping"
    instruction. Small, self-contained duplication, not a shared
    dependency."""
    parts = (cpe_name or "").split(":")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return dict(zip(_CPE_FIELDS, parts[2:13]))


def _cpe_component_match(candidate_value: str | None, criteria_value: str | None) -> bool:
    """`*` (ANY) on either side always matches — a candidate's own field
    can legitimately be a dictionary-wildcarded value too, not just the
    criteria's. `-` (N/A) matches only `-` (both sides explicitly saying
    "this attribute doesn't apply"), never treated as ANY."""
    if criteria_value in (None, "*") or candidate_value in (None, "*"):
        return True
    if criteria_value == "-" or candidate_value == "-":
        return criteria_value == candidate_value
    return (candidate_value or "").lower() == (criteria_value or "").lower()


def _version_component_match(identity_version: str | None, criteria_version: str | None) -> bool | None:
    """None = UNKNOWN. A CVE requiring a specific version, with no
    observed identity_version to compare against, is genuinely
    undetermined — not a mismatch and not a confirmed match.

    criteria_version == "-" is treated the same as "*" here (always
    matches), not as "identity_version must also literally be '-'."
    Real, live-verified case this was built against: the hardware branch
    of CVE-2017-16725's real configuration has version="-" (hardware
    doesn't carry a software version in NVD's dictionary) while
    identity_version is the device's observed *firmware* version, e.g.
    "4.02.r11.3070" — those are different attributes entirely; "-" here
    means "this criterion doesn't constrain version," not "expects a
    literal dash." (Contrast with _cpe_component_match's stricter "-"
    handling, which compares two NVD-dictionary-sourced values against
    each other, a genuinely different situation.)"""
    if criteria_version in (None, "*", "-"):
        return True
    if identity_version is None:
        return None
    return identity_version.lower() == criteria_version.lower()


def _compare_versions(a: str, b: str) -> int:
    """-1/0/1. Segment-by-segment: numeric segments compare numerically,
    non-numeric segments compare lexicographically (handles suffixed
    versions like OpenSSL's "1.0.1a" > "1.0.1" correctly, since "1a" >
    "1" lexicographically matches the intended "later patch" meaning) —
    a reasonable, documented heuristic, not a full semver-aware parser.
    Always produces an answer once both inputs are non-None; this
    function is never the source of an UNKNOWN result (see module
    docstring/audit doc) — missing *input* is what produces UNKNOWN,
    not comparator failure."""
    segs_a, segs_b = a.split("."), b.split(".")
    for i in range(max(len(segs_a), len(segs_b))):
        sa = segs_a[i] if i < len(segs_a) else "0"
        sb = segs_b[i] if i < len(segs_b) else "0"
        if sa.isdigit() and sb.isdigit():
            ia, ib = int(sa), int(sb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif sa != sb:
            return -1 if sa < sb else 1
    return 0


def _version_in_range(
    identity_version: str | None,
    start_including: str | None, start_excluding: str | None,
    end_including: str | None, end_excluding: str | None,
) -> bool | None:
    if identity_version is None:
        return None
    if start_including is not None and _compare_versions(identity_version, start_including) < 0:
        return False
    if start_excluding is not None and _compare_versions(identity_version, start_excluding) <= 0:
        return False
    if end_including is not None and _compare_versions(identity_version, end_including) > 0:
        return False
    if end_excluding is not None and _compare_versions(identity_version, end_excluding) >= 0:
        return False
    return True


def _cpe_match_against_one(cpe_match: dict, parts: dict, identity_version: str | None) -> bool | None:
    """True/False/None for whether ONE candidate's parsed CPE components
    + identity_version satisfies a single cpeMatch's criteria.
    Deliberately does NOT fold in the `vulnerable` flag — "matches this
    criterion" and "this criterion represents the vulnerable component"
    are different questions (instruction 7). Version is checked against
    `identity_version` (Phase 2's observed device identity), never
    against the candidate CPE's own version field — a version-ranged
    cpeMatch exists precisely because the CPE dictionary entry itself is
    deliberately unversioned (Phase 3's real captured hardware CPE has
    version="-"); the actually-applicable version is what PISA observed
    running, not a dictionary placeholder."""
    criteria = _parse_cpe(cpe_match.get("criteria", ""))
    if criteria is None:
        return None
    for field in _CPE_FIELDS:
        if field == "version":
            continue
        if not _cpe_component_match(parts.get(field), criteria.get(field)):
            return False

    has_range = any(cpe_match.get(k) is not None for k in _RANGE_KEYS)
    if has_range:
        return _version_in_range(identity_version, *[cpe_match.get(k) for k in _RANGE_KEYS])
    return _version_component_match(identity_version, criteria.get("version"))


def _evaluate_cpe_match(cpe_match: dict, candidates: list, identity_version: str | None) -> tuple:
    """`candidates`: list of (cpe_string, parsed_parts) — the device's
    WHOLE candidate CPE set (not one at a time). Returns
    (result: bool|None, matched_candidate_cpe: str|None) — True if ANY
    single candidate in the set structurally satisfies this criterion,
    attributing which one. This is what makes an AND across two
    different real CPEs (hardware AND firmware) evaluable at all: node1
    can be satisfied by candidate A while node2 is satisfied by
    candidate B, within the same configuration."""
    saw_unknown = False
    for cpe_string, parts in candidates:
        r = _cpe_match_against_one(cpe_match, parts, identity_version)
        if r is True:
            return True, cpe_string
        if r is None:
            saw_unknown = True
    return (None if saw_unknown else False), None


# ---------------------------------------------------------------------------
# Three-valued (Kleene) AND/OR/negate combination
# ---------------------------------------------------------------------------

def _combine(operator: str, negate: bool, results: list) -> bool | None:
    if operator == "AND":
        if any(r is False for r in results):
            combined = False
        elif any(r is None for r in results):
            combined = None
        else:
            combined = True
    else:  # OR (NVD's documented default when a node's own operator is absent)
        if any(r is True for r in results):
            combined = True
        elif any(r is None for r in results):
            combined = None
        else:
            combined = False
    if negate and combined is not None:
        combined = not combined
    return combined


def _evaluate_node(node: dict, candidates: list, identity_version: str | None) -> tuple:
    """Returns (matched: bool|None, contributing: list[(cpeMatch, matched_cpe)]).
    `contributing` is only ever populated when matched is True, and only
    with cpeMatch entries that genuinely, individually matched — a node
    that becomes True purely through `negate` inverting a False result
    has no real cpeMatch to attribute the match to, so `contributing`
    stays empty for it. Documented, known limitation of the vulnerable-
    flag attribution (see audit doc — instruction 21 requires documenting
    this rather than inventing an unjustified attribution rule for a
    case with no real evidence in this project's research to resolve it
    against)."""
    results = []
    contributing = []
    for cm in node.get("cpeMatch", []):
        r, matched_cpe = _evaluate_cpe_match(cm, candidates, identity_version)
        results.append(r)
        if r is True:
            contributing.append((cm, matched_cpe))

    # Nested "children" nodes: not observed in any real NVD API 2.0
    # response captured during this project's research (Phase 3/4) — the
    # real captured configurations are exactly 2 levels deep
    # (configuration -> nodes -> cpeMatch), no node-level nesting. Handled
    # defensively/recursively here in case the schema does support it in
    # some CVE this project hasn't sampled, but this path is UNVERIFIED
    # against real data.
    for child in node.get("children", []):
        r, child_contrib = _evaluate_node(child, candidates, identity_version)
        results.append(r)
        if r is True:
            contributing.extend(child_contrib)

    matched = _combine(node.get("operator", "OR"), bool(node.get("negate", False)), results)
    return matched, (contributing if matched is True else [])


def _evaluate_configuration(config: dict, candidates: list, identity_version: str | None) -> tuple:
    """Returns (verdict, vulnerable_contributions) for one top-level
    `configurations[]` entry. verdict in AFFECTED/NOT_APPLICABLE/UNKNOWN.
    vulnerable_contributions: list[(cpeMatch, matched_cpe)]."""
    node_results = []
    all_contributing = []
    for node in config.get("nodes", []):
        matched, contributing = _evaluate_node(node, candidates, identity_version)
        node_results.append(matched)
        if matched is True:
            all_contributing.extend(contributing)

    combined = _combine(config.get("operator", "AND"), False, node_results)
    if combined is True:
        vulnerable = [(cm, cpe) for cm, cpe in all_contributing if cm.get("vulnerable")]
        if vulnerable:
            return STATUS_AFFECTED, vulnerable
        # Structurally matched, but nothing that matched is flagged
        # vulnerable — the target satisfies this configuration's required
        # components without actually hitting the vulnerable one.
        return STATUS_NOT_APPLICABLE, []
    if combined is None:
        return STATUS_UNKNOWN, []
    return STATUS_NOT_APPLICABLE, []


def evaluate_configurations(configurations: list, candidate_cpes: list, identity_version: str | None) -> dict:
    """The core evaluator. `configurations` is Phase 4's raw, verbatim-
    preserved NVD `configurations` list — a CVE's list of alternative
    configuration scenarios, OR'd together (documented NVD semantics:
    any one configuration object being satisfied is sufficient — not an
    ambiguous point, unlike some of the finer node-level questions this
    module documents separately). `candidate_cpes` is evaluated as one
    joint set (see module docstring, departure #1).
    """
    parsed = [(cpe, _parse_cpe(cpe)) for cpe in candidate_cpes]
    parsed = [(cpe, p) for cpe, p in parsed if p is not None]

    if not parsed:
        return {
            "status": STATUS_UNKNOWN, "matched_cpe": None,
            "matched_criteria_id": None, "matched_criteria": None, "version_evaluated": identity_version,
            "reason": "No parseable candidate CPE was available to evaluate.",
        }
    if not configurations:
        return {
            "status": STATUS_UNKNOWN, "matched_cpe": None,
            "matched_criteria_id": None, "matched_criteria": None, "version_evaluated": identity_version,
            "reason": "Applicability could not be determined from available NVD configuration data.",
        }

    verdicts = []
    matched_criteria_id = matched_criteria = matched_cpe = None
    for config in configurations:
        verdict, vulnerable = _evaluate_configuration(config, parsed, identity_version)
        verdicts.append(verdict)
        if verdict == STATUS_AFFECTED and matched_criteria_id is None:
            cm, cpe = vulnerable[0]
            matched_criteria_id = cm.get("matchCriteriaId")
            matched_criteria = cm.get("criteria")
            matched_cpe = cpe

    if STATUS_AFFECTED in verdicts:
        status = STATUS_AFFECTED
        reason = "Target CPE and observed version matched a vulnerable NVD configuration match criterion."
    elif STATUS_UNKNOWN in verdicts:
        status = STATUS_UNKNOWN
        reason = "Configuration requires evidence (typically a version) PISA did not observe for this device."
    else:
        status = STATUS_NOT_APPLICABLE
        reason = "Target CPE(s) do not satisfy any of this CVE's vulnerable configuration criteria."

    return {
        "status": status, "matched_cpe": matched_cpe,
        "matched_criteria_id": matched_criteria_id, "matched_criteria": matched_criteria,
        "version_evaluated": identity_version, "reason": reason,
    }


# ---------------------------------------------------------------------------
# Orchestration: one persisted device_cves row -> applicability_status
# ---------------------------------------------------------------------------

def determine_applicability(conn, device_id: int, cve_id: str) -> dict:
    """Reads a Phase-4-persisted device_cves row (and Phase 2's device
    identity), evaluates applicability locally — no NVD request — and
    persists applicability_status/applicability_reason. Returns the same
    result dict it persists.

    NO_CPE_DATA vs UNKNOWN, resolved (instruction 21 — this exact
    reconciliation is documented at length in the audit doc): the
    brief's own worked example (§3, Xiongmai/uc-httpd) says a KEYWORD
    finding under an underlying NO_CPE_DATA condition gets UNKNOWN,
    while the general rule (§13) says NO_CPE_DATA. Read together:
    NO_CPE_DATA means "nothing to evaluate at all" (no CPE and no CVE
    row would exist); UNKNOWN means "some evidence exists (a keyword
    hit) but it can't establish applicability." A KEYWORD row, by
    definition, only exists because *some* evidence was found — so it
    gets UNKNOWN, never the more absolute NO_CPE_DATA. NO_CPE_DATA is
    reserved here for the structurally-defensive case of a CPE-
    correlated row with an empty/missing source_cpe list — a data-
    integrity situation Phase 4's current design shouldn't produce, but
    guarded against rather than assumed impossible.
    """
    row = queries.get_device_cve(conn, device_id, cve_id)
    if row is None:
        return {
            "status": STATUS_UNKNOWN, "matched_cpe": None, "matched_criteria_id": None,
            "matched_criteria": None, "version_evaluated": None,
            "reason": f"No device_cves row found for device {device_id} / {cve_id}.",
        }

    device = queries.get_device_by_id(conn, device_id)
    identity_version = device.get("identity_version") if device else None

    if row.get("correlation_method") == "KEYWORD":
        result = {
            "status": STATUS_UNKNOWN, "matched_cpe": None, "matched_criteria_id": None, "matched_criteria": None,
            "version_evaluated": identity_version,
            "reason": (
                "Correlated via keyword search only, not a confirmed CPE — keyword evidence alone "
                "can never establish AFFECTED (mandatory invariant, see instruction 3)."
            ),
        }
        queries.set_device_cve_applicability(conn, device_id, cve_id, result["status"], result)
        return result

    source_cpe = json.loads(row.get("source_cpe") or "[]")
    configurations = json.loads(row["configurations"]) if row.get("configurations") else []

    if not source_cpe:
        result = {
            "status": STATUS_NO_CPE_DATA, "matched_cpe": None, "matched_criteria_id": None,
            "matched_criteria": None, "version_evaluated": identity_version,
            "reason": "CPE-correlated finding has no recorded source CPE to evaluate against.",
        }
        queries.set_device_cve_applicability(conn, device_id, cve_id, result["status"], result)
        return result

    # Real, live-discovered integration gap between Phase 4 and Phase 5
    # (documented at length in the audit doc): Phase 4 queries NVD's CVE
    # API per-candidate with isVulnerable=True, so `source_cpe` on a CVE
    # row only ever contains candidates NVD itself flagged vulnerable
    # *for that specific CVE* — a candidate that's a required but
    # non-vulnerable "environmental" branch of an AND (e.g. the real
    # Xiongmai hardware CPE, vulnerable=false for CVE-2017-16725) never
    # makes it into source_cpe, even though it's a real Phase 3 CPE
    # candidate for this device and is exactly what the AND needs.
    # Phase 3's own cpe_candidates table already has the device's full,
    # real candidate set regardless of any one CVE's isVulnerable filter
    # — supplement with it here (Phase 5's own orchestration decision,
    # not a change to Phase 3/4 code) so multi-CPE AND configurations
    # can be evaluated correctly.
    all_device_cpes = [c["cpe"] for c in queries.get_cpe_candidates(conn, device_id) if c.get("cpe")]
    evaluation_cpes = list(dict.fromkeys(source_cpe + all_device_cpes))  # union, order-preserving, deduped
    supplementary_cpes = [cpe for cpe in evaluation_cpes if cpe not in source_cpe]

    # Joint evaluation across the whole candidate set — the structurally
    # correct evaluation (see module docstring, departure #1).
    joint = evaluate_configurations(configurations, evaluation_cpes, identity_version)

    # Per-candidate independent verdicts, purely for transparency/
    # provenance (instruction 11's own phrasing/example) — computed
    # separately, never used to decide the final status when it would
    # disagree with the joint (structurally correct) evaluation.
    candidate_verdicts = [
        {"cpe": cpe, **evaluate_configurations(configurations, [cpe], identity_version)}
        for cpe in source_cpe
    ]

    status = joint["status"]
    reason = joint["reason"]

    # instruction 12: a single, non-ambiguous candidate whose own Phase 3
    # status was only CPE_CANDIDATE (not CPE_CONFIRMED) is weak identity
    # evidence — an AFFECTED verdict built on it alone is capped at
    # POTENTIALLY_AFFECTED rather than silently upgraded to AFFECTED.
    if len(source_cpe) == 1 and status == STATUS_AFFECTED:
        cpe_candidate_rows = {c["cpe"]: c for c in queries.get_cpe_candidates(conn, device_id) if c.get("cpe")}
        candidate_status = cpe_candidate_rows.get(source_cpe[0], {}).get("status")
        if candidate_status == "CPE_CANDIDATE":
            status = STATUS_POTENTIALLY_AFFECTED
            reason = reason + " (capped: underlying CPE identity was only CPE_CANDIDATE, not CPE_CONFIRMED.)"

    result = {
        "status": status,
        "matched_cpe": joint["matched_cpe"] if status in (STATUS_AFFECTED, STATUS_POTENTIALLY_AFFECTED) else None,
        "matched_criteria_id": joint["matched_criteria_id"],
        "matched_criteria": joint["matched_criteria"],
        "version_evaluated": identity_version,
        "reason": reason,
        "candidate_verdicts": candidate_verdicts,
        "ambiguity_existed": len(source_cpe) > 1,
        "supplementary_cpes_considered": supplementary_cpes,
    }
    queries.set_device_cve_applicability(conn, device_id, cve_id, result["status"], result)
    return result
