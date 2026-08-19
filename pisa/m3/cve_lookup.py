"""CPE -> CVE correlation and normalization (Phase 4). Orchestrates:

    device -> CPE candidates (Phase 3) -> NVD CVE API 2.0 -> normalized
    findings -> EPSS + KEV enrichment (reusing existing M3 clients) ->
    persistence

Explicit non-goal, by design (see .scratch/pisa-phase4-vulnerability-
intelligence.md): this module never decides whether a CVE actually
*applies* to a device (Phase 5) or was *verified* (Phase 6) — every
finding it produces is "these CVEs are associated with this CPE," never
"this device is definitely vulnerable." applicability_status/
verification_status (Phase 1 columns) are never written here.
"""
from pisa.db import queries
from pisa.m0 import oui_cve
from pisa.m3 import cpe_mapper, epss_client, exploit_score, nvd_client

CORRELATION_CPE = "CPE"
CORRELATION_CPE_AMBIGUOUS = "CPE_AMBIGUOUS"
CORRELATION_KEYWORD = "KEYWORD"

STATUS_OK = "OK"
STATUS_NO_CVE_MATCH = "NO_CVE_MATCH"
STATUS_UNAVAILABLE_DUE_TO_IDENTITY = "UNAVAILABLE_DUE_TO_IDENTITY"
STATUS_NVD_UNAVAILABLE = "NVD_UNAVAILABLE"

# (metric key, version to report if cvssData omits its own "version" field)
_CVSS_METRIC_PRIORITY = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _extract_description(raw_cve: dict) -> str | None:
    for d in raw_cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _extract_weaknesses(raw_cve: dict) -> list[str]:
    return [
        d["value"]
        for w in raw_cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("lang") == "en" and d.get("value")
    ]


def _extract_references(raw_cve: dict) -> list[dict]:
    return [
        {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags", [])}
        for r in raw_cve.get("references", [])
    ]


def _extract_cvss(raw_cve: dict) -> dict | None:
    """Priority v3.1 > v4.0 > v3.0 > v2 — matches pisa/m0/oui_cve.py's
    existing v3.1-first convention (NVD is still v3.1-primary); v4.0
    checked next so it's still captured when it's genuinely the best
    available. `baseSeverity` lives *inside* `cvssData` for v3.x/v4
    entries but as a *sibling* of `cvssData` for v2 — confirmed against
    real, live NVD responses during this phase's research (CVE-2014-0160
    for v3.1, CVE-2017-16725 for v2) — both shapes are handled here."""
    metrics = raw_cve.get("metrics", {})
    for key, fallback_version in _CVSS_METRIC_PRIORITY:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        cvss_data = entry.get("cvssData", {})
        return {
            "version": cvss_data.get("version", fallback_version),
            "vector": cvss_data.get("vectorString"),
            "base_score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity") or entry.get("baseSeverity"),
        }
    return None


def _normalize_cve(raw_cve: dict, source_cpe: list[str], correlation_method: str) -> dict:
    """Raw NVD `vulnerabilities[].cve` object -> PISA's normalized
    finding shape. `configurations` is preserved verbatim (the full
    nodes/operator/cpeMatch/version-range structure) — Phase 5's
    applicability engine needs it intact, not flattened here."""
    cvss = _extract_cvss(raw_cve)
    return {
        "cve_id": raw_cve.get("id"),
        "source_cpe": list(source_cpe),
        "correlation_method": correlation_method,
        "nvd_status": raw_cve.get("vulnStatus"),
        "nvd_published": raw_cve.get("published"),
        "nvd_last_modified": raw_cve.get("lastModified"),
        "description": _extract_description(raw_cve),
        "cvss_score": cvss["base_score"] if cvss else None,
        "cvss_version": cvss["version"] if cvss else None,
        "cvss_vector": cvss["vector"] if cvss else None,
        "cvss_severity": cvss["severity"] if cvss else None,
        "weaknesses": _extract_weaknesses(raw_cve),
        "cve_references": _extract_references(raw_cve),
        "configurations": raw_cve.get("configurations"),
    }


def _keyword_fallback_finding(cve_id: str, raw: dict) -> dict:
    """Secondary-discovery shape — deliberately thin compared to
    _normalize_cve: no configurations/weaknesses/references, because
    pisa/m0/oui_cve.py's keyword search never had that data to begin
    with (it returns cve_id/cvss_score/description only). No amount of
    downstream processing can make a keyword match carry the
    applicability evidence a real CPE match does — the missing fields
    stay missing/None here rather than being backfilled with a guess."""
    return {
        "cve_id": cve_id,
        "source_cpe": [],
        "correlation_method": CORRELATION_KEYWORD,
        "nvd_status": None, "nvd_published": None, "nvd_last_modified": None,
        "description": raw.get("description"),
        "cvss_score": raw.get("cvss_score"), "cvss_version": None, "cvss_vector": None, "cvss_severity": None,
        "weaknesses": [], "cve_references": [], "configurations": None,
    }


def _add_keyword_fallback_findings(device: dict, findings_by_cve: dict[str, dict]) -> None:
    """Reuses pisa/m0/oui_cve.py's existing keyword search rather than
    duplicating it. A CVE it finds is recorded as CORRELATION_KEYWORD
    and NEVER overwrites a CVE the CPE path already found — that would
    silently downgrade an authoritative finding's provenance, or worse,
    look like the keyword path "confirmed" something the CPE path was
    only ambiguous about."""
    keyword_cves = oui_cve.lookup_device_cves(device.get("os_guess"))
    if not keyword_cves:
        return
    for raw in keyword_cves:
        cve_id = raw.get("cve_id")
        if not cve_id or cve_id in findings_by_cve:
            continue
        findings_by_cve[cve_id] = _keyword_fallback_finding(cve_id, raw)


def _enrich_with_epss_and_kev(findings: list[dict]) -> None:
    """Reuses pisa/m3/epss_client.py and pisa/m3/exploit_score.py — no
    second EPSS/KEV implementation. Missing data is None (UNKNOWN),
    never defaulted to 0/False-as-safe (KEV absence means "not currently
    in the catalog," not "not exploitable")."""
    cve_ids = [f["cve_id"] for f in findings if f.get("cve_id")]
    epss_records = epss_client.get_epss_records(cve_ids)

    for finding in findings:
        record = epss_records.get(finding["cve_id"])
        finding["epss_score"] = record["score"] if record else None
        finding["epss_percentile"] = record["percentile"] if record else None
        finding["epss_date"] = record["date"] if record else None

        kev = exploit_score.get_kev_record(finding["cve_id"])
        finding["kev_listed"] = kev is not None
        finding["kev_date_added"] = kev.get("dateAdded") if kev else None
        finding["kev_due_date"] = kev.get("dueDate") if kev else None
        finding["kev_known_ransomware_use"] = kev.get("knownRansomwareCampaignUse") if kev else None

        # Phase 8.2: the legacy keyword path (pisa/m0/oui_cve.py + M3's
        # exploit_score.enrich_cves) has always computed exploit_score;
        # this CPE-based path didn't, which would silently drop
        # device_cves.exploit_score for any finding only ever touched by
        # this path. Reuses the exact same compute_exploit_score formula
        # — no second scoring implementation.
        finding["exploit_score"] = exploit_score.compute_exploit_score(
            finding.get("cvss_score"), finding["epss_score"], finding["kev_listed"],
        )


def correlate_device_cves(
    conn, device_id: int, force_refresh: bool = False, include_keyword_fallback: bool = True,
) -> dict:
    """Full Phase 4 pipeline for one device. Returns
    {"status": ..., "findings": [...]}.

    `status` describes the *correlation attempt* itself, not any
    individual finding:
      OK                          — at least one CVE found
      NO_CVE_MATCH                — CPE resolved, NVD reachable, genuinely no CVEs
      UNAVAILABLE_DUE_TO_IDENTITY — no defensible CPE (Phase 3's NO_CPE_DATA) —
                                     NOT the same as "no vulnerabilities"
      NVD_UNAVAILABLE             — the NVD CVE API request(s) failed

    Every finding is persisted via upsert_device_cve_intelligence
    (applicability_status/verification_status untouched — Phase 5/6's
    job) and deduplicated by cve_id, merging source_cpe across multiple
    matching CPE candidates (the CPE_AMBIGUOUS case) rather than
    creating duplicate rows.
    """
    device = queries.get_device_by_id(conn, device_id)
    if device is None:
        return {"status": STATUS_UNAVAILABLE_DUE_TO_IDENTITY, "findings": []}

    cpe_candidates = cpe_mapper.map_device_to_cpe(conn, device_id, force_refresh=force_refresh)
    real_candidates = [c for c in cpe_candidates if c.get("cpe")]

    findings_by_cve: dict[str, dict] = {}
    status = STATUS_OK

    if not real_candidates:
        cpe_status = cpe_candidates[0]["status"] if cpe_candidates else cpe_mapper.STATUS_NO_DATA
        status = (
            STATUS_NVD_UNAVAILABLE if cpe_status == cpe_mapper.STATUS_UNAVAILABLE
            else STATUS_UNAVAILABLE_DUE_TO_IDENTITY
        )
    else:
        method = CORRELATION_CPE_AMBIGUOUS if len(real_candidates) > 1 else CORRELATION_CPE
        any_nvd_failure = False
        for candidate in real_candidates:
            raw_cves = nvd_client.query_cves_by_cpe(candidate["cpe"])
            if raw_cves is None:
                any_nvd_failure = True
                continue
            for raw_cve in raw_cves:
                cve_id = raw_cve.get("id")
                if not cve_id:
                    continue
                if cve_id in findings_by_cve:
                    if candidate["cpe"] not in findings_by_cve[cve_id]["source_cpe"]:
                        findings_by_cve[cve_id]["source_cpe"].append(candidate["cpe"])
                    continue
                findings_by_cve[cve_id] = _normalize_cve(raw_cve, [candidate["cpe"]], method)
        if any_nvd_failure and not findings_by_cve:
            status = STATUS_NVD_UNAVAILABLE

    if include_keyword_fallback and status != STATUS_NVD_UNAVAILABLE:
        _add_keyword_fallback_findings(device, findings_by_cve)

    if status == STATUS_OK and not findings_by_cve:
        status = STATUS_NO_CVE_MATCH

    findings = list(findings_by_cve.values())
    _enrich_with_epss_and_kev(findings)

    for finding in findings:
        queries.upsert_device_cve_intelligence(conn, device_id, finding)

    return {"status": status, "findings": findings}
