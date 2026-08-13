"""FIRST EPSS API client: probability (0-1) a CVE will be exploited in
the wild in the next 30 days.
"""
import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def _fetch_epss_raw(cve_ids: list[str]) -> list[dict]:
    """The one networking call, shared by get_epss_scores (unchanged,
    Phase-3-and-earlier callers) and get_epss_records (Phase 4, wants the
    percentile/date fields the former discards). Returns FIRST's raw
    `data` array, or [] on any failure — never raises."""
    if not cve_ids:
        return []
    try:
        resp = requests.get(EPSS_API_URL, params={"cve": ",".join(cve_ids)}, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as e:
        print(f"[EPSS] request failed: {e}")
        return []
    return raw.get("data", [])


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Batch-fetch EPSS scores in one request (FIRST's API takes a
    comma-separated CVE list). Returns {cve_id: score}; a CVE with no EPSS
    record (too new, or rejected) is simply absent from the result rather
    than defaulted to 0 — callers decide how to treat "unknown"."""
    return {
        item["cve"]: float(item["epss"])
        for item in _fetch_epss_raw(cve_ids)
        if "cve" in item and "epss" in item
    }


def get_epss_records(cve_ids: list[str]) -> dict[str, dict]:
    """Batch-fetch full EPSS records (Phase 4: vulnerability intelligence
    needs percentile and retrieval date preserved, not just the bare
    score get_epss_scores keeps for backward compatibility). Returns
    {cve_id: {"score": float, "percentile": float|None, "date": str|None}};
    a CVE with no EPSS record is absent, same contract as
    get_epss_scores — never defaulted to 0/UNKNOWN by this function
    itself, callers decide how to represent "unknown"."""
    records = {}
    for item in _fetch_epss_raw(cve_ids):
        if "cve" not in item or "epss" not in item:
            continue
        records[item["cve"]] = {
            "score": float(item["epss"]),
            "percentile": float(item["percentile"]) if "percentile" in item else None,
            "date": item.get("date"),
        }
    return records
