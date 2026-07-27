"""FIRST EPSS API client: probability (0-1) a CVE will be exploited in
the wild in the next 30 days.
"""
import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Batch-fetch EPSS scores in one request (FIRST's API takes a
    comma-separated CVE list). Returns {cve_id: score}; a CVE with no EPSS
    record (too new, or rejected) is simply absent from the result rather
    than defaulted to 0 — callers decide how to treat "unknown"."""
    if not cve_ids:
        return {}

    try:
        resp = requests.get(EPSS_API_URL, params={"cve": ",".join(cve_ids)}, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as e:
        print(f"[EPSS] request failed: {e}")
        return {}

    return {
        item["cve"]: float(item["epss"])
        for item in raw.get("data", [])
        if "cve" in item and "epss" in item
    }
