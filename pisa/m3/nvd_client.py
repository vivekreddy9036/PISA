"""Low-level, paginated NVD CVE API 2.0 client (Phase 4). Revives what
was a 1-line dead stub (flagged in the Phase 0 baseline) — the real
low-level client for CPE-based CVE lookup now lives here, with the
higher-level correlation/normalization orchestration in
pisa/m3/cve_lookup.py. See .scratch/pisa-phase4-vulnerability-intelligence.md
for the exact API mechanics this was built against (verified live, not
assumed, where noted).

pisa/m0/oui_cve.py's existing free-text keyword client is untouched and
still the mechanism behind the keyword fallback path (see cve_lookup.py)
— this module is additive, not a replacement.
"""
import time

import requests

import config

_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
_MAX_RETRIES = 3
_BACKOFF_BASE_SECONDS = 2
_DEFAULT_RESULTS_PER_PAGE = 100
_DEFAULT_MAX_PAGES = 5  # bounded — never an infinite pagination loop


def _request_with_retry(params: dict) -> dict | None:
    """One NVD CVE API request with bounded retry/backoff on 429/5xx.
    Returns the parsed JSON body, or None after exhausting retries — the
    caller distinguishes this from a confirmed-empty result the same way
    pisa/m3/cpe_mapper.py::_query_nvd_cpe already does (None vs []) for
    NVD_UNAVAILABLE vs. a real zero-match answer."""
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.get(_CVE_API_URL, params=params, headers=headers, timeout=15)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_BACKOFF_BASE_SECONDS * (2 ** attempt))
                    continue
                print(f"[NVD-CVE] request failed after {_MAX_RETRIES} attempts: HTTP {resp.status_code}")
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_BACKOFF_BASE_SECONDS * (2 ** attempt))
                continue
            print(f"[NVD-CVE] request failed after {_MAX_RETRIES} attempts: {e}")
            return None
    return None


def query_cves_by_cpe(
    cpe_name: str,
    is_vulnerable: bool = True,
    max_pages: int = _DEFAULT_MAX_PAGES,
    results_per_page: int = _DEFAULT_RESULTS_PER_PAGE,
) -> list[dict] | None:
    """Paginated NVD CVE API 2.0 lookup by cpeName. Returns None on any
    request failure (NVD_UNAVAILABLE, distinguishable from a confirmed
    zero-match []), else the raw list of `vulnerabilities[].cve` objects
    — full NVD shape preserved, nothing flattened here (see
    cve_lookup.py::_normalize_cve for that). Bounded to max_pages even if
    totalResults implies more, so a very large result set can never spin
    forever.
    """
    params = {"cpeName": cpe_name, "resultsPerPage": results_per_page}
    if is_vulnerable:
        # NVD's isVulnerable is a boolean *flag* parameter — its mere
        # presence (any value, including empty) means "true"; there is
        # no documented "isVulnerable=false" to request the inverse, so
        # this function only ever adds it or omits it.
        params["isVulnerable"] = ""

    all_cves: list[dict] = []
    start_index = 0
    for _ in range(max_pages):
        page_params = {**params, "startIndex": start_index}
        raw = _request_with_retry(page_params)
        if raw is None:
            return None if not all_cves else all_cves
        vulnerabilities = raw.get("vulnerabilities", [])
        all_cves.extend(v["cve"] for v in vulnerabilities if "cve" in v)

        total_results = raw.get("totalResults", len(all_cves))
        start_index += raw.get("resultsPerPage", len(vulnerabilities)) or results_per_page
        if start_index >= total_results or not vulnerabilities:
            break

    return all_cves
