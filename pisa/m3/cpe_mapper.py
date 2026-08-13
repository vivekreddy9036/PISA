"""Structured device identity -> defensible CPE candidates via the
official NVD CPE Dictionary (API 2.0). See
.scratch/pisa-phase3-cpe-audit.md for the full design rationale.

Core rule: a CPE candidate must be backed by an actual NVD CPE Dictionary
match. This module never concatenates vendor+product strings into an
invented cpe:2.3:... URI and calls it confirmed — every returned
candidate's `cpe` field, when non-None, is copied verbatim from an NVD
API response.
"""
import re

import requests

import config
from pisa.db import queries

_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0/"

STATUS_CONFIRMED = "CPE_CONFIRMED"
STATUS_CANDIDATE = "CPE_CANDIDATE"
STATUS_AMBIGUOUS = "CPE_AMBIGUOUS"
STATUS_NO_DATA = "NO_CPE_DATA"
STATUS_UNAVAILABLE = "NVD_UNAVAILABLE"

# More than this many NVD matches for one keyword search is indistinguishable
# from an unconstrained listing (e.g. a bare vendor name with no product) —
# not real ambiguity between a few plausible products. Treated as NO_CPE_DATA
# rather than an unusably long AMBIGUOUS list.
_MAX_AMBIGUOUS_CANDIDATES = 5


def _query_nvd_cpe(keyword: str, max_results: int = 20) -> list[dict] | None:
    """Query the NVD CPE API 2.0's keywordSearch. Returns None (not []) on
    any request failure — the caller uses None vs. [] to distinguish
    NVD_UNAVAILABLE from a confirmed zero-match NO_CPE_DATA, which is the
    entire point of this function's return contract (see
    map_identity_to_cpe). Mirrors pisa/m0/oui_cve.py::_query_nvd's
    request pattern (apiKey header, broad try/except, no raise)."""
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    try:
        resp = requests.get(_CPE_API_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as e:
        print(f"[CPE] NVD CPE API request failed: {e}")
        return None
    return raw.get("products", [])


def _parse_cpe_name(cpe_name: str) -> dict:
    """Split a CPE 2.3 formatted name
    (cpe:2.3:part:vendor:product:version:...) into its components.
    Malformed input yields all-None fields rather than raising."""
    parts = (cpe_name or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return {"part": None, "vendor": None, "product": None, "version": None}
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5]}


def _normalize_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _loose_match(identity_value: str | None, cpe_value: str | None) -> bool:
    """Case/punctuation-insensitive containment match. NVD's CPE
    vendor/product fields are its own controlled vocabulary (e.g.
    "xiongmaitech") and are rarely identical to a human-readable OUI or
    banner string ("Hangzhou Xiongmai Technology Co.,Ltd") verbatim —
    this is intentionally permissive on its own. It never decides a
    result by itself; _score_candidate always combines it with the CPE's
    `part` field and version comparison."""
    if not identity_value or not cpe_value:
        return False
    a, b = _normalize_token(identity_value), _normalize_token(cpe_value)
    if not a or not b:
        return False
    return a in b or b in a


def _build_keyword(vendor: str | None, product: str | None) -> str | None:
    """Combine vendor+product into an NVD keywordSearch query. Uses only
    the first word of a multi-word vendor string — NVD's keywordSearch
    ANDs every whitespace-separated token (same reasoning as
    pisa/m0/oui_cve.py::_simplify_os_guess), so a verbose legal vendor
    string like "Hangzhou Xiongmai Technology Co.,Ltd" would zero out
    results a plain "Xiongmai" would find."""
    vendor_token = vendor.split()[0].strip(",.") if vendor else None
    tokens = [t for t in (vendor_token, product) if t]
    return " ".join(tokens) if tokens else None


def _no_candidate_result(status: str, source: str, identity_basis: str) -> dict:
    return {
        "cpe": None, "confidence": None, "status": status,
        "source": source, "identity_basis": identity_basis, "nvd_cpe_name_id": None,
    }


def _score_candidate(product_entry: dict, vendor: str | None, product: str | None, version: str | None) -> dict:
    """Score one NVD CPE Dictionary product entry against our identity.
    part == 'h' (hardware) is required for CPE_CONFIRMED — a match whose
    CPE `part` is 'a' (application) or 'o' (OS/firmware) identifies
    software running on the device, not necessarily the hardware itself
    (exactly the Xiongmai/uc-httpd case this phase was built around: a
    real NVD lookup on "xiongmai" returns a firmware/OS-part CPE, not a
    hardware one — verified against the live API during this phase's
    research, not assumed). That distinction is read from the CPE
    specification's own `part` field, not invented by this function.
    """
    cpe = product_entry.get("cpe", {})
    parsed = _parse_cpe_name(cpe.get("cpeName", ""))
    reasons = []
    confidence = 0.0

    vendor_match = _loose_match(vendor, parsed["vendor"])
    if vendor_match:
        confidence += 0.3
        reasons.append("vendor match")

    product_match = _loose_match(product, parsed["product"])
    if product_match:
        confidence += 0.3
        reasons.append("product match")

    is_hardware = parsed["part"] == "h"
    if parsed["part"] == "a":
        reasons.append("application/software CPE, not confirmed hardware")
    elif parsed["part"] == "o":
        reasons.append("OS/firmware CPE, not confirmed hardware")
    elif is_hardware:
        reasons.append("hardware CPE")

    version_match = False
    cpe_version = parsed["version"]
    if version and cpe_version not in (None, "-", "*"):
        if cpe_version == version:
            confidence += 0.3
            version_match = True
            reasons.append("version match")
        else:
            reasons.append(f"version mismatch (identity={version!r}, cpe={cpe_version!r})")
    elif version:
        reasons.append("CPE has no specific version to compare against — version not confirmed")

    is_deprecated = bool(cpe.get("deprecated"))
    if is_deprecated:
        reasons.append("CPE entry is deprecated in the NVD dictionary")

    status = STATUS_CANDIDATE
    # A deprecated entry can never be CPE_CONFIRMED, no matter how well
    # its fields match — NVD itself is saying this exact CPE name has
    # been superseded, which is reason enough to require a human look
    # rather than an automatic "confirmed."
    if is_hardware and vendor_match and product_match and version_match and not is_deprecated:
        status = STATUS_CONFIRMED
        confidence = max(confidence, 0.9)
    elif not (vendor_match or product_match):
        confidence = min(confidence, 0.2)

    # Applied last so it can't be overwritten by the confidence floor/
    # ceiling logic above (a real bug caught by this phase's own tests —
    # see the deprecated-CPE test case).
    if is_deprecated:
        confidence *= 0.5

    return {
        "cpe": cpe.get("cpeName"),
        "confidence": round(min(confidence, 1.0), 2),
        "status": status,
        "source": "nvd_cpe_dictionary",
        "identity_basis": "; ".join(reasons) if reasons else "no field-level match",
        "nvd_cpe_name_id": cpe.get("cpeNameId"),
    }


def map_identity_to_cpe(
    vendor: str | None,
    product: str | None,
    version: str | None,
    device_type: str | None = None,
) -> list[dict]:
    """Structured identity -> a list of CPE candidate dicts
    (cpe, confidence, status, source, identity_basis, nvd_cpe_name_id).

    Always returns at least one dict. A non-candidate outcome
    (NO_CPE_DATA / NVD_UNAVAILABLE) is represented as a single dict with
    cpe=None rather than an empty list, so callers never have to treat
    "no results" and "no attempt" differently.

    device_type is accepted but not weighted in ranking today — per
    instruction, device_type may only ever be *supporting* evidence, not
    primary identity, and there is no NVD CPE query that meaningfully
    narrows on a generic label like "IP Camera" without risking false
    precision. Kept as a parameter for interface completeness / a future
    phase to use, not silently dropped.
    """
    del device_type  # accepted, deliberately unused — see docstring

    if not vendor and not product:
        return [_no_candidate_result(STATUS_NO_DATA, "no_identity_evidence", "no vendor or product evidence available")]

    keyword = _build_keyword(vendor, product)
    if not keyword:
        return [_no_candidate_result(
            STATUS_NO_DATA, "no_identity_evidence", "insufficient evidence to build a search query",
        )]

    products = _query_nvd_cpe(keyword)
    if products is None:
        return [_no_candidate_result(
            STATUS_UNAVAILABLE, "nvd_cpe_dictionary", f"NVD CPE API request failed for keyword {keyword!r}",
        )]

    if not products:
        return [_no_candidate_result(
            STATUS_NO_DATA, "nvd_cpe_dictionary", f"no NVD CPE dictionary entries matched keyword {keyword!r}",
        )]

    if len(products) > _MAX_AMBIGUOUS_CANDIDATES:
        return [_no_candidate_result(
            STATUS_NO_DATA, "nvd_cpe_dictionary",
            f"{len(products)} NVD CPE entries matched keyword {keyword!r} — too broad to be a defensible candidate set",
        )]

    scored = [_score_candidate(p, vendor, product, version) for p in products]
    scored.sort(key=lambda c: c["confidence"], reverse=True)

    if len(scored) > 1:
        for candidate in scored:
            candidate["status"] = STATUS_AMBIGUOUS

    return scored


def map_device_to_cpe(conn, device_id: int, force_refresh: bool = False) -> list[dict]:
    """Orchestration: read a device's structured identity (Phase 2),
    generate CPE candidates, persist them (replacing any prior set), and
    return them. A cached NVD_UNAVAILABLE result is never reused — a
    prior transient failure shouldn't permanently block a retry; every
    other status is cached until force_refresh=True (mirrors the
    existing "Check CVEs" / "Recheck" pattern elsewhere in this
    codebase: explicit refresh, not silent forever-caching).
    """
    if not force_refresh:
        cached = queries.get_cpe_candidates(conn, device_id)
        if cached and cached[0]["status"] != STATUS_UNAVAILABLE:
            return cached

    device = queries.get_device_by_id(conn, device_id)
    if device is None:
        return []

    candidates = map_identity_to_cpe(
        device.get("identity_vendor"), device.get("identity_product"), device.get("identity_version"),
        device_type=device.get("device_type"),
    )
    queries.replace_cpe_candidates(conn, device_id, candidates)
    return candidates
