import os
import requests
import config

_OUI_FILE = os.path.join(os.path.dirname(__file__), "oui.txt")
_OUI_DB: dict[str, str] = {}


def _load_oui_db() -> None:
    if _OUI_DB:
        return
    if not os.path.exists(_OUI_FILE):
        try:
            download_oui_db()
        except Exception as e:
            print(f"[OUI] Could not download OUI database: {e}")
            return
    with open(_OUI_FILE, "r", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.split("(hex)")
                oui = parts[0].strip().replace("-", "").upper()
                vendor = parts[1].strip()
                _OUI_DB[oui] = vendor


def download_oui_db() -> None:
    """Download IEEE OUI database (~5 MB) if not present."""
    if os.path.exists(_OUI_FILE):
        return
    url = "https://standards-oui.ieee.org/oui/oui.txt"
    print("[OUI] Downloading IEEE OUI database...")
    # IEEE's server 418s requests' default "python-requests/x.x" User-Agent —
    # a normal browser-style one gets through.
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) PISA-OUI-Fetcher"}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    with open(_OUI_FILE, "w", errors="ignore") as f:
        f.write(resp.text)
    print(f"[OUI] Saved to {_OUI_FILE}")


def bssid_to_vendor(bssid: str) -> str:
    _load_oui_db()
    oui = bssid.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_DB.get(oui, "Unknown")


def _query_nvd(keyword: str, max_results: int = 10) -> list[dict]:
    """Query the NVD 2.0 API by a free-text keyword."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as e:
        print(f"[OUI-CVE] NVD request failed: {e}")
        return []

    cves = []
    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        cves.append({"cve_id": cve_id, "cvss_score": cvss, "description": desc})

    return cves


def lookup_cves(bssid: str, max_results: int = 10) -> list[dict]:
    """Query NVD 2.0 API by vendor name derived from BSSID OUI."""
    vendor = bssid_to_vendor(bssid)
    if vendor == "Unknown":
        return []
    return _query_nvd(vendor, max_results)


def _simplify_os_guess(os_guess: str) -> str:
    """Strip the parenthetical version detail from an Nmap os_guess, e.g.
    "Cisco Nexus switch (NX-OS 6.0(2))" -> "Cisco Nexus switch".

    NVD's keywordSearch ANDs every whitespace-separated token together, so a
    literal version string like "6.0(2))" — which will never appear verbatim
    in any CVE description — zeroes out the whole result set even when
    directly relevant CVEs exist for the product in general.
    """
    return os_guess.split("(")[0].strip()


def lookup_device_cves(os_guess: str | None, max_results: int = 10) -> list[dict] | None:
    """Query NVD 2.0 API for a discovered device using its Nmap os_guess
    (simplified to drop version-specific detail, see _simplify_os_guess) as
    the search keyword.

    Returns None — not [] — when there's no os_guess to search with, rather
    than falling back to a bare vendor name. A vendor-only search (e.g.
    "Intel Corporate") is too generic to mean anything: verified in practice
    that several genuinely different, unfingerprinted devices all returned
    the identical set of decade-old CVEs from a vendor-only query, which
    would misrepresent noise as a real finding. None means "not attempted",
    distinct from [] meaning "attempted, nothing found" — callers should
    show that distinction rather than treating them the same.
    """
    if not os_guess:
        return None
    keyword = _simplify_os_guess(os_guess)
    if not keyword:
        return None
    return _query_nvd(keyword, max_results)
