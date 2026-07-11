import os
import requests
import config

_OUI_FILE = os.path.join(os.path.dirname(__file__), "oui.txt")
_OUI_DB: dict[str, str] = {}


def _load_oui_db() -> None:
    if _OUI_DB or not os.path.exists(_OUI_FILE):
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
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    with open(_OUI_FILE, "w", errors="ignore") as f:
        f.write(resp.text)
    print(f"[OUI] Saved to {_OUI_FILE}")


def bssid_to_vendor(bssid: str) -> str:
    _load_oui_db()
    oui = bssid.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_DB.get(oui, "Unknown")


def lookup_cves(bssid: str, max_results: int = 10) -> list[dict]:
    """Query NVD 2.0 API by vendor name derived from BSSID OUI."""
    vendor = bssid_to_vendor(bssid)
    if vendor == "Unknown":
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    params = {"keywordSearch": vendor, "resultsPerPage": max_results}

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
