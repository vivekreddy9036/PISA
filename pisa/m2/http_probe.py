"""HTTP banner grab: fetch '/', inspect the Server header and a small set
of body/header keywords associated with common IoT device web UIs
(cameras, routers, printers, hubs).
"""
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# First keyword match wins — piling up multiple low-signal keyword hits
# per device would just dilute fusion's confidence sum for no benefit.
_KEYWORDS = {
    "camera": "IP Camera",
    "nvr": "Network Video Recorder",
    "router": "Router",
    "gateway": "Router",
    "printer": "Network Printer",
    "hub": "Smart Home Hub",
}


def _get(ip: str, port: int, timeout: float) -> requests.Response | None:
    """The one networking seam in this module — tests monkeypatch this
    instead of touching real sockets."""
    scheme = "https" if port in (443, 8443) else "http"
    try:
        return requests.get(f"{scheme}://{ip}:{port}/", timeout=timeout, verify=False)
    except Exception:
        return None


def probe(ip: str, port: int, timeout: float) -> list[dict]:
    resp = _get(ip, port, timeout)
    if resp is None:
        return []

    features = []
    server = resp.headers.get("Server")
    if server:
        features.append({
            "protocol": "http",
            "feature_key": "http.server",
            "feature_value": server,
            "confidence": 0.5,
            "device_type_hint": None,
        })

    haystack = f"{server or ''} {(resp.text or '')[:2000]}".lower()
    for keyword, hint in _KEYWORDS.items():
        if keyword in haystack:
            features.append({
                "protocol": "http",
                "feature_key": "http.keyword_match",
                "feature_value": keyword,
                "confidence": 0.7,
                "device_type_hint": hint,
            })
            break

    return features
