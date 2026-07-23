"""Synthetic WiFi scan data for local dev/testing without monitor-mode hardware.

Dev/testing convenience only — the shape matches beacon_capture._parse_beacon's
output exactly so it flows through the same scoring/persistence path as a real
capture. Not intended to be presented as a live capture.
"""

DEMO_VENDOR = "TP-Link"


def generate_demo_networks() -> list[dict]:
    return [
        {
            "bssid": "AA:BB:CC:00:00:01",
            "ssid": "HomeNet_5G",
            "channel": 6,
            "signal_dbm": -42,
            "security": "WPA3",
            "encryption": "WPA3",
            "beacon_interval": 100,
            "pmf_enabled": 1,
            "hidden": 0,
            "wps_enabled": 0,
        },
        {
            "bssid": "AA:BB:CC:00:00:02",
            "ssid": "Office_Guest",
            "channel": 11,
            "signal_dbm": -58,
            "security": "WPA2",
            "encryption": "WPA2",
            "beacon_interval": 100,
            "pmf_enabled": 0,
            "hidden": 0,
            "wps_enabled": 0,
        },
        {
            "bssid": "AA:BB:CC:00:00:03",
            "ssid": "TP-Link_4A2E",
            "channel": 4,
            "signal_dbm": -68,
            "security": "WPA2",
            "encryption": "WPA2",
            "beacon_interval": 100,
            "pmf_enabled": 0,
            "hidden": 0,
            "wps_enabled": 1,
        },
        {
            "bssid": "AA:BB:CC:00:00:04",
            "ssid": "NETGEAR_Legacy",
            "channel": 8,
            "signal_dbm": -75,
            "security": "WPA",
            "encryption": "WPA",
            "beacon_interval": 200,
            "pmf_enabled": 0,
            "hidden": 0,
            "wps_enabled": 1,
        },
        {
            "bssid": "AA:BB:CC:00:00:05",
            "ssid": "",
            "channel": 3,
            "signal_dbm": -82,
            "security": "Open",
            "encryption": "Open",
            "beacon_interval": 200,
            "pmf_enabled": 0,
            "hidden": 1,
            "wps_enabled": 0,
        },
        {
            "bssid": "AA:BB:CC:00:00:06",
            "ssid": "IoT_Hub_2G",
            "channel": 1,
            "signal_dbm": -50,
            "security": "WPA3",
            "encryption": "WPA3",
            "beacon_interval": 100,
            "pmf_enabled": 1,
            "hidden": 0,
            "wps_enabled": 0,
        },
        {
            "bssid": "AA:BB:CC:00:00:07",
            "ssid": "CoffeeShop_Free_WiFi",
            "channel": 7,
            "signal_dbm": -88,
            "security": "Open",
            "encryption": "Open",
            "beacon_interval": 100,
            "pmf_enabled": 0,
            "hidden": 0,
            "wps_enabled": 0,
        },
    ]


def generate_demo_cves(vendor: str) -> list[dict]:
    return [
        {
            "cve_id": "CVE-2021-40539",
            "cvss_score": 9.8,
            "description": f"Illustrative sample CVE for demo-mode {vendor} equipment — "
                            "not a live NVD lookup result.",
        },
        {
            "cve_id": "CVE-2020-10882",
            "cvss_score": 7.5,
            "description": f"Illustrative sample CVE for demo-mode {vendor} equipment — "
                            "not a live NVD lookup result.",
        },
    ]
