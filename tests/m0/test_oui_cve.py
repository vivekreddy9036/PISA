import os
from unittest.mock import MagicMock, patch

import pytest

from pisa.m0 import oui_cve


@pytest.fixture(autouse=True)
def reset_oui_state(tmp_path, monkeypatch):
    monkeypatch.setattr(oui_cve, "_OUI_FILE", str(tmp_path / "oui.txt"))
    oui_cve._OUI_DB.clear()
    yield
    oui_cve._OUI_DB.clear()


def test_download_oui_db_writes_file():
    mock_resp = MagicMock()
    mock_resp.text = "00-50-F2   (hex)\tTP-LINK TECHNOLOGIES CO.,LTD.\n"
    mock_resp.raise_for_status = MagicMock()
    with patch("pisa.m0.oui_cve.requests.get", return_value=mock_resp) as mock_get:
        oui_cve.download_oui_db()
        mock_get.assert_called_once()
    assert os.path.exists(oui_cve._OUI_FILE)


def test_download_oui_db_noop_if_file_exists():
    with open(oui_cve._OUI_FILE, "w") as f:
        f.write("existing")
    with patch("pisa.m0.oui_cve.requests.get") as mock_get:
        oui_cve.download_oui_db()
        mock_get.assert_not_called()


def test_bssid_to_vendor_parses_oui_file():
    with open(oui_cve._OUI_FILE, "w") as f:
        f.write("00-50-F2   (hex)\tTP-LINK TECHNOLOGIES CO.,LTD.\n")
    vendor = oui_cve.bssid_to_vendor("00:50:F2:AA:BB:CC")
    assert "TP-LINK" in vendor


def test_bssid_to_vendor_unknown_without_file_and_download_failing():
    with patch("pisa.m0.oui_cve.requests.get", side_effect=Exception("network down")):
        vendor = oui_cve.bssid_to_vendor("AA:BB:CC:00:00:01")
    assert vendor == "Unknown"


def test_bssid_to_vendor_downloads_db_when_missing():
    mock_resp = MagicMock()
    mock_resp.text = "00-50-F2   (hex)\tTP-LINK TECHNOLOGIES CO.,LTD.\n"
    mock_resp.raise_for_status = MagicMock()
    with patch("pisa.m0.oui_cve.requests.get", return_value=mock_resp) as mock_get:
        vendor = oui_cve.bssid_to_vendor("00:50:F2:AA:BB:CC")
    mock_get.assert_called_once()
    assert "TP-LINK" in vendor


def test_lookup_cves_returns_empty_for_unknown_vendor():
    with patch("pisa.m0.oui_cve.requests.get", side_effect=Exception("network down")):
        cves = oui_cve.lookup_cves("AA:BB:CC:00:00:01")
    assert cves == []


def test_lookup_cves_parses_cvss_fallback_chain():
    with open(oui_cve._OUI_FILE, "w") as f:
        f.write("00-50-F2   (hex)\tTP-LINK TECHNOLOGIES CO.,LTD.\n")

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-1234",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    "descriptions": [{"lang": "en", "value": "Test vuln"}],
                }
            }
        ]
    }
    with patch("pisa.m0.oui_cve.requests.get", return_value=mock_resp):
        cves = oui_cve.lookup_cves("00:50:F2:AA:BB:CC")

    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2021-1234"
    assert cves[0]["cvss_score"] == 9.8
    assert cves[0]["description"] == "Test vuln"


def test_lookup_cves_handles_request_failure():
    with open(oui_cve._OUI_FILE, "w") as f:
        f.write("00-50-F2   (hex)\tTP-LINK TECHNOLOGIES CO.,LTD.\n")
    with patch("pisa.m0.oui_cve.requests.get", side_effect=Exception("network down")):
        cves = oui_cve.lookup_cves("00:50:F2:AA:BB:CC")
    assert cves == []


def test_lookup_device_cves_prefers_os_guess_over_vendor():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"vulnerabilities": []}
    with patch("pisa.m0.oui_cve.requests.get", return_value=mock_resp) as mock_get:
        oui_cve.lookup_device_cves("Cisco Systems, Inc", "Cisco Nexus switch (NX-OS 6.0(2))")
    assert mock_get.call_args.kwargs["params"]["keywordSearch"] == "Cisco Nexus switch"


def test_simplify_os_guess_strips_version_parenthetical():
    assert oui_cve._simplify_os_guess("Cisco Nexus switch (NX-OS 6.0(2))") == "Cisco Nexus switch"
    assert oui_cve._simplify_os_guess("Linux 4.X") == "Linux 4.X"


def test_lookup_device_cves_falls_back_to_vendor_without_os_guess():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"vulnerabilities": []}
    with patch("pisa.m0.oui_cve.requests.get", return_value=mock_resp) as mock_get:
        oui_cve.lookup_device_cves("Cisco Systems, Inc", None)
    assert mock_get.call_args.kwargs["params"]["keywordSearch"] == "Cisco Systems, Inc"


def test_lookup_device_cves_returns_empty_without_vendor_or_os_guess():
    with patch("pisa.m0.oui_cve.requests.get") as mock_get:
        cves = oui_cve.lookup_device_cves("Unknown", None)
    mock_get.assert_not_called()
    assert cves == []


def test_lookup_device_cves_parses_results():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-3118",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8}}]},
                    "descriptions": [{"lang": "en", "value": "Cisco NX-OS vuln"}],
                }
            }
        ]
    }
    with patch("pisa.m0.oui_cve.requests.get", return_value=mock_resp):
        cves = oui_cve.lookup_device_cves("Cisco Systems, Inc", "Cisco Nexus switch (NX-OS 6.0(2))")

    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2020-3118"
    assert cves[0]["cvss_score"] == 8.8
