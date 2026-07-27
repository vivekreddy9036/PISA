from unittest.mock import MagicMock, patch

from pisa.m3 import epss_client


def test_get_epss_scores_returns_empty_for_no_cve_ids():
    with patch("pisa.m3.epss_client.requests.get") as mock_get:
        scores = epss_client.get_epss_scores([])
    mock_get.assert_not_called()
    assert scores == {}


def test_get_epss_scores_batches_request():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "data": [
            {"cve": "CVE-2021-1234", "epss": "0.42"},
            {"cve": "CVE-2020-5678", "epss": "0.05"},
        ]
    }
    with patch("pisa.m3.epss_client.requests.get", return_value=mock_resp) as mock_get:
        scores = epss_client.get_epss_scores(["CVE-2021-1234", "CVE-2020-5678"])

    assert mock_get.call_args.kwargs["params"]["cve"] == "CVE-2021-1234,CVE-2020-5678"
    assert scores == {"CVE-2021-1234": 0.42, "CVE-2020-5678": 0.05}


def test_get_epss_scores_omits_cves_without_a_record():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"data": [{"cve": "CVE-2021-1234", "epss": "0.42"}]}
    with patch("pisa.m3.epss_client.requests.get", return_value=mock_resp):
        scores = epss_client.get_epss_scores(["CVE-2021-1234", "CVE-9999-0000"])

    assert scores == {"CVE-2021-1234": 0.42}


def test_get_epss_scores_returns_empty_on_request_failure():
    with patch("pisa.m3.epss_client.requests.get", side_effect=Exception("network down")):
        scores = epss_client.get_epss_scores(["CVE-2021-1234"])
    assert scores == {}
