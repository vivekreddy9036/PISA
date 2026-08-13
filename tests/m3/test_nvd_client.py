from unittest.mock import MagicMock, patch

from pisa.m3 import nvd_client


def _page(vulnerabilities, total_results, results_per_page=100, start_index=0):
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "resultsPerPage": results_per_page, "startIndex": start_index,
        "totalResults": total_results, "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": vulnerabilities,
    }
    return resp


def _cve_entry(cve_id):
    return {"cve": {"id": cve_id, "descriptions": [], "metrics": {}}}


def test_query_cves_by_cpe_single_page():
    resp = _page([_cve_entry("CVE-2017-16725")], total_results=1)
    with patch("pisa.m3.nvd_client.requests.get", return_value=resp) as mock_get:
        cves = nvd_client.query_cves_by_cpe("cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*")

    assert [c["id"] for c in cves] == ["CVE-2017-16725"]
    assert mock_get.call_args.kwargs["params"]["cpeName"] == "cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*"


def test_query_cves_by_cpe_uses_bare_isVulnerable_flag_not_a_value():
    """Live-verified during this phase's research: isVulnerable=true /
    isVulnerable=false both return HTTP 404 from the real API — it must
    be a bare flag (empty value), never an explicit true/false."""
    resp = _page([], total_results=0)
    with patch("pisa.m3.nvd_client.requests.get", return_value=resp) as mock_get:
        nvd_client.query_cves_by_cpe("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*", is_vulnerable=True)

    assert mock_get.call_args.kwargs["params"]["isVulnerable"] == ""


def test_query_cves_by_cpe_omits_isVulnerable_when_false():
    resp = _page([], total_results=0)
    with patch("pisa.m3.nvd_client.requests.get", return_value=resp) as mock_get:
        nvd_client.query_cves_by_cpe("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*", is_vulnerable=False)

    assert "isVulnerable" not in mock_get.call_args.kwargs["params"]


def test_query_cves_by_cpe_paginates_across_multiple_pages():
    page1 = _page([_cve_entry("CVE-A"), _cve_entry("CVE-B")], total_results=3, results_per_page=2, start_index=0)
    page2 = _page([_cve_entry("CVE-C")], total_results=3, results_per_page=2, start_index=2)

    with patch("pisa.m3.nvd_client.requests.get", side_effect=[page1, page2]):
        cves = nvd_client.query_cves_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", results_per_page=2)

    assert [c["id"] for c in cves] == ["CVE-A", "CVE-B", "CVE-C"]


def test_query_cves_by_cpe_bounded_by_max_pages_even_if_more_exist():
    """Even if totalResults implies more pages, max_pages is a hard
    ceiling — never an infinite pagination loop."""
    page = _page([_cve_entry("CVE-A")], total_results=1000, results_per_page=1, start_index=0)

    with patch("pisa.m3.nvd_client.requests.get", return_value=page) as mock_get:
        cves = nvd_client.query_cves_by_cpe(
            "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", max_pages=3, results_per_page=1,
        )

    assert mock_get.call_count == 3
    assert len(cves) == 3  # same page mocked 3x, but the bound is what's under test


def test_query_cves_by_cpe_returns_none_after_retries_exhausted(monkeypatch):
    monkeypatch.setattr(nvd_client.time, "sleep", lambda s: None)
    error_resp = MagicMock()
    error_resp.status_code = 429

    with patch("pisa.m3.nvd_client.requests.get", return_value=error_resp) as mock_get:
        cves = nvd_client.query_cves_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

    assert cves is None
    assert mock_get.call_count == nvd_client._MAX_RETRIES


def test_query_cves_by_cpe_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(nvd_client.time, "sleep", lambda s: None)
    error_resp = MagicMock()
    error_resp.status_code = 429
    success_resp = _page([_cve_entry("CVE-A")], total_results=1)

    with patch("pisa.m3.nvd_client.requests.get", side_effect=[error_resp, success_resp]):
        cves = nvd_client.query_cves_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

    assert [c["id"] for c in cves] == ["CVE-A"]


def test_query_cves_by_cpe_returns_none_on_request_exception(monkeypatch):
    monkeypatch.setattr(nvd_client.time, "sleep", lambda s: None)
    import requests as real_requests
    with patch("pisa.m3.nvd_client.requests.get", side_effect=real_requests.exceptions.ConnectionError("down")):
        cves = nvd_client.query_cves_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

    assert cves is None


def test_query_cves_by_cpe_returns_empty_list_for_confirmed_zero_results():
    resp = _page([], total_results=0)
    with patch("pisa.m3.nvd_client.requests.get", return_value=resp):
        cves = nvd_client.query_cves_by_cpe("cpe:2.3:a:vendor:nonexistent:1.0:*:*:*:*:*:*:*")

    assert cves == []
    assert cves is not None  # the None-vs-[] distinction is the whole point
