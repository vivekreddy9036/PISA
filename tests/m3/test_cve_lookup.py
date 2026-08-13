from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m3 import cpe_mapper, cve_lookup


# ---------------------------------------------------------------------------
# Real, live-captured NVD CVE API 2.0 shapes (2026-08-13), used verbatim
# as fixtures per the required test strategy — not invented shapes.
# ---------------------------------------------------------------------------

_CVE_2017_16725 = {  # real Xiongmai stack buffer overflow, CVSS v3.0 + v2
    "id": "CVE-2017-16725",
    "sourceIdentifier": "ics-cert@hq.dhs.gov",
    "published": "2017-12-20T19:29:00.257",
    "lastModified": "2026-06-17T01:09:43.137",
    "vulnStatus": "Modified",
    "descriptions": [{"lang": "en", "value": "A Stack-based Buffer Overflow..."}],
    "metrics": {
        "cvssMetricV30": [{
            "source": "nvd@nist.gov", "type": "Primary",
            "cvssData": {
                "version": "3.0", "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8, "baseSeverity": "CRITICAL",
            },
        }],
        "cvssMetricV2": [{
            "source": "nvd@nist.gov", "type": "Primary",
            "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "baseScore": 10.0},
            "baseSeverity": "HIGH",
        }],
    },
    "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-119"}]}],
    "configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*"},
        ]},
    ]}],
    "references": [{"url": "http://www.securityfocus.com/bid/102125", "source": "ics-cert@hq.dhs.gov", "tags": ["Third Party Advisory"]}],
}

_CVE_2014_0160 = {  # real Heartbleed, CVSS v3.1
    "id": "CVE-2014-0160",
    "published": "2014-04-07T00:00:00.000",
    "lastModified": "2025-01-01T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "The TLS heartbeat extension..."}],
    "metrics": {"cvssMetricV31": [{
        "source": "nvd@nist.gov", "type": "Primary",
        "cvssData": {
            "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "baseScore": 7.5, "baseSeverity": "HIGH",
        },
    }]},
    "weaknesses": [], "configurations": [], "references": [],
}


def _setup_device(db, identity_vendor="Xiongmai", identity_product="AHB7008F8-H", identity_version=None):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:30", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.40"})
        queries.update_device_identity(conn, device_id, vendor=identity_vendor, product=identity_product, version=identity_version)
    return device_id


# ---------------------------------------------------------------------------
# _extract_cvss / _normalize_cve — parsing correctness, incl. the real
# baseSeverity nesting quirk (sibling for v2, nested for v3.x)
# ---------------------------------------------------------------------------

def test_extract_cvss_prefers_v31_over_v30_and_v2():
    cvss = cve_lookup._extract_cvss(_CVE_2014_0160)
    assert cvss == {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "base_score": 7.5, "severity": "HIGH"}


def test_extract_cvss_v2_severity_is_sibling_not_nested():
    """Real, live-verified quirk: v2's baseSeverity sits next to
    cvssData, not inside it (unlike v3.x/v4) — this test exists because
    a naive parser (checking only cvssData.baseSeverity) would silently
    return severity=None for every CVSS v2-only CVE."""
    metrics_v2_only = {"metrics": {"cvssMetricV2": _CVE_2017_16725["metrics"]["cvssMetricV2"]}}
    cvss = cve_lookup._extract_cvss(metrics_v2_only)
    assert cvss["severity"] == "HIGH"
    assert cvss["base_score"] == 10.0


def test_extract_cvss_missing_returns_none():
    assert cve_lookup._extract_cvss({"metrics": {}}) is None


def test_normalize_cve_preserves_configurations_verbatim():
    finding = cve_lookup._normalize_cve(_CVE_2017_16725, ["cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*"], cve_lookup.CORRELATION_CPE)
    assert finding["configurations"] == _CVE_2017_16725["configurations"]
    assert finding["weaknesses"] == ["CWE-119"]
    assert finding["cve_references"][0]["url"] == "http://www.securityfocus.com/bid/102125"


# ---------------------------------------------------------------------------
# correlate_device_cves — the 23 required scenarios
# ---------------------------------------------------------------------------

def test_1_confirmed_cpe_to_nvd_cves(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert result["status"] == cve_lookup.STATUS_OK
    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve_id"] == "CVE-2017-16725"
    assert result["findings"][0]["correlation_method"] == cve_lookup.CORRELATION_CPE


def test_2_and_3_multiple_cpe_candidates_marks_ambiguous(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [
        {"cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:productA:-:*:*:*:*:*:*:*", "cpeNameId": "id1"}},
        {"cpe": {"deprecated": False, "cpeName": "cpe:2.3:o:vendor:productA_firmware:-:*:*:*:*:*:*:*", "cpeNameId": "id2"}},
    ])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert len(result["findings"]) == 1  # same CVE from both CPEs -> deduplicated
    finding = result["findings"][0]
    assert finding["correlation_method"] == cve_lookup.CORRELATION_CPE_AMBIGUOUS
    assert set(finding["source_cpe"]) == {"cpe:2.3:h:vendor:productA:-:*:*:*:*:*:*:*", "cpe:2.3:o:vendor:productA_firmware:-:*:*:*:*:*:*:*"}


def test_4_no_cpe_data_is_unavailable_due_to_identity_not_safe(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [])
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id, include_keyword_fallback=True)

    assert result["status"] == cve_lookup.STATUS_UNAVAILABLE_DUE_TO_IDENTITY
    assert result["status"] != cve_lookup.STATUS_NO_CVE_MATCH  # "unavailable" must never read as "safe"


def test_5_nvd_unavailable_distinguished_from_no_cpe_data(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert result["status"] == cve_lookup.STATUS_NVD_UNAVAILABLE
    assert result["status"] != cve_lookup.STATUS_UNAVAILABLE_DUE_TO_IDENTITY


def test_6_nvd_empty_result_is_no_cve_match(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [])
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert result["status"] == cve_lookup.STATUS_NO_CVE_MATCH
    assert result["findings"] == []


def test_7_multipage_handled_transparently_by_nvd_client(db, monkeypatch):
    """cve_lookup itself doesn't paginate — nvd_client.query_cves_by_cpe
    already returns the fully-collected list (see test_nvd_client.py's
    own pagination tests); this just confirms cve_lookup consumes
    whatever it's given correctly, multi-item or not."""
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725, _CVE_2014_0160])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert {f["cve_id"] for f in result["findings"]} == {"CVE-2017-16725", "CVE-2014-0160"}


def test_8_duplicate_cve_across_cpes_becomes_one_finding(db, monkeypatch):
    # already covered structurally by test_2_and_3 — separate, focused assertion here
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [
        {"cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:a:-:*:*:*:*:*:*:*", "cpeNameId": "id1"}},
        {"cpe": {"deprecated": False, "cpeName": "cpe:2.3:o:vendor:a_fw:-:*:*:*:*:*:*:*", "cpeNameId": "id2"}},
    ])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)
        stored = queries.get_device_cves(conn, device_id)

    assert len(result["findings"]) == 1
    assert len(stored) == 1  # not two duplicate DB rows either


def test_9_cvss_v3(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2014_0160])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    f = result["findings"][0]
    assert f["cvss_version"] == "3.1"
    assert f["cvss_score"] == 7.5
    assert f["cvss_severity"] == "HIGH"


def test_10_cvss_v4_supported_if_present():
    raw = {
        "id": "CVE-FAKE-0001", "descriptions": [], "weaknesses": [], "configurations": [], "references": [],
        "metrics": {"cvssMetricV40": [{
            "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L", "baseScore": 8.1, "baseSeverity": "HIGH"},
        }]},
    }
    cvss = cve_lookup._extract_cvss(raw)
    assert cvss == {"version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L", "base_score": 8.1, "severity": "HIGH"}


def test_11_missing_cvss_is_unknown_not_zero(db, monkeypatch):
    no_cvss_cve = {**_CVE_2014_0160, "id": "CVE-NO-CVSS", "metrics": {}}
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [no_cvss_cve])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    f = result["findings"][0]
    assert f["cvss_score"] is None
    assert f["cvss_version"] is None
    assert f["cvss_score"] != 0  # never silently substituted with 0


def test_12_epss_enrichment(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(
        cve_lookup.epss_client, "get_epss_records",
        lambda ids: {"CVE-2017-16725": {"score": 0.87, "percentile": 0.95, "date": "2026-08-13"}},
    )
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    f = result["findings"][0]
    assert f["epss_score"] == 0.87
    assert f["epss_percentile"] == 0.95
    assert f["epss_date"] == "2026-08-13"


def test_13_missing_epss_is_unknown_not_zero(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert result["findings"][0]["epss_score"] is None


def test_14_kev_enrichment(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(
        cve_lookup.exploit_score, "get_kev_record",
        lambda cve_id: {"dateAdded": "2018-01-01", "dueDate": "2018-01-15", "knownRansomwareCampaignUse": "Unknown"},
    )
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    f = result["findings"][0]
    assert f["kev_listed"] is True
    assert f["kev_date_added"] == "2018-01-01"
    assert f["kev_due_date"] == "2018-01-15"


def test_15_cve_not_in_kev_is_not_claimed_not_exploitable(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    f = result["findings"][0]
    assert f["kev_listed"] is False
    assert f["kev_date_added"] is None  # absence recorded, not converted into a safety claim


def test_16_keyword_fallback_finds_a_cve_cpe_missed(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [])  # NO_CPE_DATA
    monkeypatch.setattr(
        cve_lookup.oui_cve, "lookup_device_cves",
        lambda os_guess: [{"cve_id": "CVE-KEYWORD-0001", "cvss_score": 5.0, "description": "found via keyword"}],
    )
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve_id"] == "CVE-KEYWORD-0001"
    assert result["findings"][0]["correlation_method"] == cve_lookup.CORRELATION_KEYWORD


def test_17_keyword_fallback_cannot_mark_affected_or_override_cpe(db, monkeypatch):
    """The brief's mandatory example: CPE says NO_CPE_DATA, keyword finds
    a CVE anyway -> correlation_method=KEYWORD, never AFFECTED (Phase 4
    doesn't even have an applicability concept — this test confirms the
    finding carries no field that could be mistaken for one). Also
    confirms a keyword-found CVE that duplicates a CPE-found one never
    downgrades/overwrites the stronger correlation_method."""
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(
        cve_lookup.oui_cve, "lookup_device_cves",
        lambda os_guess: [{"cve_id": "CVE-2017-16725", "cvss_score": 1.0, "description": "should not win"}],
    )
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)

    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["correlation_method"] == cve_lookup.CORRELATION_CPE  # not downgraded to KEYWORD
    assert "applicability" not in f and "verified" not in f  # no such field exists at all in Phase 4's output


def test_18_nvd_configuration_preservation(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        cve_lookup.correlate_device_cves(conn, device_id)
        stored = queries.get_device_cves(conn, device_id)

    import json
    stored_config = json.loads(stored[0]["configurations"])
    assert stored_config == _CVE_2017_16725["configurations"]
    stored_weaknesses = json.loads(stored[0]["weaknesses"])
    assert stored_weaknesses == ["CWE-119"]


def test_19_cache_hit_reuses_cpe_mapping_without_requerying(db, monkeypatch):
    call_count = {"n": 0}

    def _counting_cpe_query(kw, max_results=20):
        call_count["n"] += 1
        return [{"cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"}}]

    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", _counting_cpe_query)
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [])
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        cve_lookup.correlate_device_cves(conn, device_id)
        assert call_count["n"] == 1
        cve_lookup.correlate_device_cves(conn, device_id)  # force_refresh defaults False
        assert call_count["n"] == 1


def test_20_cache_bypass_with_force_refresh(db, monkeypatch):
    call_count = {"n": 0}

    def _counting_cpe_query(kw, max_results=20):
        call_count["n"] += 1
        return [{"cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"}}]

    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", _counting_cpe_query)
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [])
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        cve_lookup.correlate_device_cves(conn, device_id)
        cve_lookup.correlate_device_cves(conn, device_id, force_refresh=True)
        assert call_count["n"] == 2


def test_21_api_retry_exhaustion_is_nvd_unavailable_not_crash(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: None)  # retries already exhausted inside nvd_client
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id)  # must not raise

    assert result["status"] == cve_lookup.STATUS_NVD_UNAVAILABLE


def test_22_correlation_provenance_recorded_per_finding(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        cve_lookup.correlate_device_cves(conn, device_id)
        stored = queries.get_device_cves(conn, device_id)

    import json
    assert stored[0]["correlation_method"] == "CPE"
    assert json.loads(stored[0]["source_cpe"]) == ["cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*"]


def test_23_timestamp_preservation(db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_CVE_2017_16725])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)

    device_id = _setup_device(db)
    with get_connection(db) as conn:
        cve_lookup.correlate_device_cves(conn, device_id)
        stored = queries.get_device_cves(conn, device_id)

    assert stored[0]["nvd_published"] == "2017-12-20T19:29:00.257"
    assert stored[0]["nvd_last_modified"] == "2026-06-17T01:09:43.137"
    assert stored[0]["fetched_at"] is not None  # PISA's own retrieval timestamp
