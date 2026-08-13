import pytest

from pisa.m3 import cpe_mapper

# Real NVD CPE API 2.0 response captured live during this phase's research
# (2026-08-13, keywordSearch=xiongmai) — used verbatim as a fixture rather
# than an invented shape. Confirms the real-world case this phase was
# built around: NVD's own dictionary returns a firmware/OS-part CPE for
# Xiongmai, not a hardware one.
_XIONGMAI_PRODUCT = {
    "cpe": {
        "deprecated": False,
        "cpeName": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:-:*:*:*:*:*:*:*",
        "cpeNameId": "007AB5F3-40CA-4B8B-9672-AA579270A785",
        "lastModified": "2021-04-27T17:00:34.030",
        "created": "2018-01-08T21:04:20.130",
        "titles": [{"title": "xiongmaitech AHB7008F8-H Firmware", "lang": "en"}],
        "refs": [
            {"ref": "http://www.xiongmaitech.com/en/index.php/product/product-list/2/0/1", "type": "Product"},
            {"ref": "http://www.xiongmaitech.com/en/index.php", "type": "Vendor"},
        ],
    }
}

# Illustrative hardware-part CPE, modeled on real CPE 2.3 syntax (not an
# independently-reconfirmed live NVD entry) — used to exercise the
# CPE_CONFIRMED path, which needs a part="h" example.
_TPLINK_HW_PRODUCT = {
    "cpe": {
        "deprecated": False,
        "cpeName": "cpe:2.3:h:tp-link:archer_ax21:1.0:*:*:*:*:*:*:*",
        "cpeNameId": "AAAAAAAA-0000-0000-0000-000000000001",
        "lastModified": "2022-01-01T00:00:00.000",
        "created": "2021-01-01T00:00:00.000",
        "titles": [{"title": "TP-Link Archer AX21", "lang": "en"}],
        "refs": [],
    }
}


def _deprecated_copy(product: dict) -> dict:
    import copy
    p = copy.deepcopy(product)
    p["cpe"]["deprecated"] = True
    return p


# ---------------------------------------------------------------------------
# _parse_cpe_name / _loose_match / _build_keyword — small pure helpers
# ---------------------------------------------------------------------------

def test_parse_cpe_name_extracts_fields():
    parsed = cpe_mapper._parse_cpe_name("cpe:2.3:h:tp-link:archer_ax21:1.0:*:*:*:*:*:*:*")
    assert parsed == {"part": "h", "vendor": "tp-link", "product": "archer_ax21", "version": "1.0"}


def test_parse_cpe_name_malformed_returns_all_none():
    assert cpe_mapper._parse_cpe_name("not a cpe") == {"part": None, "vendor": None, "product": None, "version": None}
    assert cpe_mapper._parse_cpe_name("") == {"part": None, "vendor": None, "product": None, "version": None}


def test_loose_match_handles_punctuation_and_case():
    assert cpe_mapper._loose_match("Hangzhou Xiongmai Technology Co.,Ltd", "xiongmaitech")
    assert cpe_mapper._loose_match("TP-Link", "tp-link")
    assert not cpe_mapper._loose_match("Cisco", "netgear")
    assert not cpe_mapper._loose_match(None, "xiongmaitech")


def test_build_keyword_uses_only_first_vendor_word():
    assert cpe_mapper._build_keyword("Hangzhou Xiongmai Technology Co.,Ltd", "uc-httpd") == "Hangzhou uc-httpd"
    assert cpe_mapper._build_keyword("Xiongmai", None) == "Xiongmai"
    assert cpe_mapper._build_keyword(None, None) is None


# ---------------------------------------------------------------------------
# map_identity_to_cpe — the 15 required scenarios
# ---------------------------------------------------------------------------

def test_1_vendor_product_version_all_present_can_reach_confirmed(monkeypatch):
    """Strongest available evidence (Phase 2 has no separate 'model'
    field with any evidence source — see the Phase 3 audit — so this is
    the maximum identity strength PISA can produce today)."""
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT])

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer_ax21", "1.0")

    assert len(candidates) == 1
    assert candidates[0]["status"] == cpe_mapper.STATUS_CONFIRMED
    assert candidates[0]["cpe"] == "cpe:2.3:h:tp-link:archer_ax21:1.0:*:*:*:*:*:*:*"
    assert candidates[0]["confidence"] >= 0.9


def test_2_vendor_product_without_version_stays_candidate(monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT])

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer_ax21", None)

    assert candidates[0]["status"] == cpe_mapper.STATUS_CANDIDATE
    assert "version not confirmed" not in candidates[0]["identity_basis"]  # version wasn't even supplied to compare


def test_3_vendor_only_identity_too_broad_is_no_cpe_data(monkeypatch):
    """A bare vendor name realistically returns hundreds of NVD CPE
    entries (confirmed live: keywordSearch=xiongmai -> 515 results) — not
    a small, defensible candidate set."""
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT] * 20)

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", None, None)

    assert len(candidates) == 1
    assert candidates[0]["status"] == cpe_mapper.STATUS_NO_DATA
    assert candidates[0]["cpe"] is None
    assert "too broad" in candidates[0]["identity_basis"]


def test_4_missing_evidence_is_no_cpe_data_without_querying_nvd(monkeypatch):
    def _fail_if_called(keyword, max_results=20):
        raise AssertionError("must not query NVD with no identity evidence at all")

    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", _fail_if_called)

    candidates = cpe_mapper.map_identity_to_cpe(None, None, None)

    assert candidates == [{
        "cpe": None, "confidence": None, "status": cpe_mapper.STATUS_NO_DATA,
        "source": "no_identity_evidence", "identity_basis": "no vendor or product evidence available",
        "nvd_cpe_name_id": None,
    }]


def test_5_generic_banner_with_no_field_match_is_low_confidence(monkeypatch):
    """A weak/unrelated NVD hit (neither vendor nor product token
    actually matches) must never be scored as if it were meaningful."""
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT])

    candidates = cpe_mapper.map_identity_to_cpe("SomeUnrelatedVendor", "GoAhead-Webs", None)

    assert candidates[0]["status"] == cpe_mapper.STATUS_CANDIDATE
    assert candidates[0]["confidence"] <= 0.2


def test_6_xiongmai_uc_httpd_never_becomes_confirmed_hardware(monkeypatch):
    """The exact case this phase was built around: vendor=Xiongmai,
    product=uc-httpd, version=1.0.0 must NOT automatically produce a
    confirmed hardware CPE. Using the real, live-captured NVD response —
    a firmware/OS-part CPE is the actual, correct outcome."""
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_XIONGMAI_PRODUCT])

    candidates = cpe_mapper.map_identity_to_cpe(
        "Hangzhou Xiongmai Technology Co.,Ltd", "uc-httpd", "1.0.0",
    )

    assert len(candidates) == 1
    assert candidates[0]["status"] != cpe_mapper.STATUS_CONFIRMED
    assert candidates[0]["cpe"] == "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:-:*:*:*:*:*:*:*"
    assert "not confirmed hardware" in candidates[0]["identity_basis"]


def test_7_multiple_plausible_candidates_are_ambiguous_not_arbitrarily_chosen(monkeypatch):
    monkeypatch.setattr(
        cpe_mapper, "_query_nvd_cpe",
        lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT, _XIONGMAI_PRODUCT],
    )

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer", "1.0")

    assert len(candidates) == 2
    assert all(c["status"] == cpe_mapper.STATUS_AMBIGUOUS for c in candidates)
    cpes = {c["cpe"] for c in candidates}
    assert cpes == {_TPLINK_HW_PRODUCT["cpe"]["cpeName"], _XIONGMAI_PRODUCT["cpe"]["cpeName"]}


def test_8_no_cpe_match(monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [])

    candidates = cpe_mapper.map_identity_to_cpe("SomeVendor", "SomeProduct", None)

    assert candidates[0]["status"] == cpe_mapper.STATUS_NO_DATA
    assert candidates[0]["source"] == "nvd_cpe_dictionary"


def test_9_nvd_api_unavailable_is_distinguishable_from_no_match(monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: None)

    candidates = cpe_mapper.map_identity_to_cpe("SomeVendor", "SomeProduct", None)

    assert candidates[0]["status"] == cpe_mapper.STATUS_UNAVAILABLE
    assert candidates[0]["status"] != cpe_mapper.STATUS_NO_DATA


def test_10_cached_result_reused_without_requerying_nvd(db, monkeypatch):
    from pisa.db import queries
    from pisa.db.connection import get_connection

    call_count = {"n": 0}

    def _counting_query(keyword, max_results=20):
        call_count["n"] += 1
        return [_TPLINK_HW_PRODUCT]

    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", _counting_query)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:20", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.30"})
        queries.update_device_identity(conn, device_id, vendor="TP-Link", product="archer_ax21", version="1.0")

        cpe_mapper.map_device_to_cpe(conn, device_id)
        assert call_count["n"] == 1

        # second call, force_refresh defaults False -> must reuse cache
        cpe_mapper.map_device_to_cpe(conn, device_id)
        assert call_count["n"] == 1

        # explicit refresh -> queries again
        cpe_mapper.map_device_to_cpe(conn, device_id, force_refresh=True)
        assert call_count["n"] == 2


def test_11_version_mismatch_is_not_confirmed(monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT])

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer_ax21", "2.0")

    assert candidates[0]["status"] != cpe_mapper.STATUS_CONFIRMED
    assert "version mismatch" in candidates[0]["identity_basis"]


def test_12_deprecated_cpe_halves_confidence(monkeypatch):
    monkeypatch.setattr(
        cpe_mapper, "_query_nvd_cpe",
        lambda keyword, max_results=20: [_deprecated_copy(_TPLINK_HW_PRODUCT)],
    )

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer_ax21", "1.0")

    assert candidates[0]["status"] != cpe_mapper.STATUS_CONFIRMED
    assert "deprecated" in candidates[0]["identity_basis"]
    assert candidates[0]["confidence"] < 0.9


def test_13_device_type_only_identity_is_no_cpe_data(monkeypatch):
    """device_type is never primary identity — with no vendor/product at
    all, this must resolve to NO_CPE_DATA without ever calling NVD, the
    same as no evidence at all (test 4)."""
    def _fail_if_called(keyword, max_results=20):
        raise AssertionError("device_type alone must not trigger an NVD query")

    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", _fail_if_called)

    candidates = cpe_mapper.map_identity_to_cpe(None, None, None, device_type="IP Camera")

    assert candidates[0]["status"] == cpe_mapper.STATUS_NO_DATA


def test_14_ranking_orders_by_confidence_descending(monkeypatch):
    weak_match = {"cpe": {
        "deprecated": False, "cpeName": "cpe:2.3:h:unrelatedvendor:unrelatedproduct:-:*:*:*:*:*:*:*",
        "cpeNameId": "id2", "titles": [], "refs": [],
    }}
    monkeypatch.setattr(
        cpe_mapper, "_query_nvd_cpe",
        lambda keyword, max_results=20: [weak_match, _TPLINK_HW_PRODUCT],
    )

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer_ax21", "1.0")

    assert candidates[0]["cpe"] == _TPLINK_HW_PRODUCT["cpe"]["cpeName"]
    assert candidates[0]["confidence"] >= candidates[1]["confidence"]


def test_15_evidence_traceability_lists_which_fields_matched(monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda keyword, max_results=20: [_TPLINK_HW_PRODUCT])

    candidates = cpe_mapper.map_identity_to_cpe("TP-Link", "archer_ax21", "1.0")

    basis = candidates[0]["identity_basis"]
    assert "vendor match" in basis
    assert "product match" in basis
    assert "version match" in basis
    assert "hardware CPE" in basis
    assert candidates[0]["nvd_cpe_name_id"] == "AAAAAAAA-0000-0000-0000-000000000001"


# ---------------------------------------------------------------------------
# Live integration test — NOT run by the default suite (no network
# dependency for CI/unit tests). Run manually with:
#   pytest tests/m3/test_cpe_mapper.py -k live --no-skip
# or remove the skip decorator locally.
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="hits the real NVD CPE API — run manually, not part of the automated suite")
def test_live_nvd_cpe_api_returns_real_data():
    products = cpe_mapper._query_nvd_cpe("xiongmai")
    assert products is not None
    assert len(products) > 0
    assert products[0]["cpe"]["cpeName"].startswith("cpe:2.3:")
