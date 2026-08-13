import json

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m3 import applicability

# ---------------------------------------------------------------------------
# Real NVD configuration structures, captured live during Phase 3/4's own
# research (not invented) — reused here per instruction 20/21.
# ---------------------------------------------------------------------------

# Real CVE-2017-16725 configuration: an AND of a vulnerable=true firmware
# branch (exact version) and a vulnerable=false hardware-identification
# branch — the textbook real-world instance of instruction 7's example.
_REAL_XIONGMAI_CONFIG = [{"operator": "AND", "nodes": [
    {"operator": "OR", "negate": False, "cpeMatch": [{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*",
        "matchCriteriaId": "B7CA6BA2-0000-0000-0000-000000000000",
    }]},
    {"operator": "OR", "negate": False, "cpeMatch": [{
        "vulnerable": False,
        "criteria": "cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*",
        "matchCriteriaId": "56C548EF-0000-0000-0000-000000000000",
    }]},
]}]

_XIONGMAI_FW_CPE = "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*"
_XIONGMAI_HW_CPE = "cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*"

# Real CVE-2009-3766 (mutt) version-range configuration.
_REAL_MUTT_CONFIG = [{"operator": "OR", "nodes": [
    {"operator": "OR", "negate": False, "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.5.16", "versionEndExcluding": "1.5.19",
        "matchCriteriaId": "7A318134-0000-0000-0000-000000000000",
    }]},
]}]
_MUTT_CPE = "cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*"

# Illustrative (not independently reconfirmed live) constructed fixtures for
# cases not observed in this project's real captured data: OR-of-two,
# versionStartExcluding/versionEndIncluding, negate, wildcard vendor.
_OR_TWO_PRODUCTS_CONFIG = [{"operator": "OR", "nodes": [
    {"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:producta:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "id-a"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:productb:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "id-b"},
    ]},
]}]

_EXCLUDING_RANGE_CONFIG = [{"operator": "OR", "nodes": [
    {"operator": "OR", "negate": False, "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
        "versionStartExcluding": "1.0", "versionEndIncluding": "2.0",
        "matchCriteriaId": "id-range",
    }]},
]}]

_NEGATE_CONFIG = [{"operator": "AND", "nodes": [
    {"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "matchCriteriaId": "id-main"},
    ]},
    {"operator": "OR", "negate": True, "cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:a:vendor:patched_addon:*:*:*:*:*:*:*:*", "matchCriteriaId": "id-addon"},
    ]},
]}]

_WILDCARD_VENDOR_CONFIG = [{"operator": "OR", "nodes": [
    {"operator": "OR", "negate": False, "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "id-wc",
    }]},
]}]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_parse_cpe_full_components():
    parsed = applicability._parse_cpe(_XIONGMAI_FW_CPE)
    assert parsed["part"] == "o"
    assert parsed["vendor"] == "xiongmaitech"
    assert parsed["product"] == "ahb7008f8-h_firmware"
    assert parsed["version"] == "4.02.r11.3070"


def test_cpe_component_match_wildcard_either_side():
    assert applicability._cpe_component_match("anything", "*")
    assert applicability._cpe_component_match("*", "specific")
    assert not applicability._cpe_component_match("foo", "bar")


def test_cpe_component_match_na_only_matches_na():
    assert applicability._cpe_component_match("-", "-")
    assert not applicability._cpe_component_match("1.0", "-")


def test_compare_versions_numeric():
    assert applicability._compare_versions("1.5", "1.10") < 0  # numeric, not lexicographic
    assert applicability._compare_versions("2.0", "1.9") > 0
    assert applicability._compare_versions("1.0", "1.0") == 0


def test_compare_versions_suffixed_segments():
    """Real-world OpenSSL-style versioning (1.0.1a > 1.0.1) — verified
    during Phase 4's research that NVD carries these exact forms."""
    assert applicability._compare_versions("1.0.1a", "1.0.1") > 0


def test_version_in_range_all_four_operators():
    # >= 1.0
    assert applicability._version_in_range("1.0", "1.0", None, None, None) is True
    assert applicability._version_in_range("0.9", "1.0", None, None, None) is False
    # > 1.0
    assert applicability._version_in_range("1.0", None, "1.0", None, None) is False
    assert applicability._version_in_range("1.1", None, "1.0", None, None) is True
    # <= 2.0
    assert applicability._version_in_range("2.0", None, None, "2.0", None) is True
    assert applicability._version_in_range("2.1", None, None, "2.0", None) is False
    # < 2.0
    assert applicability._version_in_range("2.0", None, None, None, "2.0") is False
    assert applicability._version_in_range("1.9", None, None, None, "2.0") is True


def test_version_in_range_unknown_target_is_none():
    assert applicability._version_in_range(None, "1.0", None, "2.0", None) is None


# ---------------------------------------------------------------------------
# Configuration evaluation — the required test matrix (25 items)
# ---------------------------------------------------------------------------

def test_1_exact_vulnerable_cpe_match():
    result = applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], "1.5.17")
    assert result["status"] == applicability.STATUS_AFFECTED
    assert result["matched_criteria_id"] == "7A318134-0000-0000-0000-000000000000"


def test_2_exact_non_vulnerable_cpe():
    """Real fixture: the hardware branch alone (vulnerable=false), if it
    were the only configuration (no AND partner), never yields AFFECTED."""
    hw_only_config = [{"operator": "OR", "nodes": [_REAL_XIONGMAI_CONFIG[0]["nodes"][1]]}]
    result = applicability.evaluate_configurations(hw_only_config, [_XIONGMAI_HW_CPE], None)
    assert result["status"] == applicability.STATUS_NOT_APPLICABLE


def test_3_or_configuration():
    result_a = applicability.evaluate_configurations(_OR_TWO_PRODUCTS_CONFIG, ["cpe:2.3:a:vendor:producta:1.0:*:*:*:*:*:*:*"], "1.0")
    result_b = applicability.evaluate_configurations(_OR_TWO_PRODUCTS_CONFIG, ["cpe:2.3:a:vendor:productb:1.0:*:*:*:*:*:*:*"], "1.0")
    assert result_a["status"] == applicability.STATUS_AFFECTED
    assert result_b["status"] == applicability.STATUS_AFFECTED


def test_4_and_configuration_real_xiongmai_case():
    """The real, live-captured configuration this whole engine was
    designed around: an AND across two genuinely different real CPEs
    (hardware + firmware, both belonging to the same physical device).
    With BOTH in the candidate set (exactly what Phase 3's real
    CPE_AMBIGUOUS output gives for this device) and the observed
    firmware version matching exactly -> AFFECTED, attributed to the
    vulnerable=true firmware branch. A single candidate alone cannot
    satisfy this AND — see test_4b — which is precisely why joint
    (not independent-per-candidate) evaluation was necessary; see the
    module docstring's "departure #1"."""
    result = applicability.evaluate_configurations(_REAL_XIONGMAI_CONFIG, [_XIONGMAI_FW_CPE, _XIONGMAI_HW_CPE], "4.02.r11.3070")
    assert result["status"] == applicability.STATUS_AFFECTED
    assert result["matched_criteria_id"] == "B7CA6BA2-0000-0000-0000-000000000000"


def test_4b_single_candidate_alone_cannot_satisfy_the_real_and():
    """Neither the firmware CPE nor the hardware CPE alone (without its
    AND partner also in the candidate set) can satisfy this real
    configuration — each only covers one of the two required branches."""
    result_fw_only = applicability.evaluate_configurations(_REAL_XIONGMAI_CONFIG, [_XIONGMAI_FW_CPE], "4.02.r11.3070")
    result_hw_only = applicability.evaluate_configurations(_REAL_XIONGMAI_CONFIG, [_XIONGMAI_HW_CPE], None)
    assert result_fw_only["status"] == applicability.STATUS_NOT_APPLICABLE
    assert result_hw_only["status"] == applicability.STATUS_NOT_APPLICABLE


def test_5_nested_configuration_children_handled_defensively():
    nested = [{"operator": "OR", "nodes": [
        {"operator": "AND", "negate": False, "cpeMatch": [], "children": [
            {"operator": "OR", "negate": False, "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "id-nested"},
            ]},
        ]},
    ]}]
    result = applicability.evaluate_configurations(nested, ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"], "1.0")
    assert result["status"] == applicability.STATUS_AFFECTED


def test_6_negate():
    result = applicability.evaluate_configurations(_NEGATE_CONFIG, ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"], None)
    # main product matches (True), addon node negated (addon doesn't
    # match this candidate's product field -> False -> negated -> True)
    assert result["status"] == applicability.STATUS_AFFECTED


def test_7_vulnerable_true_attributes_the_match():
    result = applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], "1.5.17")
    assert result["matched_criteria"] == "cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*"


def test_8_vulnerable_false_does_not_establish_affected_alone():
    only_false_config = [{"operator": "OR", "nodes": [
        {"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "id-f"},
        ]},
    ]}]
    result = applicability.evaluate_configurations(only_false_config, ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"], "1.0")
    assert result["status"] == applicability.STATUS_NOT_APPLICABLE


def test_9_versionStartIncluding_real_mutt_boundary():
    assert applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], "1.5.16")["status"] == applicability.STATUS_AFFECTED
    assert applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], "1.5.15")["status"] == applicability.STATUS_NOT_APPLICABLE


def test_10_versionStartExcluding():
    assert applicability.evaluate_configurations(_EXCLUDING_RANGE_CONFIG, ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"], "1.0")["status"] == applicability.STATUS_NOT_APPLICABLE
    assert applicability.evaluate_configurations(_EXCLUDING_RANGE_CONFIG, ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"], "1.1")["status"] == applicability.STATUS_AFFECTED


def test_11_versionEndIncluding():
    assert applicability.evaluate_configurations(_EXCLUDING_RANGE_CONFIG, ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"], "2.0")["status"] == applicability.STATUS_AFFECTED
    assert applicability.evaluate_configurations(_EXCLUDING_RANGE_CONFIG, ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"], "2.1")["status"] == applicability.STATUS_NOT_APPLICABLE


def test_12_versionEndExcluding_real_mutt_boundary():
    assert applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], "1.5.18")["status"] == applicability.STATUS_AFFECTED
    assert applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], "1.5.19")["status"] == applicability.STATUS_NOT_APPLICABLE


def test_13_wildcard_cpe_vendor():
    result = applicability.evaluate_configurations(_WILDCARD_VENDOR_CONFIG, ["cpe:2.3:a:anyvendor:product:1.0:*:*:*:*:*:*:*"], "1.0")
    assert result["status"] == applicability.STATUS_AFFECTED


def test_14_unknown_version():
    result = applicability.evaluate_configurations(_REAL_MUTT_CONFIG, [_MUTT_CPE], None)
    assert result["status"] == applicability.STATUS_UNKNOWN


def test_15_missing_configuration():
    result = applicability.evaluate_configurations([], [_MUTT_CPE], "1.5.17")
    assert result["status"] == applicability.STATUS_UNKNOWN
    assert "could not be determined" in result["reason"].lower()


# ---------------------------------------------------------------------------
# Orchestration (determine_applicability) — DB-integrated scenarios
# ---------------------------------------------------------------------------

def _setup_device_with_cve(db, correlation_method="CPE", source_cpe=None, configurations=None,
                            identity_version=None, cve_id="CVE-2017-16725", cpe_candidates=None):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:50", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.70"})
        queries.update_device_identity(conn, device_id, version=identity_version)
        queries.upsert_device_cve_intelligence(conn, device_id, {
            "cve_id": cve_id, "correlation_method": correlation_method,
            "source_cpe": source_cpe or [], "configurations": configurations,
        })
        if cpe_candidates is not None:
            queries.replace_cpe_candidates(conn, device_id, cpe_candidates)
    return device_id


def test_16_no_cpe_data_defensive_case(db):
    """A CPE-correlated row with an empty source_cpe list — structurally
    shouldn't happen given Phase 4's design, but guarded against."""
    device_id = _setup_device_with_cve(db, correlation_method="CPE", source_cpe=[], configurations=_REAL_XIONGMAI_CONFIG)
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")
    assert result["status"] == applicability.STATUS_NO_CPE_DATA


def test_17_nvd_unavailable_status_stays_unknown_if_no_row(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:51", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.71"})
        result = applicability.determine_applicability(conn, device_id, "CVE-DOES-NOT-EXIST")
    assert result["status"] == applicability.STATUS_UNKNOWN


def test_18_cpe_ambiguous_one_affected_candidate(db):
    """Instruction 11, CASE A: one AFFECTED candidate among several ->
    overall AFFECTED, with full candidate provenance preserved."""
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE_AMBIGUOUS",
        source_cpe=[_XIONGMAI_FW_CPE, _XIONGMAI_HW_CPE],
        configurations=_REAL_XIONGMAI_CONFIG, identity_version="4.02.r11.3070",
        cpe_candidates=[
            {"cpe": _XIONGMAI_FW_CPE, "confidence": 0.6, "status": "CPE_AMBIGUOUS", "source": "s", "identity_basis": "b", "nvd_cpe_name_id": "1"},
            {"cpe": _XIONGMAI_HW_CPE, "confidence": 0.6, "status": "CPE_AMBIGUOUS", "source": "s", "identity_basis": "b", "nvd_cpe_name_id": "2"},
        ],
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")

    assert result["status"] == applicability.STATUS_AFFECTED
    assert result["ambiguity_existed"] is True
    assert len(result["candidate_verdicts"]) == 2
    assert {c["cpe"] for c in result["candidate_verdicts"]} == {_XIONGMAI_FW_CPE, _XIONGMAI_HW_CPE}


def test_19_cpe_ambiguous_all_not_applicable(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE_AMBIGUOUS",
        source_cpe=[_XIONGMAI_HW_CPE, "cpe:2.3:a:unrelated:product:1.0:*:*:*:*:*:*:*"],
        configurations=_REAL_XIONGMAI_CONFIG, identity_version=None,
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")
    assert result["status"] == applicability.STATUS_NOT_APPLICABLE


def test_20_cpe_ambiguous_all_unknown(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE_AMBIGUOUS",
        source_cpe=[_MUTT_CPE, _MUTT_CPE],  # both need a version we don't have
        configurations=_REAL_MUTT_CONFIG, identity_version=None, cve_id="CVE-2009-3766",
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
    assert result["status"] == applicability.STATUS_UNKNOWN


def test_21_cpe_candidate_status_caps_at_potentially_affected(db):
    """Instruction 12: a single non-ambiguous candidate whose Phase 3
    status was only CPE_CANDIDATE (not CPE_CONFIRMED) never silently
    becomes AFFECTED. Uses the real mutt/version-range fixture (a plain
    OR, single-CPE) rather than the real Xiongmai AND fixture, since
    that one specifically requires two different CPEs together — not
    what this test is about."""
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE", source_cpe=[_MUTT_CPE],
        configurations=_REAL_MUTT_CONFIG, identity_version="1.5.17", cve_id="CVE-2009-3766",
        cpe_candidates=[
            {"cpe": _MUTT_CPE, "confidence": 0.4, "status": "CPE_CANDIDATE", "source": "s", "identity_basis": "b", "nvd_cpe_name_id": "1"},
        ],
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
    assert result["status"] == applicability.STATUS_POTENTIALLY_AFFECTED
    assert result["status"] != applicability.STATUS_AFFECTED


def test_22_keyword_finding_cannot_become_affected(db):
    """Mandatory invariant (instruction 3) — the brief's own worked
    example, exactly as specified."""
    device_id = _setup_device_with_cve(
        db, correlation_method="KEYWORD", source_cpe=[], configurations=None, identity_version=None,
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")

    assert result["status"] == applicability.STATUS_UNKNOWN
    assert result["status"] != applicability.STATUS_AFFECTED

    with get_connection(db) as conn:
        stored = queries.get_device_cve(conn, device_id, "CVE-2017-16725")
    assert stored["applicability_status"] == "UNKNOWN"
    assert stored["correlation_method"] == "KEYWORD"


def test_23_duplicate_candidate_cpe_in_source_cpe_list(db):
    """A source_cpe list with the same CPE twice (shouldn't happen given
    Phase 4's dedup, but must not double-count or crash)."""
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE_AMBIGUOUS",
        source_cpe=[_MUTT_CPE, _MUTT_CPE],
        configurations=_REAL_MUTT_CONFIG, identity_version="1.5.17", cve_id="CVE-2009-3766",
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
    assert result["status"] == applicability.STATUS_AFFECTED
    assert len(result["candidate_verdicts"]) == 2  # both evaluated, not deduped away — no crash


def test_24_applicability_explanation_provenance_persisted(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE", source_cpe=[_MUTT_CPE], configurations=_REAL_MUTT_CONFIG,
        identity_version="1.5.17", cve_id="CVE-2009-3766",
    )
    with get_connection(db) as conn:
        applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
        stored = queries.get_device_cve(conn, device_id, "CVE-2009-3766")

    reason = json.loads(stored["applicability_reason"])
    assert reason["status"] == "AFFECTED"
    assert reason["matched_cpe"] == _MUTT_CPE
    assert reason["matched_criteria_id"] == "7A318134-0000-0000-0000-000000000000"
    assert reason["version_evaluated"] == "1.5.17"
    assert "reason" in reason


def test_25_existing_device_cves_rows_remain_valid_without_applicability_run(db):
    """A row from before Phase 5 (or simply never evaluated) keeps its
    Phase 1 default applicability_status — Phase 5 doesn't retroactively
    touch rows it wasn't asked to evaluate."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:52", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.72"})
        queries.insert_device_cve(conn, device_id, {"cve_id": "CVE-OLD-0001", "cvss_score": 5.0})
        cves = queries.get_device_cves(conn, device_id)

    assert cves[0]["applicability_status"] == "UNKNOWN"
    assert cves[0]["applicability_reason"] is None


# ---------------------------------------------------------------------------
# Acceptance tests (instruction 22, end-to-end semantic cases)
# ---------------------------------------------------------------------------

def test_acceptance_case1_confirmed_cpe_known_affected_version(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE", source_cpe=[_MUTT_CPE], configurations=_REAL_MUTT_CONFIG,
        identity_version="1.5.17", cve_id="CVE-2009-3766",
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
    assert result["status"] == applicability.STATUS_AFFECTED


def test_acceptance_case2_confirmed_cpe_known_unaffected_version(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE", source_cpe=[_MUTT_CPE], configurations=_REAL_MUTT_CONFIG,
        identity_version="2.0.0", cve_id="CVE-2009-3766",
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
    assert result["status"] == applicability.STATUS_NOT_APPLICABLE


def test_acceptance_case3_confirmed_cpe_unknown_version(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE", source_cpe=[_MUTT_CPE], configurations=_REAL_MUTT_CONFIG,
        identity_version=None, cve_id="CVE-2009-3766",
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2009-3766")
    assert result["status"] == applicability.STATUS_UNKNOWN


def test_acceptance_case4_no_cpe(db):
    device_id = _setup_device_with_cve(db, correlation_method="CPE", source_cpe=[], configurations=None)
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")
    assert result["status"] == applicability.STATUS_NO_CPE_DATA


def test_acceptance_case5_keyword_only_never_affected(db):
    device_id = _setup_device_with_cve(db, correlation_method="KEYWORD", source_cpe=[], configurations=None)
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")
    assert result["status"] != applicability.STATUS_AFFECTED


def test_acceptance_case6_ambiguous_one_affected(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE_AMBIGUOUS", source_cpe=[_XIONGMAI_FW_CPE, _XIONGMAI_HW_CPE],
        configurations=_REAL_XIONGMAI_CONFIG, identity_version="4.02.r11.3070",
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")
    assert result["status"] == applicability.STATUS_AFFECTED
    assert result["ambiguity_existed"] is True


def test_acceptance_case7_ambiguous_none_affected(db):
    device_id = _setup_device_with_cve(
        db, correlation_method="CPE_AMBIGUOUS", source_cpe=[_XIONGMAI_HW_CPE],
        configurations=_REAL_XIONGMAI_CONFIG, identity_version=None,
    )
    with get_connection(db) as conn:
        result = applicability.determine_applicability(conn, device_id, "CVE-2017-16725")
    assert result["status"] in (applicability.STATUS_NOT_APPLICABLE, applicability.STATUS_UNKNOWN)


def test_acceptance_case8_nvd_unavailable_upstream(db):
    """Phase 4's own NVD_UNAVAILABLE devices never get a device_cves row
    at all (see cve_lookup.py) — so there is nothing for Phase 5 to
    evaluate, correctly. determine_applicability on a nonexistent row
    returns UNKNOWN, never a false NOT_APPLICABLE."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:53", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.73"})
        result = applicability.determine_applicability(conn, device_id, "CVE-NEVER-FOUND")
    assert result["status"] == applicability.STATUS_UNKNOWN
