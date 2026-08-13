import json

from pisa.db import queries
from pisa.db.connection import get_connection


def _network_data(bssid="AA:BB:CC:00:00:01", **overrides):
    data = {
        "bssid": bssid,
        "ssid": "TestNet",
        "channel": 6,
        "signal_dbm": -50,
        "security": "WPA2",
        "encryption": "WPA2",
        "beacon_interval": 100,
        "pmf_enabled": 0,
        "wps_enabled": 0,
        "hidden": 0,
        "wsps_score": 70,
        "wsps_grade": "C",
    }
    data.update(overrides)
    return data


def test_session_lifecycle(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn, target_network="TestNet")
        session = queries.get_session(conn, session_id)
        assert session["status"] == "active"
        assert session["ended_at"] is None

        queries.mark_session_running(conn, session_id)
        assert queries.get_session(conn, session_id)["status"] == "running"

        queries.close_session(conn, session_id)
        session = queries.get_session(conn, session_id)
        assert session["status"] == "done"
        assert session["ended_at"] is not None


def test_fail_session(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        queries.fail_session(conn, session_id)
        session = queries.get_session(conn, session_id)
        assert session["status"] == "error"
        assert session["ended_at"] is not None


def test_get_sessions_returns_all(db):
    with get_connection(db) as conn:
        id1 = queries.create_session(conn)
        id2 = queries.create_session(conn)
        sessions = queries.get_sessions(conn)
    ids = {s["id"] for s in sessions}
    assert {id1, id2} <= ids


def test_insert_network_upsert_updates_not_duplicates(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        queries.insert_network(conn, session_id, _network_data(signal_dbm=-50, wsps_score=70, wsps_grade="C"))
        queries.insert_network(conn, session_id, _network_data(signal_dbm=-40, wsps_score=90, wsps_grade="A"))

        networks = queries.get_networks(conn, session_id)

    assert len(networks) == 1
    assert networks[0]["signal_dbm"] == -40
    assert networks[0]["wsps_score"] == 90
    assert networks[0]["wsps_grade"] == "A"


def test_get_networks_orders_by_score_desc(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        queries.insert_network(conn, session_id, _network_data(bssid="AA:BB:CC:00:00:01", wsps_score=40))
        queries.insert_network(conn, session_id, _network_data(bssid="AA:BB:CC:00:00:02", wsps_score=90))
        queries.insert_network(conn, session_id, _network_data(bssid="AA:BB:CC:00:00:03", wsps_score=65))

        networks = queries.get_networks(conn, session_id)

    scores = [n["wsps_score"] for n in networks]
    assert scores == sorted(scores, reverse=True)


def test_insert_and_get_network_cves(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        queries.insert_network_cve(conn, network_id, {
            "cve_id": "CVE-2021-1234",
            "cvss_score": 9.8,
            "description": "Test vuln",
        })

        cves = queries.get_network_cves(conn, network_id)

    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2021-1234"


def test_insert_network_cve_upsert_updates_not_duplicates(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        queries.insert_network_cve(conn, network_id, {
            "cve_id": "CVE-2021-1234", "cvss_score": 9.8, "epss_score": 0.2, "description": "old",
        })
        queries.insert_network_cve(conn, network_id, {
            "cve_id": "CVE-2021-1234", "cvss_score": 9.8, "epss_score": 0.9, "kev_listed": 1,
            "exploit_score": 88.0, "description": "refreshed",
        })

        cves = queries.get_network_cves(conn, network_id)

    assert len(cves) == 1
    assert cves[0]["epss_score"] == 0.9
    assert cves[0]["kev_listed"] == 1
    assert cves[0]["description"] == "refreshed"


def test_insert_device_cve_upsert_updates_not_duplicates(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})
        queries.insert_device_cve(conn, device_id, {"cve_id": "CVE-2020-3118", "cvss_score": 8.8, "epss_score": 0.1})
        queries.insert_device_cve(conn, device_id, {"cve_id": "CVE-2020-3118", "cvss_score": 8.8, "epss_score": 0.7})

        cves = queries.get_device_cves(conn, device_id)

    assert len(cves) == 1
    assert cves[0]["epss_score"] == 0.7


def test_insert_alert(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        alert_id = queries.insert_alert(conn, session_id, "error", "scan", "Scan failed: boom")
        assert alert_id is not None


def test_get_network_by_id(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())

        network = queries.get_network_by_id(conn, network_id)
        assert network["id"] == network_id

        assert queries.get_network_by_id(conn, 999) is None


def test_discovery_lifecycle(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())

        queries.mark_discovery_running(conn, network_id)
        network = queries.get_network_by_id(conn, network_id)
        assert network["discovery_status"] == "running"
        assert network["discovery_started_at"] is not None

        queries.mark_discovery_done(conn, network_id)
        network = queries.get_network_by_id(conn, network_id)
        assert network["discovery_status"] == "done"
        assert network["discovery_completed_at"] is not None


def test_mark_discovery_error(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())

        queries.mark_discovery_error(conn, network_id, "join failed")
        network = queries.get_network_by_id(conn, network_id)

    assert network["discovery_status"] == "error"
    assert network["discovery_error"] == "join failed"


def test_insert_and_get_devices_for_network(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "vendor": "TestVendor",
        })

        devices = queries.get_devices_for_network(conn, network_id)

    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.10"


def test_insert_device_stores_mdns_name_and_device_type(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.10",
            "mdns_name": "sumana's MacBook Air",
            "device_type": "Apple device (AirPlay)",
        })

        devices = queries.get_devices_for_network(conn, network_id)

    assert devices[0]["mdns_name"] == "sumana's MacBook Air"
    assert devices[0]["device_type"] == "Apple device (AirPlay)"


def test_get_device_by_id(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.10",
        })

        device = queries.get_device_by_id(conn, device_id)
        assert device["id"] == device_id
        assert device["ip_address"] == "192.168.1.10"

        assert queries.get_device_by_id(conn, 999) is None


def test_insert_and_get_device_cves(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.10",
        })
        queries.insert_device_cve(conn, device_id, {
            "cve_id": "CVE-2020-3118",
            "cvss_score": 8.8,
            "description": "Cisco NX-OS vuln",
        })

        cves = queries.get_device_cves(conn, device_id)

    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2020-3118"


# ---------------------------------------------------------------------------
# Phase 1: assessments, structured device identity, vulnerability/exploit state
# ---------------------------------------------------------------------------

def test_create_and_get_assessment(db):
    with get_connection(db) as conn:
        assessment_id = queries.create_assessment(conn, notes="lab run 1")
        assessment = queries.get_assessment(conn, assessment_id)

    assert assessment["id"] == assessment_id
    assert assessment["status"] == "active"
    assert assessment["notes"] == "lab run 1"
    assert assessment["created_at"] is not None
    assert assessment["started_at"] is None
    assert assessment["completed_at"] is None


def test_session_without_assessment_id_still_works(db):
    """Existing callers that never pass assessment_id must keep working
    exactly as before — this is the backward-compatibility requirement,
    not just a nice-to-have."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn, target_network="TestNet")
        session = queries.get_session(conn, session_id)

    assert session["assessment_id"] is None


def test_session_can_link_to_assessment(db):
    with get_connection(db) as conn:
        assessment_id = queries.create_assessment(conn)
        session_id = queries.create_session(conn, assessment_id=assessment_id)
        session = queries.get_session(conn, session_id)

    assert session["assessment_id"] == assessment_id


def test_update_device_identity_persists_structured_fields(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        queries.update_device_identity(
            conn, device_id,
            vendor="Hangzhou Xiongmai", product="uc-httpd", model="XM-DVR4104", version="1.0.0",
        )
        device = queries.get_device_by_id(conn, device_id)

    assert device["identity_vendor"] == "Hangzhou Xiongmai"
    assert device["identity_product"] == "uc-httpd"
    assert device["identity_model"] == "XM-DVR4104"
    assert device["identity_version"] == "1.0.0"
    assert device["identity_firmware"] is None  # not supplied — stays NULL, not ""


def test_existing_device_fields_unaffected_by_identity_columns(db):
    """A device inserted the old way (no structured identity call at all)
    must remain fully valid — device_type/fingerprint_confidence keep
    meaning what they did before Phase 1."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.10", "device_type": "IP Camera",
        })
        device = queries.get_device_by_id(conn, device_id)

    assert device["device_type"] == "IP Camera"
    assert device["identity_vendor"] is None
    assert device["identity_product"] is None


def test_network_cve_applicability_and_verification_status_default(db):
    """Phase 1 has no applicability/verification engine yet — a freshly
    inserted CVE row must land on the explicit 'nothing determined this
    yet' states, not silently claim something has been checked."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        queries.insert_network_cve(conn, network_id, {"cve_id": "CVE-2021-1234", "cvss_score": 9.8})

        cves = queries.get_network_cves(conn, network_id)

    assert cves[0]["applicability_status"] == "UNKNOWN"
    assert cves[0]["verification_status"] == "NOT_ATTEMPTED"


def test_device_cve_applicability_and_verification_status_default(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})
        queries.insert_device_cve(conn, device_id, {"cve_id": "CVE-2020-3118", "cvss_score": 8.8})

        cves = queries.get_device_cves(conn, device_id)

    assert cves[0]["applicability_status"] == "UNKNOWN"
    assert cves[0]["verification_status"] == "NOT_ATTEMPTED"


def test_repeated_cve_check_does_not_reset_status_columns(db):
    """The keyword-search re-check upsert path (ON CONFLICT DO UPDATE)
    must not touch applicability_status/verification_status — those are
    owned by a future engine (Phase 5/6), not by a CVSS/EPSS refresh."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        queries.insert_network_cve(conn, network_id, {"cve_id": "CVE-2021-1234", "cvss_score": 9.8})
        conn.execute(
            "UPDATE network_cves SET applicability_status = 'AFFECTED', verification_status = 'VERIFIED_VULNERABLE' "
            "WHERE network_id = ? AND cve_id = ?",
            (network_id, "CVE-2021-1234"),
        )
        conn.commit()

        # simulate a re-check (same upsert path insert_network_cve always takes)
        queries.insert_network_cve(conn, network_id, {"cve_id": "CVE-2021-1234", "cvss_score": 9.9, "epss_score": 0.5})

        cves = queries.get_network_cves(conn, network_id)

    assert cves[0]["applicability_status"] == "AFFECTED"
    assert cves[0]["verification_status"] == "VERIFIED_VULNERABLE"
    assert cves[0]["cvss_score"] == 9.9  # the actual refresh still happened


def test_record_exploit_authorization_defaults_exploitation_status(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        result_id = queries.record_exploit_authorization(
            conn, device_id, "CVE-2019-16920", "exploits.routers.dlink.dir_655_866_652_rce", "vivek",
        )
        results = queries.get_exploit_results(conn, device_id)

    assert results[0]["id"] == result_id
    assert results[0]["exploitation_status"] == "NOT_ATTEMPTED"
    assert results[0]["success"] == 0  # existing field stays compatible


def test_record_exploit_outcome_sets_exploitation_status_and_keeps_success(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})
        result_id = queries.record_exploit_authorization(
            conn, device_id, "CVE-2018-9995", "exploits.cameras.multi.dvr_creds_disclosure", "vivek",
        )

        queries.record_exploit_outcome(conn, result_id, "Target seems to be vulnerable", True)
        results = queries.get_exploit_results(conn, device_id)

    assert results[0]["success"] == 1
    assert results[0]["exploitation_status"] == "EXPLOIT_SUCCESSFUL"


def test_replace_cpe_candidates_persists_and_replaces(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        queries.replace_cpe_candidates(conn, device_id, [{
            "cpe": "cpe:2.3:h:tp-link:archer_ax21:1.0:*:*:*:*:*:*:*",
            "confidence": 0.9, "status": "CPE_CONFIRMED", "source": "nvd_cpe_dictionary",
            "identity_basis": "vendor match; product match; version match",
            "nvd_cpe_name_id": "abc-123",
        }])
        candidates = queries.get_cpe_candidates(conn, device_id)
        assert len(candidates) == 1
        assert candidates[0]["cpe"] == "cpe:2.3:h:tp-link:archer_ax21:1.0:*:*:*:*:*:*:*"
        assert candidates[0]["status"] == "CPE_CONFIRMED"
        assert candidates[0]["fetched_at"] is not None

        # a fresh mapping run replaces the whole set, not upserts individual rows
        queries.replace_cpe_candidates(conn, device_id, [{
            "cpe": None, "confidence": None, "status": "NO_CPE_DATA",
            "source": "nvd_cpe_dictionary", "identity_basis": "no match", "nvd_cpe_name_id": None,
        }])
        candidates = queries.get_cpe_candidates(conn, device_id)

    assert len(candidates) == 1
    assert candidates[0]["cpe"] is None
    assert candidates[0]["status"] == "NO_CPE_DATA"


def test_get_cpe_candidates_orders_confidence_desc_nulls_last(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        queries.replace_cpe_candidates(conn, device_id, [
            {"cpe": "cpe:a", "confidence": 0.4, "status": "CPE_AMBIGUOUS", "source": "s", "identity_basis": "b", "nvd_cpe_name_id": "1"},
            {"cpe": "cpe:b", "confidence": 0.9, "status": "CPE_AMBIGUOUS", "source": "s", "identity_basis": "b", "nvd_cpe_name_id": "2"},
            {"cpe": None, "confidence": None, "status": "NO_CPE_DATA", "source": "s", "identity_basis": "b", "nvd_cpe_name_id": None},
        ])
        candidates = queries.get_cpe_candidates(conn, device_id)

    assert [c["cpe"] for c in candidates] == ["cpe:b", "cpe:a", None]


def test_upsert_device_cve_intelligence_persists_all_fields(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        queries.upsert_device_cve_intelligence(conn, device_id, {
            "cve_id": "CVE-2017-16725",
            "source_cpe": ["cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*"],
            "correlation_method": "CPE",
            "nvd_status": "Modified", "nvd_published": "2017-12-20T19:29:00.257", "nvd_last_modified": "2026-06-17T01:09:43.137",
            "description": "A Stack-based Buffer Overflow...",
            "cvss_score": 9.8, "cvss_version": "3.0", "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_severity": "CRITICAL",
            "epss_score": 0.87, "epss_percentile": 0.95, "epss_date": "2026-08-13",
            "kev_listed": True, "kev_date_added": "2018-01-01", "kev_due_date": "2018-01-15", "kev_known_ransomware_use": "Unknown",
            "weaknesses": ["CWE-119"],
            "cve_references": [{"url": "http://example.com", "source": "nvd@nist.gov", "tags": []}],
            "configurations": [{"operator": "AND", "nodes": []}],
        })

        cves = queries.get_device_cves(conn, device_id)

    assert len(cves) == 1
    row = cves[0]
    assert row["correlation_method"] == "CPE"
    assert json.loads(row["source_cpe"]) == ["cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*"]
    assert row["cvss_version"] == "3.0"
    assert row["cvss_severity"] == "CRITICAL"
    assert row["epss_percentile"] == 0.95
    assert row["kev_date_added"] == "2018-01-01"
    assert json.loads(row["weaknesses"]) == ["CWE-119"]
    assert json.loads(row["configurations"]) == [{"operator": "AND", "nodes": []}]
    assert row["kev_listed"] == 1


def test_upsert_device_cve_intelligence_does_not_touch_applicability_or_verification_status(db):
    """Phase 4 discovers, Phase 5/6 decide — enforced at the DB layer,
    not just by convention."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        queries.upsert_device_cve_intelligence(conn, device_id, {"cve_id": "CVE-2017-16725"})
        cves = queries.get_device_cves(conn, device_id)
        assert cves[0]["applicability_status"] == "UNKNOWN"
        assert cves[0]["verification_status"] == "NOT_ATTEMPTED"

        # simulate Phase 5/6 having set these, then re-run the Phase 4 upsert
        conn.execute(
            "UPDATE device_cves SET applicability_status = 'AFFECTED', verification_status = 'VERIFIED_VULNERABLE' "
            "WHERE device_id = ? AND cve_id = ?",
            (device_id, "CVE-2017-16725"),
        )
        conn.commit()
        queries.upsert_device_cve_intelligence(conn, device_id, {"cve_id": "CVE-2017-16725", "cvss_score": 9.9})
        cves = queries.get_device_cves(conn, device_id)

    assert cves[0]["applicability_status"] == "AFFECTED"
    assert cves[0]["verification_status"] == "VERIFIED_VULNERABLE"
    assert cves[0]["cvss_score"] == 9.9  # the actual refresh still happened


def test_upsert_device_cve_intelligence_enriches_existing_keyword_row(db):
    """A row insert_device_cve (the old keyword-only flow) already
    created must be enriched, not duplicated, when the new CPE-based
    pipeline later finds the same CVE."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})

        queries.insert_device_cve(conn, device_id, {"cve_id": "CVE-2017-16725", "cvss_score": 9.8, "description": "old keyword desc"})
        queries.upsert_device_cve_intelligence(conn, device_id, {
            "cve_id": "CVE-2017-16725", "cvss_score": 9.8, "correlation_method": "CPE",
            "description": "authoritative CPE-sourced description",
        })
        cves = queries.get_device_cves(conn, device_id)

    assert len(cves) == 1
    assert cves[0]["correlation_method"] == "CPE"
    assert cves[0]["description"] == "authoritative CPE-sourced description"


def test_record_exploit_outcome_failure_sets_exploit_failed_status(db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, _network_data())
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})
        result_id = queries.record_exploit_authorization(
            conn, device_id, "CVE-2018-9995", "exploits.cameras.multi.dvr_creds_disclosure", "vivek",
        )

        queries.record_exploit_outcome(conn, result_id, "Target does not appear vulnerable", False)
        results = queries.get_exploit_results(conn, device_id)

    assert results[0]["success"] == 0
    assert results[0]["exploitation_status"] == "EXPLOIT_FAILED"
