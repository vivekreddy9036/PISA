from unittest.mock import MagicMock, patch

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m3 import verification


def _setup_device_with_cve(db, applicability_status, cve_id="CVE-2018-9995", open_ports=None):
    import json as _json
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:60", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.90",
            "open_ports": _json.dumps(open_ports if open_ports is not None else [{"port": 80, "service": "http"}]),
        })
        queries.upsert_device_cve_intelligence(conn, device_id, {"cve_id": cve_id, "correlation_method": "CPE"})
        queries.set_device_cve_applicability(conn, device_id, cve_id, applicability_status)
    return device_id


def _mock_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json = MagicMock(return_value=json_data)
    else:
        resp.json = MagicMock(side_effect=ValueError("not json"))
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# Eligibility gate (matrix items 1-5)
# ---------------------------------------------------------------------------

def test_1_affected_is_eligible(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    with get_connection(db) as conn:
        avail = verification.verification_availability(conn, device_id, "CVE-2018-9995")
    assert avail["available"] is True
    assert "HTTP-CREDS-DISCLOSURE-001" in avail["test_ids"]


def test_2_potentially_affected_conditional_eligibility(db):
    """HTTP-CREDS-DISCLOSURE-001 explicitly supports POTENTIALLY_AFFECTED
    (a generic OEM-family condition, not version-sensitive) — eligible."""
    device_id = _setup_device_with_cve(db, "POTENTIALLY_AFFECTED")
    with get_connection(db) as conn:
        avail = verification.verification_availability(conn, device_id, "CVE-2018-9995")
    assert avail["available"] is True


def test_3_not_applicable_is_not_attempted(db):
    device_id = _setup_device_with_cve(db, "NOT_APPLICABLE")
    with get_connection(db) as conn:
        result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_NOT_ATTEMPTED


def test_4_unknown_is_not_attempted(db):
    device_id = _setup_device_with_cve(db, "UNKNOWN")
    with get_connection(db) as conn:
        result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_NOT_ATTEMPTED


def test_5_no_cpe_data_is_not_attempted(db):
    device_id = _setup_device_with_cve(db, "NO_CPE_DATA")
    with get_connection(db) as conn:
        result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_NOT_ATTEMPTED


# ---------------------------------------------------------------------------
# Test discovery (6-7)
# ---------------------------------------------------------------------------

def test_6_supported_verification_test_discovered():
    tests = verification.find_tests_for_cve("CVE-2018-9995")
    assert len(tests) == 1
    assert tests[0].test_id == "HTTP-CREDS-DISCLOSURE-001"


def test_7_unsupported_verification_condition(db):
    """CVE-2017-16725 (this project's own real stack-overflow testbed
    CVE) has no verification test — it requires exploitation to confirm,
    per instruction 18, and is deliberately excluded."""
    assert verification.find_tests_for_cve("CVE-2017-16725") == []
    device_id = _setup_device_with_cve(db, "AFFECTED", cve_id="CVE-2017-16725")
    with get_connection(db) as conn:
        result = verification.run_verification(conn, device_id, "CVE-2017-16725")
    assert result["status"] == verification.RESULT_NOT_ATTEMPTED


# ---------------------------------------------------------------------------
# Result interpretation (8-10)
# ---------------------------------------------------------------------------

def test_8_positive_vulnerable_response(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data={"list": [{"uid": "admin", "pwd": "12345", "role": "admin"}]})
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_VERIFIED_VULNERABLE


def test_9_expected_secure_response(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(401)
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_NOT_VERIFIED


def test_10_inconclusive_response(db):
    """Valid HTTP 200 but not valid JSON -> MALFORMED_RESPONSE -> public INCONCLUSIVE."""
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data=None, text="<html>not json</html>")
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_INCONCLUSIVE
    assert result["execution_state"] == verification.STATE_MALFORMED_RESPONSE


# ---------------------------------------------------------------------------
# Timeout / network error / malformed target (11-13)
# ---------------------------------------------------------------------------

def test_11_timeout_is_inconclusive_not_vulnerable_not_not_applicable(db):
    import requests as real_requests
    device_id = _setup_device_with_cve(db, "AFFECTED")
    with patch("pisa.m3.verification.requests.get", side_effect=real_requests.exceptions.Timeout("timed out")):
        with get_connection(db) as conn:
            result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_INCONCLUSIVE
    assert result["execution_state"] == verification.STATE_TIMEOUT
    assert result["status"] != verification.RESULT_VERIFIED_VULNERABLE
    assert result["status"] != "NOT_APPLICABLE"


def test_12_network_error_is_inconclusive(db):
    import requests as real_requests
    device_id = _setup_device_with_cve(db, "AFFECTED")
    with patch("pisa.m3.verification.requests.get", side_effect=real_requests.exceptions.ConnectionError("refused")):
        with get_connection(db) as conn:
            result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_INCONCLUSIVE
    assert result["execution_state"] == verification.STATE_TARGET_UNREACHABLE


def test_13_malformed_target_response(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data={"unexpected": "shape"})
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_NOT_VERIFIED  # valid JSON, just wrong shape -> not "vulnerable"


# ---------------------------------------------------------------------------
# Scope / evidence / provenance (14-17)
# ---------------------------------------------------------------------------

def test_14_assessment_scope_violation_no_device_no_run(db):
    with get_connection(db) as conn:
        result = verification.run_verification(conn, 999999, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_NOT_ATTEMPTED


def test_15_evidence_persistence(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data={"list": [{"uid": "admin", "pwd": "hunter2", "role": "admin"}]})
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            verification.run_verification(conn, device_id, "CVE-2018-9995")
            attempts = queries.get_verification_attempts(conn, device_id, "CVE-2018-9995")

    assert len(attempts) == 1
    import json as _json
    evidence = _json.loads(attempts[0]["evidence"])
    assert evidence["credentials_disclosed"] is True
    assert evidence["passwords"] == "***REDACTED***"  # instruction 23: never surface passwords
    assert evidence["usernames"] == ["admin"]  # non-sensitive fields preserved


def test_16_verification_provenance(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data={"list": [{"uid": "admin", "pwd": "x", "role": "admin"}]})
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            verification.run_verification(conn, device_id, "CVE-2018-9995")
            attempts = queries.get_verification_attempts(conn, device_id, "CVE-2018-9995")

    attempt = attempts[0]
    assert attempt["cve_id"] == "CVE-2018-9995"
    assert attempt["test_id"] == "HTTP-CREDS-DISCLOSURE-001"
    assert attempt["result"] == "VERIFIED_VULNERABLE"
    assert "disclosed" in attempt["reason"]
    assert attempt["started_at"] is not None
    assert attempt["completed_at"] is not None
    assert attempt["duration_ms"] is not None


def test_17_multiple_verification_attempts_preserved(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp_secure = _mock_response(401)
    resp_vulnerable = _mock_response(200, json_data={"list": [{"uid": "a", "pwd": "b", "role": "c"}]})

    with patch("pisa.m3.verification.requests.get", return_value=resp_secure):
        with get_connection(db) as conn:
            verification.run_verification(conn, device_id, "CVE-2018-9995")
    with patch("pisa.m3.verification.requests.get", return_value=resp_vulnerable):
        with get_connection(db) as conn:
            verification.run_verification(conn, device_id, "CVE-2018-9995")

    with get_connection(db) as conn:
        attempts = queries.get_verification_attempts(conn, device_id, "CVE-2018-9995")
        current = queries.get_device_cve(conn, device_id, "CVE-2018-9995")

    assert len(attempts) == 2  # both attempts preserved, not overwritten
    assert attempts[0]["result"] == "VERIFIED_VULNERABLE"  # most recent first (ORDER BY id DESC)
    assert attempts[1]["result"] == "NOT_VERIFIED"
    assert current["verification_status"] == "VERIFIED_VULNERABLE"  # reflects the latest attempt


# ---------------------------------------------------------------------------
# Compatibility / non-interference (18-20)
# ---------------------------------------------------------------------------

def test_18_existing_verification_status_compatibility(db):
    """A device_cve row created before Phase 6 ever ran (Phase 1's
    default) is a valid, unmodified starting point."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:61", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.91"})
        queries.insert_device_cve(conn, device_id, {"cve_id": "CVE-OLD-0002", "cvss_score": 5.0})
        row = queries.get_device_cve(conn, device_id, "CVE-OLD-0002")
    assert row["verification_status"] == "NOT_ATTEMPTED"


def test_19_applicability_status_unchanged_after_verification(db):
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data={"list": [{"uid": "a", "pwd": "b", "role": "c"}]})
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        with get_connection(db) as conn:
            verification.run_verification(conn, device_id, "CVE-2018-9995")
            row = queries.get_device_cve(conn, device_id, "CVE-2018-9995")
    assert row["applicability_status"] == "AFFECTED"  # completely untouched by Phase 6


def test_20_successful_verification_does_not_trigger_exploitation(db):
    """A VERIFIED_VULNERABLE result must never call RouterSploit or
    change exploitation_status — verified by patching the RouterSploit
    adapter and asserting it's never touched, plus checking the column
    directly."""
    device_id = _setup_device_with_cve(db, "AFFECTED")
    resp = _mock_response(200, json_data={"list": [{"uid": "a", "pwd": "b", "role": "c"}]})

    with patch("pisa.m4.routersploit_gate.run_exploit") as mock_exploit:
        with patch("pisa.m3.verification.requests.get", return_value=resp):
            with get_connection(db) as conn:
                result = verification.run_verification(conn, device_id, "CVE-2018-9995")
                # exploitation_status lives on exploit_results (a separate,
                # append-only audit log — pisa/m4), never on device_cves;
                # the absence of any exploit_results row at all is the
                # actual proof no exploitation was ever triggered.
                exploit_rows = queries.get_exploit_results(conn, device_id)

    assert result["status"] == verification.RESULT_VERIFIED_VULNERABLE
    mock_exploit.assert_not_called()
    assert exploit_rows == []


# ---------------------------------------------------------------------------
# Path traversal test (second implemented test, its own hypothesis)
# ---------------------------------------------------------------------------

def test_path_traversal_verified_vulnerable():
    resp = _mock_response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        outcome = verification._check_http_path_traversal("192.168.1.1", 80, 5.0)
    assert outcome.vulnerable is True
    assert outcome.execution_state == verification.STATE_OK


def test_path_traversal_not_verified_on_blocked_request():
    resp = _mock_response(403, text="Forbidden")
    with patch("pisa.m3.verification.requests.get", return_value=resp):
        outcome = verification._check_http_path_traversal("192.168.1.1", 80, 5.0)
    assert outcome.vulnerable is False


def test_no_open_port_for_protocol_is_test_unavailable(db):
    device_id = _setup_device_with_cve(db, "AFFECTED", open_ports=[{"port": 22, "service": "ssh"}])
    with get_connection(db) as conn:
        result = verification.run_verification(conn, device_id, "CVE-2018-9995")
    assert result["status"] == verification.RESULT_INCONCLUSIVE
    assert result["execution_state"] == verification.STATE_TEST_UNAVAILABLE
