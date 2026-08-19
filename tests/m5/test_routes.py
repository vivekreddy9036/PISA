import json
import time

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import beacon_capture, oui_cve
from pisa.m3 import applicability, cpe_mapper, cve_lookup, exploit_score, exploitation, verification
from pisa.m4 import routersploit_gate


def _fake_start_capture(session_id, db_path, iface, timeout):
    """Stand-in for a real monitor-mode capture, keeping routes testable
    without WiFi hardware. Goes through the same score_and_store path a real
    beacon does."""
    with get_connection(db_path) as conn:
        beacon_capture.score_and_store(conn, session_id, {
            "bssid": "AA:BB:CC:00:00:01",
            "ssid": "TestNet",
            "channel": 6,
            "signal_dbm": -50,
            "security": "WPA2",
            "encryption": "WPA2",
            "beacon_interval": 100,
            "pmf_enabled": 0,
            "wps_enabled": 0,
            "hidden": 0,
        })


def _wait_for_scan(client, session_id, attempts=50, delay=0.1):
    status = None
    for _ in range(attempts):
        status = client.get(f"/api/scan/{session_id}/status").get_json()["status"]
        if status in ("done", "error"):
            break
        time.sleep(delay)
    return status


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["db"] == "ok"


def test_index_empty_state(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"No scans yet" in resp.data


def test_scan_and_session_detail_flow(client, monkeypatch):
    monkeypatch.setattr(beacon_capture, "start_capture", _fake_start_capture)
    resp = client.post("/api/scan", json={"duration": 1})
    assert resp.status_code == 200
    session_id = resp.get_json()["session_id"]

    status = _wait_for_scan(client, session_id)
    assert status == "done"

    detail = client.get(f"/sessions/{session_id}")
    assert detail.status_code == 200
    assert b"grade grade-" in detail.data

    index = client.get("/")
    assert f"/sessions/{session_id}".encode() in index.data


def test_check_cves_for_network(client, db, monkeypatch):
    monkeypatch.setattr(beacon_capture, "start_capture", _fake_start_capture)
    monkeypatch.setattr(oui_cve, "lookup_cves", lambda bssid: [
        {"cve_id": "CVE-2021-1234", "cvss_score": 9.8, "description": "Test vuln"},
    ])
    monkeypatch.setattr(exploit_score, "enrich_cves", lambda cves: cves)

    resp = client.post("/api/scan", json={"duration": 1})
    session_id = resp.get_json()["session_id"]
    assert _wait_for_scan(client, session_id) == "done"

    with get_connection(db) as conn:
        networks = queries.get_networks(conn, session_id)
    network_id = networks[0]["id"]

    resp = client.post(f"/api/networks/{network_id}/cves")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["cves"]) > 0


def test_session_detail_404_for_missing_session(client):
    resp = client.get("/sessions/999")
    assert resp.status_code == 404


def _wait_for_discovery(client, network_id, attempts=50, delay=0.1):
    status = None
    for _ in range(attempts):
        status = client.get(f"/api/networks/{network_id}/discovery/status").get_json()["status"]
        if status in ("done", "error"):
            break
        time.sleep(delay)
    return status


def test_join_and_discover_devices(client, db, monkeypatch):
    from pisa.m1 import discovery_runner

    def fake_run_discovery(network_id, session_id, iface, ssid, password, db_path):
        with get_connection(db_path) as conn:
            queries.mark_discovery_running(conn, network_id)
            queries.insert_device(conn, session_id, network_id, {
                "ip_address": "192.168.1.42",
                "mac_address": "DE:AD:BE:EF:00:01",
                "vendor": "TestVendor",
                "open_ports": "[]",
                "os_guess": None,
            })
            queries.mark_discovery_done(conn, network_id)

    monkeypatch.setattr(discovery_runner, "run_discovery", fake_run_discovery)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})

    resp = client.post(f"/api/networks/{network_id}/join", json={"password": "hunter2"})
    assert resp.status_code == 200

    assert _wait_for_discovery(client, network_id) == "done"

    resp = client.get(f"/api/networks/{network_id}/devices")
    assert resp.status_code == 200
    devices = resp.get_json()["devices"]
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.42"


def test_join_network_404_for_missing_network(client):
    resp = client.post("/api/networks/999/join", json={"password": "x"})
    assert resp.status_code == 404


def _wait_for_fingerprinting(client, network_id, attempts=50, delay=0.1):
    status = None
    for _ in range(attempts):
        status = client.get(f"/api/networks/{network_id}/fingerprint/status").get_json()
        if status["done"] == status["total"]:
            break
        time.sleep(delay)
    return status


def test_fingerprint_network_processes_all_devices(client, db, monkeypatch):
    from pisa.m2 import fingerprint_runner

    def fake_run_fingerprint(device_id, db_path):
        with get_connection(db_path) as conn:
            queries.update_device_fingerprint(conn, device_id, "TestType", 0.7)

    monkeypatch.setattr(fingerprint_runner, "run_fingerprint", fake_run_fingerprint)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})
        device_ids = [
            queries.insert_device(conn, session_id, network_id, {
                "ip_address": f"192.168.1.{i}",
                "mac_address": f"AA:BB:CC:00:00:{i:02d}",
                "open_ports": "[]",
            })
            for i in range(3)
        ]

    resp = client.post(f"/api/networks/{network_id}/fingerprint")
    assert resp.status_code == 200

    status = _wait_for_fingerprinting(client, network_id)
    assert status == {"total": 3, "done": 3}

    with get_connection(db) as conn:
        devices = queries.get_devices_for_network(conn, network_id)
    assert all(d["fingerprint_confidence"] == 0.7 for d in devices)
    assert len(device_ids) == 3


def test_fingerprint_network_404_for_missing_network(client):
    resp = client.post("/api/networks/999/fingerprint")
    assert resp.status_code == 404
    resp = client.get("/api/networks/999/fingerprint/status")
    assert resp.status_code == 404


def test_check_device_cves(client, db, monkeypatch):
    """Phase 8.1: this device has no structured identity (identity_vendor/
    identity_product), so cpe_mapper legitimately finds NO_CPE_DATA and
    the pipeline falls through to the keyword path — proving the keyword
    fallback still works end-to-end through the live route, not that CPE
    mapping was bypassed."""
    monkeypatch.setattr(oui_cve, "lookup_device_cves", lambda os_guess: [
        {"cve_id": "CVE-2020-3118", "cvss_score": 8.8, "description": "Cisco NX-OS vuln"},
    ])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "11.12.0.1", "mac_address": "50:0F:80:9A:B2:07",
            "vendor": "Cisco Systems, Inc", "os_guess": "Cisco Nexus switch (NX-OS 6.0(2))",
        })

    resp = client.post(f"/api/devices/{device_id}/cves")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["findings"]) == 1
    assert data["findings"][0]["cve_id"] == "CVE-2020-3118"
    assert data["findings"][0]["correlation_method"] == cve_lookup.CORRELATION_KEYWORD

    with get_connection(db) as conn:
        cves = queries.get_device_cves(conn, device_id)
    assert len(cves) == 1
    # A keyword-only finding must never be silently treated as applicable
    # (applicability.py's own hardcoded invariant — see test 10 below).
    assert cves[0]["applicability_status"] == applicability.STATUS_UNKNOWN


def test_check_device_cves_no_findings_without_os_guess_or_identity(client, db, monkeypatch):
    """Replaces the old 'no_os_fingerprint' shortcut: correlate_device_cves
    now reports this honestly as UNAVAILABLE_DUE_TO_IDENTITY with an empty
    findings list, rather than a special-cased early return."""
    monkeypatch.setattr(oui_cve, "lookup_device_cves", lambda os_guess: None)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.50", "mac_address": "AA:BB:CC:DD:EE:FF",
            "vendor": "Intel Corporate", "os_guess": None,
        })

    resp = client.post(f"/api/devices/{device_id}/cves")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["findings"] == []
    assert data["status"] == cve_lookup.STATUS_UNAVAILABLE_DUE_TO_IDENTITY

    with get_connection(db) as conn:
        cves = queries.get_device_cves(conn, device_id)
    assert cves == []


def test_check_device_cves_404_for_missing_device(client):
    resp = client.post("/api/devices/999/cves")
    assert resp.status_code == 404


def _make_device_with_cve(db, cve_id="CVE-2021-1234"):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})
        queries.insert_device_cve(conn, device_id, {"cve_id": cve_id, "cvss_score": 9.8, "description": "Test vuln"})
    return device_id


def _make_gate_eligible_device(
    db, cve_id="CVE-2018-9995",
    applicability_status=applicability.STATUS_AFFECTED,
    verification_status=verification.RESULT_VERIFIED_VULNERABLE,
):
    """A device/CVE pair seeded to sit exactly at exploitation.check_gate's
    eligibility boundary for a real, registered exploit (CVE-2018-9995 /
    cameras.multi.dvr_creds_disclosure by default) — used by every test
    that needs to prove the live route actually reaches
    exploitation.attempt_exploitation()."""
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {"ip_address": "192.168.1.10"})
        queries.upsert_device_cve_intelligence(conn, device_id, {"cve_id": cve_id, "cvss_score": 9.8})
        queries.set_device_cve_applicability(conn, device_id, cve_id, applicability_status)
        queries.set_device_cve_verification(conn, device_id, cve_id, verification_status)
    return device_id


def _registered_module_path(cve_id="CVE-2018-9995"):
    return f"exploits.{exploitation.find_exploit_definition(cve_id).module_path}"


def _patch_registered_module_findable(monkeypatch, cve_id="CVE-2018-9995"):
    """exploitation.check_gate defensively re-confirms the registered
    module is still present in the installed RouterSploit package via
    routersploit_gate.find_modules_for_cve — stub that lookup so tests
    don't depend on the real installed package's index."""
    module_path = _registered_module_path(cve_id)
    monkeypatch.setattr(
        routersploit_gate, "find_modules_for_cve",
        lambda cid: [{"module_path": module_path, "name": "x", "description": "", "references": [], "devices": []}],
    )


def test_exploit_modules_for_cve_returns_matches(client, db, monkeypatch):
    device_id = _make_device_with_cve(db)
    monkeypatch.setattr(
        routersploit_gate, "find_modules_for_cve",
        lambda cve_id: [{"module_path": "fake.module", "name": "Fake", "description": "", "references": [], "devices": []}],
    )

    resp = client.get(f"/api/devices/{device_id}/cves/CVE-2021-1234/exploit-modules")

    assert resp.status_code == 200
    assert resp.get_json()["modules"][0]["module_path"] == "fake.module"


def test_exploit_modules_for_cve_404_when_cve_not_on_device(client, db):
    device_id = _make_device_with_cve(db)

    resp = client.get(f"/api/devices/{device_id}/cves/CVE-9999-9999/exploit-modules")

    assert resp.status_code == 404


def test_exploit_modules_for_cve_404_for_missing_device(client):
    resp = client.get("/api/devices/999/cves/CVE-2021-1234/exploit-modules")
    assert resp.status_code == 404


def test_run_device_exploit_requires_authorized_by(client, db):
    device_id = _make_device_with_cve(db)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2021-1234", "mode": "check",
    })

    assert resp.status_code == 400


def test_run_device_exploit_requires_valid_mode(client, db):
    device_id = _make_device_with_cve(db)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2021-1234", "mode": "destroy", "authorized_by": "vivek",
    })

    assert resp.status_code == 400


def test_run_device_exploit_404_when_cve_not_on_device(client, db):
    device_id = _make_device_with_cve(db)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-9999-9999", "mode": "check", "authorized_by": "vivek",
    })

    assert resp.status_code == 404


def test_run_device_exploit_persists_result(client, db, monkeypatch):
    """Phase 8.4: proves the live route reaches exploitation.py's real
    gate/registry (not just a mocked RouterSploit call) — the device is
    seeded at exactly AFFECTED/VERIFIED_VULNERABLE for a registered CVE,
    which is the only way this can now succeed."""
    device_id = _make_gate_eligible_device(db)
    _patch_registered_module_findable(monkeypatch)
    monkeypatch.setattr(
        routersploit_gate, "run_exploit",
        lambda ip, module_path, mode, port=None: {
            "success": True, "result": "looks vulnerable", "check_state": "CONFIRMED_VULNERABLE",
        },
    )

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
    })

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == exploitation.STATUS_EXPLOIT_SUCCESSFUL

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert len(results) == 1
    assert results[0]["authorized_by"] == "vivek"
    assert results[0]["success"] == 1
    # The executed module path came from exploitation._REGISTRY, never
    # from the (nonexistent, in this request) client-supplied field.
    assert results[0]["module_path"] == _registered_module_path()


def test_run_device_exploit_authorization_persists_even_if_run_crashes(client, db, monkeypatch):
    """NFR-7: the audit row must be committed before run_exploit() is
    called, so a crash mid-run still leaves a durable authorization
    record rather than losing it along with the failed request. Still
    true through exploitation.py: attempt_exploitation() calls
    record_exploit_authorization() before invoking routersploit_gate.run_exploit()."""
    device_id = _make_gate_eligible_device(db)
    _patch_registered_module_findable(monkeypatch)
    monkeypatch.setattr(
        routersploit_gate, "run_exploit",
        lambda ip, module_path, mode, port=None: (_ for _ in ()).throw(RuntimeError("simulated crash")),
    )

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
    })

    assert resp.status_code == 500

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert len(results) == 1
    assert results[0]["authorized_by"] == "vivek"
    assert results[0]["result"] is None


# ===========================================================================
# Phase 8.7 — route-level integration tests. Existing M3 unit tests (tests/
# m3/test_{cpe_mapper,cve_lookup,applicability,verification,exploitation}.py)
# already prove those engines are individually correct — they prove nothing
# about whether the live HTTP routes actually invoke them. These tests exist
# specifically to close that gap: every one of them goes through `client`
# (a real Flask test client, per tests/conftest.py) against a real temp
# SQLite DB, never by calling an m3 module function directly.
# ===========================================================================

# Real Xiongmai firmware CPE/CVE shape, reused verbatim from
# tests/m3/test_cve_lookup.py's own fixture (CVE-2017-16725) rather than
# inventing a new one — an AND config with a single vulnerable cpeMatch
# whose version is pinned, so applicability is deterministic based on
# whether identity_version matches it.
_ROUTE_TEST_CVE = {
    "id": "CVE-2017-16725",
    "published": "2017-12-20T19:29:00.257",
    "lastModified": "2026-06-17T01:09:43.137",
    "vulnStatus": "Modified",
    "descriptions": [{"lang": "en", "value": "A Stack-based Buffer Overflow..."}],
    "metrics": {"cvssMetricV30": [{
        "source": "nvd@nist.gov", "type": "Primary",
        "cvssData": {
            "version": "3.0", "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 9.8, "baseSeverity": "CRITICAL",
        },
    }]},
    "weaknesses": [], "references": [],
    "configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*"},
        ]},
    ]}],
}


def _patch_cpe_and_cve_lookup(monkeypatch, epss_score=None, kev_record=None):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [{
        "cpe": {"deprecated": False, "cpeName": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*", "cpeNameId": "id1"},
    }])
    monkeypatch.setattr(cve_lookup.nvd_client, "query_cves_by_cpe", lambda cpe, **kw: [_ROUTE_TEST_CVE])
    epss = {"CVE-2017-16725": {"score": epss_score, "percentile": 0.9, "date": "2026-08-13"}} if epss_score else {}
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: epss)
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: kev_record)
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: None)


def _make_device_with_identity(db, identity_version=None):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:40", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.60", "open_ports": json.dumps([{"port": 80}]),
        })
        queries.update_device_identity(conn, device_id, vendor="Xiongmai", product="AHB7008F8-H", version=identity_version)
    return device_id


# TEST 1 — CPE/CVE integration: identity -> CPE -> CVE -> applicability,
# through the live /api/devices/<id>/cves route.
def test_1_device_cve_route_reaches_cpe_and_applicability(client, db, monkeypatch):
    _patch_cpe_and_cve_lookup(monkeypatch, epss_score=0.5, kev_record={"dateAdded": "2018-01-01"})
    device_id = _make_device_with_identity(db, identity_version="4.02.r11.3070")

    resp = client.post(f"/api/devices/{device_id}/cves")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["findings"]) == 1
    assert data["findings"][0]["correlation_method"] in (cve_lookup.CORRELATION_CPE, cve_lookup.CORRELATION_CPE_AMBIGUOUS)

    with get_connection(db) as conn:
        cpe_rows = queries.get_cpe_candidates(conn, device_id)
        cve_rows = queries.get_device_cves(conn, device_id)

    assert len(cpe_rows) >= 1
    assert cpe_rows[0]["cpe"] is not None
    assert len(cve_rows) == 1
    assert cve_rows[0]["correlation_method"] in ("CPE", "CPE_AMBIGUOUS")
    # A firmware-part (not hardware-part) single CPE candidate matching the
    # vulnerable configuration's exact pinned version resolves to AFFECTED
    # or, if Phase 3's own CPE-mapping confidence was only CPE_CANDIDATE
    # (not CPE_CONFIRMED), the deliberately more conservative
    # POTENTIALLY_AFFECTED (applicability.py's single-candidate cap) — never
    # UNKNOWN/NO_CPE_DATA/NOT_APPLICABLE, since real matching evidence exists.
    assert cve_rows[0]["applicability_status"] in (
        applicability.STATUS_AFFECTED, applicability.STATUS_POTENTIALLY_AFFECTED,
    )
    # The route-level regression this phase specifically had to fix (8.2):
    # exploit_score must not be silently dropped by the new path.
    assert cve_rows[0]["exploit_score"] is not None
    assert cve_rows[0]["epss_score"] == 0.5
    assert cve_rows[0]["kev_listed"] == 1


# TEST 2 — missing version: applicability must stay honest, never AFFECTED
# merely because a CVE was found.
def test_2_device_cve_route_missing_version_stays_unknown(client, db, monkeypatch):
    _patch_cpe_and_cve_lookup(monkeypatch)
    device_id = _make_device_with_identity(db, identity_version=None)

    resp = client.post(f"/api/devices/{device_id}/cves")
    assert resp.status_code == 200

    with get_connection(db) as conn:
        cve_rows = queries.get_device_cves(conn, device_id)

    assert len(cve_rows) == 1
    assert cve_rows[0]["applicability_status"] != applicability.STATUS_AFFECTED
    assert cve_rows[0]["applicability_status"] == applicability.STATUS_UNKNOWN


# TEST 3 — verification route: eligible AFFECTED finding -> live
# /verify route -> verification_attempts + verification_status.
def test_3_verify_route_persists_attempt_and_status(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(
        db, cve_id="CVE-2018-9995",
        applicability_status=applicability.STATUS_AFFECTED,
        verification_status=verification.RESULT_NOT_ATTEMPTED,
    )
    with get_connection(db) as conn:
        conn.execute(
            "UPDATE devices SET open_ports = ? WHERE id = ?",
            (json.dumps([{"port": 80}]), device_id),
        )
        conn.commit()

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"list": [{"uid": "admin", "pwd": "admin"}]}

    monkeypatch.setattr(verification.requests, "get", lambda url, **kw: _FakeResponse())

    resp = client.post(f"/api/devices/{device_id}/cves/CVE-2018-9995/verify")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == verification.RESULT_VERIFIED_VULNERABLE

    with get_connection(db) as conn:
        attempts = queries.get_verification_attempts(conn, device_id, "CVE-2018-9995")
        cve_row = queries.get_device_cve(conn, device_id, "CVE-2018-9995")

    assert len(attempts) == 1
    assert attempts[0]["result"] == verification.RESULT_VERIFIED_VULNERABLE
    assert cve_row["verification_status"] == verification.RESULT_VERIFIED_VULNERABLE


# TEST 4 — exploit route gate: proves the live route calls
# exploitation.attempt_exploitation() with exactly (device_id, cve_id,
# mode, authorized_by) — never a client-supplied module path.
def test_4_exploit_route_reaches_exploitation_attempt(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(db)
    calls = []

    def fake_attempt(conn, device_id_, cve_id_, mode_, authorized_by_):
        calls.append((device_id_, cve_id_, mode_, authorized_by_))
        return {"status": exploitation.STATUS_EXPLOIT_SUCCESSFUL, "result_id": 1}

    monkeypatch.setattr(exploitation, "attempt_exploitation", fake_attempt)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
        "module_path": "totally.arbitrary.module",
    })

    assert resp.status_code == 200
    assert calls == [(device_id, "CVE-2018-9995", "check", "vivek")]


# TEST 5 — NOT_APPLICABLE blocks exploitation entirely, no exploit_results row.
def test_5_not_applicable_blocks_exploitation(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(
        db, applicability_status=applicability.STATUS_NOT_APPLICABLE,
        verification_status=verification.RESULT_NOT_ATTEMPTED,
    )
    ran = []
    monkeypatch.setattr(routersploit_gate, "run_exploit", lambda *a, **kw: ran.append(1))

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
    })

    assert resp.status_code == 403
    data = resp.get_json()
    assert data["status"] == exploitation.STATUS_BLOCKED
    assert data["gate_state"] == exploitation.GATE_BLOCKED_APPLICABILITY
    assert ran == []

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert results == []


# TEST 6 — AFFECTED but NOT_VERIFIED blocks exploitation, no exploit_results row.
def test_6_not_verified_blocks_exploitation(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(
        db, applicability_status=applicability.STATUS_AFFECTED,
        verification_status=verification.RESULT_NOT_VERIFIED,
    )
    ran = []
    monkeypatch.setattr(routersploit_gate, "run_exploit", lambda *a, **kw: ran.append(1))

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
    })

    assert resp.status_code == 403
    data = resp.get_json()
    assert data["status"] == exploitation.STATUS_BLOCKED
    assert data["gate_state"] == exploitation.GATE_BLOCKED_VERIFICATION
    assert ran == []

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert results == []


# TEST 7 — even a fully eligible (AFFECTED + VERIFIED_VULNERABLE) finding
# must fail closed if authorized_by is missing.
def test_7_missing_authorization_fails_closed_even_when_eligible(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(db)
    ran = []
    monkeypatch.setattr(routersploit_gate, "run_exploit", lambda *a, **kw: ran.append(1))

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check",
    })

    assert resp.status_code == 400
    assert ran == []

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert results == []


# TEST 8 — an attacker-supplied module_path cannot control what actually
# executes; exploitation._REGISTRY remains authoritative.
def test_8_arbitrary_module_path_cannot_control_execution(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(db)
    _patch_registered_module_findable(monkeypatch)
    captured = {}

    def fake_run_exploit(ip, module_path, mode, port=None):
        captured["module_path"] = module_path
        return {"success": True, "result": "looks vulnerable", "check_state": "CONFIRMED_VULNERABLE"}

    monkeypatch.setattr(routersploit_gate, "run_exploit", fake_run_exploit)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
        "module_path": "exploits.routers.netgear.dgn2200_ping_cgi_rce",
    })

    assert resp.status_code == 200
    assert captured["module_path"] == _registered_module_path()
    assert captured["module_path"] != "exploits.routers.netgear.dgn2200_ping_cgi_rce"


# TEST 9 — a real RouterSploit timeout through the live route must persist
# exploitation_status = TIMEOUT, not a generic EXPLOIT_FAILED.
def test_9_timeout_persists_as_timeout_not_generic_failure(client, db, monkeypatch):
    device_id = _make_gate_eligible_device(db)
    _patch_registered_module_findable(monkeypatch)
    monkeypatch.setattr(
        routersploit_gate, "run_exploit",
        lambda ip, module_path, mode, port=None: {"success": False, "result": "timed out", "timeout": True},
    )

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
    })

    assert resp.status_code == 200
    assert resp.get_json()["status"] == exploitation.STATUS_TIMEOUT

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert len(results) == 1
    assert results[0]["exploitation_status"] == "TIMEOUT"


# TEST 10 — keyword safety invariant, proven at the route level, not just
# inside applicability.py's own unit tests: a keyword-only finding must
# stay UNKNOWN and must fail closed at both the verify and exploit routes.
def test_10_keyword_finding_cannot_reach_verification_or_exploitation(client, db, monkeypatch):
    monkeypatch.setattr(cpe_mapper, "_query_nvd_cpe", lambda kw, max_results=20: [])  # NO_CPE_DATA
    monkeypatch.setattr(cve_lookup.oui_cve, "lookup_device_cves", lambda os_guess: [
        {"cve_id": "CVE-2018-9995", "cvss_score": 9.8, "description": "keyword hit only"},
    ])
    monkeypatch.setattr(cve_lookup.epss_client, "get_epss_records", lambda ids: {})
    monkeypatch.setattr(cve_lookup.exploit_score, "get_kev_record", lambda cve_id: None)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:50", "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.70", "os_guess": "some DVR", "open_ports": json.dumps([{"port": 80}]),
        })

    resp = client.post(f"/api/devices/{device_id}/cves")
    assert resp.status_code == 200
    with get_connection(db) as conn:
        cve_row = queries.get_device_cve(conn, device_id, "CVE-2018-9995")
    assert cve_row["correlation_method"] == cve_lookup.CORRELATION_KEYWORD
    assert cve_row["applicability_status"] == applicability.STATUS_UNKNOWN

    verify_resp = client.post(f"/api/devices/{device_id}/cves/CVE-2018-9995/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.get_json()["status"] == verification.RESULT_NOT_ATTEMPTED

    ran = []
    monkeypatch.setattr(routersploit_gate, "run_exploit", lambda *a, **kw: ran.append(1))
    exploit_resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2018-9995", "mode": "check", "authorized_by": "vivek",
    })
    assert exploit_resp.status_code == 403
    assert exploit_resp.get_json()["gate_state"] == exploitation.GATE_BLOCKED_APPLICABILITY
    assert ran == []

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert results == []
