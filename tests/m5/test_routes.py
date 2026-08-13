import time

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import beacon_capture, oui_cve
from pisa.m3 import exploit_score
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
    monkeypatch.setattr(oui_cve, "lookup_device_cves", lambda os_guess: [
        {"cve_id": "CVE-2020-3118", "cvss_score": 8.8, "description": "Cisco NX-OS vuln"},
    ])
    monkeypatch.setattr(exploit_score, "enrich_cves", lambda cves: cves)

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
    assert len(data["cves"]) == 1
    assert data["cves"][0]["cve_id"] == "CVE-2020-3118"

    with get_connection(db) as conn:
        cves = queries.get_device_cves(conn, device_id)
    assert len(cves) == 1


def test_check_device_cves_not_attempted_without_os_guess(client, db, monkeypatch):
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
    assert data["cves"] is None
    assert data["reason"] == "no_os_fingerprint"

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
        "cve_id": "CVE-2021-1234", "module_path": "fake.module", "mode": "check",
    })

    assert resp.status_code == 400


def test_run_device_exploit_requires_valid_mode(client, db):
    device_id = _make_device_with_cve(db)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2021-1234", "module_path": "fake.module", "mode": "destroy",
        "authorized_by": "vivek",
    })

    assert resp.status_code == 400


def test_run_device_exploit_404_when_cve_not_on_device(client, db):
    device_id = _make_device_with_cve(db)

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-9999-9999", "module_path": "fake.module", "mode": "check",
        "authorized_by": "vivek",
    })

    assert resp.status_code == 404


def test_run_device_exploit_persists_result(client, db, monkeypatch):
    device_id = _make_device_with_cve(db)
    monkeypatch.setattr(
        routersploit_gate, "run_exploit",
        lambda ip, module_path, mode, port=None: {"success": True, "result": "looks vulnerable"},
    )

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2021-1234", "module_path": "fake.module", "mode": "check",
        "authorized_by": "vivek",
    })

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["result"] == "looks vulnerable"

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert len(results) == 1
    assert results[0]["authorized_by"] == "vivek"
    assert results[0]["success"] == 1


def test_run_device_exploit_authorization_persists_even_if_run_crashes(client, db, monkeypatch):
    """NFR-7: the audit row must be committed before run_exploit() is
    called, so a crash mid-run still leaves a durable authorization
    record rather than losing it along with the failed request."""
    device_id = _make_device_with_cve(db)
    monkeypatch.setattr(
        routersploit_gate, "run_exploit",
        lambda ip, module_path, mode, port=None: (_ for _ in ()).throw(RuntimeError("simulated crash")),
    )

    resp = client.post(f"/api/devices/{device_id}/exploit", json={
        "cve_id": "CVE-2021-1234", "module_path": "fake.module", "mode": "check",
        "authorized_by": "vivek",
    })

    assert resp.status_code == 500

    with get_connection(db) as conn:
        results = queries.get_exploit_results(conn, device_id)
    assert len(results) == 1
    assert results[0]["authorized_by"] == "vivek"
    assert results[0]["result"] is None
