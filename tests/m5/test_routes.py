import time

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import beacon_capture, oui_cve


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


def test_check_device_cves(client, db, monkeypatch):
    monkeypatch.setattr(oui_cve, "lookup_device_cves", lambda os_guess: [
        {"cve_id": "CVE-2020-3118", "cvss_score": 8.8, "description": "Cisco NX-OS vuln"},
    ])

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
