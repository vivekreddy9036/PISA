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
