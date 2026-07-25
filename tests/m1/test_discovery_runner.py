from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m1 import arp_sweep, discovery_runner, nmap_scan, wifi_join


def test_run_discovery_persists_devices_on_success(db, monkeypatch):
    monkeypatch.setattr(
        wifi_join, "join_network",
        lambda iface, ssid, password, **kw: {"connected": True, "ip": "192.168.1.5", "gateway": "192.168.1.1", "error": None},
    )
    monkeypatch.setattr(
        arp_sweep, "scan_subnet",
        lambda iface, **kw: [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}],
    )
    monkeypatch.setattr(nmap_scan, "scan_host", lambda ip, **kw: {"open_ports": [{"port": 80, "service": "http"}], "os_guess": "Linux"})

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})

    discovery_runner.run_discovery(network_id, session_id, "wlan0", "TestNet", "s3cret", db_path=db)

    with get_connection(db) as conn:
        network = queries.get_network_by_id(conn, network_id)
        devices = queries.get_devices_for_network(conn, network_id)

    assert network["discovery_status"] == "done"
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.10"
    assert devices[0]["vendor"]  # oui_cve.bssid_to_vendor ran, unknown or not


def test_run_discovery_marks_error_when_join_fails(db, monkeypatch):
    monkeypatch.setattr(
        wifi_join, "join_network",
        lambda iface, ssid, password, **kw: {"connected": False, "ip": None, "gateway": None, "error": "bad password"},
    )

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})

    discovery_runner.run_discovery(network_id, session_id, "wlan0", "TestNet", "wrong", db_path=db)

    with get_connection(db) as conn:
        network = queries.get_network_by_id(conn, network_id)
        alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE session_id = ?", (session_id,))]

    assert network["discovery_status"] == "error"
    assert network["discovery_error"] == "bad password"
    assert any(a["category"] == "discovery" for a in alerts)
