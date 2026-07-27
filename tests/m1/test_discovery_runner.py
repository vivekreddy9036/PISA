from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m1 import arp_sweep, discovery_runner, mdns_discover, nmap_scan, wifi_join


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
    monkeypatch.setattr(
        mdns_discover, "identify_hosts",
        lambda target_ips, **kw: {"192.168.1.10": {"name": "sumana's MacBook Air", "device_type": "Apple device (AirPlay)"}},
    )

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
    assert devices[0]["mdns_name"] == "sumana's MacBook Air"
    assert devices[0]["device_type"] == "Apple device (AirPlay)"


def test_run_discovery_includes_the_scanning_host_itself(db, monkeypatch):
    """arp-scan (like any ARP sweep) never sees the scanning host's own
    address — there's no reason to ARP-request yourself — so it has to be
    added explicitly for the inventory to be complete."""
    monkeypatch.setattr(
        wifi_join, "join_network",
        lambda iface, ssid, password, **kw: {"connected": True, "ip": "192.168.1.99", "gateway": "192.168.1.1", "error": None},
    )
    monkeypatch.setattr(
        arp_sweep, "scan_subnet",
        lambda iface, **kw: [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}],
    )
    monkeypatch.setattr(discovery_runner, "_local_mac", lambda iface: "11:22:33:44:55:66")
    monkeypatch.setattr(nmap_scan, "scan_host", lambda ip, **kw: {"open_ports": [], "os_guess": None})
    monkeypatch.setattr(mdns_discover, "identify_hosts", lambda target_ips, **kw: {})

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:02", "ssid": "TestNet"})

    discovery_runner.run_discovery(network_id, session_id, "wlan0", "TestNet", "s3cret", db_path=db)

    with get_connection(db) as conn:
        devices = queries.get_devices_for_network(conn, network_id)

    ips = {d["ip_address"] for d in devices}
    assert ips == {"192.168.1.10", "192.168.1.99"}
    self_device = next(d for d in devices if d["ip_address"] == "192.168.1.99")
    assert self_device["mac_address"] == "11:22:33:44:55:66"


def test_run_discovery_does_not_duplicate_self_if_arp_already_found_it(db, monkeypatch):
    monkeypatch.setattr(
        wifi_join, "join_network",
        lambda iface, ssid, password, **kw: {"connected": True, "ip": "192.168.1.99", "gateway": "192.168.1.1", "error": None},
    )
    monkeypatch.setattr(
        arp_sweep, "scan_subnet",
        lambda iface, **kw: [{"ip": "192.168.1.99", "mac": "11:22:33:44:55:66"}],
    )
    monkeypatch.setattr(discovery_runner, "_local_mac", lambda iface: "11:22:33:44:55:66")
    monkeypatch.setattr(nmap_scan, "scan_host", lambda ip, **kw: {"open_ports": [], "os_guess": None})
    monkeypatch.setattr(mdns_discover, "identify_hosts", lambda target_ips, **kw: {})

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:03", "ssid": "TestNet"})

    discovery_runner.run_discovery(network_id, session_id, "wlan0", "TestNet", "s3cret", db_path=db)

    with get_connection(db) as conn:
        devices = queries.get_devices_for_network(conn, network_id)

    assert len(devices) == 1


def test_run_discovery_isolates_one_bad_host_from_the_rest(db, monkeypatch):
    """One host's nmap/vendor lookup raising must not lose devices already
    scanned successfully by other threads in the pool."""
    monkeypatch.setattr(
        wifi_join, "join_network",
        lambda iface, ssid, password, **kw: {"connected": True, "ip": "192.168.1.5", "gateway": "192.168.1.1", "error": None},
    )
    monkeypatch.setattr(
        arp_sweep, "scan_subnet",
        lambda iface, **kw: [
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
            {"ip": "192.168.1.11", "mac": "AA:BB:CC:DD:EE:00"},
        ],
    )

    def flaky_scan_host(ip, **kw):
        if ip == "192.168.1.11":
            raise RuntimeError("nmap crashed")
        return {"open_ports": [{"port": 80, "service": "http"}], "os_guess": "Linux"}

    monkeypatch.setattr(nmap_scan, "scan_host", flaky_scan_host)
    monkeypatch.setattr(mdns_discover, "identify_hosts", lambda target_ips, **kw: {})

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "TestNet"})

    discovery_runner.run_discovery(network_id, session_id, "wlan0", "TestNet", "s3cret", db_path=db)

    with get_connection(db) as conn:
        network = queries.get_network_by_id(conn, network_id)
        devices = queries.get_devices_for_network(conn, network_id)
        alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE session_id = ?", (session_id,))]

    assert network["discovery_status"] == "done"
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.10"
    assert any(a["severity"] == "warning" and "192.168.1.11" in a["message"] for a in alerts)


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
