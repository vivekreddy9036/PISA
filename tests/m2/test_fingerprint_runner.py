import json

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m2 import coap_probe, fingerprint_runner


def _make_device(db, open_ports, bssid="AA:BB:CC:00:00:01"):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": bssid, "ssid": "TestNet"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "open_ports": json.dumps(open_ports),
        })
    return device_id


def test_run_fingerprint_probes_matching_protocol_and_persists(db, monkeypatch):
    device_id = _make_device(db, [{"port": 1883, "service": "mqtt"}])

    monkeypatch.setitem(
        fingerprint_runner._PROBES, "mqtt",
        lambda ip, port, timeout: [{
            "protocol": "mqtt", "feature_key": "mqtt.connack", "feature_value": "reason_code=0",
            "confidence": 0.9, "device_type_hint": "MQTT Broker",
        }],
    )
    monkeypatch.setattr(coap_probe, "probe", lambda ip, port, timeout: [])

    result = fingerprint_runner.run_fingerprint(device_id, db_path=db)

    assert result["device_type"] == "MQTT Broker"
    assert result["confidence"] == 0.9

    with get_connection(db) as conn:
        device = queries.get_device_by_id(conn, device_id)
        signatures = queries.get_fingerprint_signatures(conn, device_id)

    assert device["device_type"] == "MQTT Broker"
    assert device["fingerprint_confidence"] == 0.9
    assert len(signatures) == 1
    assert signatures[0]["protocol"] == "mqtt"


def test_run_fingerprint_always_probes_coap_even_when_not_in_open_ports(db, monkeypatch):
    device_id = _make_device(db, [])
    called = {}

    def fake_coap_probe(ip, port, timeout):
        called["port"] = port
        return []

    monkeypatch.setattr(coap_probe, "probe", fake_coap_probe)

    fingerprint_runner.run_fingerprint(device_id, db_path=db)

    assert called["port"] == 5683


def test_run_fingerprint_returns_error_for_missing_device(db):
    assert fingerprint_runner.run_fingerprint(999999, db_path=db) == {"error": "not found"}


def test_run_fingerprint_handles_malformed_open_ports(db, monkeypatch):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:02", "ssid": "TestNet2"})
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.1.11",
            "open_ports": "not json",
        })

    monkeypatch.setattr(coap_probe, "probe", lambda ip, port, timeout: [])

    result = fingerprint_runner.run_fingerprint(device_id, db_path=db)

    assert result["device_type"] is None
    assert result["confidence"] == 0.0


def test_run_fingerprint_network_processes_every_device_on_the_network(db, monkeypatch):
    monkeypatch.setattr(coap_probe, "probe", lambda ip, port, timeout: [])

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:03", "ssid": "TestNet3"})
        other_network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:04", "ssid": "OtherNet"})
        device_ids = [
            queries.insert_device(conn, session_id, network_id, {
                "ip_address": f"192.168.1.{i}",
                "mac_address": f"AA:BB:CC:11:11:{i:02d}",
                "open_ports": "[]",
            })
            for i in range(5)
        ]
        other_device_id = queries.insert_device(conn, session_id, other_network_id, {
            "ip_address": "192.168.2.1",
            "mac_address": "AA:BB:CC:22:22:01",
            "open_ports": "[]",
        })

    fingerprint_runner.run_fingerprint_network(network_id, db_path=db)

    with get_connection(db) as conn:
        devices = {d["id"]: d for d in queries.get_devices_for_network(conn, network_id)}
        other_device = queries.get_device_by_id(conn, other_device_id)

    assert set(devices) == set(device_ids)
    assert all(d["fingerprint_confidence"] is not None for d in devices.values())
    assert other_device["fingerprint_confidence"] is None


def test_run_fingerprint_network_isolates_one_bad_device_from_the_rest(db, monkeypatch):
    """One device raising inside the thread pool must not silently kill the
    whole batch with no record of it — see the matching fix in
    pisa/m1/discovery_runner.py for per-host nmap/vendor failures."""
    monkeypatch.setattr(coap_probe, "probe", lambda ip, port, timeout: [])

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        network_id = queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:05", "ssid": "TestNet5"})
        good_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.3.1", "mac_address": "AA:BB:CC:33:33:01", "open_ports": "[]",
        })
        bad_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "192.168.3.2", "mac_address": "AA:BB:CC:33:33:02", "open_ports": "[]",
        })

    real_run_fingerprint = fingerprint_runner.run_fingerprint

    def flaky_run_fingerprint(device_id, db_path):
        if device_id == bad_id:
            raise RuntimeError("probe blew up")
        return real_run_fingerprint(device_id, db_path=db_path)

    monkeypatch.setattr(fingerprint_runner, "run_fingerprint", flaky_run_fingerprint)

    fingerprint_runner.run_fingerprint_network(network_id, db_path=db)

    with get_connection(db) as conn:
        good = queries.get_device_by_id(conn, good_id)
        bad = queries.get_device_by_id(conn, bad_id)
        alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE session_id = ?", (session_id,))]

    assert good["fingerprint_confidence"] is not None
    assert bad["fingerprint_confidence"] is None
    assert any(
        a["severity"] == "warning" and a["category"] == "fingerprint" and "192.168.3.2" in a["message"]
        for a in alerts
    )
