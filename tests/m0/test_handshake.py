from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import handshake


def test_parse_hc22000_line_pmkid():
    line = "WPA*01*aabbccddeeff00112233445566778899*aabbccddeeff*112233445566*4d794e6574***"
    parsed = handshake._parse_hc22000_line(line)
    assert parsed["type"] == "PMKID"
    assert parsed["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert parsed["essid"] == "MyNet"


def test_parse_hc22000_line_eapol():
    line = "WPA*02*aabbccddeeff00112233445566778899*aabbccddeeff*112233445566*4d794e6574*abcd*efab*02"
    parsed = handshake._parse_hc22000_line(line)
    assert parsed["type"] == "EAPOL"
    assert parsed["bssid"] == "AA:BB:CC:DD:EE:FF"


def test_parse_hc22000_line_rejects_malformed():
    assert handshake._parse_hc22000_line("") is None
    assert handshake._parse_hc22000_line("not*a*wpa*line") is None
    assert handshake._parse_hc22000_line("WPA*99*x*y*z*w") is None


def test_build_hcxdumptool_cmd_passive_never_transmits():
    cmd = handshake._build_hcxdumptool_cmd("wlan0mon", "/tmp/out.pcapng", passive=True)
    assert "--disable_deauthentication" in cmd
    assert "--disable_proberequest" in cmd
    assert "--disable_association" in cmd
    assert "--disable_reassociation" in cmd
    assert "--disable_beacon" in cmd


def test_build_hcxdumptool_cmd_active_mode_omits_passive_flags():
    cmd = handshake._build_hcxdumptool_cmd("wlan0mon", "/tmp/out.pcapng", passive=False)
    assert "--disable_deauthentication" not in cmd
    assert "-F" in cmd


def test_capture_handshakes_filters_by_target_bssid(monkeypatch, tmp_path):
    monkeypatch.setattr(handshake, "_run_hcxdumptool", lambda cmd, timeout: None)
    monkeypatch.setattr(
        handshake, "_convert_to_hc22000",
        lambda pcapng, out: [
            "WPA*01*aabbccddeeff00112233445566778899*aabbccddeeff*112233445566*4d794e6574***",
            "WPA*01*aabbccddeeff00112233445566778899*112233445566*aabbccddeeff*4f746865722a2a***",
        ],
    )

    results = handshake.capture_handshakes(
        "wlan0mon", timeout=5, target_bssid="AA:BB:CC:DD:EE:FF", output_dir=str(tmp_path)
    )

    assert len(results) == 1
    assert results[0]["bssid"] == "AA:BB:CC:DD:EE:FF"


def test_capture_handshakes_defaults_to_passive(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, timeout):
        seen["cmd"] = cmd

    monkeypatch.setattr(handshake, "_run_hcxdumptool", fake_run)
    monkeypatch.setattr(handshake, "_convert_to_hc22000", lambda pcapng, out: [])

    handshake.capture_handshakes("wlan0mon", timeout=5, output_dir=str(tmp_path))

    assert "--disable_deauthentication" in seen["cmd"]


def test_capture_handshakes_authorized_allows_active(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, timeout):
        seen["cmd"] = cmd

    monkeypatch.setattr(handshake, "_run_hcxdumptool", fake_run)
    monkeypatch.setattr(handshake, "_convert_to_hc22000", lambda pcapng, out: [])

    handshake.capture_handshakes("wlan0mon", timeout=5, authorized=True, output_dir=str(tmp_path))

    assert "--disable_deauthentication" not in seen["cmd"]


def test_capture_handshakes_parses_conversion_output(monkeypatch, tmp_path):
    monkeypatch.setattr(handshake, "_run_hcxdumptool", lambda cmd, timeout: None)
    monkeypatch.setattr(
        handshake, "_convert_to_hc22000",
        lambda pcapng, out: ["WPA*01*aabbccddeeff00112233445566778899*aabbccddeeff*112233445566*4d794e6574***"],
    )

    results = handshake.capture_handshakes("wlan0mon", timeout=5, output_dir=str(tmp_path))

    assert len(results) == 1
    assert results[0]["type"] == "PMKID"
    assert results[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert results[0]["essid"] == "MyNet"


def test_run_capture_session_marks_matching_network_and_alerts(db, monkeypatch):
    monkeypatch.setattr(
        handshake, "capture_handshakes",
        lambda iface, timeout, target_bssid, authorized: [
            {"type": "PMKID", "bssid": "AA:BB:CC:00:00:01", "essid": "Net1", "hc22000_path": "/tmp/x.hc22000"}
        ],
    )

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "Net1"})

    handshake.run_capture_session(session_id, "wlan0mon", timeout=5, db_path=db)

    with get_connection(db) as conn:
        networks = queries.get_networks(conn, session_id)
        c = conn.execute("SELECT * FROM alerts WHERE session_id = ?", (session_id,))
        alerts = [dict(r) for r in c.fetchall()]

    assert networks[0]["handshake_captured"] == 1
    assert networks[0]["handshake_type"] == "PMKID"
    assert len(alerts) == 1
    assert alerts[0]["category"] == "handshake"


def test_run_capture_session_ignores_unmatched_bssid(db, monkeypatch):
    monkeypatch.setattr(
        handshake, "capture_handshakes",
        lambda iface, timeout, target_bssid, authorized: [
            {"type": "PMKID", "bssid": "FF:FF:FF:FF:FF:FF", "essid": "Unknown", "hc22000_path": "/tmp/x.hc22000"}
        ],
    )

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)
        queries.insert_network(conn, session_id, {"bssid": "AA:BB:CC:00:00:01", "ssid": "Net1"})

    results = handshake.run_capture_session(session_id, "wlan0mon", timeout=5, db_path=db)

    with get_connection(db) as conn:
        networks = queries.get_networks(conn, session_id)

    assert len(results) == 1
    assert networks[0]["handshake_captured"] == 0
