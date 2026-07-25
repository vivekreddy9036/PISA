from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import beacon_capture


def _rsn_bytes(akm_type: int, mfp_capable: bool = False) -> bytes:
    """Build a minimal standards-shaped RSN IE body (1 pairwise, 1 AKM suite)."""
    version = b"\x01\x00"
    group_cipher = b"\x00\x0f\xac\x04"
    pairwise_count = b"\x01\x00"
    pairwise_list = b"\x00\x0f\xac\x04"
    akm_count = b"\x01\x00"
    akm_list = b"\x00\x0f\xac" + bytes([akm_type])
    caps = (0x0040 if mfp_capable else 0x0000).to_bytes(2, "little")
    return version + group_cipher + pairwise_count + pairwise_list + akm_count + akm_list + caps


RSN_WPA2_PSK = _rsn_bytes(akm_type=2)          # standard WPA2-PSK, no PMF
RSN_WPA3_SAE_PMF = _rsn_bytes(akm_type=8, mfp_capable=True)  # WPA3-SAE with PMF required

WPS_VENDOR_IE = b"\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"


def _build_beacon(bssid, ssid="TestNet", channel=6, beacon_interval=100, extra_elts=None):
    pkt = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(beacon_interval=beacon_interval)
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=3, info=bytes([channel]))
    )
    for elt in extra_elts or []:
        pkt = pkt / elt
    return pkt


def test_detect_security_open_network():
    pkt = _build_beacon("AA:BB:CC:00:00:01")
    security, pmf, wps = beacon_capture._detect_security(pkt)
    assert security == "Open"
    assert pmf is False
    assert wps is False


def test_detect_security_wpa2_psk_no_pmf():
    pkt = _build_beacon("AA:BB:CC:00:00:02", extra_elts=[Dot11Elt(ID=48, info=RSN_WPA2_PSK)])
    security, pmf, wps = beacon_capture._detect_security(pkt)
    assert security == "WPA2"
    assert pmf is False


def test_detect_security_wpa3_sae_with_pmf():
    pkt = _build_beacon("AA:BB:CC:00:00:03", extra_elts=[Dot11Elt(ID=48, info=RSN_WPA3_SAE_PMF)])
    security, pmf, wps = beacon_capture._detect_security(pkt)
    assert security == "WPA3"
    assert pmf is True


def test_detect_security_wps_enabled():
    pkt = _build_beacon(
        "AA:BB:CC:00:00:04",
        extra_elts=[Dot11Elt(ID=48, info=RSN_WPA2_PSK), Dot11Elt(ID=221, info=WPS_VENDOR_IE)],
    )
    security, pmf, wps = beacon_capture._detect_security(pkt)
    assert security == "WPA2"
    assert wps is True


def test_parse_beacon_hidden_ssid():
    pkt = _build_beacon("AA:BB:CC:00:00:05", ssid="")
    data = beacon_capture._parse_beacon(pkt)
    assert data["hidden"] == 1
    assert data["ssid"] == ""


def test_parse_beacon_visible_ssid():
    pkt = _build_beacon("AA:BB:CC:00:00:06", ssid="MyNetwork")
    data = beacon_capture._parse_beacon(pkt)
    assert data["hidden"] == 0
    assert data["ssid"] == "MyNetwork"
    assert data["bssid"] == "AA:BB:CC:00:00:06"


def test_start_capture_sweeps_all_configured_channels(db, monkeypatch):
    seen_channels = []
    monkeypatch.setattr(beacon_capture, "_set_channel", lambda iface, channel: seen_channels.append(channel))
    monkeypatch.setattr(beacon_capture, "sniff", lambda **kw: None)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)

    timeout = 0.5 * len(beacon_capture.config.SCAN_CHANNELS)
    beacon_capture.start_capture(session_id, db_path=db, iface="wlan1test", timeout=timeout)

    assert seen_channels == beacon_capture.config.SCAN_CHANNELS


def test_start_capture_stops_sweeping_once_timeout_exhausted(db, monkeypatch):
    seen_channels = []
    monkeypatch.setattr(beacon_capture, "_set_channel", lambda iface, channel: seen_channels.append(channel))
    monkeypatch.setattr(beacon_capture, "sniff", lambda **kw: None)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)

    beacon_capture.start_capture(session_id, db_path=db, iface="wlan1test", timeout=1)

    # dwell floor is 0.5s/channel, so a 1s budget only covers 2 channels
    assert seen_channels == beacon_capture.config.SCAN_CHANNELS[:2]


def test_start_capture_persists_scored_networks(db, monkeypatch):
    pkt = _build_beacon(
        "AA:BB:CC:00:00:10",
        ssid="Net1",
        channel=6,
        extra_elts=[Dot11Elt(ID=48, info=RSN_WPA3_SAE_PMF)],
    )

    def fake_sniff(iface, prn, store, timeout, lfilter):
        if lfilter(pkt):
            prn(pkt)

    monkeypatch.setattr(beacon_capture, "sniff", fake_sniff)

    with get_connection(db) as conn:
        session_id = queries.create_session(conn)

    beacon_capture.start_capture(session_id, db_path=db, iface="wlan1test", timeout=1)

    with get_connection(db) as conn:
        networks = queries.get_networks(conn, session_id)

    assert len(networks) == 1
    assert networks[0]["bssid"] == "AA:BB:CC:00:00:10"
    assert networks[0]["security"] == "WPA3"
    assert networks[0]["pmf_enabled"] == 1
    assert networks[0]["wsps_grade"] in ("A", "B", "C", "D", "E", "F")
