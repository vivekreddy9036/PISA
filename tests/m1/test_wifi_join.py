import subprocess
from types import SimpleNamespace

from pisa.m1 import wifi_join


def test_build_connect_cmd():
    cmd = wifi_join._build_connect_cmd("wlan0", "HomeNet", "s3cret")
    assert cmd == ["nmcli", "device", "wifi", "connect", "HomeNet", "password", "s3cret", "ifname", "wlan0"]


def test_join_network_success(monkeypatch):
    monkeypatch.setattr(wifi_join, "_forget_profile", lambda ssid: None)
    monkeypatch.setattr(wifi_join, "_rescan", lambda iface: None)
    monkeypatch.setattr(wifi_join, "_run", lambda cmd, timeout=None: SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(wifi_join, "_read_ipv4", lambda iface: ("192.168.1.5", "192.168.1.1"))

    result = wifi_join.join_network("wlan0", "HomeNet", "s3cret")

    assert result == {"connected": True, "ip": "192.168.1.5", "gateway": "192.168.1.1", "error": None}


def test_join_network_failure_reports_nmcli_stderr(monkeypatch):
    monkeypatch.setattr(wifi_join, "_forget_profile", lambda ssid: None)
    monkeypatch.setattr(wifi_join, "_rescan", lambda iface: None)
    monkeypatch.setattr(
        wifi_join, "_run",
        lambda cmd, timeout=None: SimpleNamespace(returncode=1, stdout="", stderr="Error: password incorrect"),
    )

    result = wifi_join.join_network("wlan0", "HomeNet", "wrong")

    assert result["connected"] is False
    assert result["error"] == "Error: password incorrect"


def test_join_network_timeout(monkeypatch):
    monkeypatch.setattr(wifi_join, "_forget_profile", lambda ssid: None)
    monkeypatch.setattr(wifi_join, "_rescan", lambda iface: None)

    def raise_timeout(cmd, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(wifi_join, "_run", raise_timeout)

    result = wifi_join.join_network("wlan0", "HomeNet", "s3cret", timeout=1)

    assert result["connected"] is False
    assert "timed out" in result["error"]


def test_join_network_forgets_stale_profile_then_rescans_then_connects(monkeypatch):
    calls = []
    monkeypatch.setattr(wifi_join, "_forget_profile", lambda ssid: calls.append("forget"))
    monkeypatch.setattr(wifi_join, "_rescan", lambda iface: calls.append("rescan"))
    monkeypatch.setattr(wifi_join, "_run", lambda cmd, timeout=None: calls.append("connect") or SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(wifi_join, "_read_ipv4", lambda iface: (None, None))

    wifi_join.join_network("wlan0", "HomeNet", "s3cret")

    assert calls == ["forget", "rescan", "connect"]


def test_read_ipv4_parses_cidr_and_multivalue(monkeypatch):
    outputs = iter(["192.168.1.5/24|10.0.0.1/8", "192.168.1.1"])
    monkeypatch.setattr(wifi_join, "_run", lambda cmd, timeout=None: SimpleNamespace(stdout=next(outputs)))

    ip, gateway = wifi_join._read_ipv4("wlan0")

    assert ip == "192.168.1.5"
    assert gateway == "192.168.1.1"
