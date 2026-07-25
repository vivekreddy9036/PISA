from types import SimpleNamespace

from pisa.m1 import arp_sweep


def test_subnet_cidr_parses_ip_addr_output(monkeypatch):
    output = "2: wlan0    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic wlan0"

    monkeypatch.setattr(
        arp_sweep.subprocess, "run",
        lambda cmd, capture_output, text: SimpleNamespace(stdout=output),
    )

    assert arp_sweep._subnet_cidr("wlan0") == "192.168.1.5/24"


def test_subnet_cidr_returns_none_when_unassigned(monkeypatch):
    monkeypatch.setattr(
        arp_sweep.subprocess, "run",
        lambda cmd, capture_output, text: SimpleNamespace(stdout=""),
    )

    assert arp_sweep._subnet_cidr("wlan0") is None


def test_scan_subnet_returns_hosts_from_arp_responses(monkeypatch):
    monkeypatch.setattr(arp_sweep, "_subnet_cidr", lambda iface: "192.168.1.0/24")

    fake_response = SimpleNamespace(psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(arp_sweep, "_send_arp", lambda cidr, iface, timeout: [(None, fake_response)])

    hosts = arp_sweep.scan_subnet("wlan0", timeout=1)

    assert hosts == [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}]


def test_scan_subnet_returns_empty_when_no_ip(monkeypatch):
    monkeypatch.setattr(arp_sweep, "_subnet_cidr", lambda iface: None)

    assert arp_sweep.scan_subnet("wlan0", timeout=1) == []
