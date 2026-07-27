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


def test_scan_subnet_returns_hosts_from_arp_scan_output(monkeypatch):
    monkeypatch.setattr(arp_sweep, "_subnet_cidr", lambda iface: "192.168.1.0/24")
    monkeypatch.setattr(
        arp_sweep, "_run_arp_scan",
        lambda cidr, iface, timeout: "192.168.1.10\taa:bb:cc:dd:ee:ff\n",
    )

    hosts = arp_sweep.scan_subnet("wlan0", timeout=1)

    assert hosts == [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}]


def test_scan_subnet_parses_multiple_hosts(monkeypatch):
    monkeypatch.setattr(arp_sweep, "_subnet_cidr", lambda iface: "192.168.1.0/24")
    monkeypatch.setattr(
        arp_sweep, "_run_arp_scan",
        lambda cidr, iface, timeout: "192.168.1.10\taa:bb:cc:dd:ee:ff\n192.168.1.11\t11:22:33:44:55:66\n",
    )

    hosts = arp_sweep.scan_subnet("wlan0", timeout=1)

    assert hosts == [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
        {"ip": "192.168.1.11", "mac": "11:22:33:44:55:66"},
    ]


def test_scan_subnet_ignores_blank_lines(monkeypatch):
    monkeypatch.setattr(arp_sweep, "_subnet_cidr", lambda iface: "192.168.1.0/24")
    monkeypatch.setattr(
        arp_sweep, "_run_arp_scan",
        lambda cidr, iface, timeout: "\n192.168.1.10\taa:bb:cc:dd:ee:ff\n\n",
    )

    hosts = arp_sweep.scan_subnet("wlan0", timeout=1)

    assert hosts == [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}]


def test_scan_subnet_returns_empty_when_no_ip(monkeypatch):
    monkeypatch.setattr(arp_sweep, "_subnet_cidr", lambda iface: None)

    assert arp_sweep.scan_subnet("wlan0", timeout=1) == []


def test_run_arp_scan_returns_empty_on_timeout(monkeypatch):
    def raise_timeout(cmd, capture_output, text, timeout):
        raise arp_sweep.subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(arp_sweep.subprocess, "run", raise_timeout)

    assert arp_sweep._run_arp_scan("192.168.1.0/24", "wlan0", 1) == ""
