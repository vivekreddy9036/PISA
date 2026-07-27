"""ARP sweep to discover live hosts on the network just joined.

Shells out to arp-scan (like pisa/m1/nmap_scan.py shells out to nmap) rather
than using scapy's srp(). Verified on a real campus /19 (~8k addresses):
scapy's pure-Python reply matching couldn't keep up with the reply volume
(this network's flat L2 domain returns a heavy duplicate-ARP-reply flood) and
only surfaced a handful of the live hosts within any timeout short enough to
be usable; arp-scan swept the same subnet completely in ~30s.
"""
import subprocess

import config


def _subnet_cidr(iface: str) -> str | None:
    """Return iface's IPv4 CIDR (e.g. "192.168.1.5/24") or None if unassigned."""
    proc = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1]
    return None


def _run_arp_scan(cidr: str, iface: str, timeout: int) -> str:
    try:
        proc = subprocess.run(
            ["arp-scan", "--interface", iface, "--plain", "--quiet", "--ignoredups", cidr],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ""
    return proc.stdout


def _parse_arp_scan(output: str) -> list[dict]:
    hosts = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
            hosts.append({"ip": parts[0].strip(), "mac": parts[1].strip().upper()})
    return hosts


def scan_subnet(iface: str, timeout: int = config.ARP_SWEEP_TIMEOUT) -> list[dict]:
    """Return [{"ip": ..., "mac": ...}, ...] for every host answering an ARP
    request on iface's local subnet. iface must already have an IP (i.e. be
    joined to the target network) — see pisa.m1.wifi_join.join_network.
    """
    cidr = _subnet_cidr(iface)
    if not cidr:
        return []

    output = _run_arp_scan(cidr, iface, timeout)
    return _parse_arp_scan(output)
