"""ARP sweep to discover live hosts on the network just joined.

Uses scapy (already a project dependency, see pisa/m0/beacon_capture.py)
rather than shelling out to arp-scan, matching the FYP doc's stated design.
"""
import subprocess

from scapy.all import ARP, Ether, srp

import config


def _subnet_cidr(iface: str) -> str | None:
    """Return iface's IPv4 CIDR (e.g. "192.168.1.5/24") or None if unassigned."""
    proc = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1]
    return None


def _send_arp(cidr: str, iface: str, timeout: int):
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
        timeout=timeout,
        iface=iface,
        verbose=False,
    )
    return ans


def scan_subnet(iface: str, timeout: int = config.ARP_SWEEP_TIMEOUT) -> list[dict]:
    """Return [{"ip": ..., "mac": ...}, ...] for every host answering an ARP
    request on iface's local subnet. iface must already have an IP (i.e. be
    joined to the target network) — see pisa.m1.wifi_join.join_network.
    """
    cidr = _subnet_cidr(iface)
    if not cidr:
        return []

    ans = _send_arp(cidr, iface, timeout)
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc.upper()} for _, rcv in ans]
