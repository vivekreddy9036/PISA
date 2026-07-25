"""mDNS-based device identification.

OUI vendor only identifies the WiFi chip maker ("Intel Corporate" tells you
nothing about whether it's a phone, laptop, or shield). Nmap's OS guess only
works when a scanned port happens to be open. Reverse DNS was tried first
and confirmed dead on the actual target network (campus WiFi doesn't run
internal PTR records — not even our own IP resolves). mDNS, tested live
against that same network, works: devices self-announce service types
(_airplay._tcp.local., _nvstream_dbd._tcp.local., ...) and, per service
type, a friendly instance name (e.g. "Vivek's iPhone") — independent of
whatever the network's own DNS infrastructure does or doesn't support.

Two-phase DNS-SD over plain UDP multicast (no root needed, unlike the raw
AF_PACKET sockets M0 needs for beacon capture):
  1. Query the meta-service `_services._dns-sd._udp.local.` — each
     responding host's PTR answers are the service types it advertises.
  2. For each service type of interest, query it directly — the PTR answer
     target is `<InstanceName>.<service_type>`; strip the suffix for the
     friendly name.
"""
import socket
import time

from scapy.layers.dns import DNS, DNSQR

import config

MCAST_GRP = "224.0.0.251"
MCAST_PORT = 5353
_META_SERVICE = "_services._dns-sd._udp.local."

# Small curated map from service type -> human-readable label. Unknown
# types fall back to a cleaned-up version of the type string itself.
SERVICE_LABELS = {
    "_airplay._tcp.local.": "Apple device (AirPlay)",
    "_raop._tcp.local.": "Apple device (AirPlay audio)",
    "_companion-link._tcp.local.": "Apple device (Continuity)",
    "_nvstream_dbd._tcp.local.": "NVIDIA Shield / GameStream",
    "_mi-connect._udp.local.": "Xiaomi device",
    "_kdeconnect._udp.local.": "Linux/Android (KDE Connect)",
    "_smb._tcp.local.": "Windows/Samba file share",
    "_googlecast._tcp.local.": "Chromecast",
    "_spotify-connect._tcp.local.": "Spotify Connect device",
    "_printer._tcp.local.": "Network printer",
    "_ipp._tcp.local.": "Network printer (IPP)",
}


def _build_query(qname: str) -> bytes:
    return bytes(DNS(rd=0, qd=DNSQR(qname=qname, qtype="PTR", qclass="IN")))


def _send_and_collect(qname: str, timeout: float) -> list[tuple[str, DNS]]:
    """Send one mDNS PTR query and collect every (source_ip, parsed_DNS)
    response received within timeout. The one networking seam in this
    module — tests monkeypatch this instead of touching real sockets."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    responses = []
    try:
        sock.sendto(_build_query(qname), (MCAST_GRP, MCAST_PORT))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                responses.append((addr[0], DNS(data)))
            except socket.timeout:
                break
            except Exception:
                continue
    finally:
        sock.close()
    return responses


def _ptr_targets(dns: DNS) -> list[str]:
    """Extract PTR record target names from a DNS response's answer section."""
    targets = []
    for i in range(dns.ancount):
        rr = dns.an[i]
        if rr.type != 12:  # PTR
            continue
        rdata = rr.rdata
        targets.append(rdata.decode(errors="ignore") if isinstance(rdata, bytes) else str(rdata))
    return targets


def discover_service_types(timeout: float = config.MDNS_QUERY_TIMEOUT) -> dict[str, set[str]]:
    """{ip: {service_type, ...}} from the DNS-SD meta-service query."""
    by_ip: dict[str, set[str]] = {}
    for ip, dns in _send_and_collect(_META_SERVICE, timeout):
        by_ip.setdefault(ip, set()).update(_ptr_targets(dns))
    return by_ip


def discover_instance_names(service_type: str, timeout: float = config.MDNS_QUERY_TIMEOUT) -> dict[str, list[str]]:
    """{ip: [friendly_name, ...]} for one service type, suffix stripped."""
    by_ip: dict[str, list[str]] = {}
    suffix = "." + service_type.rstrip(".")
    for ip, dns in _send_and_collect(service_type, timeout):
        for target in _ptr_targets(dns):
            # Both sides carry an inconsistent trailing "." depending on
            # what the responder sent — normalize before comparing/slicing.
            cleaned = target.rstrip(".")
            name = cleaned[: -len(suffix)] if cleaned.endswith(suffix) else cleaned
            by_ip.setdefault(ip, []).append(name)
    return by_ip


def _label_for(service_type: str) -> str:
    return SERVICE_LABELS.get(service_type, service_type.strip(".").lstrip("_").split(".")[0])


def identify_hosts(target_ips: set[str], timeout: float = config.MDNS_QUERY_TIMEOUT) -> dict[str, dict]:
    """Identify only the given hosts (e.g. an M1 ARP-sweep result set) —
    scoped deliberately, not the whole broadcast domain, to keep discovery
    time bounded. Returns {ip: {"name": str|None, "device_type": str|None}}.
    """
    by_ip_types = discover_service_types(timeout)
    relevant_types = {t for ip, types in by_ip_types.items() if ip in target_ips for t in types}

    names_by_ip: dict[str, list[str]] = {}
    for service_type in relevant_types:
        for ip, names in discover_instance_names(service_type, timeout).items():
            names_by_ip.setdefault(ip, []).extend(names)

    result: dict[str, dict] = {}
    for ip in target_ips:
        types = by_ip_types.get(ip, set())
        names = names_by_ip.get(ip, [])
        device_type = "; ".join(sorted({_label_for(t) for t in types})) if types else None
        result[ip] = {"name": names[0] if names else None, "device_type": device_type}
    return result
