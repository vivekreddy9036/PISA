import json

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import oui_cve
from pisa.m1 import arp_sweep, mdns_discover, nmap_scan, wifi_join


def run_discovery(
    network_id: int,
    session_id: int,
    iface: str,
    ssid: str,
    password: str,
    db_path: str = config.DB_PATH,
) -> None:
    """Join a target network and enumerate devices on it: ARP sweep for live
    hosts, then Nmap for open ports/OS per host. Persists devices against
    network_id/session_id. Used by both the web API and the CLI
    --join-network path."""
    with get_connection(db_path) as conn:
        queries.mark_discovery_running(conn, network_id)

    join = wifi_join.join_network(iface, ssid, password)
    if not join["connected"]:
        with get_connection(db_path) as conn:
            queries.mark_discovery_error(conn, network_id, join["error"])
            queries.insert_alert(
                conn, session_id, "error", "discovery",
                f"Failed to join {ssid}: {join['error']}",
                related_id=network_id, related_type="network",
            )
        return

    try:
        hosts = arp_sweep.scan_subnet(iface)
        mdns_by_ip = mdns_discover.identify_hosts({h["ip"] for h in hosts})
        for host in hosts:
            vendor = oui_cve.bssid_to_vendor(host["mac"])
            nmap_result = nmap_scan.scan_host(host["ip"])
            mdns_info = mdns_by_ip.get(host["ip"], {})
            with get_connection(db_path) as conn:
                queries.insert_device(conn, session_id, network_id, {
                    "ip_address": host["ip"],
                    "mac_address": host["mac"],
                    "vendor": vendor,
                    "open_ports": json.dumps(nmap_result["open_ports"]),
                    "os_guess": nmap_result["os_guess"],
                    "mdns_name": mdns_info.get("name"),
                    "device_type": mdns_info.get("device_type"),
                })
    except Exception as e:
        with get_connection(db_path) as conn:
            queries.mark_discovery_error(conn, network_id, str(e))
            queries.insert_alert(
                conn, session_id, "error", "discovery", f"Discovery failed: {e}",
                related_id=network_id, related_type="network",
            )
        return

    with get_connection(db_path) as conn:
        queries.mark_discovery_done(conn, network_id)
        queries.insert_alert(
            conn, session_id, "info", "discovery",
            f"Discovered {len(hosts)} device(s) on {ssid}",
            related_id=network_id, related_type="network",
        )
