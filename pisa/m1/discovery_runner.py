import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import oui_cve
from pisa.m1 import arp_sweep, mdns_discover, nmap_scan, wifi_join


def _local_mac(iface: str) -> str | None:
    """iface's own MAC, so the scanning host can be added to its own
    inventory — arp-scan (like any ARP sweep) never sees itself, since a
    host has no reason to ARP-request its own address."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except OSError:
        return None


def _scan_host(host: dict, mdns_info: dict) -> dict:
    vendor = oui_cve.bssid_to_vendor(host["mac"])
    nmap_result = nmap_scan.scan_host(host["ip"])
    return {
        "ip_address": host["ip"],
        "mac_address": host["mac"],
        "vendor": vendor,
        "open_ports": json.dumps(nmap_result["open_ports"]),
        "os_guess": nmap_result["os_guess"],
        "mdns_name": mdns_info.get("name"),
        "device_type": mdns_info.get("device_type"),
    }


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

        self_mac = _local_mac(iface)
        if join["ip"] and self_mac and not any(h["ip"] == join["ip"] for h in hosts):
            hosts.append({"ip": join["ip"], "mac": self_mac})

        mdns_by_ip = mdns_discover.identify_hosts({h["ip"] for h in hosts})
    except Exception as e:
        with get_connection(db_path) as conn:
            queries.mark_discovery_error(conn, network_id, str(e))
            queries.insert_alert(
                conn, session_id, "error", "discovery", f"Discovery failed: {e}",
                related_id=network_id, related_type="network",
            )
        return

    # Per-host failures (one bad nmap/vendor lookup out of hundreds) must not
    # abort devices already scanned successfully — isolate each future's
    # result instead of letting one exception propagate out of the loop.
    inserted = 0
    failed_hosts: list[str] = []
    with ThreadPoolExecutor(max_workers=config.NMAP_MAX_WORKERS) as pool:
        futures = {
            pool.submit(_scan_host, host, mdns_by_ip.get(host["ip"], {})): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                device = future.result()
            except Exception as e:
                failed_hosts.append(host["ip"])
                with get_connection(db_path) as conn:
                    queries.insert_alert(
                        conn, session_id, "warning", "discovery",
                        f"Failed to scan host {host['ip']}: {e}",
                        related_id=network_id, related_type="network",
                    )
                continue
            inserted += 1
            with get_connection(db_path) as conn:
                queries.insert_device(conn, session_id, network_id, device)

    message = f"Discovered {inserted} device(s) on {ssid}"
    if failed_hosts:
        message += f" ({len(failed_hosts)} host(s) failed to scan)"
    with get_connection(db_path) as conn:
        queries.mark_discovery_done(conn, network_id)
        queries.insert_alert(
            conn, session_id, "info", "discovery", message,
            related_id=network_id, related_type="network",
        )
