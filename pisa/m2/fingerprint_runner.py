"""Probe a discovered device's open ports for protocol behavior (M2/FR-8),
fuse the signals into a device_type + confidence, and persist both the raw
per-feature evidence and the fused result.
"""
import json
from concurrent.futures import ThreadPoolExecutor

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m2 import coap_probe, fusion, http_probe, mqtt_probe, rtsp_probe

_PROBES = {
    "mqtt": mqtt_probe.probe,
    "coap": coap_probe.probe,
    "http": http_probe.probe,
    "rtsp": rtsp_probe.probe,
}


def run_fingerprint(device_id: int, db_path: str = config.DB_PATH) -> dict:
    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
    if device is None:
        return {"error": "not found"}

    try:
        open_ports = json.loads(device.get("open_ports") or "[]")
    except (ValueError, TypeError):
        open_ports = []

    all_features: list[dict] = []
    probed_coap = False

    for entry in open_ports:
        port = entry.get("port")
        protocol = config.M2_PROTOCOL_PORTS.get(port)
        if protocol is None:
            continue
        all_features.extend(_PROBES[protocol](device["ip_address"], port, config.M2_PROBE_TIMEOUT))
        probed_coap = probed_coap or protocol == "coap"

    # CoAP is UDP — never appears in nmap_scan's TCP-only open_ports — so
    # probe it unconditionally unless it was somehow already covered above.
    if not probed_coap:
        all_features.extend(coap_probe.probe(device["ip_address"], 5683, config.M2_PROBE_TIMEOUT))

    device_type, confidence = fusion.fuse(device.get("device_type"), all_features)

    with get_connection(db_path) as conn:
        for feature in all_features:
            queries.insert_fingerprint_signature(
                conn, device_id, feature["protocol"], feature["feature_key"],
                feature.get("feature_value"), feature.get("confidence"),
            )
        queries.update_device_fingerprint(conn, device_id, device_type, confidence)

    return {"device_type": device_type, "confidence": confidence, "features": all_features}


def run_fingerprint_network(network_id: int, db_path: str = config.DB_PATH) -> None:
    """Fingerprint every device on a network concurrently. Each device's
    mandatory CoAP probe alone costs up to M2_PROBE_TIMEOUT; run_fingerprint
    opens its own DB connections per call, same as M1's discovery_runner, so
    fanning out across a thread pool is safe.

    One device raising must not silently kill the pool thread with no record
    of it (the failure mode this had before) — isolate per-device like
    pisa/m1/discovery_runner.py does for per-host nmap/vendor failures.
    """
    with get_connection(db_path) as conn:
        network = queries.get_network_by_id(conn, network_id)
        devices = queries.get_devices_for_network(conn, network_id)
    if network is None:
        return

    def _safe_fingerprint(device: dict) -> None:
        try:
            run_fingerprint(device["id"], db_path=db_path)
        except Exception as e:
            with get_connection(db_path) as conn:
                queries.insert_alert(
                    conn, network["session_id"], "warning", "fingerprint",
                    f"Failed to fingerprint device {device['ip_address']}: {e}",
                    related_id=device["id"], related_type="device",
                )

    with ThreadPoolExecutor(max_workers=config.M2_MAX_WORKERS) as pool:
        list(pool.map(_safe_fingerprint, devices))
