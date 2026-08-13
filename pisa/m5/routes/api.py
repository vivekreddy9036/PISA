import threading

from flask import Blueprint, current_app, jsonify, request

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import oui_cve
from pisa.m0.scan_runner import run_scan
from pisa.m1 import discovery_runner
from pisa.m2 import fingerprint_runner
from pisa.m3 import exploit_score
from pisa.m4 import routersploit_gate

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/scan", methods=["POST"])
def start_scan():
    body = request.get_json(silent=True) or {}
    iface = body.get("iface") or config.WIFI_IFACE
    duration = int(body.get("duration") or config.SCAN_DEFAULT_DURATION)
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        session_id = queries.create_session(conn)

    thread = threading.Thread(
        target=run_scan,
        args=(session_id, iface, duration),
        kwargs={"db_path": db_path},
        daemon=True,
    )
    thread.start()

    return jsonify({"session_id": session_id})


@bp.route("/scan/<int:session_id>/status")
def scan_status(session_id):
    with get_connection(current_app.config["DB_PATH"]) as conn:
        session = queries.get_session(conn, session_id)
    if session is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"status": session["status"]})


@bp.route("/networks/<int:network_id>/cves", methods=["POST"])
def check_cves(network_id):
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        network = queries.get_network_by_id(conn, network_id)
        if network is None:
            return jsonify({"error": "not found"}), 404

    cves = exploit_score.enrich_cves(oui_cve.lookup_cves(network["bssid"]))

    with get_connection(db_path) as conn:
        for cve in cves:
            queries.insert_network_cve(conn, network_id, cve)

    return jsonify({"cves": cves})


@bp.route("/networks/<int:network_id>/join", methods=["POST"])
def join_network(network_id):
    body = request.get_json(silent=True) or {}
    password = body.get("password") or ""
    iface = body.get("iface") or config.JOIN_IFACE
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        network = queries.get_network_by_id(conn, network_id)
        if network is None:
            return jsonify({"error": "not found"}), 404

    thread = threading.Thread(
        target=discovery_runner.run_discovery,
        args=(network_id, network["session_id"], iface, network["ssid"], password),
        kwargs={"db_path": db_path},
        daemon=True,
    )
    thread.start()

    return jsonify({"network_id": network_id})


@bp.route("/networks/<int:network_id>/discovery/status")
def discovery_status(network_id):
    with get_connection(current_app.config["DB_PATH"]) as conn:
        network = queries.get_network_by_id(conn, network_id)
        if network is None:
            return jsonify({"error": "not found"}), 404
        devices = queries.get_devices_for_network(conn, network_id)
    return jsonify({
        "status": network["discovery_status"],
        "error": network["discovery_error"],
        "device_count": len(devices),
    })


@bp.route("/networks/<int:network_id>/devices")
def network_devices(network_id):
    with get_connection(current_app.config["DB_PATH"]) as conn:
        network = queries.get_network_by_id(conn, network_id)
        if network is None:
            return jsonify({"error": "not found"}), 404
        devices = queries.get_devices_for_network(conn, network_id)
    return jsonify({"devices": devices})


@bp.route("/devices/<int:device_id>/cves", methods=["POST"])
def check_device_cves(device_id):
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404

    cves = oui_cve.lookup_device_cves(device["os_guess"])
    if cves is None:
        return jsonify({"cves": None, "reason": "no_os_fingerprint"})
    cves = exploit_score.enrich_cves(cves)

    with get_connection(db_path) as conn:
        for cve in cves:
            queries.insert_device_cve(conn, device_id, cve)

    return jsonify({"cves": cves})


@bp.route("/devices/<int:device_id>/fingerprint", methods=["POST"])
def fingerprint_device(device_id):
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
    if device is None:
        return jsonify({"error": "not found"}), 404

    result = fingerprint_runner.run_fingerprint(device_id, db_path=db_path)
    return jsonify(result)


@bp.route("/networks/<int:network_id>/fingerprint", methods=["POST"])
def fingerprint_network(network_id):
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        network = queries.get_network_by_id(conn, network_id)
    if network is None:
        return jsonify({"error": "not found"}), 404

    thread = threading.Thread(
        target=fingerprint_runner.run_fingerprint_network,
        args=(network_id,),
        kwargs={"db_path": db_path},
        daemon=True,
    )
    thread.start()

    return jsonify({"network_id": network_id})


@bp.route("/networks/<int:network_id>/fingerprint/status")
def fingerprint_network_status(network_id):
    with get_connection(current_app.config["DB_PATH"]) as conn:
        network = queries.get_network_by_id(conn, network_id)
        if network is None:
            return jsonify({"error": "not found"}), 404
        devices = queries.get_devices_for_network(conn, network_id)

    total = len(devices)
    done = sum(1 for d in devices if d["fingerprint_confidence"] is not None)
    return jsonify({"total": total, "done": done})


def _get_device_cve_or_none(conn, device_id, cve_id):
    return next((c for c in queries.get_device_cves(conn, device_id) if c["cve_id"] == cve_id), None)


@bp.route("/devices/<int:device_id>/cves/<cve_id>/exploit-modules")
def exploit_modules_for_cve(device_id, cve_id):
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404
        if _get_device_cve_or_none(conn, device_id, cve_id) is None:
            return jsonify({"error": "cve not associated with this device"}), 404

    return jsonify({"modules": routersploit_gate.find_modules_for_cve(cve_id)})


@bp.route("/devices/<int:device_id>/exploit", methods=["POST"])
def run_device_exploit(device_id):
    db_path = current_app.config["DB_PATH"]
    body = request.get_json(silent=True) or {}
    cve_id = body.get("cve_id") or ""
    module_path = body.get("module_path") or ""
    mode = body.get("mode") or ""
    authorized_by = (body.get("authorized_by") or "").strip()
    port = body.get("port")

    if not authorized_by:
        return jsonify({"error": "authorized_by is required"}), 400
    if mode not in ("check", "run"):
        return jsonify({"error": "mode must be 'check' or 'run'"}), 400
    if not module_path:
        return jsonify({"error": "module_path is required"}), 400

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404
        if _get_device_cve_or_none(conn, device_id, cve_id) is None:
            return jsonify({"error": "cve not associated with this device"}), 404

    with get_connection(db_path) as conn:
        result_id = queries.record_exploit_authorization(
            conn, device_id, cve_id, module_path, authorized_by,
        )

    outcome = routersploit_gate.run_exploit(device["ip_address"], module_path, mode, port=port)

    with get_connection(db_path) as conn:
        queries.record_exploit_outcome(conn, result_id, outcome["result"], outcome["success"])

    return jsonify({"id": result_id, **outcome})
