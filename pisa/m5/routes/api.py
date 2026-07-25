import threading

from flask import Blueprint, current_app, jsonify, request

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import oui_cve
from pisa.m0.scan_runner import run_scan
from pisa.m1 import discovery_runner

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

    cves = oui_cve.lookup_cves(network["bssid"])

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
