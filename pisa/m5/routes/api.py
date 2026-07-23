import threading

from flask import Blueprint, current_app, jsonify, request

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import demo_data, oui_cve
from pisa.m0.scan_runner import run_scan

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/scan", methods=["POST"])
def start_scan():
    body = request.get_json(silent=True) or {}
    iface = body.get("iface") or config.WIFI_IFACE
    duration = int(body.get("duration") or config.SCAN_DEFAULT_DURATION)
    demo = bool(body.get("demo"))
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        session_id = queries.create_session(conn, notes="demo" if demo else None)

    thread = threading.Thread(
        target=run_scan,
        args=(session_id, iface, duration),
        kwargs={"demo": demo, "db_path": db_path},
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
        row = conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        network = dict(row)
        session = queries.get_session(conn, network["session_id"])

    is_demo = bool(session and session.get("notes") == "demo")
    if is_demo:
        cves = demo_data.generate_demo_cves(demo_data.DEMO_VENDOR)
    else:
        cves = oui_cve.lookup_cves(network["bssid"])

    with get_connection(db_path) as conn:
        for cve in cves:
            queries.insert_network_cve(conn, network_id, cve)

    return jsonify({"cves": cves})
