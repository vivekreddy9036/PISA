import threading

from flask import Blueprint, current_app, jsonify, request

import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import oui_cve
from pisa.m0.scan_runner import run_scan
from pisa.m1 import discovery_runner
from pisa.m2 import fingerprint_runner
from pisa.m3 import applicability, cve_lookup, exploit_score, exploitation, verification
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
    """Phase 8.1: device-level CVE correlation now goes through the CPE-
    first pipeline (pisa/m3/cve_lookup.py::correlate_device_cves), which
    already handles CPE mapping, the keyword fallback (for devices with
    no usable structured identity), and EPSS/KEV/exploit_score
    enrichment internally — this route does not duplicate any of that
    logic, it only orchestrates the one additional cross-module step
    (applicability) the two modules deliberately don't call each other
    for (see cve_lookup.py's own docstring on that boundary)."""
    db_path = current_app.config["DB_PATH"]
    body = request.get_json(silent=True) or {}
    force_refresh = bool(body.get("force_refresh"))

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404

    with get_connection(db_path) as conn:
        result = cve_lookup.correlate_device_cves(conn, device_id, force_refresh=force_refresh)
        for finding in result["findings"]:
            applicability.determine_applicability(conn, device_id, finding["cve_id"])

    return jsonify(result)


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
    """Informational only (Phase 8.5) — lists every RouterSploit module
    whose own metadata references this CVE ID, purely so an operator can
    see what RouterSploit itself knows about. This is NOT an execution
    allowlist: /exploit (below) never accepts a module path from the
    client and never executes anything outside
    pisa/m3/exploitation.py's own registry. `pisa_supported` on each
    entry, and the top-level `supported_module_path`, tell the UI which
    (if any) of these discovered modules is the one PISA can actually
    run — everything else is shown for awareness only."""
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404
        if _get_device_cve_or_none(conn, device_id, cve_id) is None:
            return jsonify({"error": "cve not associated with this device"}), 404

    modules = routersploit_gate.find_modules_for_cve(cve_id)
    definition = exploitation.find_exploit_definition(cve_id)
    supported_path = f"exploits.{definition.module_path}" if definition and definition.supported else None
    for module in modules:
        module["pisa_supported"] = module.get("module_path") == supported_path

    return jsonify({
        "modules": modules,
        "supported_module_path": supported_path,
        "note": (
            "Informational RouterSploit module search, not an execution allowlist. "
            "Only the module at 'supported_module_path' (if any) can ever run via "
            "POST /exploit — the client cannot select or influence which module executes."
        ),
    })


@bp.route("/devices/<int:device_id>/cves/<cve_id>/verify", methods=["POST"])
def verify_device_cve(device_id, cve_id):
    """Phase 8.3: the only live entry point for pisa/m3/verification.py.
    All verification logic — eligibility gating on applicability_status,
    test selection, timeout, evidence redaction, persistence — lives
    entirely in verification.run_verification(); this route is a thin
    wrapper that returns its result unmodified."""
    db_path = current_app.config["DB_PATH"]

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404
        if _get_device_cve_or_none(conn, device_id, cve_id) is None:
            return jsonify({"error": "cve not associated with this device"}), 404
        result = verification.run_verification(conn, device_id, cve_id)

    return jsonify(result)


@bp.route("/devices/<int:device_id>/exploit", methods=["POST"])
def run_device_exploit(device_id):
    """Phase 8.4: the client supplies only cve_id/mode/authorized_by —
    never a module_path. pisa/m3/exploitation.py::attempt_exploitation
    is the sole, authoritative, server-side gate: it looks up the
    RouterSploit module from its own _REGISTRY (never from the request),
    and requires applicability_status == AFFECTED AND verification_status
    == VERIFIED_VULNERABLE AND a supported exploit is registered, before
    ever calling RouterSploit. This route does not re-implement, weaken,
    or duplicate any part of that gate — a blocked attempt is not
    persisted at all (exploitation.py's own behavior), so no
    exploit_results row is created unless the gate actually passed."""
    db_path = current_app.config["DB_PATH"]
    body = request.get_json(silent=True) or {}
    cve_id = body.get("cve_id") or ""
    mode = body.get("mode") or ""
    authorized_by = (body.get("authorized_by") or "").strip()

    if not authorized_by:
        return jsonify({"error": "authorized_by is required"}), 400
    if mode not in ("check", "run"):
        return jsonify({"error": "mode must be 'check' or 'run'"}), 400
    if not cve_id:
        return jsonify({"error": "cve_id is required"}), 400

    with get_connection(db_path) as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            return jsonify({"error": "not found"}), 404
        if _get_device_cve_or_none(conn, device_id, cve_id) is None:
            return jsonify({"error": "cve not associated with this device"}), 404

    with get_connection(db_path) as conn:
        outcome = exploitation.attempt_exploitation(conn, device_id, cve_id, mode, authorized_by)

    status_code = 403 if outcome["status"] == exploitation.STATUS_BLOCKED else 200
    return jsonify(outcome), status_code
