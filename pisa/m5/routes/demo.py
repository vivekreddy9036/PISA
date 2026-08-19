"""DEMO / PRESENTATION MODE — read-only visualization of a seeded,
clearly-labeled demonstration assessment. Every route here reads
exclusively from current_app.config["DEMO_DB_PATH"] — never DB_PATH
(the real assessment database) — so demo data structurally cannot mix
with, or be mistaken for, a real assessment. See pisa/m5/demo_seed.py
for how the demo data is produced (real PISA state-machine functions,
real CVE/CVSS/EPSS data, seeded evidence).
"""
import json

from flask import Blueprint, abort, current_app, render_template

from pisa.db import queries
from pisa.db.connection import get_connection

bp = Blueprint("demo", __name__, url_prefix="/demo")


def _demo_conn():
    return get_connection(current_app.config["DEMO_DB_PATH"])


@bp.route("/")
def overview():
    with _demo_conn() as conn:
        sessions = [s for s in queries.get_sessions(conn) if s.get("notes") == "DEMO_REPLAY"]
        if not sessions:
            abort(404, "Demo data not seeded — restart the app to auto-seed it.")
        session = sessions[0]
        networks = queries.get_networks(conn, session["id"])
        devices = []
        for n in networks:
            devices.extend(queries.get_devices_for_network(conn, n["id"]))

        summary = {
            "device_count": len(devices),
            "service_count": sum(len(json.loads(d["open_ports"] or "[]")) for d in devices),
            "vulnerability_count": 0,
            "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
            "applicability": {}, "verification": {}, "exploitation": {},
        }
        device_rows = []
        for d in devices:
            cves = queries.get_device_cves(conn, d["id"])
            summary["vulnerability_count"] += len(cves)
            worst_appl, worst_sev, worst_score = "UNKNOWN", "UNKNOWN", -1
            for c in cves:
                summary["applicability"][c["applicability_status"]] = summary["applicability"].get(c["applicability_status"], 0) + 1
                summary["verification"][c["verification_status"]] = summary["verification"].get(c["verification_status"], 0) + 1
                sev = (c["cvss_severity"] or "UNKNOWN").upper()
                if sev not in summary["severity"]:
                    sev = "UNKNOWN"
                summary["severity"][sev] += 1
                if (c["exploit_score"] or 0) > worst_score:
                    worst_score, worst_sev, worst_appl = c["exploit_score"] or 0, sev, c["applicability_status"]
            results = queries.get_exploit_results(conn, d["id"])
            for r in results:
                summary["exploitation"][r["exploitation_status"]] = summary["exploitation"].get(r["exploitation_status"], 0) + 1
            device_rows.append({
                "device": d, "cve_count": len(cves),
                "worst_severity": worst_sev, "worst_applicability": worst_appl,
                "exploited": any(r["exploitation_status"] == "EXPLOIT_SUCCESSFUL" for r in results),
            })

    return render_template("demo_overview.html", session=session, device_rows=device_rows, summary=summary)


@bp.route("/devices/<int:device_id>")
def device_detail(device_id):
    with _demo_conn() as conn:
        device = queries.get_device_by_id(conn, device_id)
        if device is None:
            abort(404)
        cves = queries.get_device_cves(conn, device_id)
        signatures = queries.get_fingerprint_signatures(conn, device_id)
        cpe_candidates = queries.get_cpe_candidates(conn, device_id)
        verification_attempts = queries.get_verification_attempts(conn, device_id)
        exploit_results = queries.get_exploit_results(conn, device_id)

    return render_template(
        "demo_device.html", device=device, cves=cves, signatures=signatures,
        cpe_candidates=cpe_candidates, verification_attempts=verification_attempts,
        exploit_results=exploit_results,
    )
