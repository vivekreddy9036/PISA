"""Seed data for DEMO / PRESENTATION MODE (pisa/m5/routes/demo.py).

Every state shown in demo mode is produced by PISA's own real functions —
applicability.determine_applicability(), verification's persistence helpers,
exploitation's authorization/outcome helpers, the real CPE/CVSS/EPSS/KEV
data structures — never hand-invented JSON blobs. The only thing that's
"simulated" is which specific device observed the evidence; the CVE IDs,
CVSS scores, and CPE strings used below are real, and the CVSS/EPSS values
are live NVD/FIRST.org data captured during this feature's development
(2026-08-19) rather than made up.

Isolation: this module is only ever pointed at config.DEMO_DB_PATH (a
separate SQLite file from the real config.DB_PATH) — see
pisa/m5/routes/demo.py and pisa/m5/app.py. It is never called against
production pisa.db.

Provenance: the seeded session's `notes` field is set to the literal
string "DEMO_REPLAY" — the existing `sessions.notes` column, reused
rather than adding a new schema column, per the smallest-footprint
requirement for this feature. pisa/m5/routes/demo.py additionally never
reads from any DB file except config.DEMO_DB_PATH, so isolation does not
depend on this marker alone.
"""
import json

from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.db.models import create_tables
from pisa.m3 import applicability, exploit_score, exploitation, verification

DEMO_MARKER = "DEMO_REPLAY"

# Real CVSS (live NVD, 2026-08-19) + real EPSS (live FIRST.org, 2026-08-19).
# KEV: confirmed NOT listed for either CVE in the real, locally-cached
# CISA KEV catalog (pisa/m3/kev_catalog.json) as of the same date.
_REAL_CVE_2017_7577 = {
    "cve_id": "CVE-2017-7577",
    "description": "uc-httpd 1.0.0, as used on Xiongmai devices and rebranded products, allows "
                    "remote attackers to obtain sensitive information via a .. (dot dot) sequence.",
    "cvss_score": 9.8, "cvss_version": "3.0", "cvss_severity": "CRITICAL",
    "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.28966, "epss_percentile": 0.98005, "epss_date": "2026-08-19",
    "kev_listed": False,
    # Real CPE strings, verbatim from the NVD CPE Dictionary — the same
    # fixture used by tests/m3/test_cve_lookup.py, not invented here.
    "cpe_hardware": "cpe:2.3:h:xiongmaitech:ahb7008f8-h:-:*:*:*:*:*:*:*",
    "cpe_firmware": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*",
    "configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:xiongmaitech:ahb7008f8-h_firmware:4.02.r11.3070:*:*:*:*:*:*:*"},
        ]},
    ]}],
}
_REAL_CVE_2017_16725 = {
    "cve_id": "CVE-2017-16725",
    "description": "A Stack-based Buffer Overflow issue was discovered in Multiple Xiongmai "
                    "Uni-Directional and NVMS product web interfaces.",
    "cvss_score": 9.8, "cvss_version": "3.0", "cvss_severity": "CRITICAL",
    "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.09216, "epss_percentile": 0.9493, "epss_date": "2026-08-19",
    "kev_listed": False,
}


def _score(cve: dict) -> float:
    return exploit_score.compute_exploit_score(cve["cvss_score"], cve["epss_score"], cve["kev_listed"])


def _already_seeded(conn) -> bool:
    for row in queries.get_sessions(conn):
        if row.get("notes") == DEMO_MARKER:
            return True
    return False


def seed_demo_data(db_path: str) -> None:
    """Idempotent — safe to call on every app startup. Does nothing if a
    DEMO_REPLAY session already exists in this DB file."""
    with get_connection(db_path) as conn:
        create_tables(conn)
        if _already_seeded(conn):
            return
        _seed(conn)


def _seed(conn) -> None:
    session_id = queries.create_session(
        conn, target_network="DEMO — Simulated IoT Assessment", notes=DEMO_MARKER,
    )
    network_id = queries.insert_network(conn, session_id, {
        "bssid": "DE:M0:00:00:00:01", "ssid": "DEMO — Simulated IoT Assessment",
        "channel": 6, "signal_dbm": -50, "security": "WPA2", "encryption": "WPA2",
        "beacon_interval": 100, "pmf_enabled": 1, "wps_enabled": 0, "hidden": 0,
        "wsps_score": 82, "wsps_grade": "B",
    })

    # -----------------------------------------------------------------
    # Camera-01 — CVE-2017-7577, real CPE_CONFIRMED-quality candidate,
    # real firmware version match -> AFFECTED -> real verification test
    # (HTTP-PATH-TRAVERSAL-001) result -> real, gated exploitation.
    # -----------------------------------------------------------------
    cve = _REAL_CVE_2017_7577
    cam_id = queries.insert_device(conn, session_id, network_id, {
        "ip_address": "203.0.113.10",  # RFC 5737 TEST-NET-3 — never a real routable device
        "mac_address": "DE:M0:00:00:01:01",
        "vendor": "Hangzhou Xiongmai Technology Co.,Ltd.",
        "open_ports": json.dumps([{"port": 80, "service": "http"}, {"port": 554, "service": "rtsp"}]),
        "os_guess": None, "device_type": "IP Camera", "mdns_name": None,
        "fingerprint_confidence": 0.9,
    })
    queries.update_device_identity(conn, cam_id, vendor="Xiongmai", product="uc-httpd", version="4.02.r11.3070")
    queries.insert_fingerprint_signature(conn, cam_id, "rtsp", "rtsp.options", "RTSP/1.0 200 OK", 0.9)
    queries.insert_fingerprint_signature(conn, cam_id, "http", "http.server", "uc-httpd/1.0.0", 0.5)
    queries.replace_cpe_candidates(conn, cam_id, [
        {"cpe": cve["cpe_firmware"], "confidence": 0.9, "status": "CPE_CONFIRMED",
         "source": "nvd_cpe_dictionary", "identity_basis": "vendor match; product match; version match; hardware/firmware CPE"},
    ])
    queries.upsert_device_cve_intelligence(conn, cam_id, {
        "cve_id": cve["cve_id"], "source_cpe": [cve["cpe_firmware"]], "correlation_method": "CPE",
        "description": cve["description"], "cvss_score": cve["cvss_score"], "cvss_version": cve["cvss_version"],
        "cvss_vector": cve["cvss_vector"], "cvss_severity": cve["cvss_severity"],
        "epss_score": cve["epss_score"], "epss_percentile": cve["epss_percentile"], "epss_date": cve["epss_date"],
        "kev_listed": cve["kev_listed"], "exploit_score": _score(cve),
        "configurations": cve["configurations"], "weaknesses": ["CWE-22"], "cve_references": [],
    })
    real_appl = applicability.determine_applicability(conn, cam_id, cve["cve_id"])  # real code, real verdict
    assert real_appl["status"] == "AFFECTED", f"seed assumption broken: {real_appl}"
    queries.record_verification_attempt(
        conn, cam_id, cve["cve_id"], "HTTP-PATH-TRAVERSAL-001", verification.RESULT_VERIFIED_VULNERABLE,
        verification.STATE_OK,
        "[DEMO — simulated] Response body matches the /etc/passwd file structure — path traversal succeeded.",
        {"status_code": 200, "body_preview": "[DEMO — simulated evidence, no real device was contacted]"},
        "2026-08-19T00:00:00+00:00", "2026-08-19T00:00:01+00:00", 42.0,
    )
    queries.set_device_cve_verification(conn, cam_id, cve["cve_id"], verification.RESULT_VERIFIED_VULNERABLE)
    gate = exploitation.check_gate(conn, cam_id, cve["cve_id"])
    result_id = queries.record_exploit_authorization(
        conn, cam_id, cve["cve_id"],
        f"exploits.{exploitation.find_exploit_definition(cve['cve_id']).module_path}" if gate["eligible"] else "N/A",
        "DEMO — simulated operator",
    )
    queries.record_exploit_outcome(
        conn, result_id,
        "[DEMO — SIMULATED, NOT A REAL EXPLOIT] This illustrates the EXPLOIT_SUCCESSFUL state and the "
        "real cameras.xiongmai.uc_httpd_path_traversal registry entry. No real device was contacted or exploited.",
        True,
    )

    # -----------------------------------------------------------------
    # DVR-01 — same real CVE/CPE data, but the CPE candidate is seeded at
    # CPE_CANDIDATE (not CONFIRMED) confidence -> applicability.py's own
    # real single-candidate cap -> POTENTIALLY_AFFECTED, not AFFECTED.
    # Verification deliberately not run -> exploitation gate blocks.
    # -----------------------------------------------------------------
    dvr_id = queries.insert_device(conn, session_id, network_id, {
        "ip_address": "203.0.113.11", "mac_address": "DE:M0:00:00:01:02",
        "vendor": "Hangzhou Xiongmai Technology Co.,Ltd.",
        "open_ports": json.dumps([{"port": 80, "service": "http"}]),
        "os_guess": None, "device_type": "DVR", "mdns_name": None, "fingerprint_confidence": 0.7,
    })
    queries.update_device_identity(conn, dvr_id, vendor="Xiongmai", product="uc-httpd", version="4.02.r11.3070")
    queries.replace_cpe_candidates(conn, dvr_id, [
        {"cpe": cve["cpe_firmware"], "confidence": 0.6, "status": "CPE_CANDIDATE",
         "source": "nvd_cpe_dictionary", "identity_basis": "vendor+product match, version match, but hardware part not confirmed"},
    ])
    queries.upsert_device_cve_intelligence(conn, dvr_id, {
        "cve_id": cve["cve_id"], "source_cpe": [cve["cpe_firmware"]], "correlation_method": "CPE",
        "description": cve["description"], "cvss_score": cve["cvss_score"], "cvss_version": cve["cvss_version"],
        "cvss_vector": cve["cvss_vector"], "cvss_severity": cve["cvss_severity"],
        "epss_score": cve["epss_score"], "epss_percentile": cve["epss_percentile"], "epss_date": cve["epss_date"],
        "kev_listed": cve["kev_listed"], "exploit_score": _score(cve),
        "configurations": cve["configurations"], "weaknesses": ["CWE-22"], "cve_references": [],
    })
    real_appl_dvr = applicability.determine_applicability(conn, dvr_id, cve["cve_id"])
    assert real_appl_dvr["status"] == "POTENTIALLY_AFFECTED", f"seed assumption broken: {real_appl_dvr}"
    # verification/exploitation deliberately never called for this device —
    # demonstrates the gate blocking on NOT_ATTEMPTED verification.

    # -----------------------------------------------------------------
    # MQTT-01 — real CVE-2017-16725, but keyword-correlated only (no CPE
    # data at all) -> applicability.py's hardcoded KEYWORD safety
    # invariant -> UNKNOWN, structurally, never AFFECTED.
    # -----------------------------------------------------------------
    cve2 = _REAL_CVE_2017_16725
    mqtt_id = queries.insert_device(conn, session_id, network_id, {
        "ip_address": "203.0.113.12", "mac_address": "DE:M0:00:00:01:03",
        "vendor": "Unknown", "open_ports": json.dumps([{"port": 1883, "service": "mqtt"}]),
        "os_guess": "Embedded Linux (guessed)", "device_type": "IoT Gateway", "mdns_name": None,
        "fingerprint_confidence": 0.9,
    })
    queries.insert_fingerprint_signature(conn, mqtt_id, "mqtt", "mqtt.connack", "accepted", 0.9)
    queries.upsert_device_cve_intelligence(conn, mqtt_id, {
        "cve_id": cve2["cve_id"], "source_cpe": [], "correlation_method": "KEYWORD",
        "description": cve2["description"], "cvss_score": cve2["cvss_score"],
        "epss_score": cve2["epss_score"], "kev_listed": cve2["kev_listed"], "exploit_score": _score(cve2),
    })
    real_appl_mqtt = applicability.determine_applicability(conn, mqtt_id, cve2["cve_id"])
    assert real_appl_mqtt["status"] == "UNKNOWN", f"seed assumption broken: {real_appl_mqtt}"

    # -----------------------------------------------------------------
    # Router-01 — real CVE-2017-7577/CPE data again, but a deliberately
    # mismatched observed firmware version -> applicability.py's real
    # version-comparison logic -> NOT_APPLICABLE, not a guess.
    # -----------------------------------------------------------------
    router_id = queries.insert_device(conn, session_id, network_id, {
        "ip_address": "203.0.113.13", "mac_address": "DE:M0:00:00:01:04",
        "vendor": "Hangzhou Xiongmai Technology Co.,Ltd.",
        "open_ports": json.dumps([{"port": 80, "service": "http"}]),
        "os_guess": None, "device_type": "Router", "mdns_name": None, "fingerprint_confidence": 0.6,
    })
    queries.update_device_identity(conn, router_id, vendor="Xiongmai", product="uc-httpd", version="5.00.r00.0000")
    queries.replace_cpe_candidates(conn, router_id, [
        {"cpe": cve["cpe_firmware"], "confidence": 0.6, "status": "CPE_CANDIDATE",
         "source": "nvd_cpe_dictionary", "identity_basis": "vendor+product match; observed version does not match the vulnerable configuration"},
    ])
    queries.upsert_device_cve_intelligence(conn, router_id, {
        "cve_id": cve["cve_id"], "source_cpe": [cve["cpe_firmware"]], "correlation_method": "CPE",
        "description": cve["description"], "cvss_score": cve["cvss_score"], "cvss_version": cve["cvss_version"],
        "cvss_vector": cve["cvss_vector"], "cvss_severity": cve["cvss_severity"],
        "epss_score": cve["epss_score"], "epss_percentile": cve["epss_percentile"], "epss_date": cve["epss_date"],
        "kev_listed": cve["kev_listed"], "exploit_score": _score(cve),
        "configurations": cve["configurations"], "weaknesses": ["CWE-22"], "cve_references": [],
    })
    real_appl_router = applicability.determine_applicability(conn, router_id, cve["cve_id"])
    assert real_appl_router["status"] == "NOT_APPLICABLE", f"seed assumption broken: {real_appl_router}"
