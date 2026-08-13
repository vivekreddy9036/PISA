import json
import sqlite3
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_session(
    conn: sqlite3.Connection,
    target_network: str = None,
    notes: str = None,
    assessment_id: int | None = None,
) -> int:
    c = conn.cursor()
    c.execute(
        "INSERT INTO sessions (started_at, target_network, notes, assessment_id) VALUES (?, ?, ?, ?)",
        (_now(), target_network, notes, assessment_id),
    )
    conn.commit()
    return c.lastrowid


def create_assessment(conn: sqlite3.Connection, notes: str = None) -> int:
    c = conn.cursor()
    now = _now()
    c.execute(
        "INSERT INTO assessments (status, created_at, notes) VALUES ('active', ?, ?)",
        (now, notes),
    )
    conn.commit()
    return c.lastrowid


def get_assessment(conn: sqlite3.Connection, assessment_id: int) -> dict | None:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
    row = c.fetchone()
    return dict(row) if row else None


def close_session(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute(
        "UPDATE sessions SET ended_at = ?, status = 'done' WHERE id = ?",
        (_now(), session_id),
    )
    conn.commit()


def mark_session_running(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute("UPDATE sessions SET status = 'running' WHERE id = ?", (session_id,))
    conn.commit()


def fail_session(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute(
        "UPDATE sessions SET ended_at = ?, status = 'error' WHERE id = ?",
        (_now(), session_id),
    )
    conn.commit()


def insert_network(conn: sqlite3.Connection, session_id: int, data: dict) -> int:
    c = conn.cursor()
    now = _now()
    c.execute(
        """
        INSERT INTO networks
            (session_id, bssid, ssid, channel, signal_dbm, security, encryption,
             beacon_interval, pmf_enabled, wps_enabled, hidden, wsps_score, wsps_grade,
             first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(bssid, session_id) DO UPDATE SET
            signal_dbm = excluded.signal_dbm,
            wsps_score  = excluded.wsps_score,
            wsps_grade  = excluded.wsps_grade,
            last_seen   = excluded.last_seen
        """,
        (
            session_id,
            data["bssid"],
            data.get("ssid"),
            data.get("channel"),
            data.get("signal_dbm"),
            data.get("security"),
            data.get("encryption"),
            data.get("beacon_interval"),
            data.get("pmf_enabled", 0),
            data.get("wps_enabled", 0),
            data.get("hidden", 0),
            data.get("wsps_score"),
            data.get("wsps_grade"),
            now,
            now,
        ),
    )
    conn.commit()
    return c.lastrowid


def insert_device(conn: sqlite3.Connection, session_id: int, network_id: int, data: dict) -> int:
    c = conn.cursor()
    now = _now()
    c.execute(
        """
        INSERT INTO devices
            (session_id, network_id, ip_address, mac_address, vendor, open_ports,
             os_guess, device_type, mdns_name, fingerprint_confidence, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            network_id,
            data["ip_address"],
            data.get("mac_address"),
            data.get("vendor"),
            data.get("open_ports"),
            data.get("os_guess"),
            data.get("device_type"),
            data.get("mdns_name"),
            data.get("fingerprint_confidence"),
            now,
            now,
        ),
    )
    conn.commit()
    return c.lastrowid


def insert_network_cve(conn: sqlite3.Connection, network_id: int, data: dict) -> int:
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO network_cves
            (network_id, cve_id, cvss_score, epss_score, kev_listed,
             exploit_score, description, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(network_id, cve_id) DO UPDATE SET
            cvss_score    = excluded.cvss_score,
            epss_score    = excluded.epss_score,
            kev_listed    = excluded.kev_listed,
            exploit_score = excluded.exploit_score,
            description   = excluded.description,
            fetched_at    = excluded.fetched_at
        """,
        (
            network_id,
            data["cve_id"],
            data.get("cvss_score"),
            data.get("epss_score"),
            data.get("kev_listed", 0),
            data.get("exploit_score"),
            data.get("description"),
            _now(),
        ),
    )
    conn.commit()
    return c.lastrowid


def insert_device_cve(conn: sqlite3.Connection, device_id: int, data: dict) -> int:
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO device_cves
            (device_id, cve_id, cvss_score, epss_score, kev_listed,
             exploit_score, description, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, cve_id) DO UPDATE SET
            cvss_score    = excluded.cvss_score,
            epss_score    = excluded.epss_score,
            kev_listed    = excluded.kev_listed,
            exploit_score = excluded.exploit_score,
            description   = excluded.description,
            fetched_at    = excluded.fetched_at
        """,
        (
            device_id,
            data["cve_id"],
            data.get("cvss_score"),
            data.get("epss_score"),
            data.get("kev_listed", 0),
            data.get("exploit_score"),
            data.get("description"),
            _now(),
        ),
    )
    conn.commit()
    return c.lastrowid


def upsert_device_cve_intelligence(conn: sqlite3.Connection, device_id: int, finding: dict) -> int:
    """Persist a normalized CPE/keyword-correlated CVE finding (Phase 4 —
    pisa/m3/cve_lookup.py). Same (device_id, cve_id) unique key as
    insert_device_cve (the old keyword-only flow, unmodified) — an
    upsert here on a row insert_device_cve already created enriches it
    with authoritative CPE-sourced data rather than creating a
    duplicate. Deliberately does NOT touch applicability_status /
    verification_status (Phase 1 columns): CVE discovery is Phase 4's
    job, deciding whether it applies or was verified is Phase 5/6's —
    leaving those columns out of this ON CONFLICT clause means they keep
    whatever value they already had (or the column DEFAULT for a brand
    new row), never silently advanced by this function."""
    c = conn.cursor()
    now = _now()
    c.execute(
        """
        INSERT INTO device_cves
            (device_id, cve_id, cvss_score, epss_score, kev_listed, description, fetched_at,
             correlation_method, source_cpe, nvd_status, nvd_published, nvd_last_modified,
             cvss_version, cvss_vector, cvss_severity, epss_percentile, epss_date,
             kev_date_added, kev_due_date, kev_known_ransomware_use,
             weaknesses, cve_references, configurations)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, cve_id) DO UPDATE SET
            cvss_score               = excluded.cvss_score,
            epss_score                = excluded.epss_score,
            kev_listed                 = excluded.kev_listed,
            description                = excluded.description,
            fetched_at                 = excluded.fetched_at,
            correlation_method         = excluded.correlation_method,
            source_cpe                 = excluded.source_cpe,
            nvd_status                 = excluded.nvd_status,
            nvd_published               = excluded.nvd_published,
            nvd_last_modified          = excluded.nvd_last_modified,
            cvss_version                = excluded.cvss_version,
            cvss_vector                 = excluded.cvss_vector,
            cvss_severity                = excluded.cvss_severity,
            epss_percentile              = excluded.epss_percentile,
            epss_date                    = excluded.epss_date,
            kev_date_added               = excluded.kev_date_added,
            kev_due_date                  = excluded.kev_due_date,
            kev_known_ransomware_use       = excluded.kev_known_ransomware_use,
            weaknesses                     = excluded.weaknesses,
            cve_references                 = excluded.cve_references,
            configurations                  = excluded.configurations
        """,
        (
            device_id,
            finding["cve_id"],
            finding.get("cvss_score"),
            finding.get("epss_score"),
            int(bool(finding.get("kev_listed"))),
            finding.get("description"),
            now,
            finding.get("correlation_method"),
            json.dumps(finding.get("source_cpe") or []),
            finding.get("nvd_status"),
            finding.get("nvd_published"),
            finding.get("nvd_last_modified"),
            finding.get("cvss_version"),
            finding.get("cvss_vector"),
            finding.get("cvss_severity"),
            finding.get("epss_percentile"),
            finding.get("epss_date"),
            finding.get("kev_date_added"),
            finding.get("kev_due_date"),
            finding.get("kev_known_ransomware_use"),
            json.dumps(finding.get("weaknesses") or []),
            json.dumps(finding.get("cve_references") or []),
            json.dumps(finding.get("configurations")) if finding.get("configurations") is not None else None,
        ),
    )
    conn.commit()
    return c.lastrowid


def get_device_cves(conn: sqlite3.Connection, device_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM device_cves WHERE device_id = ?", (device_id,))
    return [dict(r) for r in c.fetchall()]


def get_device_cve(conn: sqlite3.Connection, device_id: int, cve_id: str) -> dict | None:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM device_cves WHERE device_id = ? AND cve_id = ?", (device_id, cve_id))
    row = c.fetchone()
    return dict(row) if row else None


def set_device_cve_applicability(
    conn: sqlite3.Connection, device_id: int, cve_id: str, status: str, reason: dict | None = None,
) -> None:
    """Phase 5 only ever writes applicability_status/applicability_reason
    — never verification_status (Phase 6's column, untouched here) and
    never exploitation_status (Phase 7's)."""
    conn.execute(
        "UPDATE device_cves SET applicability_status = ?, applicability_reason = ? WHERE device_id = ? AND cve_id = ?",
        (status, json.dumps(reason) if reason is not None else None, device_id, cve_id),
    )
    conn.commit()


def set_device_cve_verification(conn: sqlite3.Connection, device_id: int, cve_id: str, status: str) -> None:
    """Phase 6 only ever writes verification_status here — never
    applicability_status (Phase 5's, one-way dependency: applicability
    feeds verification, never the reverse) and never exploitation_status
    (a future phase's)."""
    conn.execute(
        "UPDATE device_cves SET verification_status = ? WHERE device_id = ? AND cve_id = ?",
        (status, device_id, cve_id),
    )
    conn.commit()


def record_verification_attempt(
    conn: sqlite3.Connection, device_id: int, cve_id: str, test_id: str,
    result: str, execution_state: str, reason: str, evidence: dict,
    started_at: str, completed_at: str, duration_ms: float,
) -> int:
    """Append-only audit log of verification attempts — same pattern as
    exploit_results (pisa/m4/routersploit_gate.py's audit trail), not a
    new architecture: one row per attempt, device_cves.verification_status
    holds only the latest/current conclusion. Supports "multiple
    verification attempts over time" without overwriting history."""
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO verification_attempts
            (device_id, cve_id, test_id, result, execution_state, reason,
             evidence, duration_ms, started_at, completed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_id, cve_id, test_id, result, execution_state, reason,
            json.dumps(evidence) if evidence is not None else None,
            duration_ms, started_at, completed_at,
        ),
    )
    conn.commit()
    return c.lastrowid


def get_verification_attempts(conn: sqlite3.Connection, device_id: int, cve_id: str | None = None) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if cve_id is not None:
        c.execute(
            "SELECT * FROM verification_attempts WHERE device_id = ? AND cve_id = ? ORDER BY id DESC",
            (device_id, cve_id),
        )
    else:
        c.execute("SELECT * FROM verification_attempts WHERE device_id = ? ORDER BY id DESC", (device_id,))
    return [dict(r) for r in c.fetchall()]


def get_device_by_id(conn: sqlite3.Connection, device_id: int) -> dict | None:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = c.fetchone()
    return dict(row) if row else None


def record_exploit_authorization(
    conn: sqlite3.Connection,
    device_id: int,
    cve_id: str,
    module_path: str,
    authorized_by: str,
) -> int:
    """Insert the audit row *before* routersploit_gate.run_exploit() is
    called (NFR-7): authorization is durably committed even if the
    RouterSploit call hangs or the process dies mid-run.
    record_exploit_outcome() fills in the result afterwards. executed_at
    starts equal to authorized_at (satisfies NOT NULL) and is overwritten
    once the outcome is known."""
    c = conn.cursor()
    now = _now()
    c.execute(
        """
        INSERT INTO exploit_results
            (device_id, cve_id, module_path, authorized_by, authorized_at,
             result, success, executed_at)
        VALUES (?, ?, ?, ?, ?, NULL, 0, ?)
        """,
        (device_id, cve_id, module_path, authorized_by, now, now),
    )
    conn.commit()
    return c.lastrowid


def record_exploit_outcome(
    conn: sqlite3.Connection, result_id: int, result: str, success: bool, timed_out: bool = False,
) -> None:
    """Fill in the outcome of an already-authorized exploit attempt (see
    record_exploit_authorization). Phase 7: `timed_out` now gives TIMEOUT
    its own exploitation_status, distinct from EXPLOIT_FAILED — a hung
    RouterSploit call is not evidence the target isn't vulnerable, and
    collapsing the two would lose exactly the distinction instruction 7
    requires. Defaults to False so every pre-Phase-7 caller is
    unaffected."""
    c = conn.cursor()
    if timed_out:
        status = "TIMEOUT"
    else:
        status = "EXPLOIT_SUCCESSFUL" if success else "EXPLOIT_FAILED"
    c.execute(
        "UPDATE exploit_results SET result = ?, success = ?, executed_at = ?, exploitation_status = ? WHERE id = ?",
        (result, int(success), _now(), status, result_id),
    )
    conn.commit()


def get_exploit_results(conn: sqlite3.Connection, device_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM exploit_results WHERE device_id = ? ORDER BY executed_at DESC", (device_id,))
    return [dict(r) for r in c.fetchall()]


def insert_fingerprint_signature(
    conn: sqlite3.Connection,
    device_id: int,
    protocol: str,
    feature_key: str,
    feature_value: str | None,
    confidence: float | None,
) -> int:
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO fingerprint_signatures
            (device_id, protocol, feature_key, feature_value, confidence, captured_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (device_id, protocol, feature_key, feature_value, confidence, _now()),
    )
    conn.commit()
    return c.lastrowid


def get_fingerprint_signatures(conn: sqlite3.Connection, device_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM fingerprint_signatures WHERE device_id = ?", (device_id,))
    return [dict(r) for r in c.fetchall()]


def update_device_fingerprint(
    conn: sqlite3.Connection,
    device_id: int,
    device_type: str | None,
    confidence: float | None,
) -> None:
    conn.execute(
        "UPDATE devices SET device_type = ?, fingerprint_confidence = ?, last_seen = ? WHERE id = ?",
        (device_type, confidence, _now(), device_id),
    )
    conn.commit()


def update_device_identity(
    conn: sqlite3.Connection,
    device_id: int,
    vendor: str | None = None,
    product: str | None = None,
    model: str | None = None,
    firmware: str | None = None,
    version: str | None = None,
) -> None:
    """Write structured identity fields (Phase 1 data model only — no
    fusion logic calls this yet; that's Phase 2). Distinct from
    update_device_fingerprint, which owns the existing device_type/
    fingerprint_confidence pair."""
    conn.execute(
        """
        UPDATE devices
        SET identity_vendor = ?, identity_product = ?, identity_model = ?,
            identity_firmware = ?, identity_version = ?, last_seen = ?
        WHERE id = ?
        """,
        (vendor, product, model, firmware, version, _now(), device_id),
    )
    conn.commit()


def replace_cpe_candidates(conn: sqlite3.Connection, device_id: int, candidates: list[dict]) -> None:
    """Replace a device's whole CPE candidate set in one transaction. A
    fresh CPE mapping run is a full re-evaluation, not an incremental
    update to individual CPEs, so delete-then-insert (not an upsert keyed
    on `cpe`) matches the actual semantics — and sidesteps needing a
    UNIQUE constraint that would have to tolerate multiple NULL `cpe`
    rows (the NO_CPE_DATA/NVD_UNAVAILABLE status-only outcomes)."""
    now = _now()
    conn.execute("DELETE FROM cpe_candidates WHERE device_id = ?", (device_id,))
    for c in candidates:
        conn.execute(
            """
            INSERT INTO cpe_candidates
                (device_id, cpe, confidence, status, source, identity_basis, nvd_cpe_name_id, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id, c.get("cpe"), c.get("confidence"), c["status"], c.get("source"),
                c.get("identity_basis"), c.get("nvd_cpe_name_id"), now,
            ),
        )
    conn.commit()


def get_cpe_candidates(conn: sqlite3.Connection, device_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "SELECT * FROM cpe_candidates WHERE device_id = ? ORDER BY (confidence IS NULL) ASC, confidence DESC, id ASC",
        (device_id,),
    )
    return [dict(r) for r in c.fetchall()]


def insert_alert(
    conn: sqlite3.Connection,
    session_id: int,
    severity: str,
    category: str,
    message: str,
    related_id: int = None,
    related_type: str = None,
) -> int:
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO alerts
            (session_id, severity, category, message, related_id, related_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, severity, category, message, related_id, related_type, _now()),
    )
    conn.commit()
    return c.lastrowid


def get_sessions(conn: sqlite3.Connection) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM sessions ORDER BY started_at DESC")
    return [dict(r) for r in c.fetchall()]


def get_session(conn: sqlite3.Connection, session_id: int) -> dict | None:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    row = c.fetchone()
    return dict(row) if row else None


def get_network_cves(conn: sqlite3.Connection, network_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM network_cves WHERE network_id = ?", (network_id,))
    return [dict(r) for r in c.fetchall()]


def get_networks(conn: sqlite3.Connection, session_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM networks WHERE session_id = ? ORDER BY wsps_score DESC", (session_id,))
    return [dict(r) for r in c.fetchall()]


def get_devices(conn: sqlite3.Connection, session_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE session_id = ?", (session_id,))
    return [dict(r) for r in c.fetchall()]


def get_devices_for_network(conn: sqlite3.Connection, network_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE network_id = ?", (network_id,))
    return [dict(r) for r in c.fetchall()]


def get_network_by_id(conn: sqlite3.Connection, network_id: int) -> dict | None:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM networks WHERE id = ?", (network_id,))
    row = c.fetchone()
    return dict(row) if row else None


def mark_discovery_running(conn: sqlite3.Connection, network_id: int) -> None:
    conn.execute(
        "UPDATE networks SET discovery_status = 'running', discovery_started_at = ?, discovery_error = NULL WHERE id = ?",
        (_now(), network_id),
    )
    conn.commit()


def mark_discovery_done(conn: sqlite3.Connection, network_id: int) -> None:
    conn.execute(
        "UPDATE networks SET discovery_status = 'done', discovery_completed_at = ? WHERE id = ?",
        (_now(), network_id),
    )
    conn.commit()


def mark_discovery_error(conn: sqlite3.Connection, network_id: int, message: str) -> None:
    conn.execute(
        "UPDATE networks SET discovery_status = 'error', discovery_completed_at = ?, discovery_error = ? WHERE id = ?",
        (_now(), message, network_id),
    )
    conn.commit()


def find_network_by_bssid(conn: sqlite3.Connection, session_id: int, bssid: str) -> int | None:
    c = conn.cursor()
    c.execute(
        "SELECT id FROM networks WHERE session_id = ? AND bssid = ?",
        (session_id, bssid),
    )
    row = c.fetchone()
    return row[0] if row else None


def mark_handshake_captured(
    conn: sqlite3.Connection, network_id: int, handshake_type: str, path: str
) -> None:
    conn.execute(
        """
        UPDATE networks
        SET handshake_captured = 1, handshake_type = ?, handshake_path = ?, handshake_captured_at = ?
        WHERE id = ?
        """,
        (handshake_type, path, _now(), network_id),
    )
    conn.commit()
