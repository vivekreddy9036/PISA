import sqlite3
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_session(conn: sqlite3.Connection, target_network: str = None, notes: str = None) -> int:
    c = conn.cursor()
    c.execute(
        "INSERT INTO sessions (started_at, target_network, notes) VALUES (?, ?, ?)",
        (_now(), target_network, notes),
    )
    conn.commit()
    return c.lastrowid


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


def get_device_cves(conn: sqlite3.Connection, device_id: int) -> list:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM device_cves WHERE device_id = ?", (device_id,))
    return [dict(r) for r in c.fetchall()]


def get_device_by_id(conn: sqlite3.Connection, device_id: int) -> dict | None:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = c.fetchone()
    return dict(row) if row else None


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
