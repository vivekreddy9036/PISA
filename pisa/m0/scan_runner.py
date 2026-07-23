import config
from pisa.db import queries
from pisa.db.connection import get_connection
from pisa.m0 import beacon_capture, demo_data


def run_scan(
    session_id: int,
    iface: str,
    timeout: int,
    demo: bool = False,
    db_path: str = config.DB_PATH,
) -> None:
    """Run a WiFi scan (real or demo) and drive the session through
    running -> done/error. Used by both the CLI (--scan) and the web API."""
    with get_connection(db_path) as conn:
        queries.mark_session_running(conn, session_id)

    try:
        if demo:
            with get_connection(db_path) as conn:
                for data in demo_data.generate_demo_networks():
                    beacon_capture.score_and_store(conn, session_id, dict(data))
        else:
            beacon_capture.start_capture(session_id, db_path, iface, timeout)
    except Exception as e:
        with get_connection(db_path) as conn:
            queries.insert_alert(conn, session_id, "error", "scan", f"Scan failed: {e}")
            queries.fail_session(conn, session_id)
        return

    with get_connection(db_path) as conn:
        queries.close_session(conn, session_id)
