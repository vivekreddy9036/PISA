import argparse

import config
from pisa.db.connection import get_connection
from pisa.db.models import create_tables
from pisa.m5.app import create_app


def init_db() -> None:
    with get_connection(config.DB_PATH) as conn:
        create_tables(conn)
    print(f"[PISA] Database ready at {config.DB_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PISA — Portable IoT Security Assessment")
    parser.add_argument("--scan", action="store_true", help="Run one scan headlessly and exit (no Flask server)")
    parser.add_argument("--demo", action="store_true", help="Use synthetic demo data instead of live capture")
    parser.add_argument("--duration", type=int, default=config.SCAN_DEFAULT_DURATION, help="Scan duration in seconds")
    parser.add_argument("--iface", default=config.WIFI_IFACE, help="WiFi interface in monitor mode")
    args = parser.parse_args()

    init_db()

    if args.scan:
        from pisa.db import queries
        from pisa.m0.scan_runner import run_scan

        with get_connection(config.DB_PATH) as conn:
            session_id = queries.create_session(conn, notes="demo" if args.demo else None)
        run_scan(session_id, args.iface, args.duration, demo=args.demo, db_path=config.DB_PATH)
        return

    app = create_app()
    print(f"[PISA] Listening on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)


if __name__ == "__main__":
    main()
