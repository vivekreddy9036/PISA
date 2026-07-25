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
    parser.add_argument("--duration", type=int, default=config.SCAN_DEFAULT_DURATION, help="Scan duration in seconds")
    parser.add_argument("--iface", default=config.WIFI_IFACE, help="WiFi interface in monitor mode")
    parser.add_argument("--join-network", metavar="SSID", help="Join this SSID and run device discovery, headlessly")
    parser.add_argument("--password", default="", help="Password for --join-network")
    parser.add_argument("--join-iface", default=config.JOIN_IFACE, help="Managed-mode interface used to join the network")
    args = parser.parse_args()

    init_db()

    if args.scan:
        from pisa.db import queries
        from pisa.m0.scan_runner import run_scan

        with get_connection(config.DB_PATH) as conn:
            session_id = queries.create_session(conn)
        run_scan(session_id, args.iface, args.duration, db_path=config.DB_PATH)
        return

    if args.join_network:
        from pisa.db import queries
        from pisa.m1.discovery_runner import run_discovery

        with get_connection(config.DB_PATH) as conn:
            session_id = queries.create_session(conn, target_network=args.join_network)
            # Standalone CLI join has no prior beacon scan to source a real BSSID
            # from; the network row exists only to anchor discovered devices.
            network_id = queries.insert_network(conn, session_id, {
                "bssid": "00:00:00:00:00:00", "ssid": args.join_network,
            })
        run_discovery(network_id, session_id, args.join_iface, args.join_network, args.password, db_path=config.DB_PATH)
        return

    app = create_app()
    print(f"[PISA] Listening on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)


if __name__ == "__main__":
    main()
