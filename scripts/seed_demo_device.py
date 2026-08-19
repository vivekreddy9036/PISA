"""Seed a session/network/device row pointing at scripts/demo_iot_target.py's
local listeners, into a dedicated demo DB — never production pisa.db.

Deliberately bypasses M1's join/ARP-sweep entry point (no subnet scan): this
is the manual single-device seed path scripts/demo_iot_target.py's own
docstring suggests ("add a device row pointing at 127.0.0.1 ... or just call
the API directly against an existing device you've retargeted").

Usage:
    venv/bin/python scripts/seed_demo_device.py

No root needed (pure DB writes). Run scripts/demo_iot_target.py separately
(needs root, for RTSP's port 554) before fingerprinting the seeded device.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pisa.db.connection import get_connection
from pisa.db.models import create_tables
from pisa.db import queries

DEMO_DB = "/tmp/pisa_review_demo.db"


def main() -> None:
    if os.path.exists(DEMO_DB):
        os.remove(DEMO_DB)

    with get_connection(DEMO_DB) as conn:
        create_tables(conn)
        session_id = queries.create_session(conn, target_network="Controlled Local Demo")
        network_id = queries.insert_network(conn, session_id, {
            "bssid": "00:00:00:00:00:00", "ssid": "Controlled Local Demo",
        })
        device_id = queries.insert_device(conn, session_id, network_id, {
            "ip_address": "127.0.0.1",
            "open_ports": json.dumps([
                {"port": 8080, "service": "http"},
                {"port": 554, "service": "rtsp"},
            ]),
        })

    print(f"[seed] db={DEMO_DB}")
    print(f"[seed] session_id={session_id} network_id={network_id} device_id={device_id}")
    print(f"[seed] Now run: venv/bin/python scripts/run_demo_dashboard.py")
    print(f"[seed] Then open http://127.0.0.1:5050/sessions/{session_id} and click Fingerprint / Check CVEs.")


if __name__ == "__main__":
    main()
