"""Start the real PISA dashboard against the dedicated demo DB (never
production pisa.db), on a different port than the production instance so
both can run side by side during a demo.

Usage:
    venv/bin/python scripts/run_demo_dashboard.py

Run scripts/seed_demo_device.py first. No root needed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pisa.m5.app import create_app

DEMO_DB = "/tmp/pisa_review_demo.db"
DEMO_PORT = 5050

if __name__ == "__main__":
    app = create_app(db_path=DEMO_DB)
    print(f"[demo-dashboard] http://127.0.0.1:{DEMO_PORT}  (db={DEMO_DB})")
    app.run(host="127.0.0.1", port=DEMO_PORT, debug=False)
