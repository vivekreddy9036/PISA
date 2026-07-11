import sqlite3
from flask import Flask, jsonify
import config
from pisa.db.models import create_tables


def create_app() -> Flask:
    app = Flask(__name__)

    with sqlite3.connect(config.DB_PATH) as conn:
        create_tables(conn)

    @app.route("/")
    def index():
        return jsonify({
            "system": "PISA — Portable IoT Security Assessment",
            "version": "0.1.0",
            "status": "running",
            "modules": {
                "M0": "WiFi / WSPS",
                "M1": "Network Discovery",
                "M2": "Behavioral Fingerprinting",
                "M3": "CVE Correlation",
                "M4": "Exploit Pipeline",
                "M5": "Reporting",
            },
        })

    @app.route("/health")
    def health():
        try:
            with sqlite3.connect(config.DB_PATH) as conn:
                conn.execute("SELECT 1")
            db_ok = True
        except Exception as e:
            db_ok = False
        return jsonify({
            "db": "ok" if db_ok else "error",
            "wifi_iface": config.WIFI_IFACE,
        }), 200 if db_ok else 503

    return app
