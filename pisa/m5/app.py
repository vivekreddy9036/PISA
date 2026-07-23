from flask import Flask, jsonify
import config
from pisa.db.connection import get_connection
from pisa.db.models import create_tables
from pisa.m5.routes.api import bp as api_bp
from pisa.m5.routes.dashboard import bp as dashboard_bp
from pisa.m5.routes.sessions import bp as sessions_bp


def create_app(db_path: str = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or config.DB_PATH

    with get_connection(app.config["DB_PATH"]) as conn:
        create_tables(conn)

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(sessions_bp)
    app.register_blueprint(api_bp)

    @app.route("/api/info")
    def info():
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
            with get_connection(app.config["DB_PATH"]) as conn:
                conn.execute("SELECT 1")
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({
            "db": "ok" if db_ok else "error",
            "wifi_iface": config.WIFI_IFACE,
        }), 200 if db_ok else 503

    return app
