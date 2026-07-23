from flask import Blueprint, current_app, render_template

import config
from pisa.db import queries
from pisa.db.connection import get_connection

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    with get_connection(current_app.config["DB_PATH"]) as conn:
        sessions = queries.get_sessions(conn)
    return render_template(
        "index.html",
        sessions=sessions,
        default_iface=config.WIFI_IFACE,
        default_duration=config.SCAN_DEFAULT_DURATION,
    )
