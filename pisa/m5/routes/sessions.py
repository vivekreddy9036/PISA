from flask import Blueprint, abort, current_app, render_template

from pisa.db import queries
from pisa.db.connection import get_connection

bp = Blueprint("sessions", __name__)


@bp.route("/sessions/<int:session_id>")
def detail(session_id):
    with get_connection(current_app.config["DB_PATH"]) as conn:
        session = queries.get_session(conn, session_id)
        if session is None:
            abort(404)
        networks = queries.get_networks(conn, session_id)
        cves_by_network = {n["id"]: queries.get_network_cves(conn, n["id"]) for n in networks}
    return render_template(
        "session_detail.html",
        session=session,
        networks=networks,
        cves_by_network=cves_by_network,
    )
