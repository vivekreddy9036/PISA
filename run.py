import sqlite3
import config
from pisa.db.models import create_tables
from pisa.m5.app import create_app


def init_db() -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        create_tables(conn)
    print(f"[PISA] Database ready at {config.DB_PATH}")


if __name__ == "__main__":
    init_db()
    app = create_app()
    print(f"[PISA] Listening on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
