import sqlite3


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection with FK enforcement and dict-like rows.

    PRAGMA foreign_keys is per-connection, not persisted in the DB file,
    so every call site must go through here rather than sqlite3.connect().
    """
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn
