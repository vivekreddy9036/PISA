import sqlite3


def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS sessions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at      TEXT    NOT NULL,
        ended_at        TEXT,
        target_network  TEXT,
        status          TEXT    DEFAULT 'active',
        notes           TEXT
    );

    CREATE TABLE IF NOT EXISTS networks (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id       INTEGER REFERENCES sessions(id),
        bssid            TEXT    NOT NULL,
        ssid             TEXT,
        channel          INTEGER,
        signal_dbm       INTEGER,
        security         TEXT,
        encryption       TEXT,
        beacon_interval  INTEGER,
        pmf_enabled      INTEGER DEFAULT 0,
        wps_enabled      INTEGER DEFAULT 0,
        hidden           INTEGER DEFAULT 0,
        wsps_score       INTEGER,
        wsps_grade       TEXT,
        first_seen       TEXT    NOT NULL,
        last_seen        TEXT    NOT NULL,
        handshake_captured    INTEGER DEFAULT 0,
        handshake_type        TEXT,
        handshake_path        TEXT,
        handshake_captured_at TEXT,
        discovery_status         TEXT,
        discovery_started_at     TEXT,
        discovery_completed_at   TEXT,
        discovery_error          TEXT,
        UNIQUE(bssid, session_id)
    );

    CREATE TABLE IF NOT EXISTS network_cves (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        network_id     INTEGER REFERENCES networks(id),
        cve_id         TEXT    NOT NULL,
        cvss_score     REAL,
        epss_score     REAL,
        kev_listed     INTEGER DEFAULT 0,
        exploit_score  REAL,
        description    TEXT,
        fetched_at     TEXT    NOT NULL,
        UNIQUE(network_id, cve_id)
    );

    CREATE TABLE IF NOT EXISTS devices (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id            INTEGER REFERENCES sessions(id),
        network_id            INTEGER REFERENCES networks(id),
        ip_address            TEXT    NOT NULL,
        mac_address           TEXT,
        vendor                TEXT,
        open_ports            TEXT,
        os_guess              TEXT,
        device_type           TEXT,
        mdns_name             TEXT,
        fingerprint_confidence REAL,
        first_seen            TEXT    NOT NULL,
        last_seen             TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS device_cves (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id      INTEGER REFERENCES devices(id),
        cve_id         TEXT    NOT NULL,
        cvss_score     REAL,
        epss_score     REAL,
        kev_listed     INTEGER DEFAULT 0,
        exploit_score  REAL,
        description    TEXT,
        fetched_at     TEXT    NOT NULL,
        UNIQUE(device_id, cve_id)
    );

    CREATE TABLE IF NOT EXISTS exploit_results (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id      INTEGER REFERENCES devices(id),
        cve_id         TEXT,
        module_path    TEXT    NOT NULL,
        authorized_by  TEXT    NOT NULL,
        authorized_at  TEXT    NOT NULL,
        result         TEXT,
        success        INTEGER DEFAULT 0,
        executed_at    TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fingerprint_signatures (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id     INTEGER REFERENCES devices(id),
        protocol      TEXT    NOT NULL,
        feature_key   TEXT    NOT NULL,
        feature_value TEXT,
        confidence    REAL,
        captured_at   TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS behavioral_drift (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id        INTEGER REFERENCES devices(id),
        protocol         TEXT    NOT NULL,
        baseline_value   TEXT,
        observed_value   TEXT,
        drift_score      REAL,
        flagged          INTEGER DEFAULT 0,
        detected_at      TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id    INTEGER REFERENCES sessions(id),
        severity      TEXT    NOT NULL,
        category      TEXT    NOT NULL,
        message       TEXT    NOT NULL,
        related_id    INTEGER,
        related_type  TEXT,
        acknowledged  INTEGER DEFAULT 0,
        created_at    TEXT    NOT NULL
    );
    """)
    conn.commit()
    _migrate_handshake_columns(conn)
    _migrate_discovery_columns(conn)
    _migrate_mdns_column(conn)
    _migrate_cve_uniqueness(conn)


def _migrate_handshake_columns(conn: sqlite3.Connection) -> None:
    """Add handshake_* columns to networks for DBs created before Sprint 2."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(networks)")}
    migrations = {
        "handshake_captured": "ALTER TABLE networks ADD COLUMN handshake_captured INTEGER DEFAULT 0",
        "handshake_type": "ALTER TABLE networks ADD COLUMN handshake_type TEXT",
        "handshake_path": "ALTER TABLE networks ADD COLUMN handshake_path TEXT",
        "handshake_captured_at": "ALTER TABLE networks ADD COLUMN handshake_captured_at TEXT",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)
    conn.commit()


def _migrate_mdns_column(conn: sqlite3.Connection) -> None:
    """Add mdns_name to devices for DBs created before mDNS identification."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    if "mdns_name" not in existing:
        conn.execute("ALTER TABLE devices ADD COLUMN mdns_name TEXT")
    conn.commit()


def _migrate_discovery_columns(conn: sqlite3.Connection) -> None:
    """Add discovery_* columns to networks for DBs created before M1."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(networks)")}
    migrations = {
        "discovery_status": "ALTER TABLE networks ADD COLUMN discovery_status TEXT",
        "discovery_started_at": "ALTER TABLE networks ADD COLUMN discovery_started_at TEXT",
        "discovery_completed_at": "ALTER TABLE networks ADD COLUMN discovery_completed_at TEXT",
        "discovery_error": "ALTER TABLE networks ADD COLUMN discovery_error TEXT",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)
    conn.commit()


def _table_has_unique(conn: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> bool:
    for idx in conn.execute(f"PRAGMA index_list({table})").fetchall():
        if not idx[2]:  # not a UNIQUE index
            continue
        idx_columns = [c[2] for c in conn.execute(f"PRAGMA index_info({idx[1]})").fetchall()]
        if idx_columns == list(columns):
            return True
    return False


def _migrate_cve_uniqueness(conn: sqlite3.Connection) -> None:
    """Enforce one row per (network_id/device_id, cve_id) on network_cves
    and device_cves. Repeated "Check CVEs" clicks used to blindly INSERT
    instead of upserting, so a DB from before this migration may already
    have duplicate rows per CVE — this rebuild keeps only the
    highest-id (most recently fetched) row per duplicate group. SQLite
    can't ALTER TABLE to add a UNIQUE constraint after the fact, so the
    table is recreated rather than altered in place."""
    for table, fk_column, ref_table in (
        ("network_cves", "network_id", "networks"),
        ("device_cves", "device_id", "devices"),
    ):
        if _table_has_unique(conn, table, (fk_column, "cve_id")):
            continue
        conn.executescript(f"""
            CREATE TABLE {table}_new (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                {fk_column}    INTEGER REFERENCES {ref_table}(id),
                cve_id         TEXT    NOT NULL,
                cvss_score     REAL,
                epss_score     REAL,
                kev_listed     INTEGER DEFAULT 0,
                exploit_score  REAL,
                description    TEXT,
                fetched_at     TEXT    NOT NULL,
                UNIQUE({fk_column}, cve_id)
            );
            INSERT INTO {table}_new
                (id, {fk_column}, cve_id, cvss_score, epss_score, kev_listed, exploit_score, description, fetched_at)
            SELECT id, {fk_column}, cve_id, cvss_score, epss_score, kev_listed, exploit_score, description, fetched_at
            FROM {table}
            WHERE id IN (SELECT MAX(id) FROM {table} GROUP BY {fk_column}, cve_id);
            DROP TABLE {table};
            ALTER TABLE {table}_new RENAME TO {table};
        """)
        conn.commit()
