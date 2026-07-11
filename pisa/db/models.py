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
        hidden           INTEGER DEFAULT 0,
        wsps_score       INTEGER,
        wsps_grade       TEXT,
        first_seen       TEXT    NOT NULL,
        last_seen        TEXT    NOT NULL,
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
        fetched_at     TEXT    NOT NULL
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
        fetched_at     TEXT    NOT NULL
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
