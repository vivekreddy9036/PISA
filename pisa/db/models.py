import sqlite3


def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS assessments (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        status          TEXT    DEFAULT 'active',
        created_at      TEXT    NOT NULL,
        started_at      TEXT,
        completed_at    TEXT,
        notes           TEXT
    );

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

    CREATE TABLE IF NOT EXISTS verification_attempts (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id         INTEGER REFERENCES devices(id),
        cve_id            TEXT    NOT NULL,
        test_id           TEXT    NOT NULL,
        result            TEXT    NOT NULL,
        execution_state   TEXT,
        reason            TEXT,
        evidence          TEXT,
        duration_ms       REAL,
        started_at        TEXT    NOT NULL,
        completed_at      TEXT
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

    CREATE TABLE IF NOT EXISTS cpe_candidates (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id        INTEGER REFERENCES devices(id),
        cpe              TEXT,
        confidence       REAL,
        status           TEXT    NOT NULL,
        source           TEXT,
        identity_basis   TEXT,
        nvd_cpe_name_id  TEXT,
        fetched_at       TEXT    NOT NULL
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
    _migrate_assessment_link(conn)
    _migrate_device_identity_columns(conn)
    _migrate_cve_status_columns(conn)
    _migrate_exploit_status_column(conn)
    _migrate_device_cve_intelligence_columns(conn)
    _migrate_applicability_reason_column(conn)


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


def _migrate_assessment_link(conn: sqlite3.Connection) -> None:
    """Add a nullable assessment_id to sessions (Phase 1). Assessment is a
    higher-level grouping a session may optionally belong to — existing
    sessions, and all existing code that creates/reads them, keep working
    unmodified with assessment_id left NULL."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    if "assessment_id" not in existing:
        conn.execute("ALTER TABLE sessions ADD COLUMN assessment_id INTEGER REFERENCES assessments(id)")
    conn.commit()


def _migrate_device_identity_columns(conn: sqlite3.Connection) -> None:
    """Add structured identity columns to devices (Phase 1), distinct from
    the existing `vendor` column: `vendor` is the raw OUI-derived guess M1
    already populates during discovery: identity_* is reserved for a future
    fused/verified identity (Phase 2), which may agree with, refine, or
    contradict the raw OUI guess. Nullable/unpopulated until Phase 2 writes
    to them; existing device_type/fingerprint_confidence are untouched and
    keep meaning exactly what they did before."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    migrations = {
        "identity_vendor": "ALTER TABLE devices ADD COLUMN identity_vendor TEXT",
        "identity_product": "ALTER TABLE devices ADD COLUMN identity_product TEXT",
        "identity_model": "ALTER TABLE devices ADD COLUMN identity_model TEXT",
        "identity_firmware": "ALTER TABLE devices ADD COLUMN identity_firmware TEXT",
        "identity_version": "ALTER TABLE devices ADD COLUMN identity_version TEXT",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)
    conn.commit()


def _migrate_cve_status_columns(conn: sqlite3.Connection) -> None:
    """Add applicability_status/verification_status to network_cves and
    device_cves (Phase 1). Defaults are the honest "nothing has determined
    this yet" state, not an inferred guess: UNKNOWN for applicability
    (Phase 1 has no CPE/applicability logic to run), NOT_ATTEMPTED for
    verification (no verification engine exists yet, so nothing has been
    attempted for any existing row either). insert_network_cve/
    insert_device_cve's ON CONFLICT clauses don't reference these columns,
    so a repeated "Check CVEs" keyword-search re-fetch leaves whatever
    applicability/verification state Phase 5/6 later set untouched."""
    for table in ("network_cves", "device_cves"):
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if "applicability_status" not in existing:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN applicability_status TEXT DEFAULT 'UNKNOWN'"
            )
        if "verification_status" not in existing:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN verification_status TEXT DEFAULT 'NOT_ATTEMPTED'"
            )
    conn.commit()


def _migrate_exploit_status_column(conn: sqlite3.Connection) -> None:
    """Add exploitation_status to exploit_results (Phase 1), backfilling
    existing rows from the pre-existing `success`/`result` columns rather
    than leaving genuinely-already-attempted historical rows mislabeled
    NOT_ATTEMPTED. The enum has no generic "errored" bucket yet (that's
    Phase 7's RouterSploit-reliability work), so a row whose authorization
    was recorded but never got an outcome (crashed mid-run, see NFR-7) is
    conservatively backfilled to EXPLOIT_FAILED rather than invented as
    something more specific. Runs exactly once per database, guarded the
    same way every other migration here is — by the column not existing
    yet — so it never re-touches a row after Phase 7 starts setting this
    column with full state-transition precision."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(exploit_results)")}
    if "exploitation_status" not in existing:
        conn.execute(
            "ALTER TABLE exploit_results ADD COLUMN exploitation_status TEXT DEFAULT 'NOT_ATTEMPTED'"
        )
        conn.execute(
            """
            UPDATE exploit_results
            SET exploitation_status = CASE WHEN success = 1 THEN 'EXPLOIT_SUCCESSFUL' ELSE 'EXPLOIT_FAILED' END
            WHERE authorized_at IS NOT NULL
            """
        )
    conn.commit()


def _migrate_device_cve_intelligence_columns(conn: sqlite3.Connection) -> None:
    """Phase 4: extend device_cves with the fields the CPE-based NVD CVE
    API 2.0 pipeline produces, on top of the cvss_score/epss_score/
    kev_listed/exploit_score/description columns that already exist and
    are reused as-is (not duplicated). All nullable — an existing row
    from the old keyword-only flow (pisa/m0/oui_cve.py, still unmodified
    and still working) simply has these as NULL/'KEYWORD' until Phase 4's
    pipeline enriches it, never silently reinterpreted as CPE-sourced
    data it doesn't have.

    network_cves is deliberately NOT extended here — networks have no
    structured identity/CPE input (Phase 2/3 are device-scoped only), so
    there is no code path that would ever populate these columns for a
    network row. See .scratch/pisa-phase4-vulnerability-intelligence.md
    for the full column-by-column justification.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(device_cves)")}
    migrations = {
        # how this row was found: 'CPE' (authoritative), 'CPE_AMBIGUOUS'
        # (authoritative but multi-candidate), 'KEYWORD' (secondary,
        # never promotes applicability — see cve_lookup.py)
        "correlation_method": "ALTER TABLE device_cves ADD COLUMN correlation_method TEXT",
        # JSON list of the CPE(s) that produced this finding — a list
        # even for a single CPE, for a consistent shape; [] for KEYWORD
        "source_cpe": "ALTER TABLE device_cves ADD COLUMN source_cpe TEXT",
        "nvd_status": "ALTER TABLE device_cves ADD COLUMN nvd_status TEXT",
        "nvd_published": "ALTER TABLE device_cves ADD COLUMN nvd_published TEXT",
        "nvd_last_modified": "ALTER TABLE device_cves ADD COLUMN nvd_last_modified TEXT",
        "cvss_version": "ALTER TABLE device_cves ADD COLUMN cvss_version TEXT",
        "cvss_vector": "ALTER TABLE device_cves ADD COLUMN cvss_vector TEXT",
        "cvss_severity": "ALTER TABLE device_cves ADD COLUMN cvss_severity TEXT",
        "epss_percentile": "ALTER TABLE device_cves ADD COLUMN epss_percentile REAL",
        "epss_date": "ALTER TABLE device_cves ADD COLUMN epss_date TEXT",
        "kev_date_added": "ALTER TABLE device_cves ADD COLUMN kev_date_added TEXT",
        "kev_due_date": "ALTER TABLE device_cves ADD COLUMN kev_due_date TEXT",
        "kev_known_ransomware_use": "ALTER TABLE device_cves ADD COLUMN kev_known_ransomware_use TEXT",
        "weaknesses": "ALTER TABLE device_cves ADD COLUMN weaknesses TEXT",  # JSON list of CWE IDs
        # JSON list; column named cve_references, not "references" (reserved word)
        "cve_references": "ALTER TABLE device_cves ADD COLUMN cve_references TEXT",
        # full raw NVD configurations block, verbatim — Phase 5's
        # applicability engine needs version ranges/cpeMatch/logical
        # nodes intact, not flattened away here
        "configurations": "ALTER TABLE device_cves ADD COLUMN configurations TEXT",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)
    conn.commit()


def _migrate_applicability_reason_column(conn: sqlite3.Connection) -> None:
    """Phase 5: one additional column, not a parallel status system.
    applicability_status (Phase 1) keeps holding the enum value
    (UNKNOWN/NO_CPE_DATA/POTENTIALLY_AFFECTED/AFFECTED/NOT_APPLICABLE);
    this column holds the JSON-encoded explanation (matched_cpe,
    matched_criteria_id, matched_criteria, version_evaluated,
    candidate_verdicts for the CPE_AMBIGUOUS case, reason text,
    evaluated_at) an evaluation produced for it. Deliberately one
    compact provenance column, not six+ separate ones — see
    .scratch/pisa-phase5-applicability.md for why a full second
    evaluation-result table wasn't necessary."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(device_cves)")}
    if "applicability_reason" not in existing:
        conn.execute("ALTER TABLE device_cves ADD COLUMN applicability_reason TEXT")
    conn.commit()
