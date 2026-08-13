import sqlite3

from pisa.db.models import _table_has_unique, create_tables


def test_create_tables_adds_cve_uniqueness_constraints(db):
    with sqlite3.connect(db) as conn:
        assert _table_has_unique(conn, "network_cves", ("network_id", "cve_id"))
        assert _table_has_unique(conn, "device_cves", ("device_id", "cve_id"))


def test_migrate_cve_uniqueness_dedupes_pre_existing_duplicates(tmp_path):
    """Simulate a DB created before the UNIQUE constraint existed, with
    the duplicate rows that blindly-appending inserts used to produce,
    and confirm the migration collapses them to one row each, keeping
    the most recently inserted (highest-id) values."""
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, ended_at TEXT, target_network TEXT, status TEXT DEFAULT 'active', notes TEXT);
        CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, bssid TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, network_id INTEGER, ip_address TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE network_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT, network_id INTEGER, cve_id TEXT NOT NULL,
            cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL,
            description TEXT, fetched_at TEXT NOT NULL
        );
        CREATE TABLE device_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT NOT NULL,
            cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL,
            description TEXT, fetched_at TEXT NOT NULL
        );
        INSERT INTO network_cves (network_id, cve_id, cvss_score, epss_score, fetched_at)
            VALUES (1, 'CVE-2021-1234', 9.8, 0.1, 't1'), (1, 'CVE-2021-1234', 9.8, 0.9, 't2');
        INSERT INTO device_cves (device_id, cve_id, cvss_score, epss_score, fetched_at)
            VALUES (5, 'CVE-2020-3118', 8.8, 0.1, 't1'), (5, 'CVE-2020-3118', 8.8, 0.4, 't2'), (5, 'CVE-2020-3118', 8.8, 0.9, 't3');
    """)
    conn.commit()
    conn.close()

    with sqlite3.connect(db_path) as conn:
        create_tables(conn)
        network_cves = conn.execute("SELECT * FROM network_cves").fetchall()
        device_cves = conn.execute("SELECT * FROM device_cves").fetchall()
        assert _table_has_unique(conn, "network_cves", ("network_id", "cve_id"))
        assert _table_has_unique(conn, "device_cves", ("device_id", "cve_id"))

    assert len(network_cves) == 1
    assert len(device_cves) == 1
    # kept the highest-id (most recently inserted) row's data
    assert device_cves[0][4] == 0.9  # epss_score column


# ---------------------------------------------------------------------------
# Phase 1: assessments, structured identity, vulnerability/exploit state
# ---------------------------------------------------------------------------

def test_fresh_database_has_phase1_tables_and_columns(db):
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "assessments" in tables

        session_cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
        assert "assessment_id" in session_cols

        device_cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        assert {"identity_vendor", "identity_product", "identity_model", "identity_firmware", "identity_version"} <= device_cols

        for table in ("network_cves", "device_cves"):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            assert {"applicability_status", "verification_status"} <= cols

        exploit_cols = {r[1] for r in conn.execute("PRAGMA table_info(exploit_results)")}
        assert "exploitation_status" in exploit_cols


def test_fresh_database_has_cpe_candidates_table(db):
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "cpe_candidates" in tables
        cols = {r[1] for r in conn.execute("PRAGMA table_info(cpe_candidates)")}
        assert {"device_id", "cpe", "confidence", "status", "source", "identity_basis", "nvd_cpe_name_id", "fetched_at"} <= cols


def test_migrate_pre_phase3_database_adds_cpe_candidates_table(tmp_path):
    """cpe_candidates is a wholly new table — CREATE TABLE IF NOT EXISTS
    is sufficient for both fresh and pre-existing databases, no ALTER-
    based migration function needed (same pattern as Phase 1's
    `assessments` table)."""
    db_path = str(tmp_path / "legacy3.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, ended_at TEXT, target_network TEXT, status TEXT DEFAULT 'active', notes TEXT);
        CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, bssid TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, network_id INTEGER, ip_address TEXT, first_seen TEXT, last_seen TEXT);
    """)
    conn.commit()
    conn.close()

    with sqlite3.connect(db_path) as conn:
        create_tables(conn)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    assert "cpe_candidates" in tables


def test_fresh_database_has_device_cve_intelligence_columns(db):
    with sqlite3.connect(db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(device_cves)")}
    expected = {
        "correlation_method", "source_cpe", "nvd_status", "nvd_published", "nvd_last_modified",
        "cvss_version", "cvss_vector", "cvss_severity", "epss_percentile", "epss_date",
        "kev_date_added", "kev_due_date", "kev_known_ransomware_use", "weaknesses",
        "cve_references", "configurations",
    }
    assert expected <= cols


def test_fresh_database_has_verification_attempts_table(db):
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "verification_attempts" in tables
        cols = {r[1] for r in conn.execute("PRAGMA table_info(verification_attempts)")}
    expected = {
        "device_id", "cve_id", "test_id", "result", "execution_state",
        "reason", "evidence", "duration_ms", "started_at", "completed_at",
    }
    assert expected <= cols

    with sqlite3.connect(db) as conn:
        applicability_cols = {r[1] for r in conn.execute("PRAGMA table_info(device_cves)")}
    assert "applicability_reason" in applicability_cols  # Phase 5's column, still present/unmodified


def test_migrate_pre_phase4_database_adds_columns_without_data_loss(tmp_path):
    """A pre-Phase-4 device_cves row (from the old keyword-only flow)
    must survive migration intact, with the new columns present and
    NULL — never silently backfilled with a guess."""
    db_path = str(tmp_path / "legacy4.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, ended_at TEXT, target_network TEXT, status TEXT DEFAULT 'active', notes TEXT);
        CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, bssid TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, network_id INTEGER, ip_address TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE device_cves (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT NOT NULL, cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL, description TEXT, fetched_at TEXT NOT NULL, UNIQUE(device_id, cve_id));
        INSERT INTO device_cves (device_id, cve_id, cvss_score, description, fetched_at) VALUES (1, 'CVE-2017-16725', 9.8, 'legacy keyword-found row', 't0');
    """)
    conn.commit()
    conn.close()

    with sqlite3.connect(db_path) as conn:
        create_tables(conn)
        row = dict(zip(
            [d[0] for d in conn.execute("SELECT * FROM device_cves").description],
            conn.execute("SELECT * FROM device_cves WHERE cve_id = 'CVE-2017-16725'").fetchone(),
        ))

    assert row["cvss_score"] == 9.8
    assert row["description"] == "legacy keyword-found row"
    assert row["correlation_method"] is None
    assert row["configurations"] is None


def test_migrate_pre_phase1_database_adds_columns_without_data_loss(tmp_path):
    """Simulate a real pre-Phase-1 database (the exact schema shape
    create_tables produced before this phase) with existing rows, and
    confirm the migration adds every new table/column without touching
    or losing existing data."""
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, ended_at TEXT, target_network TEXT, status TEXT DEFAULT 'active', notes TEXT);
        CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, bssid TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, network_id INTEGER, ip_address TEXT, vendor TEXT, device_type TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE network_cves (id INTEGER PRIMARY KEY AUTOINCREMENT, network_id INTEGER, cve_id TEXT NOT NULL, cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL, description TEXT, fetched_at TEXT NOT NULL, UNIQUE(network_id, cve_id));
        CREATE TABLE device_cves (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT NOT NULL, cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL, description TEXT, fetched_at TEXT NOT NULL, UNIQUE(device_id, cve_id));
        CREATE TABLE exploit_results (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT, module_path TEXT NOT NULL, authorized_by TEXT NOT NULL, authorized_at TEXT NOT NULL, result TEXT, success INTEGER DEFAULT 0, executed_at TEXT NOT NULL);

        INSERT INTO sessions (started_at, target_network) VALUES ('t0', 'LegacyNet');
        INSERT INTO devices (session_id, ip_address, vendor, device_type) VALUES (1, '192.168.1.10', 'Xiongmai', 'IP Camera');
        INSERT INTO network_cves (network_id, cve_id, cvss_score, fetched_at) VALUES (1, 'CVE-2017-7577', 7.5, 't0');
        INSERT INTO exploit_results (device_id, cve_id, module_path, authorized_by, authorized_at, result, success, executed_at)
            VALUES (1, 'CVE-2019-16920', 'exploits.routers.dlink.dir_655_866_652_rce', 'vivek', 't0', 'Target appears vulnerable.', 1, 't0');
        INSERT INTO exploit_results (device_id, cve_id, module_path, authorized_by, authorized_at, result, success, executed_at)
            VALUES (1, 'CVE-2017-6077', 'exploits.routers.netgear.dgn2200_ping_cgi_rce', 'vivek', 't0', NULL, 0, 't0');
    """)
    conn.commit()
    conn.close()

    with sqlite3.connect(db_path) as conn:
        create_tables(conn)

        # existing data intact
        session = conn.execute("SELECT * FROM sessions WHERE id = 1").fetchone()
        assert session is not None
        device = dict(zip([d[0] for d in conn.execute("SELECT * FROM devices").description],
                           conn.execute("SELECT * FROM devices WHERE id = 1").fetchone()))
        assert device["vendor"] == "Xiongmai"
        assert device["device_type"] == "IP Camera"
        assert device["identity_vendor"] is None  # new column, not backfilled with a guess

        cve = dict(zip([d[0] for d in conn.execute("SELECT * FROM network_cves").description],
                        conn.execute("SELECT * FROM network_cves WHERE id = 1").fetchone()))
        assert cve["cvss_score"] == 7.5
        assert cve["applicability_status"] == "UNKNOWN"
        assert cve["verification_status"] == "NOT_ATTEMPTED"

        # exploit_results backfill: a real prior success stays SUCCESSFUL,
        # a prior failure (success=0, result populated) becomes FAILED
        rows = {r[0]: r[1] for r in conn.execute("SELECT cve_id, exploitation_status FROM exploit_results")}
        assert rows["CVE-2019-16920"] == "EXPLOIT_SUCCESSFUL"
        assert rows["CVE-2017-6077"] == "EXPLOIT_FAILED"


def test_migrate_pre_phase1_database_is_idempotent(tmp_path):
    """Running create_tables twice against an already-migrated database
    must not error, duplicate columns, or re-run the exploit_results
    backfill a second time."""
    db_path = str(tmp_path / "legacy2.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, ended_at TEXT, target_network TEXT, status TEXT DEFAULT 'active', notes TEXT);
        CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, bssid TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, network_id INTEGER, ip_address TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE network_cves (id INTEGER PRIMARY KEY AUTOINCREMENT, network_id INTEGER, cve_id TEXT NOT NULL, cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL, description TEXT, fetched_at TEXT NOT NULL, UNIQUE(network_id, cve_id));
        CREATE TABLE device_cves (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT NOT NULL, cvss_score REAL, epss_score REAL, kev_listed INTEGER DEFAULT 0, exploit_score REAL, description TEXT, fetched_at TEXT NOT NULL, UNIQUE(device_id, cve_id));
        CREATE TABLE exploit_results (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT, module_path TEXT NOT NULL, authorized_by TEXT NOT NULL, authorized_at TEXT NOT NULL, result TEXT, success INTEGER DEFAULT 0, executed_at TEXT NOT NULL);
        INSERT INTO exploit_results (device_id, cve_id, module_path, authorized_by, authorized_at, result, success, executed_at)
            VALUES (1, 'CVE-2018-9995', 'exploits.cameras.multi.dvr_creds_disclosure', 'vivek', 't0', 'ok', 1, 't0');
    """)
    conn.commit()
    conn.close()

    with sqlite3.connect(db_path) as conn:
        create_tables(conn)
        create_tables(conn)  # second pass must be a no-op, not an error
        row = conn.execute("SELECT exploitation_status FROM exploit_results WHERE id = 1").fetchone()

    assert row[0] == "EXPLOIT_SUCCESSFUL"
