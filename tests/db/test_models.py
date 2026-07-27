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
