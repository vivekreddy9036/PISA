"""Tests for DEMO / PRESENTATION MODE (pisa/m5/routes/demo.py,
pisa/m5/demo_seed.py). Uses the same real Flask test client pattern as
tests/m5/test_routes.py — never mocks the app factory or the demo seed
logic itself, since the whole point is proving the real state-machine
functions produce the states the demo UI displays.
"""
import pytest

from pisa.db import queries
from pisa.db.connection import get_connection


@pytest.fixture
def demo_db(tmp_path):
    return str(tmp_path / "demo.db")


@pytest.fixture
def app_with_demo(db, demo_db):
    from pisa.m5.app import create_app
    return create_app(db_path=db, demo_db_path=demo_db)


@pytest.fixture
def demo_client(app_with_demo):
    return app_with_demo.test_client()


# 1. DEMO navigation exists
def test_demo_nav_link_present_on_real_dashboard(demo_client):
    resp = demo_client.get("/")
    assert resp.status_code == 200
    assert b"[ DEMO ]" in resp.data
    assert b'href="/demo/"' in resp.data


# 2. DEMO route loads
def test_demo_overview_route_loads(demo_client):
    resp = demo_client.get("/demo/")
    assert resp.status_code == 200
    assert b"DEMO MODE" in resp.data
    assert b"SIMULATED" in resp.data


# 3. DEMO database is isolated
def test_demo_database_is_a_separate_file_from_real_db(app_with_demo, db, demo_db):
    assert db != demo_db
    with get_connection(demo_db) as conn:
        demo_sessions = queries.get_sessions(conn)
    with get_connection(db) as conn:
        real_sessions = queries.get_sessions(conn)
    assert len(demo_sessions) >= 1
    assert real_sessions == []  # the real (test) DB has nothing — untouched by demo seeding


# 4. Demo provenance is present
def test_demo_session_carries_demo_replay_provenance(app_with_demo, demo_db):
    with get_connection(demo_db) as conn:
        sessions = queries.get_sessions(conn)
    assert len(sessions) == 1
    assert sessions[0]["notes"] == "DEMO_REPLAY"


# 5. Real assessments are unaffected
def test_real_dashboard_and_sessions_route_unaffected_by_demo_mode(demo_client, db):
    with get_connection(db) as conn:
        session_id = queries.create_session(conn, target_network="Real Test Net")
    resp = demo_client.get(f"/sessions/{session_id}")
    assert resp.status_code == 200
    assert b"DEMO MODE" not in resp.data


# 6. Switching DEMO -> REAL works
def test_switching_between_demo_and_real_navigation_links(demo_client):
    demo_resp = demo_client.get("/demo/")
    assert b"Real Assessments" in demo_resp.data
    real_resp = demo_client.get("/")
    assert b"[ DEMO ]" in real_resp.data


# 7. Demo device details render
def test_demo_device_detail_renders(demo_client, demo_db):
    with get_connection(demo_db) as conn:
        devices = queries.get_devices(conn, queries.get_sessions(conn)[0]["id"])
    resp = demo_client.get(f"/demo/devices/{devices[0]['id']}")
    assert resp.status_code == 200
    assert b"Identity" in resp.data
    assert b"Services / Evidence" in resp.data


# 8. Demo CVE information renders
def test_demo_device_cve_information_renders(demo_client, demo_db):
    with get_connection(demo_db) as conn:
        devices = queries.get_devices(conn, queries.get_sessions(conn)[0]["id"])
    device_id = devices[0]["id"]  # Camera-01, has a real CVE-2017-7577 finding
    resp = demo_client.get(f"/demo/devices/{device_id}")
    assert b"CVE-2017-7577" in resp.data
    assert b"CVSS" in resp.data
    assert b"EPSS" in resp.data


# 9. Demo applicability renders
def test_demo_applicability_states_render_for_all_four_devices(demo_client, demo_db):
    with get_connection(demo_db) as conn:
        devices = queries.get_devices(conn, queries.get_sessions(conn)[0]["id"])
    expected = {"AFFECTED", "POTENTIALLY_AFFECTED", "UNKNOWN", "NOT_APPLICABLE"}
    seen = set()
    for d in devices:
        resp = demo_client.get(f"/demo/devices/{d['id']}")
        for status in expected:
            if f'>{status}<'.encode() in resp.data:
                seen.add(status)
    assert seen == expected, f"missing applicability states in demo rendering: {expected - seen}"


# 10. Demo verification/exploitation state renders
def test_demo_verification_and_exploitation_states_render(demo_client, demo_db):
    with get_connection(demo_db) as conn:
        devices = queries.get_devices(conn, queries.get_sessions(conn)[0]["id"])
    device_id = devices[0]["id"]  # Camera-01 — the one seeded all the way through
    resp = demo_client.get(f"/demo/devices/{device_id}")
    assert b"VERIFIED_VULNERABLE" in resp.data
    assert b"EXPLOIT_SUCCESSFUL" in resp.data
    assert b"SIMULATED" in resp.data  # redacted/labeled evidence, never presented as a real exploit
    assert b"DEMO" in resp.data


# 11. Production pisa.db is never modified
def test_demo_seeding_never_touches_the_real_configured_db_path(tmp_path):
    import config
    from pisa.db.connection import get_connection as gc
    from pisa.db.models import create_tables

    # Simulate "production" as a distinct, pre-existing file with its own data,
    # and confirm creating a demo-enabled app never writes to it.
    prod_db = str(tmp_path / "would_be_pisa.db")
    with gc(prod_db) as conn:
        create_tables(conn)
        queries.create_session(conn, target_network="production data — must survive untouched")

    from pisa.m5.app import create_app
    demo_db = str(tmp_path / "isolated_demo.db")
    create_app(db_path=prod_db, demo_db_path=demo_db)

    with gc(prod_db) as conn:
        sessions = queries.get_sessions(conn)
    assert len(sessions) == 1
    assert sessions[0]["target_network"] == "production data — must survive untouched"
    assert sessions[0]["notes"] != "DEMO_REPLAY"


def test_demo_seed_is_idempotent_across_repeated_app_creation(tmp_path):
    from pisa.m5.app import create_app
    demo_db = str(tmp_path / "demo_idempotent.db")
    db1 = str(tmp_path / "real1.db")
    db2 = str(tmp_path / "real2.db")

    create_app(db_path=db1, demo_db_path=demo_db)
    with get_connection(demo_db) as conn:
        count_after_first = len(queries.get_sessions(conn))

    create_app(db_path=db2, demo_db_path=demo_db)  # re-create app against the same demo DB
    with get_connection(demo_db) as conn:
        count_after_second = len(queries.get_sessions(conn))

    assert count_after_first == count_after_second == 1  # not duplicated
