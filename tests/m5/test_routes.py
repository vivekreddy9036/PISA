import time

from pisa.db import queries
from pisa.db.connection import get_connection


def _wait_for_scan(client, session_id, attempts=50, delay=0.1):
    status = None
    for _ in range(attempts):
        status = client.get(f"/api/scan/{session_id}/status").get_json()["status"]
        if status in ("done", "error"):
            break
        time.sleep(delay)
    return status


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["db"] == "ok"


def test_index_empty_state(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"No scans yet" in resp.data


def test_scan_and_session_detail_flow(client):
    resp = client.post("/api/scan", json={"demo": True, "duration": 1})
    assert resp.status_code == 200
    session_id = resp.get_json()["session_id"]

    status = _wait_for_scan(client, session_id)
    assert status == "done"

    detail = client.get(f"/sessions/{session_id}")
    assert detail.status_code == 200
    assert b"grade grade-" in detail.data

    index = client.get("/")
    assert f"/sessions/{session_id}".encode() in index.data


def test_check_cves_for_demo_network(client, db):
    resp = client.post("/api/scan", json={"demo": True, "duration": 1})
    session_id = resp.get_json()["session_id"]
    assert _wait_for_scan(client, session_id) == "done"

    with get_connection(db) as conn:
        networks = queries.get_networks(conn, session_id)
    network_id = networks[0]["id"]

    resp = client.post(f"/api/networks/{network_id}/cves")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["cves"]) > 0


def test_session_detail_404_for_missing_session(client):
    resp = client.get("/sessions/999")
    assert resp.status_code == 404
