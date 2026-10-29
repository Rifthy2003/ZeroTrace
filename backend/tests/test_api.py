import os
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
from fastapi.testclient import TestClient
from app.main import app


def test_health():
    with TestClient(app) as c:
        assert c.get("/api/health").json() == {"status": "ok"}


def test_requires_authorization_confirmation():
    with TestClient(app) as c:
        r = c.post("/api/scans", json={"target_url": "http://example.com", "authorization_confirmed": False})
        assert r.status_code == 422


def test_rejects_private_target():
    with TestClient(app) as c:
        r = c.post("/api/scans", json={"target_url": "http://127.0.0.1:9000", "authorization_confirmed": True})
        assert r.status_code == 400


def test_unknown_scan_404():
    with TestClient(app) as c:
        assert c.get("/api/scans/nope").status_code == 404


def test_list_scans_and_stats():
    with TestClient(app) as c:
        assert c.get("/api/scans").status_code == 200
        assert "by_severity" in c.get("/api/scans/stats/overview").json()
