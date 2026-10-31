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
        r = c.post("/api/scans", json={"target_url": "http://10.0.0.1:9000", "authorization_confirmed": True})
        assert r.status_code == 400


def test_rejects_local_dev_target_when_disabled(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "ALLOW_LOCAL_DEV_TARGET", False)
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_NETWORK_TARGETS", False)
    with TestClient(app) as c:
        r = c.post("/api/scans", json={"target_url": "http://localhost:49704/", "authorization_confirmed": True})
        assert r.status_code == 400
        assert "local development target" in r.json()["detail"].lower()


def test_accepts_local_dev_target_when_enabled(monkeypatch):
    from app.core.config import settings
    from app.api import scans as scans_api
    monkeypatch.setattr(settings, "ALLOW_LOCAL_DEV_TARGET", True)
    monkeypatch.setattr(scans_api, "start_scan_task", lambda scan_id: None)
    with TestClient(app) as c:
        for port in (49704, 50091, 5173, 3000, 8000):
            r = c.post("/api/scans", json={"target_url": f"http://localhost:{port}/", "authorization_confirmed": True})
            assert r.status_code == 201
            data = r.json()
            assert data["status"] in ("pending", "running", "completed")



def test_unknown_scan_404():
    with TestClient(app) as c:
        assert c.get("/api/scans/nope").status_code == 404


def test_list_scans_and_stats():
    with TestClient(app) as c:
        assert c.get("/api/scans").status_code == 200
        assert "by_severity" in c.get("/api/scans/stats/overview").json()
