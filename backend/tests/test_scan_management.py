import os
import uuid
import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import SessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.finding import Finding, Severity, Confidence


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def sample_target(db_session):
    t = Target(
        id=f"t-{uuid.uuid4()}",
        base_url="https://audit-target.local",
        hostname="audit-target.local",
    )
    db_session.add(t)
    db_session.commit()
    try:
        yield t
    finally:
        # Clean up any leftover scans or target to avoid test fixture leaks
        try:
            db_session.query(Scan).filter(Scan.target_id == t.id).delete()
            db_session.delete(t)
            db_session.commit()
        except Exception:
            db_session.rollback()


def test_rename_scan(sample_target, db_session):
    scan_id = f"scan-rename-{uuid.uuid4()}"
    s = Scan(
        id=scan_id,
        target_id=sample_target.id,
        status=ScanStatus.COMPLETED,
        name="Original Scan Title",
    )
    db_session.add(s)
    db_session.commit()

    with TestClient(app) as c:
        # Rename scan
        r = c.patch(f"/api/scans/{scan_id}", json={"name": "Q4 Penetration Audit"})
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Q4 Penetration Audit"

        # Verify persisted in database
        db_session.refresh(s)
        assert s.name == "Q4 Penetration Audit"

    # Cleanup
    db_session.delete(s)
    db_session.commit()


def test_soft_delete_and_trash_filtering(sample_target, db_session):
    scan_id = f"scan-softdel-{uuid.uuid4()}"
    s = Scan(
        id=scan_id,
        target_id=sample_target.id,
        status=ScanStatus.COMPLETED,
        is_deleted=False,
    )
    db_session.add(s)
    db_session.commit()

    with TestClient(app) as c:
        # 1. Verify scan is in active list
        res_active = c.get("/api/scans").json()
        assert any(x["id"] == scan_id for x in res_active)

        # 2. Soft delete the scan
        res_del = c.delete(f"/api/scans/{scan_id}")
        assert res_del.status_code == 200
        assert res_del.json()["status"] == "deleted"

        # 3. Verify scan is now hidden from normal active scan history
        res_active_after = c.get("/api/scans").json()
        assert not any(x["id"] == scan_id for x in res_active_after)

        # 4. Verify scan is visible in Trash
        res_trash = c.get("/api/scans?trash_only=true").json()
        assert any(x["id"] == scan_id for x in res_trash)

        # 5. Verify direct GET /api/scans/{id} returns 404 (hidden)
        res_direct = c.get(f"/api/scans/{scan_id}")
        assert res_direct.status_code == 404

        # 6. Restore the scan
        res_restore = c.post(f"/api/scans/{scan_id}/restore")
        assert res_restore.status_code == 200
        assert res_restore.json()["is_deleted"] is False

        # 7. Verify back in active list
        res_active_restored = c.get("/api/scans").json()
        assert any(x["id"] == scan_id for x in res_active_restored)

    # Cleanup
    db_session.delete(s)
    db_session.commit()


def test_cannot_delete_running_scan(sample_target, db_session):
    scan_id = f"scan-running-{uuid.uuid4()}"
    s = Scan(
        id=scan_id,
        target_id=sample_target.id,
        status=ScanStatus.RUNNING,
        is_deleted=False,
    )
    db_session.add(s)
    db_session.commit()

    with TestClient(app) as c:
        # Attempt to delete running scan
        r = c.delete(f"/api/scans/{scan_id}")
        assert r.status_code == 400
        assert "running scan" in r.json()["detail"].lower()

    # Cleanup
    db_session.delete(s)
    db_session.commit()


def test_permanent_delete_from_trash(sample_target, db_session):
    scan_id = f"scan-perm-{uuid.uuid4()}"
    unrelated_id = f"scan-unrelated-{uuid.uuid4()}"

    s = Scan(
        id=scan_id,
        target_id=sample_target.id,
        status=ScanStatus.COMPLETED,
        is_deleted=False,
    )
    s_unrelated = Scan(
        id=unrelated_id,
        target_id=sample_target.id,
        status=ScanStatus.COMPLETED,
        is_deleted=False,
    )
    db_session.add_all([s, s_unrelated])
    db_session.commit()

    with TestClient(app) as c:
        # Cannot permanently delete if not in trash
        r_premature = c.delete(f"/api/scans/{scan_id}/permanent")
        assert r_premature.status_code == 400

        # Move to trash first
        c.delete(f"/api/scans/{scan_id}")

        # Now permanently delete from trash
        r_perm = c.delete(f"/api/scans/{scan_id}/permanent")
        assert r_perm.status_code == 200
        assert r_perm.json()["status"] == "permanently_deleted"

        # Verify completely gone from DB
        assert db_session.get(Scan, scan_id) is None

        # Verify unrelated scan is completely intact
        assert db_session.get(Scan, unrelated_id) is not None

    # Cleanup unrelated
    db_session.delete(s_unrelated)
    db_session.commit()


def test_bulk_delete_and_restore(sample_target, db_session):
    id1 = f"scan-b1-{uuid.uuid4()}"
    id2 = f"scan-b2-{uuid.uuid4()}"
    id_running = f"scan-b-running-{uuid.uuid4()}"

    s1 = Scan(id=id1, target_id=sample_target.id, status=ScanStatus.COMPLETED)
    s2 = Scan(id=id2, target_id=sample_target.id, status=ScanStatus.COMPLETED)
    sr = Scan(id=id_running, target_id=sample_target.id, status=ScanStatus.RUNNING)

    db_session.add_all([s1, s2, sr])
    db_session.commit()

    with TestClient(app) as c:
        # Bulk soft delete
        r_bulk = c.post("/api/scans/bulk/delete", json={"scan_ids": [id1, id2, id_running]})
        assert r_bulk.status_code == 200
        res = r_bulk.json()
        assert res["count"] == 2  # Running scan skipped
        assert id1 in res["deleted_ids"]
        assert id2 in res["deleted_ids"]
        assert id_running not in res["deleted_ids"]

        # Bulk restore
        r_restore = c.post("/api/scans/bulk/restore", json={"scan_ids": [id1, id2]})
        assert r_restore.status_code == 200
        assert r_restore.json()["count"] == 2

        # Bulk permanent delete (move back to trash first)
        c.post("/api/scans/bulk/delete", json={"scan_ids": [id1, id2]})
        r_purge = c.post("/api/scans/bulk/permanent", json={"scan_ids": [id1, id2]})
        assert r_purge.status_code == 200
        assert r_purge.json()["count"] == 2

        assert db_session.get(Scan, id1) is None
        assert db_session.get(Scan, id2) is None

    # Cleanup running
    db_session.delete(sr)
    db_session.commit()

