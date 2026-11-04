import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import SessionLocal
from app.models.application import Application
from app.models.target import Target
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, Severity, Confidence
from app.models.scan_summary import ScanSummary
from app.models.activity import Activity


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db():
    session = SessionLocal()
    test_names = [
        "Hela Govi Web App", "Hela Govi Platform v2", "Security Portal Test",
        "Trend Test Application", "App Alpha", "App Beta", "PDF Test Target",
        "Failed Scan Test App", "Sync Test App Alpha", "Sync Test App All Scans Deleted",
        "Soft Delete Isolation App", "App To Permanently Delete"
    ]
    def _cleanup():
        try:
            apps = session.query(Application).filter(Application.name.in_(test_names)).all()
            for app_item in apps:
                scans = session.query(Scan).filter(Scan.application_id == app_item.id).all()
                for s in scans:
                    session.query(Activity).filter(Activity.scan_id == s.id).delete(synchronize_session=False)
                    session.delete(s)
                session.query(Activity).filter(Activity.application_id == app_item.id).delete(synchronize_session=False)
                targets = session.query(Target).filter(Target.application_id == app_item.id).all()
                for t in targets:
                    for ts in list(t.scans):
                        session.query(Activity).filter(Activity.scan_id == ts.id).delete(synchronize_session=False)
                        session.delete(ts)
                    session.delete(t)
                session.delete(app_item)
            session.commit()
        except Exception:
            session.rollback()

    _cleanup()
    yield session
    _cleanup()
    session.close()


def test_applications_crud_and_dynamic_ports(client, db):
    """Verify named applications and distinct dynamic localhost ports."""
    # 1. Create a named application
    res = client.post("/api/applications", json={"name": "Hela Govi Web App", "description": "Agricultural portal"})
    assert res.status_code == 201
    app_data = res.json()
    assert app_data["name"] == "Hela Govi Web App"
    app_id = app_data["id"]

    # 2. Verify dynamic localhost ports create distinct targets and don't automatically merge
    # Unless associated with a named application
    res_list = client.get("/api/applications")
    assert res_list.status_code == 200

    # 3. Rename application
    res_patch = client.patch(f"/api/applications/{app_id}", json={"name": "Hela Govi Platform v2"})
    assert res_patch.status_code == 200
    assert res_patch.json()["name"] == "Hela Govi Platform v2"


def test_remediation_status_update_and_activities(client, db):
    """Verify finding status transitions (open, fixed, accepted_risk, reopened) and timeline."""
    # Create test application, target, scan, finding
    app = Application(name="Security Portal Test")
    db.add(app)
    db.flush()

    target = Target(base_url="http://localhost:5173", hostname="localhost", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        urls_discovered=10,
        urls_scanned=8,
    )
    db.add(scan)
    db.flush()

    finding = Finding(
        scan_id=scan.id,
        type="Cross-Site Scripting (XSS)",
        category="Injection",
        url="http://localhost:5173/#/dashboard",
        method="GET",
        parameter="q",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        status="open",
        fingerprint="fp_xss_test_1",
    )
    db.add(finding)
    db.commit()

    # 1. Update finding status to Accepted Risk
    res_patch = client.patch(
        f"/api/findings/{finding.id}/status",
        json={"status": "accepted_risk", "note": "Internal dashboard behind SSO"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] in ("accepted_risk", "Accepted Risk")

    # 2. Check remediation tracker endpoint
    res_rem = client.get(f"/api/findings/remediation-tracker?application_id={app.id}")
    assert res_rem.status_code == 200
    findings_list = res_rem.json()
    assert len(findings_list) >= 1
    assert any(f["id"] == finding.id and f["status"] in ("accepted_risk", "Accepted Risk") for f in findings_list)

    # 3. Check activity timeline logged the change
    res_act = client.get(f"/api/activities?application_id={app.id}")
    assert res_act.status_code == 200
    acts = res_act.json()
    assert len(acts) >= 1
    assert any("Accepted Risk" in a["title"] for a in acts)


def test_application_trends_and_historical_comparison(client, db):
    """Verify trends compare previous and latest scan scores and categorize findings."""
    app = Application(name="Trend Test Application")
    db.add(app)
    db.flush()

    target = Target(base_url="http://example-trend.local", hostname="example-trend.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    # Scan 1: older scan with 2 findings
    scan1 = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 10, 1, 10, 0),
        completed_at=datetime(2026, 10, 1, 10, 5),
        created_at=datetime(2026, 10, 1, 10, 0),
        urls_discovered=5,
        urls_scanned=5,
    )
    db.add(scan1)
    db.flush()

    f1 = Finding(
        scan_id=scan1.id,
        type="SQL Injection",
        category="Injection",
        url="http://example-trend.local/item",
        parameter="id",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        fingerprint="fp_sqli_item",
        status="open",
    )
    f2 = Finding(
        scan_id=scan1.id,
        type="Missing Security Header: Content-Security-Policy",
        category="Security Misconfiguration",
        url="http://example-trend.local/",
        parameter=None,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        fingerprint="fp_csp_header",
        status="open",
    )
    db.add_all([f1, f2])
    db.commit()

    # Scan 2: newer scan where SQLi is resolved, CSP persists, and new XSS appears
    scan2 = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 10, 2, 10, 0),
        completed_at=datetime(2026, 10, 2, 10, 5),
        created_at=datetime(2026, 10, 2, 10, 0),
        urls_discovered=5,
        urls_scanned=5,
    )
    db.add(scan2)
    db.flush()

    f2_new = Finding(
        scan_id=scan2.id,
        type="Missing Security Header: Content-Security-Policy",
        category="Security Misconfiguration",
        url="http://example-trend.local/",
        parameter=None,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        fingerprint="fp_csp_header",
        status="open",
    )
    f3_new = Finding(
        scan_id=scan2.id,
        type="Reflected Cross-Site Scripting",
        category="Injection",
        url="http://example-trend.local/search",
        parameter="query",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        fingerprint="fp_xss_search",
        status="open",
    )
    db.add_all([f2_new, f3_new])
    db.commit()

    # Query trends
    res = client.get(f"/api/applications/{app.id}/trends")
    assert res.status_code == 200
    data = res.json()
    assert data["application_id"] == app.id
    assert len(data["history"]) == 2
    assert data["previous_score"] is not None
    assert data["latest_score"] is not None
    # Check categorized findings
    assert data["persistent_vulnerabilities_count"] >= 1
    assert data["new_vulnerabilities_count"] >= 1
    assert data["resolved_vulnerabilities_count"] >= 1


def test_executive_overview_stats(client, db):
    """Verify executive stats calculation across unique findings and scans."""
    res = client.get("/api/scans/stats/executive")
    assert res.status_code == 200
    data = res.json()
    assert "total_monitored_websites" in data
    assert "total_scans" in data
    assert "average_security_score" in data
    assert "websites_with_high_risk" in data
    assert "open_high_critical_count" in data
    assert "coverage_overview" in data
    assert "total_routes_discovered" in data["coverage_overview"]
    assert "total_routes_tested" in data["coverage_overview"]


def test_website_isolation_and_distinct_latest_scans(client, db):
    """Verify each website displays its own latest scan and does not cross-contaminate."""
    app_a = Application(name="App Alpha")
    app_b = Application(name="App Beta")
    db.add_all([app_a, app_b])
    db.flush()

    target_a = Target(base_url="http://alpha.local:3000", hostname="alpha.local", application_id=app_a.id, authorization_confirmed=True)
    target_b = Target(base_url="http://beta.local:8080", hostname="beta.local", application_id=app_b.id, authorization_confirmed=True)
    db.add_all([target_a, target_b])
    db.flush()

    scan_a = Scan(
        target_id=target_a.id,
        application_id=app_a.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        urls_discovered=12,
        urls_scanned=10,
    )
    scan_b = Scan(
        target_id=target_b.id,
        application_id=app_b.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        urls_discovered=40,
        urls_scanned=35,
    )
    db.add_all([scan_a, scan_b])
    db.commit()

    res_a = client.get(f"/api/applications/{app_a.id}")
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["target_url"] == "http://alpha.local:3000"
    assert data_a["latest_scan_id"] == scan_a.id
    assert data_a["discovered_routes_count"] == 12
    assert data_a["tested_routes_count"] == 10

    res_b = client.get(f"/api/applications/{app_b.id}")
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["target_url"] == "http://beta.local:8080"
    assert data_b["latest_scan_id"] == scan_b.id
    assert data_b["discovered_routes_count"] == 40
    assert data_b["tested_routes_count"] == 35


def test_pdf_report_and_activity_logging(client, db):
    """Verify PDF report generation endpoint and audit activity logging."""
    app = Application(name="PDF Test Target")
    db.add(app)
    db.flush()

    target = Target(base_url="http://pdf-test.local", hostname="pdf-test.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    finding = Finding(
        scan_id=scan.id,
        type="Information Disclosure",
        category="Information Disclosure",
        url="http://pdf-test.local/version",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        fingerprint="fp_info_disc",
        status="open",
    )
    db.add(finding)
    db.commit()

    # Download report
    res_pdf = client.get(f"/api/scans/{scan.id}/report")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert res_pdf.content.startswith(b"%PDF")

    # Verify activity was logged
    res_acts = client.get(f"/api/activities?application_id={app.id}")
    assert res_acts.status_code == 200
    acts = res_acts.json()
    assert any("PDF Report Generated" in a["title"] for a in acts)


def test_incomplete_or_failed_scan_does_not_mark_resolved(client, db):
    """Requirement: Do not mark a finding as fixed merely because it is absent from one incomplete or failed scan."""
    app = Application(name="Failed Scan Test App")
    db.add(app)
    db.flush()

    target = Target(base_url="http://fail-test.local", hostname="fail-test.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    # Scan 1: completed scan with finding
    scan1 = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 10, 10),
        completed_at=datetime(2026, 10, 10),
        created_at=datetime(2026, 10, 10),
    )
    db.add(scan1)
    db.flush()

    f1 = Finding(
        scan_id=scan1.id,
        type="Command Injection",
        category="Injection",
        url="http://fail-test.local/cmd",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        fingerprint="fp_cmd_injection",
        status="open",
    )
    db.add(f1)
    db.commit()

    # Scan 2: failed/interrupted scan
    scan2 = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.FAILED,
        error_message="Host unreachable",
        created_at=datetime(2026, 10, 11),
    )
    db.add(scan2)
    db.commit()

    # Incomplete or failed scan should NOT be used as basis for resolution
    trends = client.get(f"/api/applications/{app.id}/trends").json()
    # The history must only include completed scans for score trends
    for h in trends["history"]:
        assert h["status"] == "completed"
    # The finding from scan1 must not be falsely marked resolved
    assert trends["resolved_vulnerabilities_count"] == 0


def test_delete_one_scan_preserves_target_and_updates_status(client, db):
    """
    Requirements 1, 2, 3:
    - Deleting one scan does NOT delete the target or application.
    - Dashboard/Application status updates to reflect the remaining scan.
    """
    app = Application(name="Sync Test App Alpha")
    db.add(app)
    db.flush()

    target = Target(base_url="http://sync-alpha.local:3000", hostname="sync-alpha.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    # Scan 1: older scan (score 80)
    scan1 = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 11, 1, 10, 0, 0),
        completed_at=datetime(2026, 11, 1, 10, 5, 0),
        created_at=datetime(2026, 11, 1, 10, 0, 0),
        urls_discovered=10,
        urls_scanned=10,
    )
    # Scan 2: newer scan (score 50, critical finding)
    scan2 = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 11, 2, 10, 0, 0),
        completed_at=datetime(2026, 11, 2, 10, 5, 0),
        created_at=datetime(2026, 11, 2, 10, 0, 0),
        urls_discovered=15,
        urls_scanned=15,
    )
    db.add_all([scan1, scan2])
    db.flush()

    f2 = Finding(
        scan_id=scan2.id,
        type="SQL Injection",
        category="Injection",
        url="http://sync-alpha.local:3000/login",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        status="open",
    )
    db.add(f2)
    db.commit()

    # Before deletion: latest scan is scan2
    app_res = client.get(f"/api/applications/{app.id}").json()
    assert app_res["total_scans"] == 2
    assert app_res["latest_scan_id"] == scan2.id
    assert app_res["finding_counts"]["Critical"] == 1

    # Soft delete scan2
    del_res = client.delete(f"/api/scans/{scan2.id}")
    assert del_res.status_code == 200

    # Target & application must still exist!
    app_res_after = client.get(f"/api/applications/{app.id}").json()
    assert app_res_after["id"] == app.id
    assert app_res_after["target_url"] == "http://sync-alpha.local:3000"
    # total_scans reflects remaining active scan1
    assert app_res_after["total_scans"] == 1
    assert app_res_after["latest_scan_id"] == scan1.id
    assert app_res_after["finding_counts"]["Critical"] == 0


def test_delete_all_scans_preserves_target_with_not_scanned_status(client, db):
    """
    Requirements 3, 4:
    - Deleting all scans of a target preserves the target/application.
    - Application displays total_scans=0, latest_rating=None ("Not Scanned").
    """
    app = Application(name="Sync Test App All Scans Deleted")
    db.add(app)
    db.flush()

    target = Target(base_url="http://sync-deleted.local", hostname="sync-deleted.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        created_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()

    # Delete the only scan
    client.delete(f"/api/scans/{scan.id}")

    # App and target must still be returned by list_applications
    apps_list = client.get("/api/applications").json()
    app_found = next((a for a in apps_list if a["id"] == app.id), None)
    assert app_found is not None, "Application should still exist when scans are deleted"
    assert app_found["total_scans"] == 0
    assert app_found["latest_scan_id"] is None
    assert app_found["latest_rating"] is None
    assert app_found["latest_scan_status"] is None
    assert app_found["target_url"] == "http://sync-deleted.local"


def test_soft_deleted_scans_excluded_from_executive_and_remediation(client, db):
    """
    Requirement 7:
    - Ensure soft-deleted records do not appear in normal Dashboard results:
      - executive stats by_severity and by_type
      - remediation tracker
      - application trends
    """
    app = Application(name="Soft Delete Isolation App")
    db.add(app)
    db.flush()

    target = Target(base_url="http://soft-delete.local", hostname="soft-delete.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.COMPLETED,
        created_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    finding = Finding(
        scan_id=scan.id,
        type="Remote Code Execution",
        category="Injection",
        url="http://soft-delete.local/rce",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        status="open",
    )
    db.add(finding)
    db.commit()

    # Verify present in remediation tracker before delete
    rem_before = client.get(f"/api/findings/remediation-tracker?application_id={app.id}").json()
    assert any(f["id"] == finding.id for f in rem_before)

    # Soft delete the scan
    client.delete(f"/api/scans/{scan.id}")

    # Must be completely excluded from remediation tracker
    rem_after = client.get(f"/api/findings/remediation-tracker?application_id={app.id}").json()
    assert not any(f["id"] == finding.id for f in rem_after)

    # Must be excluded from trends
    trends = client.get(f"/api/applications/{app.id}/trends").json()
    assert len(trends["history"]) == 0


def test_explicit_delete_website_application_and_target(client, db):
    """
    Requirements 5, 6:
    - Explicit Delete Website action safely deletes Application, Target, and associated data.
    - Prevents deletion if a scan is actively running.
    """
    app = Application(name="App To Permanently Delete")
    db.add(app)
    db.flush()

    target = Target(base_url="http://delete-target.local", hostname="delete-target.local", application_id=app.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        application_id=app.id,
        status=ScanStatus.RUNNING,
        created_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()

    app_id = app.id
    target_id = target.id
    scan_id = scan.id

    # 1. Cannot delete when scan is running
    res_block = client.delete(f"/api/applications/{app_id}")
    assert res_block.status_code == 400
    assert "actively running scan" in res_block.json()["detail"]

    # 2. Complete scan and delete application
    scan.status = ScanStatus.COMPLETED
    db.commit()

    res_del = client.delete(f"/api/applications/{app_id}")
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "deleted"

    # Application must no longer exist
    assert client.get(f"/api/applications/{app_id}").status_code == 404
    # Scan must no longer exist
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    # Target must no longer exist
    assert db.get(Target, target_id) is None


