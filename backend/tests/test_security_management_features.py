import uuid
from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import SessionLocal, init_db
from app.models.application import Application
from app.models.target import Target
from app.models.scan import Scan, ScanStatus
from app.models.endpoint import Endpoint
from app.models.parameter import Parameter
from app.models.finding import Finding, Severity, Confidence
from app.models.profile import ScanProfile, ScanProgram
from app.scanner.scope_enforcer import validate_url_in_scope, compute_effective_scan_config


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db():
    init_db()
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def test_builtin_scan_profiles_seeded_and_protected(client, db):
    """Verify built-in profiles exist, full scan is default, and built-ins cannot be deleted/updated."""
    res = client.get("/api/profiles")
    assert res.status_code == 200
    profiles = res.json()
    names = {p["name"]: p for p in profiles}

    assert "Quick Scan" in names
    assert "Full Scan" in names
    assert "Passive Scan" in names
    assert "Custom Scan" in names

    # Restore default if previous test changed it
    if not names["Full Scan"]["is_default"]:
        client.post(f"/api/profiles/{names['Full Scan']['id']}/set-default")
        profiles = client.get("/api/profiles").json()
        names = {p["name"]: p for p in profiles}

    assert names["Full Scan"]["is_default"] is True
    assert names["Passive Scan"]["send_payloads"] is False

    # Attempt to delete built-in profile -> 403 Forbidden
    quick_id = names["Quick Scan"]["id"]
    res_del = client.delete(f"/api/profiles/{quick_id}")
    assert res_del.status_code == 403
    assert "Built-in" in res_del.json()["detail"]

    # Attempt to update built-in profile -> 403 Forbidden
    res_put = client.put(f"/api/profiles/{quick_id}", json={"name": "Modified Quick Scan"})
    assert res_put.status_code == 403


def test_custom_profile_crud_duplicate_and_set_default(client, db):
    """Verify custom profile creation, duplication, updating, and setting default."""
    prof_name = f"API Security Profile {uuid.uuid4().hex[:6]}"
    res_create = client.post(
        "/api/profiles",
        json={
            "name": prof_name,
            "description": "High-speed testing of REST and JSON endpoints",
            "modules": ["xss", "sql_injection", "cors", "sensitive_files"],
            "max_depth": 3,
            "max_urls": 40,
            "request_rate": 10.0,
            "concurrency": 4,
            "send_payloads": True,
        },
    )
    assert res_create.status_code == 201
    created = res_create.json()
    assert created["is_builtin"] is False
    profile_id = created["id"]

    # Duplicate profile
    res_dup = client.post(f"/api/profiles/{profile_id}/duplicate")
    assert res_dup.status_code == 201
    dup = res_dup.json()
    assert "Copy" in dup["name"]
    assert dup["id"] != profile_id

    # Set as default
    res_def = client.post(f"/api/profiles/{profile_id}/set-default")
    assert res_def.status_code == 200
    assert res_def.json()["is_default"] is True

    # Delete duplicate
    res_del = client.delete(f"/api/profiles/{dup['id']}")
    assert res_del.status_code == 200

    # Restore Full Scan as default for test isolation
    for p in client.get("/api/profiles").json():
        if p["name"] == "Full Scan":
            client.post(f"/api/profiles/{p['id']}/set-default")
            break


def test_bug_bounty_program_crud_and_safety_rules(client, db):
    """Verify bug bounty program CRUD, domain pattern validation, and automated scanning lockout."""
    prog_name = f"Acme Bug Bounty {uuid.uuid4().hex[:6]}"
    res_prog = client.post(
        "/api/programs",
        json={
            "name": prog_name,
            "target_domains": ["acme.org", "*.acme.org"],
            "url_patterns": [r"^https?://.*acme\.org/.*$"],
            "out_of_scope_paths": ["/admin/*", "/logout", "/billing/*"],
            "allowed_modules": ["xss", "sql_injection", "security_headers", "cors"],
            "prohibited_modules": ["command_injection"],
            "max_requests_per_second": 3.0,
            "max_concurrency": 2,
            "allow_automated_scanning": True,
        },
    )
    assert res_prog.status_code == 201
    prog = res_prog.json()
    prog_id = prog["id"]

    # Scope validation logic checks
    in_scope, _ = validate_url_in_scope("https://api.acme.org/v1/users", prog["target_domains"], prog["url_patterns"], prog["out_of_scope_paths"])
    assert in_scope is True

    # Out of scope path check
    in_scope, reason = validate_url_in_scope("https://acme.org/admin/users", prog["target_domains"], prog["url_patterns"], prog["out_of_scope_paths"])
    assert in_scope is False
    assert "admin" in reason

    # Out of scope domain check
    in_scope, reason = validate_url_in_scope("https://evil.com/landing", prog["target_domains"], prog["url_patterns"], prog["out_of_scope_paths"])
    assert in_scope is False

    # Blocked automated scanning
    res_update = client.put(f"/api/programs/{prog_id}", json={"allow_automated_scanning": False})
    assert res_update.status_code == 200
    assert res_update.json()["allow_automated_scanning"] is False

    # Creating a scan under this program must be blocked with 403
    res_scan_blocked = client.post(
        "/api/scans",
        json={"target_url": "https://acme.org/home", "program_id": prog_id, "authorization_confirmed": True},
    )
    assert res_scan_blocked.status_code == 403


def test_scope_enforcer_effective_scan_config_calculation():
    """Verify module intersection, passive scan payload suppression, and rate cap calculations."""
    profile_data = {
        "name": "Passive Audit",
        "send_payloads": False,
        "modules": ["xss", "sql_injection", "security_headers", "cookie_security"],
        "max_depth": 3,
        "max_urls": 50,
        "request_rate": 10.0,
        "concurrency": 5,
    }
    program_data = {
        "name": "Strict Scope",
        "allow_automated_scanning": True,
        "allowed_modules": ["security_headers", "cookie_security", "xss"],
        "prohibited_modules": [],
        "max_requests_per_second": 2.0,
        "max_concurrency": 1,
    }

    effective = compute_effective_scan_config(profile=profile_data, program=program_data)
    # Because send_payloads is False, xss & sql_injection must be dropped
    assert "xss" not in effective["effective_modules"]
    assert "sql_injection" not in effective["effective_modules"]
    assert "security_headers" in effective["effective_modules"]
    assert "cookie_security" in effective["effective_modules"]

    # Rate and concurrency capped by program
    assert effective["request_rate"] == 2.0
    assert effective["concurrency"] == 1
    assert effective["effective_restrictions"]["rate_limit_capped"] is True
    assert effective["effective_restrictions"]["concurrency_capped"] is True


def test_finding_lifecycle_management_eight_statuses_and_audit_history(client, db):
    """Verify all 8 researcher-managed statuses, history logging, and filtering."""
    app_obj = Application(name="Lifecycle Test Portal")
    db.add(app_obj)
    db.flush()

    target = Target(base_url="https://lifecycle.local", hostname="lifecycle.local", application_id=app_obj.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(target_id=target.id, application_id=app_obj.id, status=ScanStatus.COMPLETED)
    db.add(scan)
    db.flush()

    finding = Finding(
        scan_id=scan.id,
        type="SQL Injection",
        category="Injection",
        url="https://lifecycle.local/search",
        method="GET",
        parameter="query",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        status="New",
        detection_status="Confirmed",
        fingerprint="fp_lifecycle_1",
    )
    db.add(finding)
    db.commit()

    valid_statuses = [
        "Confirmed",
        "Requires Manual Verification",
        "False Positive",
        "Accepted Risk",
        "In Progress",
        "Fixed",
        "Reopened",
    ]

    for st in valid_statuses:
        res = client.patch(
            f"/api/findings/{finding.id}/status",
            json={"status": st, "note": f"Transitioned to {st}", "user": "Lead Pentester"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == st
        assert res.json()["detection_status"] == "Confirmed"  # Detection status unchanged

    # Invalid status should return 422
    res_inv = client.patch(
        f"/api/findings/{finding.id}/status",
        json={"status": "invalid_random_status", "note": "Should fail"},
    )
    assert res_inv.status_code == 422

    # Verify audit history timeline
    res_hist = client.get(f"/api/findings/{finding.id}/history")
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert len(hist) == len(valid_statuses)
    assert hist[0]["new_status"] == "Reopened"
    assert hist[0]["user"] == "Lead Pentester"

    # Verify findings filtering
    res_filtered = client.get(f"/api/scans/{scan.id}/findings?lifecycle_status=Reopened")
    assert res_filtered.status_code == 200
    assert len(res_filtered.json()) == 1

    res_search = client.get(f"/api/scans/{scan.id}/findings?search=query")
    assert res_search.status_code == 200
    assert len(res_search.json()) == 1


def test_endpoint_coverage_dashboard_endpoint(client, db):
    """Verify endpoint coverage computation, status breakdown, matrix, and endpoint explorer data."""
    app_obj = Application(name="Coverage App")
    db.add(app_obj)
    db.flush()

    target = Target(base_url="https://coverage.local", hostname="coverage.local", application_id=app_obj.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        application_id=app_obj.id,
        status=ScanStatus.COMPLETED,
        coverage_summary={
            "coverage_percentage": 75.0,
            "parameters_tested": 6,
            "module_matrix": [
                {"module": "security_headers", "name": "Security Headers", "status": "Tested", "findings_count": 1, "endpoints_tested": 3, "parameters_tested": 0, "reason": "Tested across 3 endpoint(s)"},
                {"module": "xss", "name": "Cross-Site Scripting", "status": "Tested", "findings_count": 0, "endpoints_tested": 2, "parameters_tested": 4, "reason": "Tested 4 parameter(s)"},
            ],
        },
    )
    db.add(scan)
    db.flush()

    ep1 = Endpoint(
        scan_id=scan.id,
        url="https://coverage.local/home",
        method="GET",
        status_code=200,
        endpoint_type="page",
        source="crawler",
        is_tested=True,
        testing_status="tested",
        modules_executed=["security_headers"],
    )
    ep2 = Endpoint(
        scan_id=scan.id,
        url="https://coverage.local/login",
        method="POST",
        status_code=200,
        endpoint_type="form",
        has_form="true",
        source="crawler",
        is_tested=True,
        testing_status="tested",
        modules_executed=["security_headers", "xss"],
    )
    ep3 = Endpoint(
        scan_id=scan.id,
        url="https://coverage.local/admin",
        method="GET",
        status_code=403,
        endpoint_type="page",
        source="crawler",
        is_tested=False,
        testing_status="auth_required",
        modules_executed=[],
    )
    db.add_all([ep1, ep2, ep3])
    db.flush()

    p1 = Parameter(endpoint_id=ep2.id, name="username", location="body", sample_value="admin")
    p2 = Parameter(endpoint_id=ep2.id, name="password", location="body", sample_value="pass")
    db.add_all([p1, p2])
    db.commit()

    res = client.get(f"/api/scans/{scan.id}/coverage")
    assert res.status_code == 200
    cov = res.json()

    assert cov["discovered_endpoints"] == 3
    assert cov["tested_endpoints"] == 2
    assert cov["untested_endpoints"] == 1
    assert cov["discovered_forms"] == 1
    assert cov["auth_protected_endpoints"] == 1
    assert cov["coverage_percentage"] == 75.0
    assert cov["method_distribution"]["GET"] == 2
    assert cov["method_distribution"]["POST"] == 1
    assert len(cov["endpoints"]) == 3
    assert len(cov["module_matrix"]) == 2


def test_scan_comparison_between_two_scans(client, db):
    """Verify scan comparison calculates score delta, unique counts, and categorizes findings as new, fixed, recurring, unchanged."""
    app_obj = Application(name="Comparison App")
    db.add(app_obj)
    db.flush()

    target = Target(base_url="https://comparison.local", hostname="comparison.local", application_id=app_obj.id, authorization_confirmed=True)
    db.add(target)
    db.flush()

    # Scan 1: Base scan
    scan1 = Scan(
        target_id=target.id,
        application_id=app_obj.id,
        status=ScanStatus.COMPLETED,
        findings_count=3,
        coverage_summary={"coverage_percentage": 50.0, "endpoints_discovered": 4, "endpoints_tested": 2},
    )
    db.add(scan1)
    db.flush()

    # Base scan findings:
    # 1. Header (will be fixed in scan 2)
    f1 = Finding(
        scan_id=scan1.id,
        type="Missing Security Header",
        category="Security Configuration",
        url="https://comparison.local/page1",
        parameter="x-frame-options",
        evidence="Missing X-Frame-Options",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        status="open",
        fingerprint="fp_comp_header_xfo",
    )
    # 2. XSS (was resolved in scan 1, reappears in scan 2 -> recurring)
    f2 = Finding(
        scan_id=scan1.id,
        type="Cross-Site Scripting (XSS)",
        category="Injection",
        url="https://comparison.local/search",
        parameter="q",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        status="Fixed",
        fingerprint="fp_comp_xss_search",
    )
    # 3. Sensitive File (still present in scan 2 -> unchanged)
    f3 = Finding(
        scan_id=scan1.id,
        type="Sensitive File Exposure",
        category="Information Disclosure",
        url="https://comparison.local/.env",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        status="New",
        fingerprint="fp_comp_file_env",
    )
    db.add_all([f1, f2, f3])
    db.flush()

    # Scan 2: Target scan
    scan2 = Scan(
        target_id=target.id,
        application_id=app_obj.id,
        status=ScanStatus.COMPLETED,
        findings_count=3,
        coverage_summary={"coverage_percentage": 75.0, "endpoints_discovered": 6, "endpoints_tested": 4},
    )
    db.add(scan2)
    db.flush()

    # Target scan findings:
    # 1. XSS reappears (recurring)
    f2_new = Finding(
        scan_id=scan2.id,
        type="Cross-Site Scripting (XSS)",
        category="Injection",
        url="https://comparison.local/search",
        parameter="q",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        status="New",
        fingerprint="fp_comp_xss_search",
    )
    # 2. Sensitive File (unchanged)
    f3_new = Finding(
        scan_id=scan2.id,
        type="Sensitive File Exposure",
        category="Information Disclosure",
        url="https://comparison.local/.env",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        status="New",
        fingerprint="fp_comp_file_env",
    )
    # 3. SQLi (brand new in scan 2 -> new)
    f4_new = Finding(
        scan_id=scan2.id,
        type="SQL Injection",
        category="Injection",
        url="https://comparison.local/item",
        parameter="id",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        status="New",
        fingerprint="fp_comp_sqli_item",
    )
    db.add_all([f2_new, f3_new, f4_new])
    db.commit()

    # Test comparable scans endpoint
    res_comps = client.get(f"/api/scans/{scan2.id}/comparable-scans")
    assert res_comps.status_code == 200
    comp_list = res_comps.json()
    assert any(s["id"] == scan1.id for s in comp_list)

    # Test comparison endpoint
    res_compare = client.get(f"/api/scans/compare?base_scan_id={scan1.id}&target_scan_id={scan2.id}")
    assert res_compare.status_code == 200
    comp_data = res_compare.json()

    assert comp_data["base_unique_count"] == 3
    assert comp_data["target_unique_count"] == 3
    assert "score_delta" in comp_data
    assert comp_data["coverage_changes"]["coverage_delta"] == 25.0

    findings_summary = comp_data["findings_summary"]
    assert findings_summary["new"] == 1        # SQL Injection
    assert findings_summary["fixed"] == 1      # Missing Security Header
    assert findings_summary["recurring"] == 1  # XSS
    assert findings_summary["unchanged"] == 1  # Sensitive File

    status_map = {f["fingerprint"]: f["comparison_status"] for f in comp_data["compared_findings"]}
    assert status_map["fp_comp_sqli_item"] == "new"
    assert status_map["fp_comp_header_xfo"] == "fixed"
    assert status_map["fp_comp_xss_search"] == "recurring"
    assert status_map["fp_comp_file_env"] == "unchanged"
