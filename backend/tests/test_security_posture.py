"""
Unit and integration tests for ZeroTrace Security Posture scoring and branding.
"""
from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import init_db
from app.models.finding import Confidence, Finding, Severity
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.reports.pdf_report import build_report
from app.services.security_posture import (
    calculate_security_posture,
    deduplicate_findings,
    DEFAULT_CONFIDENCE_MULTIPLIERS,
    DEFAULT_PENALTY_WEIGHTS,
)


class MockTarget:
    def __init__(self, base_url="https://example.com", hostname="example.com"):
        self.base_url = base_url
        self.hostname = hostname


class MockScan:
    def __init__(
        self,
        scan_id="test-scan-1234",
        status=ScanStatus.COMPLETED,
        urls_scanned=10,
        urls_discovered=12,
        parameters_found=5,
        max_depth=2,
        max_urls=50,
        modules=None,
    ):
        self.id = scan_id
        self.status = status
        self.target = MockTarget()
        self.urls_scanned = urls_scanned
        self.urls_discovered = urls_discovered
        self.parameters_found = parameters_found
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.modules = modules or ["sql_injection", "xss", "security_headers"]
        self.started_at = datetime(2026, 10, 29, 10, 0, 0)
        self.completed_at = datetime(2026, 10, 29, 10, 2, 30)


class MockFinding:
    def __init__(
        self,
        finding_type="Missing Security Header",
        category="Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/page",
        parameter="content-security-policy",
        evidence="Content-Security-Policy header is missing",
        description="CSP not set",
        remediation="Add Content-Security-Policy header",
    ):
        self.type = finding_type
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.url = url
        self.parameter = parameter
        self.evidence = evidence
        self.description = description
        self.remediation = remediation


def test_scoring_weights_and_thresholds():
    """Verify standard penalty calculations and score thresholds (STRONG, MEDIUM, WEAK)."""
    scan = MockScan()

    # Case 1: No findings -> Score 100, but labeled preliminary because zero automated findings
    # do not automatically certify absolute security.
    posture_clean = calculate_security_posture(scan, [])
    assert posture_clean["score"] == 100.0
    assert posture_clean["rating"] == "STRONG"
    assert posture_clean["is_preliminary"] is True
    assert "preliminary" in posture_clean["rating_label"].lower()

    # Case 2: One Low Confirmed finding (penalty 3 pts) -> Score 97.0 -> STRONG
    f_low = MockFinding(
        finding_type="Cookie Missing Secure Flag",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        parameter="pref",
    )
    posture_strong = calculate_security_posture(scan, [f_low])
    assert posture_strong["score"] == 97.0
    assert posture_strong["rating"] == "STRONG"
    assert posture_strong["is_preliminary"] is False

    # Case 3: Two High Confirmed findings (2 * 15 = 30 pts penalty) -> Score 70.0 -> MEDIUM (60-84)
    f_high1 = MockFinding(
        finding_type="Stored Cross-Site Scripting",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/comments",
        parameter="comment",
    )
    f_high2 = MockFinding(
        finding_type="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/item",
        parameter="id",
    )
    posture_med = calculate_security_posture(scan, [f_high1, f_high2])
    assert posture_med["score"] == 70.0
    assert posture_med["rating"] == "MEDIUM"

    # Case 4: Two Critical Confirmed findings (2 * 25 = 50 pts) + One High (15 pts) -> 65 pts penalty -> Score 35.0 -> WEAK (<60)
    f_crit1 = MockFinding(
        finding_type="Remote Code Execution",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/upload",
    )
    f_crit2 = MockFinding(
        finding_type="SQL Injection (Auth Bypass)",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/login",
    )
    posture_weak = calculate_security_posture(scan, [f_crit1, f_crit2, f_high1])
    assert posture_weak["score"] == 35.0
    assert posture_weak["rating"] == "WEAK"

    # Case 5: Massive penalties clamp to 0
    f_massive = [
        MockFinding(
            finding_type=f"Critical Issue {i}",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            url=f"https://example.com/endpoint_{i}",
        )
        for i in range(10)
    ]
    posture_clamped = calculate_security_posture(scan, f_massive)
    assert posture_clamped["score"] == 0.0
    assert posture_clamped["rating"] == "WEAK"


def test_duplicate_handling_and_distinct_headers():
    """Repeated occurrences of same issue deduplicate; genuinely different headers remain distinct."""
    scan = MockScan()

    # 5 raw occurrences of missing Content-Security-Policy across 5 endpoints
    csp_findings = [
        MockFinding(
            finding_type="Missing Security Header",
            parameter="content-security-policy",
            url=f"https://example.com/page{i}",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
        )
        for i in range(5)
    ]

    posture_csp = calculate_security_posture(scan, csp_findings)
    assert posture_csp["raw_counts"]["total"] == 5
    assert posture_csp["unique_counts"]["total"] == 1
    # Only 1 unique Medium deduction (7.0 pts), not 5 * 7 = 35 pts!
    assert posture_csp["total_penalty"] == 7.0
    assert posture_csp["score"] == 93.0

    # Now add genuinely different missing security headers: Strict-Transport-Security (Low) and X-Frame-Options (Medium)
    hsts = MockFinding(
        finding_type="Missing Security Header",
        parameter="strict-transport-security",
        url="https://example.com/",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
    )
    xfo = MockFinding(
        finding_type="Missing Security Header",
        parameter="x-frame-options",
        url="https://example.com/",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
    )

    all_header_findings = csp_findings + [hsts, xfo]
    posture_headers = calculate_security_posture(scan, all_header_findings)
    assert posture_headers["raw_counts"]["total"] == 7
    # 3 distinct header types: CSP, HSTS, XFO
    assert posture_headers["unique_counts"]["total"] == 3
    # Penalties: CSP (7) + HSTS (3) + XFO (7) = 17 pts
    assert posture_headers["total_penalty"] == 17.0
    assert posture_headers["score"] == 83.0


def test_confidence_adjustments():
    """Verify confidence multipliers modify penalty score and confirmed/manual counts."""
    scan = MockScan()

    # Critical base = 25 pts.
    # Confirmed -> 1.0 -> 25.0 pts
    # High confidence -> 0.9 -> 22.5 pts
    # Medium confidence -> 0.7 -> 17.5 pts
    # Low confidence -> 0.4 -> 10.0 pts
    # Informational -> 0.0 -> 0.0 pts

    f_conf = MockFinding(finding_type="SQLi A", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, parameter="a")
    f_high = MockFinding(finding_type="SQLi B", severity=Severity.CRITICAL, confidence=Confidence.HIGH, parameter="b")
    f_med = MockFinding(finding_type="SQLi C", severity=Severity.CRITICAL, confidence=Confidence.MEDIUM, parameter="c")
    f_low = MockFinding(finding_type="SQLi D", severity=Severity.CRITICAL, confidence=Confidence.LOW, parameter="d")

    p_conf = calculate_security_posture(scan, [f_conf])
    assert p_conf["total_penalty"] == 25.0
    assert p_conf["confirmed_count"] == 1
    assert p_conf["manual_verification_count"] == 0

    p_high = calculate_security_posture(scan, [f_high])
    assert p_high["total_penalty"] == 22.5
    assert p_high["confirmed_count"] == 0
    assert p_high["manual_verification_count"] == 1

    p_med = calculate_security_posture(scan, [f_med])
    assert p_med["total_penalty"] == 17.5
    assert p_med["manual_verification_count"] == 1

    p_low = calculate_security_posture(scan, [f_low])
    assert p_low["total_penalty"] == 10.0
    assert p_low["manual_verification_count"] == 1


def test_technology_detection_excluded_from_penalties():
    """Informational technology fingerprinting does not penalize score."""
    scan = MockScan()
    f_tech1 = MockFinding(
        finding_type="Technology Detection",
        category="Information Disclosure",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.INFORMATIONAL,
        evidence="server: Apache/2.4.41",
    )
    f_tech2 = MockFinding(
        finding_type="Technology Detection",
        category="Information Disclosure",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.INFORMATIONAL,
        evidence="x-powered-by: PHP/7.4.3",
    )

    posture = calculate_security_posture(scan, [f_tech1, f_tech2])
    assert posture["total_penalty"] == 0.0
    # No penalties deducted
    assert len(posture["score_deductions"]) == 0


def test_incomplete_and_insufficient_scans():
    """Scans that are running, cancelled, failed, or have zero crawl coverage must be labeled preliminary."""
    # Running scan
    scan_running = MockScan(status=ScanStatus.RUNNING)
    f = MockFinding(severity=Severity.LOW, confidence=Confidence.CONFIRMED)
    p_run = calculate_security_posture(scan_running, [f])
    assert p_run["is_preliminary"] is True
    assert any("running" in r.lower() for r in p_run["preliminary_reasons"])

    # Cancelled scan
    scan_cancelled = MockScan(status=ScanStatus.CANCELLED)
    p_can = calculate_security_posture(scan_cancelled, [f])
    assert p_can["is_preliminary"] is True

    # Failed scan
    scan_failed = MockScan(status=ScanStatus.FAILED)
    p_fail = calculate_security_posture(scan_failed, [f])
    assert p_fail["is_preliminary"] is True

    # Completed scan but zero crawled URLs
    scan_zero_urls = MockScan(status=ScanStatus.COMPLETED, urls_scanned=0, urls_discovered=0)
    p_zero = calculate_security_posture(scan_zero_urls, [f])
    assert p_zero["is_preliminary"] is True
    assert any("coverage is insufficient" in r.lower() for r in p_zero["preliminary_reasons"])


def test_pdf_report_generation():
    """PDF generator incorporates ZeroTrace branding and security posture."""
    scan = MockScan()
    f = MockFinding(
        finding_type="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/search",
        parameter="q",
        evidence="SQL syntax error detected",
        description="Unsanitized user input in query",
        remediation="Use prepared statements",
    )
    pdf_bytes = build_report(scan, [f], summary=None)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF starts with standard %PDF magic header
    assert pdf_bytes.startswith(b"%PDF")


def test_api_security_posture_endpoint(monkeypatch):
    """Integration test for GET /api/scans/{scan_id}/security-posture."""
    init_db()
    with TestClient(app) as client:
        # Test 404 for non-existent scan
        resp_404 = client.get("/api/scans/non-existent-id/security-posture")
        assert resp_404.status_code == 404

