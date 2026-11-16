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

    # Case 2: One Low Confirmed exploitable finding (penalty 3 pts) -> Score 97.0 -> STRONG
    f_low = MockFinding(
        finding_type="Open Redirect",
        category="Other Vulnerabilities",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        parameter="redirect_url",
    )
    posture_strong = calculate_security_posture(scan, [f_low])
    assert posture_strong["score"] == 97.0
    assert posture_strong["rating"] == "STRONG"
    assert posture_strong["is_preliminary"] is False

    # Case 3: Two High Confirmed findings (2 * 20 = 40 pts penalty) -> Score 60.0 -> MEDIUM (60-84)
    f_high1 = MockFinding(
        finding_type="Stored Cross-Site Scripting",
        category="Other Vulnerabilities",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/comments",
        parameter="comment",
    )
    f_high2 = MockFinding(
        finding_type="SQL Injection",
        category="Critical Security Vulnerabilities",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/item",
        parameter="id",
    )
    posture_med = calculate_security_posture(scan, [f_high1, f_high2])
    assert posture_med["score"] == 60.0
    assert posture_med["rating"] == "MEDIUM"

    # Case 4: Two Critical Confirmed findings (2 * 35 = 70 pts) + One High (20 pts) -> 90 pts penalty -> Score 10.0 -> WEAK (<60)
    f_crit1 = MockFinding(
        finding_type="Remote Code Execution",
        category="Critical Security Vulnerabilities",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/upload",
    )
    f_crit2 = MockFinding(
        finding_type="SQL Injection (Auth Bypass)",
        category="Critical Security Vulnerabilities",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/login",
    )
    posture_weak = calculate_security_posture(scan, [f_crit1, f_crit2, f_high1])
    assert posture_weak["score"] == 10.0
    assert posture_weak["rating"] == "WEAK"

    # Case 5: Massive penalties clamp to 0
    f_massive = [
        MockFinding(
            finding_type=f"Critical Exploit {i}",
            category="Critical Security Vulnerabilities",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            url=f"https://example.com/endpoint_{i}",
            parameter="payload",
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
    # Only 1 unique Medium configuration deduction (4.0 pts), not 5 * 4 = 20 pts!
    assert posture_csp["total_penalty"] == 4.0
    assert posture_csp["score"] == 96.0

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
    # Proportional configuration penalties on HTTPS: CSP (4.0) + HSTS (1.5) + XFO (4.0) = 9.5 pts
    assert posture_headers["total_penalty"] == 9.5
    assert posture_headers["score"] == 90.5


def test_confidence_adjustments():
    """Verify confidence multipliers modify penalty score and confirmed/manual counts."""
    scan = MockScan()

    # Critical exploitable base = 35.0 pts.
    # Confirmed -> 1.0 -> 35.0 pts
    # High confidence -> 0.9 -> 31.5 pts
    # Medium confidence -> 0.7 -> 24.5 pts
    # Low confidence -> 0.4 -> 14.0 pts
    # Informational -> 0.0 -> 0.0 pts

    f_conf = MockFinding(finding_type="SQLi A", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, parameter="a")
    f_high = MockFinding(finding_type="SQLi B", severity=Severity.CRITICAL, confidence=Confidence.HIGH, parameter="b")
    f_med = MockFinding(finding_type="SQLi C", severity=Severity.CRITICAL, confidence=Confidence.MEDIUM, parameter="c")
    f_low = MockFinding(finding_type="SQLi D", severity=Severity.CRITICAL, confidence=Confidence.LOW, parameter="d")

    p_conf = calculate_security_posture(scan, [f_conf])
    assert p_conf["total_penalty"] == 35.0
    assert p_conf["confirmed_count"] == 1
    assert p_conf["manual_verification_count"] == 0

    p_high = calculate_security_posture(scan, [f_high])
    assert p_high["total_penalty"] == 31.5
    assert p_high["confirmed_count"] == 0
    assert p_high["manual_verification_count"] == 1

    p_med = calculate_security_posture(scan, [f_med])
    assert p_med["total_penalty"] == 24.5
    assert p_med["manual_verification_count"] == 1

    p_low = calculate_security_posture(scan, [f_low])
    assert p_low["total_penalty"] == 14.0
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


def test_target_77_endpoints_sharing_missing_headers_does_not_multiply_penalty():
    """
    Requirement 1 & 6: Test target with 77 endpoints sharing the same missing headers.
    Verify raw occurrences (77 * 4 = 308) do not multiply penalties, and all affected URLs are preserved.
    """
    scan = MockScan(urls_scanned=77, urls_discovered=77)
    scan.target = MockTarget(base_url="https://example.com", hostname="example.com")

    # 77 endpoints missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
    raw_findings = []
    for i in range(77):
        url = f"https://example.com/api/endpoint_{i}"
        raw_findings.append(MockFinding(finding_type="Missing Security Header", parameter="content-security-policy", url=url, severity=Severity.MEDIUM))
        raw_findings.append(MockFinding(finding_type="Missing Security Header", parameter="x-frame-options", url=url, severity=Severity.MEDIUM))
        raw_findings.append(MockFinding(finding_type="Missing Security Header", parameter="x-content-type-options", url=url, severity=Severity.LOW))
        raw_findings.append(MockFinding(finding_type="Missing Security Header", parameter="referrer-policy", url=url, severity=Severity.LOW))

    assert len(raw_findings) == 308

    posture = calculate_security_posture(scan, raw_findings)
    assert posture["raw_counts"]["total"] == 308
    # 4 distinct configuration issues
    assert posture["unique_counts"]["total"] == 4

    # Penalties are domain-level (applied once per unique issue, never multiplied by 77!):
    # CSP (4.0) + XFO (4.0) + XCTO (1.5) + Referrer-Policy (1.5) = 11.0 pts
    assert posture["total_penalty"] == 11.0
    assert posture["score"] == 89.0
    assert posture["rating"] == "STRONG"

    # Verify that all 77 affected URLs are fully preserved in deduplicated results
    csp_group = next(d for d in posture["score_deductions"] if "content-security-policy" in d["summary"].lower())
    assert csp_group["occurrences"] == 77
    assert "77 instances" in csp_group["summary"]


def test_hsts_context_validation_http_vs_https():
    """
    Requirement 3 & 6: Test HTTP and HTTPS HSTS behavior separately.
    HTTP targets classify missing HSTS as Not Applicable with 0 score penalty.
    HTTPS targets assess missing HSTS as a valid Low vulnerability.
    """
    # 1. HTTP Target (e.g. localhost or plain HTTP)
    scan_http = MockScan()
    scan_http.target = MockTarget(base_url="http://localhost:3001", hostname="localhost")
    hsts_finding_http = MockFinding(
        finding_type="Missing Security Header",
        parameter="strict-transport-security",
        url="http://localhost:3001/rest/user/login",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
    )
    posture_http = calculate_security_posture(scan_http, [hsts_finding_http])
    assert posture_http["total_penalty"] == 0.0
    assert posture_http["score"] == 100.0
    assert posture_http["unique_counts"]["low"] == 0
    assert posture_http["unique_counts"]["not_applicable"] == 1
    assert any("HSTS" in r and "Not Applicable" in r for r in posture_http["coverage"]["limitations"])

    # 2. HTTPS Target (valid TLS transport)
    scan_https = MockScan()
    scan_https.target = MockTarget(base_url="https://secure.example.com", hostname="secure.example.com")
    hsts_finding_https = MockFinding(
        finding_type="Missing Security Header",
        parameter="strict-transport-security",
        url="https://secure.example.com/login",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
    )
    posture_https = calculate_security_posture(scan_https, [hsts_finding_https])
    assert posture_https["total_penalty"] == 1.5
    assert posture_https["score"] == 98.5
    assert posture_https["unique_counts"]["low"] == 1
    assert posture_https["unique_counts"]["not_applicable"] == 0


def test_overlapping_x_frame_options_and_clickjacking_double_counting_prevention():
    """
    Requirement 2 & 6: Test overlapping X-Frame-Options and Clickjacking findings.
    Both represent framing weakness (CWE-1021); verify they consolidate into 1 risk deduction.
    """
    scan = MockScan()
    f_clickjacking = MockFinding(
        finding_type="Clickjacking Protection Missing",
        category="Security Configuration",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/",
    )
    f_xfo = MockFinding(
        finding_type="Missing Security Header",
        parameter="x-frame-options",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/about",
    )
    f_csp = MockFinding(
        finding_type="Missing Security Header",
        parameter="content-security-policy",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/",
    )

    # When both clickjacking and missing x-frame-options exist, they must NOT double-count
    posture = calculate_security_posture(scan, [f_clickjacking, f_xfo, f_csp])
    assert posture["raw_counts"]["total"] == 3
    # Clickjacking + XFO merged into 1 framing issue; CSP is distinct = 2 unique issues
    assert posture["unique_counts"]["total"] == 2
    # Framing (4.0) + CSP (4.0) = 8.0 pts, NOT 4 + 4 + 4 = 12.0 pts!
    assert posture["total_penalty"] == 8.0
    assert posture["score"] == 92.0


def test_exploitable_vulnerabilities_retain_dominant_impact():
    """
    Requirement 4 & 6: Verify confirmed SQL Injection and high-impact vulnerabilities dominate score,
    while configuration findings contribute proportionately.
    """
    scan = MockScan()

    # Confirmed Critical SQL Injection
    f_sqli = MockFinding(
        finding_type="SQL Injection",
        category="Critical Security Vulnerabilities",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/rest/user/login",
        parameter="email",
    )
    p_sqli = calculate_security_posture(scan, [f_sqli])
    # 1 Confirmed Critical vulnerability drops score significantly (-35 pts)
    assert p_sqli["total_penalty"] == 35.0
    assert p_sqli["score"] == 65.0
    assert p_sqli["rating"] == "MEDIUM"

    # Confirmed SQL Injection + Confirmed DOM XSS (High)
    f_xss = MockFinding(
        finding_type="DOM XSS",
        category="Other Vulnerabilities",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        url="https://example.com/#/search",
        parameter="q",
    )
    p_both = calculate_security_posture(scan, [f_sqli, f_xss])
    # 35.0 (SQLi) + 20.0 (XSS) = 55.0 pts penalty -> 45.0 (WEAK)
    assert p_both["total_penalty"] == 55.0
    assert p_both["score"] == 45.0
    assert p_both["rating"] == "WEAK"

    # Combined with 4 missing headers (11.0 pts)
    f_headers = [
        MockFinding(finding_type="Missing Security Header", parameter="content-security-policy", severity=Severity.MEDIUM),
        MockFinding(finding_type="Clickjacking Protection Missing", severity=Severity.MEDIUM),
        MockFinding(finding_type="Missing Security Header", parameter="x-content-type-options", severity=Severity.LOW),
        MockFinding(finding_type="Missing Security Header", parameter="referrer-policy", severity=Severity.LOW),
    ]
    p_full = calculate_security_posture(scan, [f_sqli, f_xss] + f_headers)
    # 55.0 (exploits) + 11.0 (config) = 66.0 pts penalty -> 34.0 (WEAK)
    assert p_full["total_penalty"] == 66.0
    assert p_full["score"] == 34.0
    assert p_full["rating"] == "WEAK"
    # Ensure Critical SQLi and High XSS appear at the very top of score deductions
    assert p_full["score_deductions"][0]["finding_type"] == "SQL Injection"
    assert p_full["score_deductions"][1]["finding_type"] == "DOM XSS"


def test_configuration_penalty_ceiling_prevents_overwhelming_score():
    """
    Requirement 4: Verify aggregate configuration penalty ceiling (max 20 pts).
    Even if an app misses numerous security headers and flags, configuration issues
    cannot overwhelm the score or categorize an exploit-free app as Weak.
    """
    scan = MockScan()
    # 8 different configuration weaknesses (raw sum: 4*3 + 1.5*5 = 19.5 + 4 = 23.5)
    config_findings = [
        MockFinding(finding_type="Missing Security Header", parameter="content-security-policy", severity=Severity.MEDIUM),
        MockFinding(finding_type="Clickjacking Protection Missing", severity=Severity.MEDIUM),
        MockFinding(finding_type="CORS Misconfiguration", category="Security Configuration", severity=Severity.MEDIUM),
        MockFinding(finding_type="Missing Security Header", parameter="x-content-type-options", severity=Severity.LOW),
        MockFinding(finding_type="Missing Security Header", parameter="referrer-policy", severity=Severity.LOW),
        MockFinding(finding_type="Cookie Without HttpOnly", category="Security Configuration", severity=Severity.LOW, parameter="session"),
        MockFinding(finding_type="Cookie Without Secure", category="Security Configuration", severity=Severity.LOW, parameter="session"),
        MockFinding(finding_type="Cookie Without SameSite", category="Security Configuration", severity=Severity.LOW, parameter="session"),
    ]
    posture = calculate_security_posture(scan, config_findings)
    # Total penalty capped at 20.0
    assert posture["total_penalty"] <= 20.0
    assert posture["score"] >= 80.0
    assert posture["rating"] in ("STRONG", "MEDIUM")

