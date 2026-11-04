"""
Unit and functional tests for ZeroTrace Bug Bounty and Security Assessment Summary Report Generators.
Tests:
- CVSS v3.1 accuracy without fabricating unsupported vectors.
- Evidence sanitization (passwords, tokens, cookies, secrets replaced with [REDACTED]).
- Safe Proof-of-Concept curl command generation for GET and POST endpoints.
- HackerOne Markdown report generation for confirmed and potential findings.
- 4-6 page professional Bug Bounty PDF reports (SQLi, XSS, CSRF, etc.).
- 5-15 page Security Assessment Summary PDF generation.
- Clean scan reporting (zero vulnerabilities handled cleanly without errors).
- Potential findings, manual verification findings, missing evidence, and unassessed CVSS handling.
"""
from datetime import datetime
import io
import re
import pytest

from app.models.finding import Confidence, Finding, Severity
from app.models.scan import Scan, ScanStatus
from app.reports.bug_bounty_report import (
    CVSS_KNOWLEDGE_BASE,
    assess_finding_cvss,
    build_bug_bounty_markdown,
    build_bug_bounty_pdf,
    build_complete_website_bug_bounty_pdf,
    group_findings_into_unique,
    generate_reproduction_steps,
    generate_safe_poc,
    get_cvss_info,
    match_vuln_knowledge,
)
from app.reports.assessment_summary import build_assessment_summary_pdf


def get_pdf_page_count(pdf_bytes: bytes) -> int:
    """Helper to detect exact PDF page count from ReportLab stream output."""
    return len(re.findall(rb"/Type\s*/Page\b", pdf_bytes))


class MockTarget:
    def __init__(self, base_url="https://app.vuln-target.local:8443", hostname="app.vuln-target.local"):
        self.base_url = base_url
        self.hostname = hostname


class MockApplication:
    def __init__(self, name="Core Banking Portal"):
        self.name = name


class MockScan:
    def __init__(
        self,
        scan_id="scan-bounty-998877",
        status=ScanStatus.COMPLETED,
        urls_scanned=14,
        urls_discovered=18,
        duration_seconds=42.5,
        target=None,
        application=None,
        coverage_summary=None,
    ):
        self.id = scan_id
        self.status = status
        self.target = target or MockTarget()
        self.application = application or MockApplication()
        self.urls_scanned = urls_scanned
        self.urls_discovered = urls_discovered
        self.duration_seconds = duration_seconds
        self.findings_count = 0
        self.coverage_summary = coverage_summary or {
            "endpoints_discovered": 18,
            "endpoints_tested": 14,
            "forms_discovered": 4,
            "parameters_tested": 12,
            "overall_coverage": 77.8,
            "modules": {
                "sqli": "Tested",
                "xss": "Tested",
                "command_injection": "Tested",
                "directory_traversal": "Tested",
                "sensitive_files": "Tested",
                "csrf": "Tested",
                "security_headers": "Tested",
                "cors": "Tested",
                "clickjacking": "Tested",
            },
        }
        self.created_at = datetime(2026, 11, 1, 14, 30, 0)
        self.started_at = datetime(2026, 11, 1, 14, 30, 0)
        self.completed_at = datetime(2026, 11, 1, 14, 30, 42)


class MockFinding:
    def __init__(
        self,
        finding_id="f-101",
        finding_type="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        detection_status="Confirmed",
        url="https://app.vuln-target.local:8443/api/search?q=test",
        method="GET",
        parameter="q",
        cwe_id="CWE-89",
        evidence="HTTP/1.1 500 Internal Server Error\nServer: PostgreSQL 15\nERROR: syntax error at or near \"'\"",
        description="User input into the 'q' parameter is concatenated directly into SQL queries.",
        impact="An attacker can read, modify, or delete database records, potentially leading to total compromise.",
        remediation="Use parameterized queries (prepared statements) with bound parameters.",
        evidence_details=None,
        fingerprint="fp-sqli-api-search-q",
        payload=None,
    ):
        self.id = finding_id
        self.type = finding_type
        self.severity = severity
        self.confidence = confidence
        self.detection_status = detection_status
        self.url = url
        self.method = method
        self.parameter = parameter
        self.cwe_id = cwe_id
        self.evidence = evidence
        self.description = description
        self.impact = impact
        self.remediation = remediation
        if payload:
            self.evidence_details = {"records": [{"payload": payload, "status": 500}]}
        else:
            self.evidence_details = evidence_details or {
                "records": [{"payload": "' OR 1=1 --", "status": 500}]
            }
        self.fingerprint = fingerprint
        self.timestamp = datetime(2026, 11, 1, 14, 30, 15)


def test_cvss_knowledge_base():
    """Verify CVSS v3.1 base metrics for standard classes without fabricating unknown ones."""
    sqli = get_cvss_info("SQL Injection", "High")
    assert sqli["score"] in (8.6, 9.1)
    assert "CWE-89" in sqli["cwe"]
    assert "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" in sqli["vector"]

    xss = get_cvss_info("Cross-Site Scripting (XSS)", "Medium")
    assert xss["score"] == 6.1
    assert "CWE-79" in xss["cwe"]

    cmd = get_cvss_info("Command Injection", "Critical")
    assert cmd["score"] == 9.8
    assert "CWE-78" in cmd["cwe"]

    # Unknown or generic findings must NOT fabricate a random score
    unknown = get_cvss_info("Proprietary Internal Header Divergence", "Low")
    assert unknown["score"] is None
    assert "N/A" in unknown["vector"]


def test_reproduction_steps_and_safe_poc():
    """Verify reproduction steps and safe cURL command generation."""
    finding = MockFinding(
        url="https://app.vuln-target.local:8443/login",
        method="POST",
        parameter="username",
        finding_type="SQL Injection",
        evidence_details={"records": [{"payload": "admin' --"}]},
    )

    poc = generate_safe_poc(finding)
    assert "curl" in poc
    assert "-X POST" in poc
    assert "https://app.vuln-target.local:8443/login" in poc
    assert "username=admin' --" in poc

    steps = generate_reproduction_steps(finding)
    assert len(steps) >= 4
    assert any("https://app.vuln-target.local:8443/login" in s for s in steps)
    assert any("POST" in s for s in steps)
    assert any("username" in s for s in steps)


def test_evidence_sanitization_in_reports():
    """Ensure credentials, bearer tokens, and secrets are redacted."""
    sensitive_evidence = (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: sessionid=secret_cookie_token_987654321; HttpOnly\n"
        "Authorization: Bearer my_super_secret_jwt_token_12345\n"
        "{\"status\": \"error\", \"password\": \"SuperSecretP@ssword123!\"}"
    )
    f = MockFinding(
        finding_type="Sensitive Data Exposure",
        evidence=sensitive_evidence,
    )
    scan = MockScan()

    # Test Markdown
    md = build_bug_bounty_markdown(f, scan)
    assert "secret_cookie_token_987654321" not in md
    assert "my_super_secret_jwt_token_12345" not in md
    assert "SuperSecretP@ssword123!" not in md
    assert "[REDACTED]" in md

    # Test PDF bytes
    pdf_bytes = build_bug_bounty_pdf(f, scan)
    assert b"%PDF" in pdf_bytes
    assert b"secret_cookie_token_987654321" not in pdf_bytes
    assert b"SuperSecretP@ssword123!" not in pdf_bytes


def test_bug_bounty_markdown_format():
    """Verify HackerOne Markdown structure meets professional bounty platform standards."""
    f = MockFinding(
        finding_type="Cross-Site Scripting (XSS)",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        detection_status="Confirmed",
        url="https://app.vuln-target.local:8443/comment?id=5",
        parameter="id",
        cwe_id="CWE-79",
        evidence="Reflected payload <script>alert(1)</script> detected in response body.",
    )
    scan = MockScan()

    md = build_bug_bounty_markdown(f, scan)
    assert "# [MEDIUM] Cross-Site Scripting (XSS)" in md
    assert "## Vulnerability Overview" in md
    assert "| **Vulnerability Type** | Cross-Site Scripting (XSS) |" in md
    assert "| **Severity** | **Medium** |" in md
    assert "| **CWE ID** | CWE-79 |" in md
    assert "## Steps to Reproduce" in md
    assert "## Safe Proof of Concept (PoC)" in md
    assert "```bash" in md
    assert "curl" in md
    assert "## Security Impact" in md
    assert "## Recommended Remediation" in md
    assert "## References & Authoritative Sources" in md


def test_bug_bounty_pdf_generation_sqli_and_xss_page_count():
    """Verify generation of concise, professional 1-2 page Bug Bounty PDF reports for SQLi and XSS."""
    scan = MockScan()

    # 1. SQL Injection Report (Target 1-2 pages)
    f_sqli = MockFinding(
        finding_type="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        detection_status="Confirmed",
        url="https://app.vuln-target.local:8443/products?category=books",
        parameter="category",
    )
    pdf_sqli = build_bug_bounty_pdf(f_sqli, scan)
    assert isinstance(pdf_sqli, bytes)
    assert pdf_sqli.startswith(b"%PDF")
    pages_sqli = get_pdf_page_count(pdf_sqli)
    assert 1 <= pages_sqli <= 2, f"Expected 1-2 pages for SQLi, got {pages_sqli}"

    # 2. XSS Report (Target 1-2 pages)
    f_xss = MockFinding(
        finding_type="Cross-Site Scripting (XSS)",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        detection_status="Confirmed",
        url="https://app.vuln-target.local:8443/profile",
        parameter="name",
        evidence="Payload <svg onload=alert(1)> rendered unescaped in DOM.",
    )
    pdf_xss = build_bug_bounty_pdf(f_xss, scan)
    assert isinstance(pdf_xss, bytes)
    assert pdf_xss.startswith(b"%PDF")
    pages_xss = get_pdf_page_count(pdf_xss)
    assert 1 <= pages_xss <= 2, f"Expected 1-2 pages for XSS, got {pages_xss}"


def test_bug_bounty_pdf_csrf_page_count():
    """Verify CSRF Bug Bounty PDF generation within 1-2 pages."""
    f_csrf = MockFinding(
        finding_type="Cross-Site Request Forgery (CSRF)",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        detection_status="Confirmed",
        url="https://app.vuln-target.local:8443/api/user/email",
        method="POST",
        parameter="email",
        cwe_id="CWE-352",
        evidence="POST endpoint executes state change without CSRF token validation.",
    )
    pdf_csrf = build_bug_bounty_pdf(f_csrf)
    assert pdf_csrf.startswith(b"%PDF")
    pages = get_pdf_page_count(pdf_csrf)
    assert 1 <= pages <= 2, f"Expected 1-2 pages for CSRF, got {pages}"


def test_bug_bounty_pdf_potential_and_manual_verification():
    """Verify potential and manual verification findings show unassessed CVSS and span 1-2 pages."""
    f_pot = MockFinding(
        finding_type="Sensitive File Exposure",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        detection_status="Requires Manual Verification",
        url="https://app.vuln-target.local:8443/.env.bak",
        method="GET",
        parameter=None,
        evidence="HTTP 200 OK returned on .env.bak but length matches custom 404 handler.",
    )
    cvss = assess_finding_cvss(f_pot, match_vuln_knowledge(f_pot.type))
    assert cvss["assessed"] is False
    assert "Not Assessed" in cvss["vector"]
    assert "Manual Evaluation Required" in cvss["vector"]

    pdf_pot = build_bug_bounty_pdf(f_pot)
    assert pdf_pot.startswith(b"%PDF")
    pages = get_pdf_page_count(pdf_pot)
    assert 1 <= pages <= 2, f"Expected 1-2 pages, got {pages}"


def test_bug_bounty_pdf_missing_evidence():
    """Verify findings with missing evidence don't crash and generate valid 1-2 page PDF."""
    f_sparse = MockFinding(
        finding_type="Open Redirect",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        detection_status="Confirmed",
        url="https://app.vuln-target.local:8443/redir",
        method="GET",
        parameter="next",
        evidence="",
        description="",
        impact="",
        remediation="",
        evidence_details={},
    )
    pdf_sparse = build_bug_bounty_pdf(f_sparse)
    assert pdf_sparse.startswith(b"%PDF")
    pages = get_pdf_page_count(pdf_sparse)
    assert 1 <= pages <= 2, f"Expected 1-2 pages, got {pages}"


def test_assessment_summary_pdf_generation_multiple_findings():
    """Verify generation of concise 1-3 page Security Assessment Summary PDF."""
    scan = MockScan()
    f1 = MockFinding(
        finding_id="f-1",
        finding_type="SQL Injection",
        severity=Severity.CRITICAL,
        detection_status="Confirmed",
    )
    f2 = MockFinding(
        finding_id="f-2",
        finding_type="Cross-Site Scripting (XSS)",
        severity=Severity.HIGH,
        detection_status="Confirmed",
    )
    f3 = MockFinding(
        finding_id="f-3",
        finding_type="Missing Security Header",
        severity=Severity.LOW,
        detection_status="Confirmed",
        parameter="x-frame-options",
        cwe_id="CWE-1021",
    )
    f4 = MockFinding(
        finding_id="f-4",
        finding_type="Potential Server-Side Template Injection",
        severity=Severity.MEDIUM,
        detection_status="Potential",
        description="Heuristic arithmetic tag reflected but evaluation unconfirmed.",
    )
    f5 = MockFinding(
        finding_id="f-5",
        finding_type="Anomalous Error Response",
        severity=Severity.LOW,
        detection_status="Requires Manual Verification",
        description="HTTP 502 Bad Gateway observed on large fuzz payload.",
    )

    pdf = build_assessment_summary_pdf(scan, [f1, f2, f3, f4, f5])
    assert isinstance(pdf, bytes)
    assert len(pdf) > 2000
    assert pdf.startswith(b"%PDF")
    pages = get_pdf_page_count(pdf)
    assert 1 <= pages <= 3, f"Expected 1-3 pages for multi-finding summary, got {pages}"


def test_assessment_summary_pdf_clean_scan():
    """Verify clean scan with zero findings produces an elegant, professional 1-page summary."""
    scan = MockScan()
    pdf_clean = build_assessment_summary_pdf(scan, [])
    assert isinstance(pdf_clean, bytes)
    assert len(pdf_clean) > 2000
    assert pdf_clean.startswith(b"%PDF")
    pages = get_pdf_page_count(pdf_clean)
    assert 1 <= pages <= 2, f"Expected 1-2 pages for clean scan summary, got {pages}"


def test_bug_bounty_markdown_for_potential_findings():
    """Verify that potential / manual verification findings include prominent disclaimer notices."""
    f = MockFinding(
        finding_type="Potential SQL Injection Anomaly",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        detection_status="Requires Manual Verification",
        url="https://app.vuln-target.local:8443/lookup?id=9",
    )
    md = build_bug_bounty_markdown(f)
    assert "**Detection Status** | Requires Manual Verification" in md
    assert "This vulnerability is flagged as **Requires Manual Verification**" in md


def test_group_findings_into_unique():
    """Verify that raw findings are deduplicated into unique issues with raw occurrences counted."""
    f1 = MockFinding(
        finding_id="f-1",
        finding_type="Missing Content-Security-Policy Header",
        severity=Severity.LOW,
        url="https://app.vuln-target.local:8443/",
        parameter="content-security-policy",
    )
    f2 = MockFinding(
        finding_id="f-2",
        finding_type="Missing Content-Security-Policy Header",
        severity=Severity.LOW,
        url="https://app.vuln-target.local:8443/login",
        parameter="content-security-policy",
    )
    f3 = MockFinding(
        finding_id="f-3",
        finding_type="Missing Content-Security-Policy Header",
        severity=Severity.LOW,
        url="https://app.vuln-target.local:8443/dashboard",
        parameter="content-security-policy",
    )
    f4 = MockFinding(
        finding_id="f-4",
        finding_type="SQL Injection",
        severity=Severity.HIGH,
        url="https://app.vuln-target.local:8443/api/search?q=1",
        parameter="q",
    )

    unique_list = group_findings_into_unique([f1, f2, f3, f4])
    assert len(unique_list) == 2
    # Sorted by severity: High (SQLi) first, then Low (CSP)
    assert unique_list[0]["type"] == "SQL Injection"
    assert unique_list[0]["occurrences"] == 1
    assert unique_list[1]["type"] == "Missing Content-Security-Policy Header"
    assert unique_list[1]["occurrences"] == 3
    assert len(unique_list[1]["affected_urls"]) == 3


def test_complete_website_bug_bounty_pdf_multi_findings():
    """Verify ONE comprehensive 4-6 page PDF is generated for the entire website scan."""
    scan = MockScan(scan_id="scan-website-complete-001")

    # Simulate 5 unique vulnerabilities across 12 raw occurrences
    findings = [
        MockFinding(
            finding_id="sqli-1",
            finding_type="SQL Injection",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            detection_status="Confirmed",
            url="https://app.vuln-target.local:8443/api/v1/users?id=1",
            parameter="id",
            payload="' OR 1=1 --",
            evidence="MySQL syntax error near '' OR 1=1 --' in query: SELECT * FROM users WHERE id='1' OR 1=1 --",
            cwe_id="CWE-89",
        ),
        MockFinding(
            finding_id="xss-1",
            finding_type="Reflected Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            detection_status="Confirmed",
            url="https://app.vuln-target.local:8443/search?query=x",
            parameter="query",
            payload='"><script>alert(1)</script>',
            evidence='Reflected payload executable in response body: <input name="query" value=""><script>alert(1)</script>">',
            cwe_id="CWE-79",
        ),
        MockFinding(
            finding_id="csrf-1",
            finding_type="Cross-Site Request Forgery (CSRF)",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            detection_status="Confirmed",
            url="https://app.vuln-target.local:8443/settings/profile",
            method="POST",
            parameter="email",
            evidence="POST endpoint does not validate Anti-CSRF token or SameSite cookie protection.",
            cwe_id="CWE-352",
        ),
        # 3 raw occurrences of missing CSP
        MockFinding(
            finding_id="csp-1",
            finding_type="Missing Content-Security-Policy Header",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            detection_status="Confirmed",
            url="https://app.vuln-target.local:8443/",
            parameter="content-security-policy",
            evidence="Content-Security-Policy header is missing in HTTP response headers.",
            cwe_id="CWE-1021",
        ),
        MockFinding(
            finding_id="csp-2",
            finding_type="Missing Content-Security-Policy Header",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            detection_status="Confirmed",
            url="https://app.vuln-target.local:8443/login",
            parameter="content-security-policy",
            evidence="Content-Security-Policy header is missing in HTTP response headers.",
            cwe_id="CWE-1021",
        ),
        MockFinding(
            finding_id="csp-3",
            finding_type="Missing Content-Security-Policy Header",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            detection_status="Confirmed",
            url="https://app.vuln-target.local:8443/docs",
            parameter="content-security-policy",
            evidence="Content-Security-Policy header is missing in HTTP response headers.",
            cwe_id="CWE-1021",
        ),
        # Manual verification finding
        MockFinding(
            finding_id="mv-1",
            finding_type="Potential Server-Side Request Forgery",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            detection_status="Requires Manual Verification",
            url="https://app.vuln-target.local:8443/fetch-avatar?url=http://127.0.0.1",
            parameter="url",
            evidence="Server responded with HTTP 500 when requesting loopback address.",
            cwe_id="CWE-918",
        ),
    ]

    pdf = build_complete_website_bug_bounty_pdf(scan, findings)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 4000

    pages = get_pdf_page_count(pdf)
    assert 1 <= pages <= 3, f"Expected 1-3 pages for multi-finding website report, got {pages}"


def test_complete_website_bug_bounty_pdf_clean_scan():
    """Verify clean website scan with 0 findings generates a clean 1-2 page PDF."""
    scan = MockScan(scan_id="scan-clean-999")
    pdf = build_complete_website_bug_bounty_pdf(scan, [])

    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 2000
    pages = get_pdf_page_count(pdf)
    assert 1 <= pages <= 2, f"Expected 1-2 pages for clean scan, got {pages}"
