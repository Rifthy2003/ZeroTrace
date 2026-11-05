import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime

from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter, ScanFinding
from app.models.finding import Finding, Severity, Confidence
from app.models.scan import Scan, ScanStatus
from app.models.scan_summary import ScanSummary
from app.scanner.engine import run_scan
from app.reports.bug_bounty_report import build_complete_website_bug_bounty_pdf
from app.reports.assessment_summary import build_assessment_summary_pdf
from app.reports.pdf_report import build_report
from app.database.session import SessionLocal


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.mark.asyncio
async def test_reporting_module_with_vulnerabilities(db_session):
    """Verify complete reporting execution path: correlation, _get_module_for_finding, ORM persistence, and summary."""
    from app.models.target import Target

    target = Target(base_url="https://vulnerable.test.local", hostname="vulnerable.test.local")
    db_session.add(target)
    db_session.commit()

    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
        max_depth=2,
        max_urls=10,
        modules=["sql_injection", "xss", "clickjacking", "command_injection"],
    )
    db_session.add(scan)
    db_session.commit()

    # Mock the crawler and scanners to return realistic discovered endpoints & findings
    mock_ep = DiscoveredEndpoint(
        url="https://vulnerable.test.local/login",
        method="POST",
        status_code=200,
        parameters=[DiscoveredParameter(name="username", location="form", sample_value="admin")],
    )

    mock_findings = [
        ScanFinding(
            type="SQL Injection",
            category="Injection",
            owasp_category="A03:2021 - Injection",
            url="https://vulnerable.test.local/login",
            method="POST",
            parameter="username",
            severity="Critical",
            confidence="High confidence",
            cwe_id="CWE-89",
            mitre_attack="T1190",
            detection_status="Confirmed",
            evidence="Auth bypass: SQL payload returned 200 with JWT session token",
            description="SQL Injection in login form allows complete authentication bypass.",
            impact="Unauthorized full account access.",
            remediation="Use parameterized prepared statements.",
            module="sql_injection",
        ),
        ScanFinding(
            type="Clickjacking Protection Missing",
            category="Security Misconfiguration",
            owasp_category="A05:2021 - Security Misconfiguration",
            url="https://vulnerable.test.local/login",
            method="GET",
            parameter="X-Frame-Options",
            severity="Medium",
            confidence="High confidence",
            cwe_id="CWE-1021",
            mitre_attack="T1189",
            detection_status="Confirmed",
            evidence="Neither X-Frame-Options nor CSP frame-ancestors header present",
            description="Page can be embedded in malicious iframe.",
            impact="UI redressing / clickjacking attack.",
            remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
            module="clickjacking",
        ),
    ]

    with patch("app.scanner.engine.Crawler.crawl", new_callable=AsyncMock) as mock_crawl, \
         patch("app.scanner.scanners.sql_injection.scan", new_callable=AsyncMock) as mock_sqli, \
         patch("app.scanner.scanners.clickjacking.scan") as mock_click, \
         patch("app.scanner.scanners.xss.scan", new_callable=AsyncMock) as mock_xss, \
         patch("app.scanner.scanners.command_injection.scan", new_callable=AsyncMock) as mock_cmdi:

        mock_crawl.return_value = [mock_ep]
        mock_sqli.return_value = [mock_findings[0]]
        mock_click.return_value = [mock_findings[1]]
        mock_xss.return_value = []
        mock_cmdi.return_value = []

        # Run scan engine
        await run_scan(scan.id)

    db_session.refresh(scan)

    # 1. Verify scan completed successfully (did not fail with ScanFinding NameError)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.error_message is None
    assert scan.progress_percent == 100.0
    assert scan.findings_count == 2

    # 2. Verify findings stored in database
    db_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(db_findings) == 2
    types = [f.type for f in db_findings]
    assert "SQL Injection" in types
    assert "Clickjacking Protection Missing" in types

    # 3. Verify scan summary
    summary = db_session.query(ScanSummary).filter(ScanSummary.scan_id == scan.id).first()
    assert summary is not None
    assert summary.critical_count == 1
    assert summary.medium_count == 1

    # 4. Verify module matrix
    matrix = scan.coverage_summary.get("module_matrix", [])
    sqli_row = next((r for r in matrix if r["module"] == "sql_injection"), None)
    assert sqli_row is not None
    assert sqli_row["findings_count"] == 1
    assert sqli_row["status"] == "Tested"

    # 5. Generate both Short Report PDF and Security Summary PDF
    short_pdf = build_complete_website_bug_bounty_pdf(scan, db_findings, summary)
    assert short_pdf.startswith(b"%PDF-")
    assert len(short_pdf) > 1000

    summary_pdf = build_assessment_summary_pdf(scan, db_findings, summary)
    assert summary_pdf.startswith(b"%PDF-")
    assert len(summary_pdf) > 1000

    full_pdf = build_report(scan, db_findings, summary)
    assert full_pdf.startswith(b"%PDF-")
    assert len(full_pdf) > 1000


@pytest.mark.asyncio
async def test_reporting_module_zero_findings(db_session):
    """Verify reporting execution path for a clean scan with zero findings."""
    from app.models.target import Target

    target = Target(base_url="https://secure.test.local", hostname="secure.test.local")
    db_session.add(target)
    db_session.commit()

    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
        max_depth=1,
        max_urls=5,
        modules=["sql_injection", "xss"],
    )
    db_session.add(scan)
    db_session.commit()

    mock_ep = DiscoveredEndpoint(
        url="https://secure.test.local/about",
        method="GET",
        status_code=200,
        parameters=[],
    )

    with patch("app.scanner.engine.Crawler.crawl", new_callable=AsyncMock) as mock_crawl, \
         patch("app.scanner.scanners.sql_injection.scan", new_callable=AsyncMock) as mock_sqli, \
         patch("app.scanner.scanners.xss.scan", new_callable=AsyncMock) as mock_xss:

        mock_crawl.return_value = [mock_ep]
        mock_sqli.return_value = []
        mock_xss.return_value = []

        await run_scan(scan.id)

    db_session.refresh(scan)

    assert scan.status == ScanStatus.COMPLETED
    assert scan.findings_count == 0
    assert scan.error_message is None

    db_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(db_findings) == 0

    summary = db_session.query(ScanSummary).filter(ScanSummary.scan_id == scan.id).first()
    assert summary is not None
    assert summary.critical_count == 0
    assert summary.high_count == 0

    # Verify PDF generation with 0 findings does not crash
    short_pdf = build_complete_website_bug_bounty_pdf(scan, [], summary)
    assert short_pdf.startswith(b"%PDF-")
    assert len(short_pdf) > 1000

    summary_pdf = build_assessment_summary_pdf(scan, [], summary)
    assert summary_pdf.startswith(b"%PDF-")
    assert len(summary_pdf) > 1000

    full_pdf = build_report(scan, [], summary)
    assert full_pdf.startswith(b"%PDF-")
    assert len(full_pdf) > 1000
