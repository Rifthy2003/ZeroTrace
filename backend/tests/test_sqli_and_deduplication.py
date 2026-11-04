import pytest
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import unquote
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter, ScanFinding
from app.scanner.scanners import sql_injection
from app.scanner.severity import correlate, classify_finding_group


@pytest.mark.asyncio
async def test_sqli_auth_bypass_detection_json():
    """
    Test SQL injection authentication bypass on REST/JSON login endpoints
    (similar to OWASP Juice Shop /rest/user/login).
    Verifies that ' OR 1=1-- yields authentication token and ' OR 1=2--
    negative control confirms reproducible exploit.
    """
    ep = DiscoveredEndpoint(
        url="http://localhost:3000/rest/user/login",
        method="POST",
        parameters=[
            DiscoveredParameter(name="email", location="body", sample_value="admin@juice-sh.op"),
            DiscoveredParameter(name="password", location="body", sample_value="admin123"),
        ],
    )

    client = MagicMock()

    async def mock_post(url, json=None, data=None, **kwargs):
        resp = MagicMock()
        payload_data = json or data or {}
        email_val = payload_data.get("email", "")

        # Vulnerable SQL query behavior:
        # SELECT * FROM Users WHERE email = '{email}' AND password = '{pwd}'
        if "' OR 1=1--" in email_val or "' or 1=1 limit 1--" in email_val or "admin'--" in email_val:
            resp.status_code = 200
            resp.text = (
                '{"authentication": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoiYWRtaW4ifQ.signature",'
                '"bid": 1, "umail": "admin@juice-sh.op"}}'
            )
            resp.headers = {"content-type": "application/json"}
        elif "' OR 1=2--" in email_val or "1' AND '1'='2" in email_val:
            # Negative control fails correctly
            resp.status_code = 401
            resp.text = '{"error": "Invalid email or password."}'
            resp.headers = {"content-type": "application/json"}
        else:
            resp.status_code = 401
            resp.text = '{"error": "Invalid email or password."}'
            resp.headers = {"content-type": "application/json"}
        return resp

    client.post = AsyncMock(side_effect=mock_post)
    client.get = AsyncMock()

    findings = await sql_injection.scan(ep, client)
    assert len(findings) >= 1, "Expected SQL injection auth bypass finding"

    auth_bypass_findings = [f for f in findings if "Authentication Bypass" in (f.evidence or "") or f.severity == "Critical"]
    assert len(auth_bypass_findings) >= 1, "Expected critical auth-bypass finding"

    f = auth_bypass_findings[0]
    assert f.type == "SQL Injection"
    assert f.parameter == "email"
    assert f.severity == "Critical"
    assert f.confidence == "Confirmed"
    assert f.detection_status == "Confirmed"
    assert f.finding_group == "critical_vulnerabilities"
    assert "negative control" in f.evidence.lower()
    assert "token" in f.evidence.lower() or "authentication" in f.evidence.lower()


@pytest.mark.asyncio
async def test_sqli_auth_bypass_negative_control_prevents_false_positive():
    """
    If a server returns 200 OK / tokens regardless of payload (e.g. a stub/mock or open endpoint),
    negative control probe (' OR 1=2--) also succeeds, which MUST reject the finding.
    """
    ep = DiscoveredEndpoint(
        url="http://localhost:3000/rest/user/login",
        method="POST",
        parameters=[
            DiscoveredParameter(name="email", location="body", sample_value="test@example.com"),
            DiscoveredParameter(name="password", location="body", sample_value="secret"),
        ],
    )

    client = MagicMock()

    # Stub server returns JWT on all requests regardless of input
    async def mock_post_always_auth(url, json=None, data=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy", "user": "guest"}'
        resp.headers = {"content-type": "application/json"}
        return resp

    client.post = AsyncMock(side_effect=mock_post_always_auth)
    client.get = AsyncMock()

    findings = await sql_injection.scan(ep, client)
    auth_findings = [f for f in findings if "Authentication Bypass" in (f.evidence or "")]
    assert len(auth_findings) == 0, "Permissive server must not generate an Authentication Bypass finding"


@pytest.mark.asyncio
async def test_sqli_sqlite_sequelize_error_detection():
    """
    Test SQLite and Sequelize database error regex matching.
    """
    ep = DiscoveredEndpoint(
        url="http://localhost:3000/api/Products",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="apple")],
    )

    client = MagicMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock()
        decoded_url = unquote(url)
        if "apple'" in decoded_url or "apple\"" in decoded_url:
            resp.status_code = 500
            resp.text = '{"error": "SQLITE_ERROR: near \\"syntax error\\": SELECT * FROM Products WHERE name LIKE \'%apple\'%\'"}'
        else:
            resp.status_code = 200
            resp.text = '{"data": []}'
        return resp

    client.get = AsyncMock(side_effect=mock_get)
    client.post = AsyncMock()

    findings = await sql_injection.scan(ep, client)
    assert len(findings) >= 1
    f = findings[0]
    assert f.type == "SQL Injection"
    assert f.parameter == "q"
    assert "syntax error" in f.evidence.lower() or "sqlite" in f.evidence.lower()


def test_clickjacking_deduplication_site_wide():
    """
    Verifies that 20 Clickjacking Protection Missing findings across 20 distinct URLs
    are consolidated into exactly 1 unique finding with 20 raw occurrences.
    """
    raw_findings = []
    for i in range(1, 21):
        raw_findings.append(
            ScanFinding(
                type="Clickjacking Protection Missing",
                category="Configuration",
                method="GET",
                severity="Medium",
                confidence="Confirmed",
                description="Clickjacking defense is missing",
                impact="User interface redress attack",
                remediation="Configure X-Frame-Options or CSP frame-ancestors",
                url=f"http://example.com/page{i}",
                parameter="X-Frame-Options",
                evidence="Neither X-Frame-Options nor CSP frame-ancestors header present",
                cwe_id="CWE-1021",
                mitre_attack="T1190",
            )
        )

    correlated = correlate(raw_findings)
    assert len(correlated) == 1, f"Expected exactly 1 consolidated finding, got {len(correlated)}"

    f = correlated[0]
    assert f.type == "Clickjacking Protection Missing"
    assert f.finding_group == "security_configuration"
    assert f.raw_instances == 20
    assert f.evidence_details is not None
    assert len(f.evidence_details["affected_urls"]) == 20
    assert f.evidence_details["total_affected_endpoints"] == 20
    assert len(f.evidence_details["occurrences"]) == 20


def test_missing_header_deduplication_site_wide():
    """
    Verifies that Missing Security Header findings for CSP and HSTS across 15 URLs
    are consolidated into 2 unique findings, each with 15 raw occurrences.
    """
    raw_findings = []
    for i in range(1, 16):
        raw_findings.append(
            ScanFinding(
                type="Missing Security Header",
                category="Configuration",
                method="GET",
                severity="Medium",
                confidence="Confirmed",
                description="Missing CSP",
                impact="Potential XSS exploitation",
                remediation="Implement CSP header",
                url=f"http://example.com/sub/path{i}",
                parameter="Content-Security-Policy",
                evidence="Content-Security-Policy header is missing",
                cwe_id="CWE-693",
                mitre_attack="T1562",
            )
        )
        raw_findings.append(
            ScanFinding(
                type="Missing Security Header",
                category="Configuration",
                method="GET",
                severity="Low",
                confidence="Confirmed",
                description="Missing HSTS",
                impact="Potential MitM vulnerability",
                remediation="Implement Strict-Transport-Security header",
                url=f"http://example.com/sub/path{i}",
                parameter="Strict-Transport-Security",
                evidence="Strict-Transport-Security header is missing",
                cwe_id="CWE-693",
                mitre_attack="T1562",
            )
        )

    correlated = correlate(raw_findings)
    assert len(correlated) == 2, f"Expected 2 unique findings (CSP and HSTS), got {len(correlated)}"

    csp_finding = next((f for f in correlated if f.parameter.lower() == "content-security-policy"), None)
    hsts_finding = next((f for f in correlated if f.parameter.lower() == "strict-transport-security"), None)

    assert csp_finding is not None
    assert csp_finding.finding_group == "security_configuration"
    assert csp_finding.raw_instances == 15
    assert len(csp_finding.evidence_details["affected_urls"]) == 15

    assert hsts_finding is not None
    assert hsts_finding.finding_group == "security_configuration"
    assert hsts_finding.raw_instances == 15
    assert len(hsts_finding.evidence_details["affected_urls"]) == 15


def test_prioritized_group_classification():
    """
    Test finding group classification taxonomy:
    - critical_vulnerabilities
    - other_vulnerabilities
    - security_configuration
    """
    # Critical Group
    assert classify_finding_group("SQL Injection", "Injection", "Critical") == "critical_vulnerabilities"
    assert classify_finding_group("Remote Code Execution", "Code Execution", "Critical") == "critical_vulnerabilities"
    assert classify_finding_group("Authentication Bypass", "Broken Authentication", "Critical") == "critical_vulnerabilities"

    # Other Group
    assert classify_finding_group("Cross-Site Scripting (Reflected)", "XSS", "High") == "other_vulnerabilities"
    assert classify_finding_group("Open Redirect", "Redirection", "Medium") == "other_vulnerabilities"
    assert classify_finding_group("Cross-Site Request Forgery", "CSRF", "Medium") == "other_vulnerabilities"

    # Security Configuration Group
    assert classify_finding_group("Missing Security Header", "Configuration", "Low") == "security_configuration"
    assert classify_finding_group("Clickjacking Protection Missing", "Configuration", "Medium") == "security_configuration"
    assert classify_finding_group("Insecure Cookie (Missing Secure Flag)", "Cookies", "Low") == "security_configuration"
    assert classify_finding_group("CORS Misconfiguration", "Configuration", "Medium") == "security_configuration"
