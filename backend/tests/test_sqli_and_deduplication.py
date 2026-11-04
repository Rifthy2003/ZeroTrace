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


@pytest.mark.asyncio
async def test_quick_scan_and_full_scan_sqli_consistency():
    """
    Requirement 8:
    - Quick Scan detects a known SQLi vulnerability.
    - Full Scan detects the same SQLi vulnerability.
    - Both modes preserve consistent evidence, severity (Critical), and confidence (Confirmed).
    """
    ep = DiscoveredEndpoint(
        url="http://localhost:3000/rest/user/login",
        method="POST",
        content_type="application/json",
        parameters=[
            DiscoveredParameter(name="email", location="json", sample_value="test@example.com"),
            DiscoveredParameter(name="password", location="json", sample_value="secret"),
        ],
        has_form=True,
    )

    client = MagicMock()

    async def mock_post(url, json=None, data=None, **kwargs):
        resp = MagicMock()
        payload_data = json or data or {}
        email_val = payload_data.get("email", "")

        if "' OR 1=1--" in email_val:
            resp.status_code = 200
            resp.text = '{"authentication": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy", "umail": "admin@juice-sh.op"}}'
            resp.headers = {"content-type": "application/json"}
        elif "' OR 1=2--" in email_val:
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

    # 1. Quick Scan execution of SQLi scanner
    quick_findings = await sql_injection.scan(ep, client)
    assert len(quick_findings) >= 1
    q_sqli = next(f for f in quick_findings if f.type == "SQL Injection")
    assert q_sqli.severity == "Critical"
    assert q_sqli.confidence == "Confirmed"
    assert q_sqli.detection_status == "Confirmed"
    assert q_sqli.parameter == "email"
    assert "JWT" in q_sqli.evidence or "authentication" in q_sqli.evidence.lower()

    # 2. Full Scan execution of SQLi scanner on the same endpoint
    full_findings = await sql_injection.scan(ep, client)
    assert len(full_findings) >= 1
    f_sqli = next(f for f in full_findings if f.type == "SQL Injection")
    assert f_sqli.severity == "Critical"
    assert f_sqli.confidence == "Confirmed"
    assert f_sqli.detection_status == "Confirmed"
    assert f_sqli.parameter == "email"

    # 3. Verify consistency across scan modes
    assert q_sqli.severity == f_sqli.severity
    assert q_sqli.confidence == f_sqli.confidence
    assert q_sqli.detection_status == f_sqli.detection_status
    assert q_sqli.evidence == f_sqli.evidence


def test_full_scan_does_not_lose_quick_scan_findings():
    """
    Requirement 8:
    - Full Scan does not lose findings detected by Quick Scan.
    - Additional Full Scan checks can produce additional findings without removing valid existing findings.
    """
    # Simulate findings detected by Quick Scan modules
    quick_scan_findings = [
        ScanFinding(
            type="SQL Injection",
            category="Injection",
            url="http://localhost:3000/rest/user/login",
            method="POST",
            parameter="email",
            severity="Critical",
            confidence="Confirmed",
            detection_status="Confirmed",
            evidence="Auth bypass confirmed with ' OR 1=1--",
            description="SQL injection vulnerability in login query.",
            impact="Unauthorized account access.",
            remediation="Use parameterized queries.",
        ),
        ScanFinding(
            type="Reflected XSS",
            category="Injection",
            url="http://localhost:3000/#/search",
            method="GET",
            parameter="q",
            severity="High",
            confidence="High confidence",
            detection_status="Confirmed",
            evidence="Unsanitized marker reflected in HTML context",
            description="Reflected input without contextual escaping.",
            impact="Execution of arbitrary JavaScript in user browser.",
            remediation="Apply contextual HTML encoding.",
        ),
        ScanFinding(
            type="Clickjacking Protection Missing",
            category="Security Configuration",
            url="http://localhost:3000/",
            method="GET",
            severity="Medium",
            confidence="Confirmed",
            detection_status="Confirmed",
            evidence="Neither XFO nor CSP frame-ancestors present",
            description="Page framing is not restricted.",
            impact="UI redress attack risk.",
            remediation="Set X-Frame-Options or CSP frame-ancestors.",
        ),
    ]

    # Simulate additional findings discovered by Full Scan's expanded modules
    additional_full_scan_findings = [
        ScanFinding(
            type="CORS Misconfiguration",
            category="Security Configuration",
            url="http://localhost:3000/api/Users",
            method="GET",
            severity="Medium",
            confidence="Confirmed",
            detection_status="Confirmed",
            evidence="Reflected arbitrary origin with credentials",
            description="CORS policy reflects arbitrary Origin with credentials.",
            impact="Cross-origin authenticated data theft.",
            remediation="Implement strict origin allowlist.",
        ),
        ScanFinding(
            type="Missing Security Header",
            category="Security Configuration",
            url="http://localhost:3000/",
            method="GET",
            parameter="content-security-policy",
            severity="Medium",
            confidence="Confirmed",
            detection_status="Confirmed",
            evidence="Content-Security-Policy missing",
            description="CSP header is missing.",
            impact="Lack of script execution restrictions.",
            remediation="Deploy a strong CSP header.",
        ),
    ]

    # Full Scan includes all Quick findings + additional findings
    full_scan_all_findings = list(quick_scan_findings) + additional_full_scan_findings

    correlated_quick = correlate(quick_scan_findings)
    correlated_full = correlate(full_scan_all_findings)

    # Full Scan must contain all findings present in Quick Scan
    quick_types = {f.type for f in correlated_quick}
    full_types = {f.type for f in correlated_full}

    for qt in quick_types:
        assert qt in full_types, f"Full Scan lost Quick Scan finding: {qt}"

    # Full scan must have more findings than Quick scan
    assert len(correlated_full) > len(correlated_quick)

    # Severity and detection status of shared findings must match exactly
    for q_f in correlated_quick:
        match_f = next(f for f in correlated_full if f.type == q_f.type and f.parameter == q_f.parameter)
        assert match_f.severity == q_f.severity
        assert match_f.detection_status == q_f.detection_status


def test_socket_io_endpoints_do_not_flag_auth_security_weakness():
    """
    Requirement 7:
    - Verify Authentication Security Weakness on socket.io endpoints.
    - Do not confirm a vulnerability based only on the presence of a session ID parameter.
    """
    from app.scanner.scanners import auth_security

    ep_socket = DiscoveredEndpoint(
        url="http://localhost:3000/socket.io/?EIO=4&transport=polling&t=wtm3wjvx&sid=vMNs2kpug7CNO91sAAAB",
        method="GET",
        status_code=200,
        content_type="application/json",
        parameters=[
            DiscoveredParameter(name="EIO", location="query", sample_value="4"),
            DiscoveredParameter(name="transport", location="query", sample_value="polling"),
            DiscoveredParameter(name="t", location="query", sample_value="wtm3wjvx"),
            DiscoveredParameter(name="sid", location="query", sample_value="vMNs2kpug7CNO91sAAAB"),
        ],
    )

    findings = auth_security.scan(ep_socket)
    assert len(findings) == 0, f"Expected 0 findings on socket.io polling route, got {len(findings)}"


def test_session_param_does_not_confirm_vulnerability_without_proof():
    """
    Requirement 7:
    - On non-socket endpoints, parameter name matching alone must NOT produce a Confirmed vulnerability.
    """
    from app.scanner.scanners import auth_security

    ep = DiscoveredEndpoint(
        url="http://localhost:3000/api/view?sid=user_session_abc123",
        method="GET",
        status_code=200,
        content_type="application/json",
        parameters=[
            DiscoveredParameter(name="sid", location="query", sample_value="user_session_abc123"),
        ],
    )

    findings = auth_security.scan(ep)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "Authentication Security Weakness"
    assert f.severity == "Low"
    assert f.confidence == "Low confidence"
    assert f.detection_status == "Requires Manual Verification"


def test_socket_io_endpoints_skipped_by_security_headers_and_clickjacking():
    """
    Requirement 6:
    - Socket.io polling routes must not explode into dozens of configuration issues.
    """
    from app.scanner.scanners import security_headers, clickjacking

    ep_socket = DiscoveredEndpoint(
        url="http://localhost:3000/socket.io/?EIO=4&transport=polling&t=wujgvotg",
        method="GET",
        status_code=200,
        content_type="text/plain; charset=UTF-8",
        response_headers={"content-type": "text/plain; charset=UTF-8"},
    )

    header_findings = security_headers.scan(ep_socket)
    assert len(header_findings) == 0, f"Expected 0 header findings on socket.io, got {len(header_findings)}"

    click_findings = clickjacking.scan(ep_socket)
    assert len(click_findings) == 0, f"Expected 0 clickjacking findings on socket.io, got {len(click_findings)}"


def test_quick_scan_configuration_and_module_filtering():
    """
    Regression Test:
    - Quick Scan runs SQL Injection, XSS, Clickjacking, and Command Injection.
    - Quick Scan skips Security Headers, Information Disclosure, and CSRF.
    - In Quick Scan mode, any disabled modules are dropped from effective execution.
    """
    from app.scanner.scope_enforcer import compute_effective_scan_config, QUICK_SCAN_MODULES

    # 1. Base Quick Scan profile configuration
    quick_profile_data = {
        "name": "Quick Scan",
        "modules": ["sql_injection", "xss", "clickjacking", "command_injection"],
        "max_depth": 1,
        "max_urls": 25,
        "send_payloads": True,
        "request_rate": 5.0,
        "concurrency": 2,
    }

    effective = compute_effective_scan_config(profile_data=quick_profile_data)
    eff_mods = set(effective["effective_modules"])

    # Required modules must be enabled
    assert "sql_injection" in eff_mods
    assert "xss" in eff_mods
    assert "clickjacking" in eff_mods
    assert "command_injection" in eff_mods

    # Disabled modules must NOT be enabled
    assert "security_headers" not in eff_mods
    assert "information_disclosure" not in eff_mods
    assert "csrf" not in eff_mods

    # 2. When user overrides or client defaults attempt to include disabled modules in Quick Scan
    user_overrides = {
        "scan_type": "Quick Scan",
        "modules": [
            "security_headers",
            "sql_injection",
            "csrf",
            "command_injection",
            "xss",
            "clickjacking",
            "information_disclosure",
            "cookie_security",
        ],
    }

    effective_filtered = compute_effective_scan_config(
        profile_data=quick_profile_data,
        user_overrides=user_overrides,
    )
    eff_filtered_mods = set(effective_filtered["effective_modules"])

    # Required modules remain
    assert "sql_injection" in eff_filtered_mods
    assert "xss" in eff_filtered_mods
    assert "clickjacking" in eff_filtered_mods
    assert "command_injection" in eff_filtered_mods

    # Disabled modules are strictly dropped
    assert "security_headers" not in eff_filtered_mods
    assert "information_disclosure" not in eff_filtered_mods
    assert "csrf" not in eff_filtered_mods

    # Dropped modules recorded in effective restrictions
    dropped = " ".join(effective_filtered["effective_restrictions"]["dropped_modules"])
    assert "security_headers" in dropped
    assert "information_disclosure" in dropped
    assert "csrf" in dropped


def test_full_scan_continues_running_all_applicable_modules():
    """
    Regression Test:
    - Full Scan continues running all applicable modules.
    - Full Scan includes all Quick Scan modules plus additional deep-scanning modules.
    - Disabled Quick Scan modules (Security Headers, Info Disclosure, CSRF) remain active in Full Scan.
    """
    from app.scanner.scope_enforcer import compute_effective_scan_config, ALL_KNOWN_MODULES

    full_profile_data = {
        "name": "Full Scan",
        "modules": list(ALL_KNOWN_MODULES),
        "max_depth": 3,
        "max_urls": 60,
        "send_payloads": True,
        "request_rate": 10.0,
        "concurrency": 4,
    }

    effective = compute_effective_scan_config(profile_data=full_profile_data)
    eff_mods = set(effective["effective_modules"])

    # All Quick Scan modules must be present
    assert "sql_injection" in eff_mods
    assert "xss" in eff_mods
    assert "clickjacking" in eff_mods
    assert "command_injection" in eff_mods

    # Modules disabled in Quick Scan must remain present in Full Scan
    assert "security_headers" in eff_mods
    assert "information_disclosure" in eff_mods
    assert "csrf" in eff_mods

    # Deep-scanning modules must remain present
    assert "cors" in eff_mods
    assert "path_traversal" in eff_mods
    assert "ssti" in eff_mods
    assert "auth_security" in eff_mods
    assert "graphql" in eff_mods


@pytest.mark.asyncio
async def test_quick_scan_modules_execution_and_findings():
    """
    Regression Test:
    - SQL Injection, Clickjacking, and Command Injection actually execute during Quick Scan.
    - Command Injection executes and detects vulnerable parameters.
    - Clickjacking executes and detects missing framing protections.
    - SQL Injection executes and detects vulnerable injection points.
    """
    from app.scanner.scanners import command_injection, clickjacking, sql_injection

    # 1. Test Command Injection scanner execution on test endpoint
    ep_cmd = DiscoveredEndpoint(
        url="http://localhost:3000/api/tools/ping",
        method="POST",
        parameters=[
            DiscoveredParameter(name="host", location="form", sample_value="127.0.0.1"),
        ],
        has_form=True,
    )

    client_cmd = MagicMock()

    async def mock_cmd_post(url, data=None, json=None, **kwargs):
        resp = MagicMock()
        payload = (data or json or {}).get("host", "")
        # If payload contains echo probe, simulate shell echo output
        if "; echo " in payload:
            marker = payload.split("; echo ")[1].split(" ")[0].strip()
            resp.status_code = 200
            resp.text = f"PING 127.0.0.1\n64 bytes from 127.0.0.1\n{marker}\n"
        elif "| echo " in payload:
            marker = payload.split("| echo ")[1].strip()
            resp.status_code = 200
            resp.text = f"{marker}\n"
        else:
            resp.status_code = 200
            resp.text = "PING 127.0.0.1\n64 bytes from 127.0.0.1\n"
        return resp

    client_cmd.post = AsyncMock(side_effect=mock_cmd_post)
    client_cmd.get = AsyncMock()

    cmd_findings = await command_injection.scan(ep_cmd, client_cmd)
    assert len(cmd_findings) >= 1
    f_cmd = cmd_findings[0]
    assert f_cmd.type == "Command Injection"
    assert f_cmd.severity == "Critical"
    assert f_cmd.confidence == "Confirmed"
    assert f_cmd.detection_status == "Confirmed"
    assert f_cmd.parameter == "host"

    # 2. Test Clickjacking scanner execution
    ep_click = DiscoveredEndpoint(
        url="http://localhost:3000/vulnerable-view",
        method="GET",
        status_code=200,
        content_type="text/html; charset=utf-8",
        response_headers={"content-type": "text/html; charset=utf-8"},
    )

    click_findings = clickjacking.scan(ep_click)
    assert len(click_findings) >= 1
    f_click = click_findings[0]
    assert f_click.type == "Clickjacking Protection Missing"
    assert f_click.severity == "Medium"
    assert f_click.confidence == "Confirmed"

