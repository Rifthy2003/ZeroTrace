import pytest
import re
from unittest.mock import AsyncMock, MagicMock
from bs4 import BeautifulSoup
from urllib.parse import unquote, unquote_plus

from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter, ScanFinding
from app.scanner.scanners import (
    sql_injection,
    xss,
    command_injection,
    ssti,
    path_traversal,
    cors,
    clickjacking,
    auth_security,
)
from app.scanner.severity import correlate, CWE_MITRE_MAP
from app.scanner.crawler import Crawler


@pytest.mark.asyncio
async def test_sqli_error_and_boolean_detection():
    ep = DiscoveredEndpoint(
        url="http://localhost:5000/products",
        method="GET",
        parameters=[DiscoveredParameter(name="id", location="query", sample_value="10")],
    )

    client = MagicMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        # If single quote is present, return MySQL syntax error
        if "10'" in url or "10%27" in url:
            resp.text = "You have an error in your SQL syntax near '10'' at line 1"
        else:
            resp.text = "Product: Organic Apples, Price: $4.99"
        return resp

    client.get = AsyncMock(side_effect=mock_get)
    client.post = AsyncMock()

    findings = await sql_injection.scan(ep, client)
    assert len(findings) >= 1
    f = findings[0]
    assert f.type == "SQL Injection"
    assert f.parameter == "id"
    assert f.cwe_id == "CWE-89"
    assert f.mitre_attack == "T1190"
    assert f.detection_status in ("Confirmed", "Requires Manual Verification")
    assert "syntax" in f.evidence.lower()


@pytest.mark.asyncio
async def test_sqli_post_parameter_support():
    ep = DiscoveredEndpoint(
        url="http://localhost:5000/login",
        method="POST",
        parameters=[DiscoveredParameter(name="username", location="body", sample_value="admin")],
    )

    client = MagicMock()

    async def mock_post(url, data=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        val = data.get("username", "") if data else ""
        if "'" in val:
            resp.text = "org.postgresql.util.PSQLException: syntax error at or near \"'\""
        else:
            resp.text = "Invalid credentials"
        return resp

    client.post = AsyncMock(side_effect=mock_post)
    client.get = AsyncMock()

    findings = await sql_injection.scan(ep, client)
    assert len(findings) >= 1
    assert findings[0].type == "SQL Injection"
    assert findings[0].parameter == "username"
    assert findings[0].method == "POST"


@pytest.mark.asyncio
async def test_xss_reflected_and_dom_detection():
    # 1. Reflected XSS
    ep = DiscoveredEndpoint(
        url="http://localhost:5000/search",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="test")],
    )

    client = MagicMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "text/html; charset=utf-8"}
        # Reflect whatever was sent in q unencoded
        match = re.search(r"q=([^&]+)", url)
        reflected = unquote_plus(match.group(1)) if match else "test"
        resp.text = f"<html><body>Search Results for: {reflected}</body></html>"
        return resp

    client.get = AsyncMock(side_effect=mock_get)
    findings = await xss.scan(ep, client)
    assert len(findings) >= 1
    assert any(f.type == "Reflected XSS" for f in findings)
    assert findings[0].cwe_id == "CWE-79"

    # 2. DOM-based XSS
    dom_ep = DiscoveredEndpoint(
        url="http://localhost:5000/client",
        method="GET",
        html="<script>document.getElementById('out').innerHTML = location.search;</script>",
    )
    dom_findings = await xss.scan(dom_ep, client)
    assert any(f.type == "DOM XSS" for f in dom_findings)


@pytest.mark.asyncio
async def test_command_injection_and_ssti():
    client = MagicMock()

    # Test SSTI
    ssti_ep = DiscoveredEndpoint(
        url="http://localhost:5000/greeting",
        method="GET",
        parameters=[DiscoveredParameter(name="name", location="query", sample_value="John")],
    )

    async def mock_ssti_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        decoded_url = unquote(url)
        if "49*43" in decoded_url:
            resp.text = "Hello 2107! Welcome back."
        else:
            resp.text = "Hello John! Welcome back."
        return resp

    client.get = AsyncMock(side_effect=mock_ssti_get)
    ssti_findings = await ssti.scan(ssti_ep, client)
    assert len(ssti_findings) == 1
    assert ssti_findings[0].type == "Server-Side Template Injection"
    assert ssti_findings[0].cwe_id == "CWE-1336"
    assert ssti_findings[0].severity == "Critical"

    # Test Command Injection
    cmd_ep = DiscoveredEndpoint(
        url="http://localhost:5000/ping",
        method="GET",
        parameters=[DiscoveredParameter(name="host", location="query", sample_value="127.0.0.1")],
    )

    async def mock_cmd_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        decoded_url = unquote(url)
        if "expr" in decoded_url:
            resp.text = "78\nPING 127.0.0.1 (127.0.0.1) 56(84) bytes of data."
        else:
            resp.text = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data."
        return resp

    client.get = AsyncMock(side_effect=mock_cmd_get)
    cmd_findings = await command_injection.scan(cmd_ep, client)
    assert len(cmd_findings) == 1
    assert cmd_findings[0].type == "Command Injection"
    assert cmd_findings[0].cwe_id == "CWE-78"


def test_cors_clickjacking_and_auth_security():
    # Clickjacking
    click_ep = DiscoveredEndpoint(
        url="http://localhost:5000/profile",
        method="GET",
        content_type="text/html",
        response_headers={"content-type": "text/html"},
    )
    click_findings = clickjacking.scan(click_ep)
    assert len(click_findings) == 1
    assert click_findings[0].type == "Clickjacking Protection Missing"
    assert click_findings[0].cwe_id == "CWE-1021"

    # Auth Security: Cleartext HTTP login form
    auth_ep = DiscoveredEndpoint(
        url="http://example.com/login",
        method="GET",
        html="<form action='http://example.com/login' method='post'><input type='password' name='p'></form>",
    )
    auth_findings = auth_security.scan(auth_ep)
    assert any(f.type == "Authentication Security Weakness" for f in auth_findings)


def test_crawler_form_discovery():
    html = """
    <html>
      <body>
        <a href="/about">About Us</a>
        <form action="/login" method="POST">
          <input type="text" name="email" value="user@test.com">
          <input type="password" name="password">
          <input type="submit" value="Log In">
        </form>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    ep = DiscoveredEndpoint(url="http://localhost:5000/", method="GET")
    crawler = Crawler("http://localhost:5000/", max_depth=1)
    form_eps = crawler._extract_forms(soup, "http://localhost:5000/", ep)

    assert ep.has_form is True
    assert crawler.total_forms_discovered == 1
    assert len(form_eps) == 1
    login_ep = form_eps[0]
    assert login_ep.url == "http://localhost:5000/login"
    assert login_ep.method == "POST"
    assert len(login_ep.parameters) == 2
    param_names = [p.name for p in login_ep.parameters]
    assert "email" in param_names
    assert "password" in param_names


def test_deduplication_and_raw_instances():
    raw_findings = [
        ScanFinding(
            type="Missing Security Header",
            category="Security Configuration",
            url=f"http://localhost:5000/page{i}",
            method="GET",
            severity="Medium",
            confidence="Confirmed",
            evidence="Strict-Transport-Security header is missing",
            description="HSTS header missing",
            impact="Risk of downgrade attacks",
            remediation="Add Strict-Transport-Security header",
            parameter="Strict-Transport-Security",
        )
        for i in range(1, 6)
    ]

    correlated = correlate(raw_findings)
    # 5 raw instances across 5 different pages should be grouped into 1 unique finding
    assert len(correlated) == 1
    unique_f = correlated[0]
    assert unique_f.raw_instances == 5
    assert len(unique_f.evidence_details["occurrences"]) == 5
    assert unique_f.cwe_id == "CWE-693"
    assert unique_f.mitre_attack == "T1562"
    assert unique_f.detection_status == "Confirmed"
