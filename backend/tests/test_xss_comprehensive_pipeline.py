import pytest
import httpx
from urllib.parse import quote
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter, ScanFinding
from app.scanner.scanners.xss import scan as xss_scan, _set_url_param, _test_browser_dom_xss
from app.scanner.http_client import SafeHTTPClient
from app.services.security_posture import _matches_module_finding
from tests.vulnerable_test_app import app as test_app


@pytest.mark.asyncio
async def test_reflected_xss_vulnerable_vs_safe():
    """Requirement 1, 2, 7, 8, 9: Reflected XSS detects unencoded execution vs safe encoded reflection."""
    transport = httpx.ASGITransport(app=test_app)
    client = SafeHTTPClient(transport=transport)

    # 1. Vulnerable reflected parameter
    vuln_ep = DiscoveredEndpoint(
        url="http://testserver/search",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="test")],
    )
    vuln_findings = await xss_scan(vuln_ep, client)
    assert len(vuln_findings) == 1
    f = vuln_findings[0]
    assert f.type == "Reflected XSS"
    assert f.severity == "High"
    assert f.detection_status == "Confirmed"
    assert f.cwe_id == "CWE-79"
    assert f.module == "xss"
    assert _matches_module_finding(f, "xss") is True

    # 2. Safe HTML-escaped reflected parameter
    safe_ep = DiscoveredEndpoint(
        url="http://testserver/safe-xss",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="test")],
    )
    safe_findings = await xss_scan(safe_ep, client)
    assert len(safe_findings) == 1
    sf = safe_findings[0]
    assert sf.type == "Input Reflection"
    assert sf.severity == "Informational"
    assert sf.detection_status == "Potential"
    assert sf.cwe_id == "CWE-79"
    # Safe input reflection must NOT be classified as confirmed XSS
    assert _matches_module_finding(sf, "xss") is False

    await client.close()


@pytest.mark.asyncio
async def test_post_json_reflected_xss():
    """Requirement 1, 2: POST JSON bodies are tested and detected."""
    transport = httpx.ASGITransport(app=test_app)
    client = SafeHTTPClient(transport=transport)

    json_ep = DiscoveredEndpoint(
        url="http://testserver/vulnerable-post-xss",
        method="POST",
        content_type="application/json",
        parameters=[DiscoveredParameter(name="message", location="json", sample_value="hello")],
    )
    findings = await xss_scan(json_ep, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "Reflected XSS"
    assert f.severity == "High"
    assert f.detection_status == "Confirmed"

    await client.close()


@pytest.mark.asyncio
async def test_stored_xss_persistence_and_revisit():
    """Requirement 6: Stored XSS submits input and checks persistence on viewing page."""
    transport = httpx.ASGITransport(app=test_app)
    client = SafeHTTPClient(transport=transport)

    stored_ep = DiscoveredEndpoint(
        url="http://testserver/feedback",
        method="POST",
        content_type="application/json",
        parameters=[DiscoveredParameter(name="comment", location="json", sample_value="great")],
    )
    findings = await xss_scan(stored_ep, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "Stored XSS"
    assert f.severity == "High"
    assert f.detection_status == "Confirmed"
    assert "Stored payload" in f.evidence
    assert _matches_module_finding(f, "xss") is True

    await client.close()


@pytest.mark.asyncio
async def test_spa_hash_route_url_parameter_formatting():
    """Requirement 4, 7: URL parameter formatting preserves SPA hash routes correctly."""
    url = "http://example.com/#/search"
    res = _set_url_param(url, "q", "<script>alert(1)</script>")
    assert res.startswith("http://example.com/#/search?q=")
    assert "%3Cscript%3E" in res or "<script>" in res

    url_existing = "http://example.com/#/search?q=old&filter=all"
    res2 = _set_url_param(url_existing, "q", "newval")
    assert "newval" in res2
    assert "filter=all" in res2


@pytest.mark.asyncio
async def test_dom_xss_playwright_live_verification():
    """Requirement 3, 4, 8, 9: Browser execution verification in Playwright against vulnerable and safe targets."""
    # Test against local OWASP Juice Shop if reachable
    client = SafeHTTPClient()
    try:
        r = await client.get("http://host.docker.internal:3001/")
        is_live_juice_shop = r is not None and r.status_code == 200
    except Exception:
        is_live_juice_shop = False
    finally:
        await client.close()

    if not is_live_juice_shop:
        pytest.skip("Local OWASP Juice Shop not reachable on host.docker.internal:3001")

    # 1. Vulnerable DOM XSS search route on Juice Shop
    juice_search_ep = DiscoveredEndpoint(
        url="http://host.docker.internal:3001/#/search",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="test")],
    )
    client_live = SafeHTTPClient()
    findings = await xss_scan(juice_search_ep, client_live)
    assert len(findings) >= 1
    dom_f = next((f for f in findings if f.type == "DOM XSS"), None)
    assert dom_f is not None, "DOM XSS must be detected on Juice Shop search endpoint"
    assert dom_f.severity == "High"
    assert dom_f.detection_status == "Confirmed"
    assert dom_f.parameter == "q"
    assert "alert" in dom_f.evidence or "dialog" in dom_f.evidence
    assert _matches_module_finding(dom_f, "xss") is True

    # 2. Non-vulnerable page on Juice Shop
    juice_about_ep = DiscoveredEndpoint(
        url="http://host.docker.internal:3001/#/about",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="test")],
    )
    about_findings = await xss_scan(juice_about_ep, client_live)
    dom_about = [f for f in about_findings if f.type in ("DOM XSS", "Reflected XSS")]
    assert len(dom_about) == 0, "Non-vulnerable page must not report confirmed DOM XSS"

    await client_live.close()

