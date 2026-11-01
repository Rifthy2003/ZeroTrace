"""
Regression test suite for React SPA Crawling, Controlled Form Discovery,
Network API Extraction, SQL Injection Detection, and Zero False Positives.
"""
import asyncio
import socket
import threading
import time
import pytest
import uvicorn
from urllib.parse import urlparse

from app.scanner.browser_crawler import BrowserCrawler
from app.scanner.crawler import Crawler
from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter
from app.scanner.scanners import sql_injection
from tests.vulnerable_react_app import app as react_app


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UvicornServer(threading.Thread):
    def __init__(self, app, port):
        super().__init__(daemon=True)
        self.app = app
        self.port = port
        self.server = None

    def run(self):
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.server.run()

    def stop(self):
        if self.server:
            self.server.should_exit = True


@pytest.fixture(scope="module")
def live_react_server():
    port = find_free_port()
    server = UvicornServer(react_app, port)
    server.start()
    base_url = f"http://127.0.0.1:{port}"

    # Wait for server ready
    import httpx
    for _ in range(30):
        try:
            r = httpx.get(f"{base_url}/")
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)

    yield base_url
    server.stop()


@pytest.mark.asyncio
async def test_react_browser_crawler_form_and_api_discovery(live_react_server):
    """
    Test that Playwright inspects live React DOM, executes React Router navigation,
    discovers controlled input components, forms, and REST APIs.
    """
    crawler = BrowserCrawler(
        base_url=live_react_server,
        max_urls=25,
        request_delay=0.1,
        timeout_seconds=8.0,
    )

    endpoints, metrics = await crawler.crawl()

    # 1. Verify forms discovered >= 3 (Login, Signup, Search forms)
    assert metrics["forms_discovered"] >= 3, f"Expected at least 3 forms, got {metrics['forms_discovered']}"

    # 2. Verify routes discovered includes React Router pages
    discovered_routes = set(metrics["routes_discovered"])
    assert any("/login" in r for r in discovered_routes), f"/login not in {discovered_routes}"
    assert any("/signup" in r for r in discovered_routes), f"/signup not in {discovered_routes}"
    assert any("/search" in r for r in discovered_routes), f"/search not in {discovered_routes}"

    # 3. Verify controlled inputs were extracted
    all_param_names = {p.name for ep in endpoints for p in ep.parameters}
    assert "username" in all_param_names, f"username not found in {all_param_names}"
    assert "password" in all_param_names, f"password not found in {all_param_names}"
    assert "email" in all_param_names, f"email not found in {all_param_names}"
    assert "category" in all_param_names or "q" in all_param_names

    # 4. Verify API endpoints were registered
    all_urls = [ep.url for ep in endpoints]
    assert any("/api/login" in u or "/login" in u for u in all_urls)
    assert any("/vulnerable-sqli" in u for u in all_urls)
    assert any("/safe-endpoint" in u for u in all_urls)


@pytest.mark.asyncio
async def test_react_sqli_detection_on_vulnerable_endpoint(live_react_server):
    """
    Test that the SQL Injection scanner detects the vulnerable React backend query.
    """
    client = SafeHTTPClient(request_delay=0.0)
    ep = DiscoveredEndpoint(
        url=f"{live_react_server}/vulnerable-sqli",
        method="GET",
        parameters=[
            DiscoveredParameter(name="category", location="query", sample_value="electronics")
        ],
    )

    findings = await sql_injection.scan(ep, client)
    await client.close()

    assert len(findings) >= 1, "Expected SQL injection finding on /vulnerable-sqli"
    f = findings[0]
    assert f.type == "SQL Injection"
    assert f.parameter == "category"
    assert f.cwe_id == "CWE-89"
    assert f.mitre_attack == "T1190"
    assert f.detection_status in ("Confirmed", "Requires Manual Verification")
    assert any(term in f.evidence.lower() for term in ("unrecognized token", "syntax error", "operationalerror", "5xx", "database error pattern detected"))


@pytest.mark.asyncio
async def test_react_sqli_safe_endpoint_zero_false_positives(live_react_server):
    """
    Test that the SQL Injection scanner produces 0 false positives on the parameterized endpoint.
    """
    client = SafeHTTPClient(request_delay=0.0)
    ep = DiscoveredEndpoint(
        url=f"{live_react_server}/safe-endpoint",
        method="GET",
        parameters=[
            DiscoveredParameter(name="category", location="query", sample_value="electronics")
        ],
    )

    findings = await sql_injection.scan(ep, client)
    await client.close()

    assert len(findings) == 0, f"Expected 0 findings on safe endpoint, got: {findings}"


@pytest.mark.asyncio
async def test_react_authenticated_crawling(live_react_server):
    """
    Test that explicitly configured test credentials or headers allow authorized access.
    """
    crawler_auth = BrowserCrawler(
        base_url=live_react_server,
        max_urls=10,
        request_delay=0.1,
        auth_config={"headers": {"Authorization": "Bearer mock-token-xyz"}},
    )

    endpoints, metrics = await crawler_auth.crawl()
    # Route /dashboard should be visited and tested
    assert "/dashboard" in metrics["routes_visited"] or any("dashboard" in r for r in metrics["routes_visited"])

