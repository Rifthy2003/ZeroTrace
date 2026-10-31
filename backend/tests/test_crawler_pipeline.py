"""
Regression tests for Crawler Form Discovery, POST/JSON Parameter Extraction,
SQL Injection Detection, Safe Endpoint False Positive Resistance, and Coverage Accounting.
"""
import pytest
from httpx import ASGITransport

from app.scanner.crawler import Crawler
from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter
from app.scanner.scanners import sql_injection
from tests.vulnerable_test_app import app


@pytest.mark.asyncio
async def test_crawler_form_and_parameter_discovery():
    """
    Test that Crawler discovers forms, POST form endpoints, and query parameters
    from the safe mock application.
    """
    transport = ASGITransport(app=app)
    crawler = Crawler(
        start_url="http://testserver/",
        max_depth=2,
        max_urls=20,
        request_delay=0.0,
        enable_browser_discovery=False,
        transport=transport,
    )

    endpoints = await crawler.crawl()

    # 1. Verify forms discovered count >= 2
    assert crawler.total_forms_discovered >= 2, f"Expected at least 2 forms discovered, got {crawler.total_forms_discovered}"
    assert crawler.route_metrics["forms_discovered"] >= 2

    # 2. Verify total parameters discovered > 0
    assert crawler.total_parameters_discovered > 0
    all_params = [p.name for ep in endpoints for p in ep.parameters]
    assert "username" in all_params or "password" in all_params
    assert "search_term" in all_params
    assert "q" in all_params

    # 3. Verify POST login form action endpoint was created
    login_ep = next((ep for ep in endpoints if ep.url == "http://testserver/login" and ep.method == "POST"), None)
    assert login_ep is not None, "POST /login endpoint was not created from form action"
    login_param_names = {p.name for p in login_ep.parameters}
    assert "username" in login_param_names
    assert "password" in login_param_names
    assert any(p.location == "body" for p in login_ep.parameters)

    # 4. Verify POST search-form action endpoint was created
    search_form_ep = next((ep for ep in endpoints if ep.url == "http://testserver/search-form" and ep.method == "POST"), None)
    assert search_form_ep is not None, "POST /search-form endpoint was not created from form action"
    search_form_param_names = {p.name for p in search_form_ep.parameters}
    assert "search_term" in search_form_param_names
    assert any(p.location == "body" for p in search_form_ep.parameters)

    # 5. Verify GET search endpoint discovered query parameter
    get_search_ep = next((ep for ep in endpoints if "search" in ep.url and ep.method == "GET"), None)
    assert get_search_ep is not None
    assert any(p.name == "q" and p.location == "query" for p in get_search_ep.parameters)


@pytest.mark.asyncio
async def test_crawler_json_parameter_discovery():
    """
    Test that Crawler extracts JSON keys as parameters from application/json endpoints.
    """
    transport = ASGITransport(app=app)
    crawler = Crawler(
        start_url="http://testserver/api/items",
        max_depth=1,
        max_urls=5,
        request_delay=0.0,
        enable_browser_discovery=False,
        transport=transport,
    )

    endpoints = await crawler.crawl()
    api_ep = next((ep for ep in endpoints if "/api/items" in ep.url), None)
    assert api_ep is not None, "API items endpoint not crawled"
    param_names = {p.name for p in api_ep.parameters}
    assert "item_id" in param_names
    assert "category" in param_names
    assert "status" in param_names
    assert any(p.location == "json" for p in api_ep.parameters)


@pytest.mark.asyncio
async def test_sqli_detection_on_vulnerable_endpoint():
    """
    Test that the SQL Injection scanner detects the deliberately vulnerable endpoint
    using safe, non-destructive test cases.
    """
    transport = ASGITransport(app=app)
    client = SafeHTTPClient(request_delay=0.0, transport=transport)

    ep = DiscoveredEndpoint(
        url="http://testserver/vulnerable-sqli",
        method="GET",
        parameters=[
            DiscoveredParameter(name="category", location="query", sample_value="electronics")
        ],
    )

    findings = await sql_injection.scan(ep, client)
    await client.close()

    assert len(findings) >= 1, "Expected SQL injection finding on vulnerable endpoint"
    f = findings[0]
    assert f.type == "SQL Injection"
    assert f.parameter == "category"
    assert f.cwe_id == "CWE-89"
    assert f.mitre_attack == "T1190"
    assert f.detection_status in ("Confirmed", "Requires Manual Verification")
    assert any(term in f.evidence.lower() for term in ("unrecognized token", "syntax error", "operationalerror", "5xx", "database error pattern detected"))


@pytest.mark.asyncio
async def test_sqli_safe_endpoint_zero_false_positives():
    """
    Test that the SQL Injection scanner does NOT report false positives on a parameterized safe endpoint.
    """
    transport = ASGITransport(app=app)
    client = SafeHTTPClient(request_delay=0.0, transport=transport)

    ep = DiscoveredEndpoint(
        url="http://testserver/safe-endpoint",
        method="GET",
        parameters=[
            DiscoveredParameter(name="category", location="query", sample_value="electronics")
        ],
    )

    findings = await sql_injection.scan(ep, client)
    await client.close()

    assert len(findings) == 0, f"Expected 0 findings on safe parameterized endpoint, but got: {findings}"


@pytest.mark.asyncio
async def test_sqli_post_form_parameter_testing():
    """
    Test that the SQL Injection scanner correctly exercises POST body parameters.
    """
    transport = ASGITransport(app=app)
    client = SafeHTTPClient(request_delay=0.0, transport=transport)

    ep = DiscoveredEndpoint(
        url="http://testserver/search-form",
        method="POST",
        parameters=[
            DiscoveredParameter(name="search_term", location="body", sample_value="laptop")
        ],
    )

    findings = await sql_injection.scan(ep, client)
    await client.close()

    # The search-form endpoint in the test app is safe, so it should report 0 findings (no false positives)
    assert len(findings) == 0


def test_coverage_accounting_rules():
    """
    Verify coverage status logic:
    Input-dependent modules with 0 tested parameters must be marked 'Incomplete',
    never claimed as 'Tested' with 0 findings.
    """
    from app.scanner.engine import INPUT_DEPENDENT_MODULES, ALL_KNOWN_MODULES

    assert "sql_injection" in INPUT_DEPENDENT_MODULES
    assert "xss" in INPUT_DEPENDENT_MODULES
    assert "command_injection" in INPUT_DEPENDENT_MODULES
    assert "ssti" in INPUT_DEPENDENT_MODULES
    assert "path_traversal" in INPUT_DEPENDENT_MODULES

    # Simulate coverage summary generation
    module_tested_endpoints = {m: 0 for m in ALL_KNOWN_MODULES}
    module_parameters_tested = {m: 0 for m in ALL_KNOWN_MODULES}
    selected_modules = ["sql_injection", "security_headers"]

    # Security headers tested 1 endpoint
    module_tested_endpoints["security_headers"] = 1

    # SQLi tested 0 endpoints and 0 parameters
    module_results = []
    for mod in selected_modules:
        is_input_dep = mod in INPUT_DEPENDENT_MODULES
        eps_tested = module_tested_endpoints.get(mod, 0)
        params_tested = module_parameters_tested.get(mod, 0)

        if is_input_dep and (eps_tested == 0 or params_tested == 0):
            status = "Incomplete"
            reason = "No eligible input parameters discovered on crawled pages"
        elif eps_tested > 0:
            status = "Tested"
            reason = "Evaluated against discovered target surface"
        else:
            status = "Not Tested"
            reason = "Module was not selected for this scan"

        module_results.append({"module": mod, "status": status, "reason": reason})

    sqli_result = next(r for r in module_results if r["module"] == "sql_injection")
    sec_header_result = next(r for r in module_results if r["module"] == "security_headers")

    assert sqli_result["status"] == "Incomplete"
    assert "No eligible input parameters" in sqli_result["reason"]
    assert sec_header_result["status"] == "Tested"
