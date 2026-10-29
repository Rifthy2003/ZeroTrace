"""
Open redirect check. Sends a harmless external URL in redirect-like
parameters and inspects the Location header WITHOUT following it.
"""
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_url", "return", "returnto", "return_url", "continue", "dest", "destination", "goto"}
TEST_DESTINATION = "https://example.org/scanner-redirect-test"


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    for param in endpoint.parameters:
        if param.location != "query" or param.name.lower() not in REDIRECT_PARAMS:
            continue
        p = urlparse(endpoint.url)
        q = dict(parse_qsl(p.query))
        q[param.name] = TEST_DESTINATION
        test_url = urlunparse(p._replace(query=urlencode(q)))
        resp = await client.get(test_url)
        if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
            continue
        location = resp.headers.get("location", "")
        if location.startswith(TEST_DESTINATION):
            findings.append(ScanFinding(
                type="Open Redirect", category="Broken Access Control",
                owasp_category="A01:2021 - Broken Access Control",
                url=endpoint.url, method="GET", parameter=param.name,
                severity="Medium", confidence="Confirmed",
                evidence=f"Server responded {resp.status_code} redirecting to an external destination supplied via '{param.name}'.",
                description="The application redirects users to a URL fully controlled by a request parameter.",
                impact="Can be abused in phishing by making malicious links appear to originate from the trusted domain.",
                remediation="Use an allow-list of redirect destinations or only permit relative paths.",
            ))
    return findings
