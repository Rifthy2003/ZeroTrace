"""
CORS (Cross-Origin Resource Sharing) Misconfiguration scanner module.

Tests whether the endpoint reflects arbitrary Origin headers or enables credentials
with wildcard or untrusted origins.
"""
from typing import List
from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    test_origin = "https://evil-attacker.example.com"

    try:
        resp = await client.request(
            "GET",
            endpoint.url,
            headers={"Origin": test_origin},
        )
    except Exception:
        return findings

    if resp is None:
        return findings

    acao = resp.headers.get("access-control-allow-origin", "").strip()
    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()

    if acao == test_origin and acac == "true":
        findings.append(ScanFinding(
            type="CORS Misconfiguration",
            category="Security Configuration",
            owasp_category="A05:2021 - Security Misconfiguration",
            url=endpoint.url,
            method="GET",
            severity="High",
            confidence="Confirmed",
            cwe_id="CWE-942",
            mitre_attack="T1190",
            detection_status="Confirmed",
            evidence=f"Reflected untrusted origin '{test_origin}' with Access-Control-Allow-Credentials: true.",
            description="The server dynamically reflects the Origin header from untrusted third parties while enabling authenticated cross-origin requests.",
            impact="An attacker hosting malicious JavaScript on an external site can issue cross-origin requests and read private user data and authenticated responses.",
            remediation="Maintain a strict whitelist of trusted domains for Access-Control-Allow-Origin, and never reflect arbitrary origins when credentials are enabled.",
        ))
    elif acao == "*" and acac == "true":
        findings.append(ScanFinding(
            type="CORS Misconfiguration",
            category="Security Configuration",
            owasp_category="A05:2021 - Security Misconfiguration",
            url=endpoint.url,
            method="GET",
            severity="Medium",
            confidence="High confidence",
            cwe_id="CWE-942",
            mitre_attack="T1190",
            detection_status="Confirmed",
            evidence="Access-Control-Allow-Origin is wildcard '*' while Access-Control-Allow-Credentials is true (invalid CORS spec, potential browser inconsistency).",
            description="Conflicting CORS policy specifies wildcard origin with credentials.",
            impact="Depending on browser behavior, authenticated responses may be accessible or request handling compromised.",
            remediation="Specify explicit origins when authenticated requests are required.",
        ))

    return findings

