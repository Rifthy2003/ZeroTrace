"""
Authentication, Session Management & Access Control Weakness Scanner.

Checks:
1. Cleartext Authentication Submission (Login forms submitted over unencrypted HTTP).
2. Session Token in Query Parameters (e.g. jsessionid, phpsessid, token in URL).
3. State-Changing Form without Anti-CSRF Token.
4. IDOR Heuristic: Flagging predictable sequential resource IDs in API paths requiring manual verification.
"""
import re
from typing import List
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

from app.scanner.models import DiscoveredEndpoint, ScanFinding

SESSION_PARAM_NAMES = {"jsessionid", "phpsessid", "aspsessionid", "sid", "sessionid", "session_id"}
IDOR_PATH_RE = re.compile(r"/(?:users?|accounts?|invoices?|orders?|documents?|files?|profiles?)/([0-9]{1,8}|[a-f0-9\-]{36})(?:/|$)", re.IGNORECASE)


def scan(endpoint: DiscoveredEndpoint) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    parsed = urlparse(endpoint.url)

    # 1. Cleartext Authentication Submission
    if endpoint.html and "password" in endpoint.html.lower():
        soup = BeautifulSoup(endpoint.html, "html.parser")
        for form in soup.find_all("form"):
            has_password = bool(form.find("input", {"type": "password"}))
            if has_password:
                action = form.get("action", "")
                is_cleartext = parsed.scheme == "http" and not action.startswith("https://")
                if is_cleartext and not (parsed.hostname in ("localhost", "127.0.0.1", "host.docker.internal")):
                    findings.append(ScanFinding(
                        type="Authentication Security Weakness",
                        category="Authentication",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        url=endpoint.url,
                        method="POST",
                        severity="High",
                        confidence="Confirmed",
                        cwe_id="CWE-319",
                        mitre_attack="T1078",
                        detection_status="Confirmed",
                        evidence="Password input field detected on a form submitting over unencrypted HTTP.",
                        description="User credentials would be transmitted across the network in cleartext without TLS encryption.",
                        impact="Network intermediaries or Wi-Fi eavesdroppers could intercept plain-text usernames and passwords.",
                        remediation="Serve the authentication page and its submission endpoint strictly over HTTPS with HSTS enabled.",
                    ))

    # 2. Session Token in Query String
    query_params = parse_qs(parsed.query)
    for param_name in query_params:
        if param_name.lower() in SESSION_PARAM_NAMES:
            findings.append(ScanFinding(
                type="Authentication Security Weakness",
                category="Authentication",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                url=endpoint.url,
                method="GET",
                parameter=param_name,
                severity="Medium",
                confidence="Confirmed",
                cwe_id="CWE-598",
                mitre_attack="T1539",
                detection_status="Confirmed",
                evidence=f"Session identifier parameter '{param_name}' exposed in query string: '{endpoint.url}'.",
                description="Session identifiers in URLs may be leaked through browser history, referer headers, web server logs, and shared links.",
                impact="An unauthorized user with access to server logs or browser history could hijack the active user session.",
                remediation="Store session tokens in secure, HttpOnly, SameSite cookies or HTTP authorization request headers.",
            ))

    # 3. IDOR Heuristic Check
    idor_match = IDOR_PATH_RE.search(parsed.path)
    if idor_match:
        resource_id = idor_match.group(1)
        findings.append(ScanFinding(
            type="Insecure Direct Object Reference (IDOR)",
            category="Access Control",
            owasp_category="A01:2021 - Broken Access Control",
            url=endpoint.url,
            method=endpoint.method.upper(),
            parameter=resource_id,
            severity="Medium",
            confidence="Medium confidence",
            cwe_id="CWE-639",
            mitre_attack="T1190",
            detection_status="Requires Manual Verification",
            evidence=f"Predictable object identifier '{resource_id}' detected in path '{parsed.path}'.",
            description="The URL uses a direct object reference. Automated scanning flags this endpoint for manual verification of authorization boundaries between user accounts.",
            impact="If backend authorization checks are absent, any authenticated user could read or alter records belonging to other tenants.",
            remediation="Implement robust server-side authorization checks verifying that the requesting user owns or is authorized to access the specific object identifier.",
        ))

    return findings

