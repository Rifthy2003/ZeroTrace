"""
Safe reflected-XSS analyzer. Sends a harmless unique marker and analyzes the
HTML context in which it is reflected. No script is executed and no
destructive payloads are used.
"""
import re
import uuid
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding


def _set_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def classify_context(html: str, marker: str) -> str | None:
    """Return the reflection context of the marker, or None if not reflected."""
    idx = html.find(marker)
    if idx == -1:
        return None
    before = html[max(0, idx - 200):idx]
    if re.search(r"<script[^>]*>[^<]*$", before, re.I):
        return "javascript"
    if re.search(r"<[a-z][^>]*=\s*[\"'][^\"']*$", before, re.I):
        return "html_attribute"
    if re.search(r"<!--[^>]*$", before):
        return "html_comment"
    return "html_body"


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    for param in [p for p in endpoint.parameters if p.location == "query"]:
        marker = "xsstest" + uuid.uuid4().hex[:8]
        # Marker containing angle brackets tests whether HTML metacharacters are encoded.
        probe = f"{marker}<b>\"'"
        resp = await client.get(_set_param(endpoint.url, param.name, probe))
        if resp is None or "text/html" not in resp.headers.get("content-type", ""):
            continue
        body = resp.text
        context = classify_context(body, marker)
        if context is None:
            continue

        unencoded = f"{marker}<b>" in body
        if unencoded:
            severity, confidence = "High", "High confidence"
            evidence = f"Marker reflected in {context} context with HTML metacharacters unencoded."
        else:
            severity, confidence = "Informational", "Low confidence"
            evidence = f"Marker reflected in {context} context but special characters appear encoded."

        findings.append(ScanFinding(
            type="Reflected XSS" if unencoded else "Input Reflection",
            category="Injection",
            owasp_category="A03:2021 - Injection",
            url=endpoint.url, method="GET", parameter=param.name,
            severity=severity, confidence=confidence, evidence=evidence,
            description="User-supplied input is reflected in the response. Unencoded reflection can allow script injection.",
            impact="An attacker could run script in a victim's browser (session abuse, content manipulation).",
            remediation="Apply context-aware output encoding, validate input, and deploy a strict Content-Security-Policy.",
        ))
    return findings
