"""
Clickjacking Protection module.

Verifies whether HTML responses provide framing protection:
- X-Frame-Options: DENY or SAMEORIGIN
- Content-Security-Policy: frame-ancestors directive
"""
from typing import List
from app.scanner.models import DiscoveredEndpoint, ScanFinding


def scan(endpoint: DiscoveredEndpoint) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    # Only applicable to HTML pages
    ctype = endpoint.content_type or endpoint.response_headers.get("content-type", "")
    if "text/html" not in ctype.lower():
        return findings

    headers = {k.lower(): v for k, v in endpoint.response_headers.items()}
    xfo = headers.get("x-frame-options", "").upper()
    csp = headers.get("content-security-policy", "").lower()

    has_xfo = xfo in ("DENY", "SAMEORIGIN")
    has_frame_ancestors = "frame-ancestors" in csp

    if not has_xfo and not has_frame_ancestors:
        findings.append(ScanFinding(
            type="Clickjacking Protection Missing",
            category="Security Configuration",
            owasp_category="A05:2021 - Security Misconfiguration",
            url=endpoint.url,
            method="GET",
            severity="Medium",
            confidence="Confirmed",
            cwe_id="CWE-1021",
            mitre_attack="T1190",
            detection_status="Confirmed",
            evidence="Neither X-Frame-Options (DENY/SAMEORIGIN) nor Content-Security-Policy frame-ancestors directive was found in response headers.",
            description="The web page does not restrict whether it can be embedded into an <iframe> or <frame> on third-party sites.",
            impact="An attacker could frame this page in an invisible overlay to trick authenticated users into clicking buttons or performing unintended actions.",
            remediation="Add 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self'' to HTTP response headers.",
        ))

    return findings

