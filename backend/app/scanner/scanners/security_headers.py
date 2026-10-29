"""
Checks for missing or weak security-relevant HTTP response headers.
"""
from typing import List
from app.scanner.models import DiscoveredEndpoint, ScanFinding

REQUIRED_HEADERS = {
    "content-security-policy": {
        "description": "Content-Security-Policy is missing, allowing a wider range of injection attacks (e.g. XSS) to succeed.",
        "remediation": "Define a restrictive Content-Security-Policy (e.g. default-src 'self') and tighten it per resource type.",
        "severity": "Medium",
    },
    "strict-transport-security": {
        "description": "Strict-Transport-Security (HSTS) is missing, so the site does not instruct browsers to enforce HTTPS.",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS is fully deployed.",
        "severity": "Low",
    },
    "x-content-type-options": {
        "description": "X-Content-Type-Options is missing, allowing browsers to MIME-sniff responses.",
        "remediation": "Add X-Content-Type-Options: nosniff to all responses.",
        "severity": "Low",
    },
    "x-frame-options": {
        "description": "X-Frame-Options is missing, which may allow the page to be framed for clickjacking.",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN, or an equivalent frame-ancestors CSP directive.",
        "severity": "Medium",
    },
    "referrer-policy": {
        "description": "Referrer-Policy is missing, which may leak full URLs (including sensitive query strings) to third parties via the Referer header.",
        "remediation": "Add a Referrer-Policy such as strict-origin-when-cross-origin.",
        "severity": "Low",
    },
    "permissions-policy": {
        "description": "Permissions-Policy is missing, so the site does not explicitly restrict access to powerful browser features.",
        "remediation": "Add a Permissions-Policy header restricting features (camera, microphone, geolocation, etc.) that are not needed.",
        "severity": "Informational",
    },
}


def scan(endpoint: DiscoveredEndpoint) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    headers_lower = {k.lower(): v for k, v in endpoint.response_headers.items()}

    for header, meta in REQUIRED_HEADERS.items():
        if header not in headers_lower:
            findings.append(
                ScanFinding(
                    type="Missing Security Header",
                    category="Security Misconfiguration",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    url=endpoint.url,
                    method=endpoint.method,
                    severity=meta["severity"],
                    confidence="Confirmed",
                    evidence=f"Response did not include a '{header}' header.",
                    description=meta["description"],
                    impact="Increases exposure to related client-side attacks (clickjacking, XSS, MIME confusion, referrer leakage).",
                    remediation=meta["remediation"],
                )
            )

    # Weak CSP that still allows 'unsafe-inline' scripts
    csp = headers_lower.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp and "script-src" in csp:
        findings.append(
            ScanFinding(
                type="Weak Content-Security-Policy",
                category="Security Misconfiguration",
                owasp_category="A05:2021 - Security Misconfiguration",
                url=endpoint.url,
                method=endpoint.method,
                severity="Medium",
                confidence="High confidence",
                evidence="Content-Security-Policy script-src includes 'unsafe-inline'.",
                description="The CSP permits inline scripts, substantially weakening its protection against XSS.",
                impact="Reduces the effectiveness of CSP as a defense-in-depth control against script injection.",
                remediation="Remove 'unsafe-inline' from script-src; use nonces or hashes for any required inline scripts.",
            )
        )

    return findings
