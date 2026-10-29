"""
Detects obvious directory-listing pages using a small, conservative set of
signatures. Does not brute-force paths beyond the endpoints already
discovered by the crawler plus a small common-path list checked by engine.py.
"""
from typing import List
from app.scanner.models import DiscoveredEndpoint, ScanFinding

SIGNATURES = [
    "Index of /",
    "<title>Index of",
    "Directory Listing For",
    "Parent Directory</a>",
]

COMMON_TEST_PATHS = ["/images/", "/uploads/", "/static/", "/backup/", "/files/", "/assets/"]


def scan(endpoint: DiscoveredEndpoint) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    if not endpoint.body_snippet:
        return findings

    for sig in SIGNATURES:
        if sig.lower() in endpoint.body_snippet.lower():
            findings.append(
                ScanFinding(
                    type="Directory Listing Enabled",
                    category="Security Misconfiguration",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    url=endpoint.url,
                    method=endpoint.method,
                    severity="Medium",
                    confidence="High confidence",
                    evidence=f"Response body matched directory-listing signature: {sig!r}",
                    description="The server appears to be returning an auto-generated directory listing instead of a controlled page.",
                    impact="May expose file names, structure, or artifacts not intended for public access.",
                    remediation="Disable directory listing/autoindex in the web server configuration for this path.",
                )
            )
            break

    return findings
