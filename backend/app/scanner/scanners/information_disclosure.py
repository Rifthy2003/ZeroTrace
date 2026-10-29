"""
Distinguishes plain technology fingerprinting (informational) from potential
information disclosure (stack traces, debug output, verbose errors).
"""
import re
from typing import List
from app.scanner.models import DiscoveredEndpoint, ScanFinding

VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

ERROR_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python traceback"),
    (re.compile(r"Warning:\s+.*on line \d+", re.I), "PHP warning with file/line detail"),
    (re.compile(r"Fatal error:", re.I), "PHP fatal error output"),
    (re.compile(r"System\.[\w.]+Exception", re.I), ".NET exception detail"),
    (re.compile(r"at\s+[\w.$]+\([\w]+\.java:\d+\)", re.I), "Java stack trace"),
    (re.compile(r"ORA-\d{5}", re.I), "Oracle database error code"),
    (re.compile(r"SQLSTATE\[\w+\]", re.I), "SQL error detail"),
]


def scan(endpoint: DiscoveredEndpoint) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    headers_lower = {k.lower(): v for k, v in endpoint.response_headers.items()}

    for header in VERSION_HEADERS:
        if header in headers_lower and headers_lower[header]:
            findings.append(
                ScanFinding(
                    type="Technology Detection",
                    category="Information Disclosure",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    url=endpoint.url,
                    method=endpoint.method,
                    severity="Informational",
                    confidence="Informational",
                    evidence=f"{header}: {headers_lower[header]}",
                    description="Server/technology banner is exposed via response headers. This is fingerprinting information, not a vulnerability by itself.",
                    impact="May help an attacker prioritize known vulnerabilities for the identified software version.",
                    remediation="Consider suppressing or genericizing version-revealing headers where feasible.",
                )
            )

    if endpoint.body_snippet:
        for pattern, label in ERROR_SIGNATURES:
            if pattern.search(endpoint.body_snippet):
                findings.append(
                    ScanFinding(
                        type="Potential Information Disclosure",
                        category="Information Disclosure",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        url=endpoint.url,
                        method=endpoint.method,
                        severity="Medium",
                        confidence="High confidence",
                        evidence=f"Response body matched pattern associated with {label}.",
                        description="The response appears to contain verbose error/debug output rather than a generic error page.",
                        impact="May reveal internal file paths, framework details, or logic useful for further attacks.",
                        remediation="Disable debug mode in production and return generic error pages to end users.",
                    )
                )

    return findings
