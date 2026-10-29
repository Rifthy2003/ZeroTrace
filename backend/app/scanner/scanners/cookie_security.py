"""
Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite attributes.
Cookie values themselves are never logged or included in findings.
"""
import re
from typing import List
from app.scanner.models import DiscoveredEndpoint, ScanFinding

COOKIE_NAME_RE = re.compile(r"^\s*([^=;]+)=")


def _cookie_name(set_cookie_value: str) -> str:
    m = COOKIE_NAME_RE.match(set_cookie_value)
    return m.group(1).strip() if m else "unknown"


def scan(endpoint: DiscoveredEndpoint) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    raw_cookies = []
    for k, v in endpoint.response_headers.items():
        if k.lower() == "set-cookie":
            raw_cookies.append(v)

    for cookie in raw_cookies:
        name = _cookie_name(cookie)
        lower = cookie.lower()
        missing = []

        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        elif "samesite=none" in lower and "secure" not in lower:
            findings.append(
                ScanFinding(
                    type="Insecure Cookie Configuration",
                    category="Security Misconfiguration",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    url=endpoint.url,
                    method=endpoint.method,
                    severity="Medium",
                    confidence="Confirmed",
                    evidence=f"Cookie '{name}' uses SameSite=None without the Secure attribute.",
                    description="SameSite=None requires Secure; browsers will reject or ignore such cookies, and if accepted it removes cross-site request protection while allowing transmission over plain HTTP.",
                    impact="Increases exposure to cross-site request forgery and cookie interception.",
                    remediation="Set Secure whenever SameSite=None is used, or prefer SameSite=Lax/Strict.",
                )
            )

        if missing:
            severity = "High" if "Secure" in missing and "HttpOnly" in missing else "Medium"
            findings.append(
                ScanFinding(
                    type="Insecure Cookie Configuration",
                    category="Security Misconfiguration",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    url=endpoint.url,
                    method=endpoint.method,
                    severity=severity,
                    confidence="Confirmed",
                    evidence=f"Cookie '{name}' is missing attribute(s): {', '.join(missing)}.",
                    description="Cookies without Secure/HttpOnly/SameSite are more exposed to interception, "
                                 "client-side script access, and cross-site request forgery respectively.",
                    impact="Session or state cookies could be exposed to XSS-based theft, network interception, or CSRF.",
                    remediation="Set Secure, HttpOnly, and an appropriate SameSite value on all session/state cookies.",
                )
            )

    return findings
