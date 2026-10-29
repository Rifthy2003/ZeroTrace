"""
CSRF analyzer: inspects HTML forms for anti-CSRF tokens and related cookie
controls. Never submits any form or performs state-changing requests.
"""
import re
from typing import List
from bs4 import BeautifulSoup

from app.scanner.models import DiscoveredEndpoint, ScanFinding

TOKEN_NAME_RE = re.compile(r"(csrf|xsrf|authenticity_token|_token|nonce)", re.I)
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def scan(endpoint: DiscoveredEndpoint, html: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    if not html:
        return findings

    soup = BeautifulSoup(html, "html.parser")
    cookies = [v.lower() for k, v in endpoint.response_headers.items() if k.lower() == "set-cookie"]
    samesite_protected = any("samesite=lax" in c or "samesite=strict" in c for c in cookies)

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        if method not in STATE_CHANGING:
            continue

        hidden_names = [i.get("name", "") for i in form.find_all("input")]
        token_inputs = [i for i in form.find_all("input") if TOKEN_NAME_RE.search(i.get("name", ""))]
        action = form.get("action") or endpoint.url

        if not token_inputs:
            confidence = "Low confidence" if samesite_protected else "Medium confidence"
            findings.append(ScanFinding(
                type="Potential CSRF",
                category="Broken Access Control",
                owasp_category="A01:2021 - Broken Access Control",
                url=endpoint.url, method=method,
                severity="Medium",
                confidence=confidence,
                evidence=f"{method} form (action={action}) has no recognizable anti-CSRF token field. "
                         f"SameSite Lax/Strict cookie observed: {samesite_protected}.",
                description="A state-changing form lacks an anti-CSRF token. Other controls (SameSite cookies, custom headers) may mitigate this.",
                impact="An attacker may be able to trick an authenticated user's browser into submitting unwanted requests.",
                remediation="Add per-session/per-request anti-CSRF tokens validated server-side and set SameSite=Lax/Strict on session cookies.",
            ))
        else:
            value = token_inputs[0].get("value", "")
            if value and len(value) < 16:
                findings.append(ScanFinding(
                    type="Weak CSRF Token",
                    category="Broken Access Control",
                    owasp_category="A01:2021 - Broken Access Control",
                    url=endpoint.url, method=method, severity="Low",
                    confidence="Low confidence",
                    evidence=f"CSRF token field '{token_inputs[0].get('name')}' has a short value ({len(value)} chars).",
                    description="The token looks short and may be guessable.",
                    impact="Predictable tokens reduce CSRF protection.",
                    remediation="Use cryptographically random tokens of at least 128 bits.",
                ))
    return findings
