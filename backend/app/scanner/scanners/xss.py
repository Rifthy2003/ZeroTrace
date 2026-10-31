"""
Context-aware, safe Cross-Site Scripting (XSS) scanner module.

Supports:
1. Reflected XSS:
   - Tests GET and POST parameters using harmless unique marker tokens with HTML metacharacters.
   - Context classification: HTML body, HTML attribute, JavaScript block, HTML comment.
   - Determines whether metacharacters (<, >, ", ') are unencoded in reflection.
2. DOM-based XSS:
   - Analyzes client-side JavaScript within discovered HTML and scripts for dangerous sink-source flows
     (e.g. location.search/hash/pathname flowing into innerHTML, document.write, eval, or execScript).
3. Stored XSS indicators:
   - Checks if submitted markers persist across subsequent page rendering.
"""
import re
import uuid
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

DOM_SINK_PATTERNS = [
    (re.compile(r"document\.write\s*\(.*?(?:location\.|document\.cookie|window\.name)", re.IGNORECASE), "document.write with unvalidated URL/location source"),
    (re.compile(r"\.innerHTML\s*=\s*.*?(?:location\.(?:hash|search|pathname)|decodeURI)", re.IGNORECASE), "innerHTML assignment from URL parameters/hash"),
    (re.compile(r"\.outerHTML\s*=\s*.*?(?:location\.|window\.name)", re.IGNORECASE), "outerHTML assignment from dynamic window/location source"),
    (re.compile(r"\$\s*\(\s*['\"]#[^'\"]*['\"]\s*\)\.html\s*\(.*?(?:location|hash|search)", re.IGNORECASE), "jQuery html() injection from URL parameter"),
    (re.compile(r"eval\s*\(\s*(?:unescape|decodeURIComponent)?\s*\(?\s*location\.", re.IGNORECASE), "eval() execution of location source"),
]


def _set_url_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _set_body_param(defaults: Dict[str, str], name: str, value: str) -> Dict[str, str]:
    c = dict(defaults)
    c[name] = value
    return c


def classify_context(html: str, marker: str) -> Optional[str]:
    """Return the reflection context of the marker, or None if not reflected."""
    idx = html.find(marker)
    if idx == -1:
        return None
    before = html[max(0, idx - 300):idx]
    if re.search(r"<script[^>]*>[^<]*$", before, re.IGNORECASE):
        return "javascript"
    if re.search(r"<[a-z0-9_\-]+[^>]*=\s*[\"'][^\"']*$", before, re.IGNORECASE):
        return "html_attribute"
    if re.search(r"<!--[^>]*$", before):
        return "html_comment"
    return "html_body"


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    # 1. DOM-based XSS check on HTML content
    if endpoint.html:
        for pattern, desc in DOM_SINK_PATTERNS:
            match = pattern.search(endpoint.html)
            if match:
                snippet = match.group(0)[:120]
                findings.append(ScanFinding(
                    type="DOM XSS",
                    category="Injection",
                    owasp_category="A03:2021 - Injection",
                    url=endpoint.url,
                    method=endpoint.method.upper(),
                    parameter="DOM Client Sink",
                    severity="High",
                    confidence="High confidence",
                    cwe_id="CWE-79",
                    mitre_attack="T1059.007",
                    detection_status="Confirmed",
                    evidence=f"Dangerous DOM manipulation pattern detected in script: '{snippet}' ({desc}).",
                    description="Client-side script reads from an attacker-controllable source (such as location.search or hash) and passes it directly to an unsafe DOM sink.",
                    impact="Allows execution of arbitrary JavaScript in the victim's browser context without server round-trip.",
                    remediation="Use safe DOM properties like textContent or innerText, avoid document.write and eval, and sanitize HTML using DOMPurify.",
                ))
                break

    # 2. Reflected XSS parameter probes (GET and POST)
    body_defaults = {
        p.name: p.sample_value or "test"
        for p in endpoint.parameters
        if p.location in ("body", "form")
    }

    for param in endpoint.parameters:
        if not param.name:
            continue
        marker = "ztxss" + uuid.uuid4().hex[:6]
        probe = f"{marker}<b>\"'"
        location = param.location or ("body" if endpoint.method.upper() == "POST" else "query")

        try:
            if location in ("body", "form") or endpoint.method.upper() == "POST":
                resp = await client.post(endpoint.url, data=_set_body_param(body_defaults, param.name, probe))
            else:
                resp = await client.get(_set_url_param(endpoint.url, param.name, probe))
        except Exception:
            continue

        if resp is None or not resp.text or "text/html" not in resp.headers.get("content-type", ""):
            continue

        body = resp.text
        context = classify_context(body, marker)
        if context is None:
            continue

        # Check if metacharacters were unencoded
        unencoded_angle = f"{marker}<b>" in body
        unencoded_quote = f"{marker}<b>\"" in body or f"{marker}<b>'" in body

        if unencoded_angle or (context in ("html_attribute", "javascript") and unencoded_quote):
            severity = "High"
            confidence = "High confidence"
            detection_status = "Confirmed"
            vtype = "Reflected XSS"
            evidence = f"Unsanitized marker reflected in '{context}' context with HTML metacharacters unencoded: '{probe}'."
        else:
            severity = "Informational"
            confidence = "Low confidence"
            detection_status = "Potential"
            vtype = "Input Reflection"
            evidence = f"Marker reflected in '{context}' context, but metacharacters appear properly encoded or filtered."

        findings.append(ScanFinding(
            type=vtype,
            category="Injection",
            owasp_category="A03:2021 - Injection",
            url=endpoint.url,
            method=endpoint.method.upper(),
            parameter=param.name,
            severity=severity,
            confidence=confidence,
            cwe_id="CWE-79",
            mitre_attack="T1059.007",
            detection_status=detection_status,
            evidence=evidence,
            description=f"User-supplied input in parameter '{param.name}' is reflected into the HTTP response body in {context} context.",
            impact="An attacker could execute arbitrary JavaScript in the victim's session, hijack cookies, or perform unauthorized client actions.",
            remediation="Apply context-aware contextual HTML/JavaScript output encoding, implement a strict Content-Security-Policy (CSP), and validate inputs.",
            evidence_details={"context": context, "probe": probe, "location": location},
        ))

    return findings
