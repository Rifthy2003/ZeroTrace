"""
Safe Path Traversal (Directory Traversal) detection module.

Techniques:
1. Tests parameters named file, path, doc, view, template, image, download, page, folder.
2. Sends non-destructive dot-dot-slash sequences:
   - ../../../../etc/passwd -> checks for root:.*:0:0: pattern.
   - ..\\..\\..\\windows\\win.ini -> checks for [fonts]|[extensions] pattern.
3. Tests harmless relative directory traversal indicators.
"""
import re
from typing import List, Dict
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

TRAVERSAL_PARAM_KEYWORDS = {"file", "path", "page", "doc", "view", "template", "image", "download", "folder", "item", "load"}

PASSWD_RE = re.compile(r"root:[^:]*:[0-9]+:[0-9]+:[^:]*:/", re.IGNORECASE)
WIN_INI_RE = re.compile(r"\[(?:fonts|extensions|files)\]", re.IGNORECASE)


def _set_url_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _set_body_param(defaults: Dict[str, str], name: str, value: str) -> Dict[str, str]:
    c = dict(defaults)
    c[name] = value
    return c


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    applicable_params = [
        p for p in endpoint.parameters
        if p.name and (any(kw in p.name.lower() for kw in TRAVERSAL_PARAM_KEYWORDS) or p.location in ("query", "body"))
    ]
    if not applicable_params:
        return findings

    body_defaults = {
        p.name: p.sample_value or "test"
        for p in endpoint.parameters
        if p.location in ("body", "form")
    }

    traversal_probes = [
        ("../../../../etc/passwd", PASSWD_RE, "Linux /etc/passwd disclosure pattern"),
        ("..\\..\\..\\..\\windows\\win.ini", WIN_INI_RE, "Windows win.ini header pattern"),
    ]

    for param in applicable_params:
        location = param.location or ("body" if endpoint.method.upper() == "POST" else "query")

        for payload, regex, desc in traversal_probes:
            try:
                if location in ("body", "form") or endpoint.method.upper() == "POST":
                    resp = await client.post(endpoint.url, data=_set_body_param(body_defaults, param.name, payload))
                else:
                    resp = await client.get(_set_url_param(endpoint.url, param.name, payload))
            except Exception:
                continue

            if resp is not None and resp.text:
                match = regex.search(resp.text)
                if match:
                    matched_snippet = match.group(0)[:60]
                    findings.append(ScanFinding(
                        type="Path Traversal",
                        category="Access Control",
                        owasp_category="A01:2021 - Broken Access Control",
                        url=endpoint.url,
                        method=endpoint.method.upper(),
                        parameter=param.name,
                        severity="High",
                        confidence="Confirmed",
                        cwe_id="CWE-22",
                        mitre_attack="T1083",
                        detection_status="Confirmed",
                        evidence=f"Path traversal sequence '{payload}' returned system file content: '{matched_snippet}' ({desc}).",
                        description=f"Parameter '{param.name}' allows stepping outside the designated web root directory to access arbitrary files.",
                        impact="An attacker could view sensitive operating system configuration files, application source code, or credentials.",
                        remediation="Use basename() to strip directory separators, maintain a strict whitelist of permitted files, and avoid direct file-path concatenation.",
                        evidence_details={"payload": payload, "matched": matched_snippet},
                    ))
                    break

    return findings

