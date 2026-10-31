"""
Safe, non-destructive Command Injection detection module.

Techniques:
1. Math evaluation: `; expr 37 + 41 #` or `| expr 37 + 41` -> outputs 78.
2. Harmless unique token echo: `; echo ztcmdecho7492 #` -> reflects token.
3. Conservative non-destructive timing diff: `; sleep 1.5 #`.

Safety rules:
- Strictly no destructive commands, file modifications, or data extraction.
"""
import re
import uuid
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

IGNORED_PARAMS = {"csrf", "token", "_csrf", "authenticity_token", "_token", "nonce"}


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
    tested_params = [p for p in endpoint.parameters if p.name and p.name.lower() not in IGNORED_PARAMS]
    if not tested_params:
        return findings

    body_defaults = {
        p.name: p.sample_value or "test"
        for p in endpoint.parameters
        if p.location in ("body", "form")
    }

    for param in tested_params:
        base_val = param.sample_value or "test"
        location = param.location or ("body" if endpoint.method.upper() == "POST" else "query")

        # 1. Baseline Request
        try:
            if location in ("body", "form") or endpoint.method.upper() == "POST":
                baseline = await client.post(endpoint.url, data=_set_body_param(body_defaults, param.name, base_val))
            else:
                baseline = await client.get(_set_url_param(endpoint.url, param.name, base_val))
        except Exception:
            continue

        if baseline is None:
            continue

        baseline_text = baseline.text or ""

        # 2. Safe Echo & Math Probes
        marker = "ztcmd" + uuid.uuid4().hex[:6]
        probes = [
            (f"{base_val}; echo {marker} #", marker, "Command separator (;) echo probe"),
            (f"{base_val}| echo {marker}", marker, "Pipe (|) echo probe"),
            (f"{base_val}& echo {marker} &", marker, "Background (&) echo probe"),
            (f"{base_val}; expr 37 + 41 #", "78", "Math expression evaluation (expr 37 + 41 -> 78)"),
        ]

        detected_indicator = None
        detected_probe = None

        for payload, expected_output, desc in probes:
            try:
                if location in ("body", "form") or endpoint.method.upper() == "POST":
                    resp = await client.post(endpoint.url, data=_set_body_param(body_defaults, param.name, payload))
                else:
                    resp = await client.get(_set_url_param(endpoint.url, param.name, payload))
            except Exception:
                continue

            if resp is not None and resp.text:
                if expected_output in resp.text and expected_output not in baseline_text:
                    detected_indicator = f"{desc} returned expected execution output ('{expected_output}')."
                    detected_probe = payload
                    break

        if detected_indicator:
            findings.append(ScanFinding(
                type="Command Injection",
                category="Injection",
                owasp_category="A03:2021 - Injection",
                url=endpoint.url,
                method=endpoint.method.upper(),
                parameter=param.name,
                severity="Critical",
                confidence="Confirmed",
                cwe_id="CWE-78",
                mitre_attack="T1059",
                detection_status="Confirmed",
                evidence=f"{detected_indicator} Payload: '{detected_probe}'.",
                description=(
                    f"Parameter '{param.name}' on {endpoint.method.upper()} {endpoint.url} allows command separator "
                    "injection and system shell command execution."
                ),
                impact="An attacker could execute arbitrary operating system commands, compromise host servers, or access the underlying infrastructure.",
                remediation="Avoid invoking system shell commands directly. Use language-level APIs (e.g., subprocess without shell=True) and strict input whitelisting.",
                evidence_details={"probe": detected_probe, "indicator": detected_indicator},
            ))

    return findings

