"""
Safe Server-Side Template Injection (SSTI) scanner module.

Tests common server-side template engine evaluation patterns (Jinja2, Twig, Freemarker, Velocity, Smarty, Ruby ERB)
using harmless mathematical multiplication expressions:
- {{49*43}} -> 2107
- ${49*43} -> 2107
- <%= 49*43 %> -> 2107
- #{49*43} -> 2107

Safety rules:
- Strictly mathematical evaluation only. No template execution of OS commands or class loaders.
"""
from typing import List, Dict
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

    # Probes that evaluate to "2107" (49 * 43)
    math_probes = [
        ("{{49*43}}", "2107", "Jinja2 / Twig / Pebble {{49*43}}"),
        ("${49*43}", "2107", "Freemarker / Velocity / Smarty ${49*43}"),
        ("<%= 49*43 %>", "2107", "Ruby ERB / EJS <%= 49*43 %>"),
        ("#{49*43}", "2107", "Ruby / El Expression #{49*43}"),
    ]

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
        if "2107" in baseline_text:
            continue  # Number already present in baseline, skip to avoid false positive

        for payload, expected_eval, desc in math_probes:
            try:
                if location in ("body", "form") or endpoint.method.upper() == "POST":
                    resp = await client.post(endpoint.url, data=_set_body_param(body_defaults, param.name, payload))
                else:
                    resp = await client.get(_set_url_param(endpoint.url, param.name, payload))
            except Exception:
                continue

            if resp is not None and resp.text:
                # If evaluated product "2107" appears in response and the literal template expression is NOT displayed
                if expected_eval in resp.text and payload not in resp.text:
                    findings.append(ScanFinding(
                        type="Server-Side Template Injection",
                        category="Injection",
                        owasp_category="A03:2021 - Injection",
                        url=endpoint.url,
                        method=endpoint.method.upper(),
                        parameter=param.name,
                        severity="Critical",
                        confidence="Confirmed",
                        cwe_id="CWE-1336",
                        mitre_attack="T1190",
                        detection_status="Confirmed",
                        evidence=f"Template expression '{payload}' ({desc}) was evaluated on the server yielding '{expected_eval}'.",
                        description=f"Parameter '{param.name}' is rendered inside a server-side template engine without sandboxing or escaping.",
                        impact="Could permit remote code execution (RCE) on the application server via template engine helper methods or sandbox escapes.",
                        remediation="Do not concatenate user input into template strings. Use logic-less templates, strict sandboxing, or pass variables into context data models.",
                        evidence_details={"payload": payload, "result": expected_eval, "engine_hint": desc},
                    ))
                    break

    return findings

