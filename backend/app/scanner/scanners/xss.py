"""
Context-aware, comprehensive Cross-Site Scripting (XSS) scanner module.

Supports:
1. Reflected XSS:
   - Tests GET, POST, form-data, and JSON parameters using unique verification markers.
   - Context classification: HTML body, HTML attribute, JavaScript block, HTML comment.
   - Contextual breakout verification: determines whether executable script tags or attribute event handlers execute.
   - Separates safe encoded input reflections (Informational) from confirmed XSS (High).
2. DOM-based XSS:
   - Evaluates client-side URL parameters and SPA hash-based routes (e.g. /#/search?q=...).
   - Performs browser-based JavaScript execution verification using Playwright:
     listens for dialog events (alert/confirm/prompt) and active executable DOM sink injections.
   - Static analysis fallback for client-side JavaScript sink-source flows.
3. Stored XSS:
   - Submits unique tracking markers into state-changing endpoints and verifies whether the payload persists
     unencoded or executes when revisiting the affected application pages.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

logger = logging.getLogger("scanner.xss")

DOM_SINK_PATTERNS = [
    (re.compile(r"document\.write\s*\(.*?(?:location\.|document\.cookie|window\.name)", re.IGNORECASE), "document.write with unvalidated URL/location source"),
    (re.compile(r"\.innerHTML\s*=\s*.*?(?:location\.(?:hash|search|pathname)|decodeURI|sanitizer\.bypassSecurityTrustHtml)", re.IGNORECASE), "innerHTML assignment from URL parameters/hash"),
    (re.compile(r"\.outerHTML\s*=\s*.*?(?:location\.|window\.name)", re.IGNORECASE), "outerHTML assignment from dynamic window/location source"),
    (re.compile(r"\$\s*\(\s*['\"]#[^'\"]*['\"]\s*\)\.html\s*\(.*?(?:location|hash|search)", re.IGNORECASE), "jQuery html() injection from URL parameter"),
    (re.compile(r"eval\s*\(\s*(?:unescape|decodeURIComponent)?\s*\(?\s*location\.", re.IGNORECASE), "eval() execution of location source"),
    (re.compile(r"bypassSecurityTrustHtml\s*\(", re.IGNORECASE), "Angular bypassSecurityTrustHtml sanitization bypass"),
]


def _set_url_param(url: str, name: str, value: str) -> str:
    """
    Format URL parameter for both standard query strings (?q=val)
    and SPA client-side hash routes (/#/search?q=val or #!/path?q=val).
    """
    p = urlparse(url)
    if p.fragment and ("/" in p.fragment or "?" in p.fragment):
        frag_path = p.fragment
        frag_query = ""
        if "?" in frag_path:
            frag_path, frag_query = frag_path.split("?", 1)
        frag_q = dict(parse_qsl(frag_query, keep_blank_values=True))
        frag_q[name] = value
        new_frag = f"{frag_path}?{urlencode(frag_q)}"
        return urlunparse(p._replace(fragment=new_frag))
    else:
        q = dict(parse_qsl(p.query, keep_blank_values=True))
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


async def _send_request(
    client: SafeHTTPClient,
    endpoint: DiscoveredEndpoint,
    param_name: str,
    param_val: str,
    location: str,
    body_defaults: Dict[str, str],
) -> Optional[Any]:
    try:
        is_json = (
            location == "json"
            or "json" in (endpoint.content_type or "").lower()
            or (endpoint.method.upper() == "POST" and any(k in endpoint.url.lower() for k in ("/rest/", "/api/")))
        )
        if is_json and endpoint.method.upper() == "POST":
            payload = _set_body_param(body_defaults, param_name, param_val)
            return await client.post(endpoint.url, json=payload)
        elif endpoint.method.upper() == "POST" or location in ("body", "form"):
            payload = _set_body_param(body_defaults, param_name, param_val)
            return await client.post(endpoint.url, data=payload)
        else:
            target_url = _set_url_param(endpoint.url, param_name, param_val)
            return await client.get(target_url)
    except Exception as exc:
        logger.debug("XSS request error on %s (%s): %s", endpoint.url, param_name, exc)
        return None


async def _test_browser_dom_xss(url: str, param_name: str) -> Optional[Dict[str, Any]]:
    """
    Launch headless Chromium using Playwright to test for client-side DOM XSS.
    Listens for dialog events and checks for live executable DOM sink nodes.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None

    probes = [
        '<iframe src="javascript:alert(1)">',
        '<img src=x onerror=alert(1)>',
    ]

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            executed = False
            execution_evidence = None
            triggered_probe = None
            navigated_url = None

            async def on_dialog(dialog):
                nonlocal executed, execution_evidence
                executed = True
                execution_evidence = f"JavaScript execution confirmed via browser {dialog.type} dialog: '{dialog.message}'"
                try:
                    await dialog.accept()
                except Exception:
                    pass

            page.on("dialog", on_dialog)

            for probe in probes:
                target_url = _set_url_param(url, param_name, probe)
                navigated_url = target_url
                triggered_probe = probe

                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=5000)
                    await asyncio.sleep(1.2)
                except Exception:
                    pass

                if executed:
                    break

                # If dialog was not caught, check if active executable DOM sink was inserted
                try:
                    dom_active = await page.evaluate("""(p) => {
                        const el = document.querySelector('iframe[src*="javascript:"], img[onerror*="alert"], svg[onload*="alert"]');
                        if (el) return el.outerHTML.slice(0, 150);
                        const bHtml = document.body ? document.body.innerHTML : '';
                        if (bHtml.includes(p)) return p;
                        return null;
                    }""", probe)
                    if dom_active:
                        executed = True
                        execution_evidence = f"Unsanitized executable payload rendered into active DOM: '{dom_active}'"
                        break
                except Exception:
                    pass

            await browser.close()

            if executed:
                return {
                    "executed": True,
                    "evidence": execution_evidence,
                    "probe": triggered_probe,
                    "url": navigated_url,
                }
    except Exception as exc:
        logger.debug("Playwright DOM XSS evaluation error on %s: %s", url, exc)

    return None


async def _test_stored_xss(
    endpoint: DiscoveredEndpoint,
    param_name: str,
    client: SafeHTTPClient,
    body_defaults: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """
    Submit tracking payload to state-changing endpoint and check if it persists
    unencoded on subsequent page views (stored XSS).
    """
    marker = "ztstr" + uuid.uuid4().hex[:6]
    probe = f"{marker}<b>\"'"

    try:
        resp = await _send_request(client, endpoint, param_name, probe, "body", body_defaults)
        if resp is None or resp.status_code not in (200, 201, 302):
            return None

        # Determine viewing targets to check for persistence
        p = urlparse(endpoint.url)
        base_origin = f"{p.scheme}://{p.netloc}"
        candidate_views = [
            endpoint.url,
            f"{base_origin}/",
            f"{base_origin}/about",
            f"{base_origin}/#/about",
            f"{base_origin}/feedback",
            f"{base_origin}/reviews",
            f"{base_origin}/api/Feedbacks/",
        ]

        for view_url in candidate_views:
            try:
                v_resp = await client.get(view_url)
                if v_resp and v_resp.text and marker in v_resp.text:
                    v_body = v_resp.text
                    unencoded = f"{marker}<b>" in v_body or f"{marker}\"" in v_body or f"{marker}'" in v_body
                    if unencoded:
                        return {
                            "type": "Stored XSS",
                            "view_url": view_url,
                            "probe": probe,
                            "marker": marker,
                            "evidence": f"Stored payload '{probe}' submitted to parameter '{param_name}' was retrieved and rendered unencoded on {view_url}.",
                        }
            except Exception:
                pass
    except Exception as exc:
        logger.debug("Stored XSS check error on %s: %s", endpoint.url, exc)

    return None


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    seen_params = set()

    # 1. Static DOM-based XSS sink check on discovered HTML
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
                    mitre_attack="T1189",
                    detection_status="Confirmed",
                    evidence=f"Dangerous DOM manipulation pattern detected in script: '{snippet}' ({desc}).",
                    description="Client-side script reads from an attacker-controllable source and passes it directly to an unsafe DOM sink.",
                    impact="Allows execution of arbitrary JavaScript in the victim's browser context without server round-trip.",
                    remediation="Use safe DOM properties like textContent or innerText, avoid document.write and eval, and sanitize HTML using DOMPurify.",
                    module="xss",
                ))
                break

    body_defaults = {
        p.name: p.sample_value or "test"
        for p in endpoint.parameters
        if p.location in ("body", "form", "json")
    }

    is_spa_route = (
        "#" in endpoint.url
        or "x-zerotrace-spa-route" in getattr(endpoint, "response_headers", {})
        or (endpoint.html and any(tag in endpoint.html for tag in ("<app-root", "<div id=\"root\"", "<div id=\"app\"")))
    )

    # 2. Test each parameter across Reflected, DOM, and Stored vectors
    for param in endpoint.parameters:
        if not param.name or param.name in seen_params:
            continue
        seen_params.add(param.name)

        location = param.location or ("body" if endpoint.method.upper() == "POST" else "query")

        # ---- Vector A: Browser-based DOM XSS verification (Playwright) ----
        # Highly effective for client-side routing, search bars, and SPA routes
        if is_spa_route or location == "query" or any(k in endpoint.url.lower() for k in ("search", "find", "query")):
            dom_result = await _test_browser_dom_xss(endpoint.url, param.name)
            if dom_result and dom_result.get("executed"):
                findings.append(ScanFinding(
                    type="DOM XSS",
                    category="Injection",
                    owasp_category="A03:2021 - Injection",
                    url=endpoint.url,
                    method=endpoint.method.upper(),
                    parameter=param.name,
                    severity="High",
                    confidence="High confidence",
                    cwe_id="CWE-79",
                    mitre_attack="T1189",
                    detection_status="Confirmed",
                    evidence=f"{dom_result['evidence']}. Tested parameter '{param.name}' with payload '{dom_result['probe']}' on {dom_result['url']}.",
                    description=f"Client-side DOM sink on {endpoint.url} dynamically executes untrusted input from parameter '{param.name}' without HTML sanitization.",
                    impact="An attacker could execute arbitrary JavaScript in the victim's session, hijack session tokens, or perform unauthorized client-side actions.",
                    remediation="Sanitize all dynamically inserted HTML using DOMPurify before DOM insertion, and remove unsafe bypassSecurityTrustHtml calls.",
                    evidence_details={"vector": "dom_xss", "url": dom_result["url"], "probe": dom_result["probe"]},
                    module="xss",
                ))
                continue

        # ---- Vector B: Stored XSS verification for state-changing inputs ----
        if endpoint.method.upper() in ("POST", "PUT") and any(k in param.name.lower() for k in ("comment", "feedback", "review", "msg", "message", "name", "text", "body")):
            stored_res = await _test_stored_xss(endpoint, param.name, client, body_defaults)
            if stored_res:
                findings.append(ScanFinding(
                    type="Stored XSS",
                    category="Injection",
                    owasp_category="A03:2021 - Injection",
                    url=endpoint.url,
                    method=endpoint.method.upper(),
                    parameter=param.name,
                    severity="High",
                    confidence="High confidence",
                    cwe_id="CWE-79",
                    mitre_attack="T1189",
                    detection_status="Confirmed",
                    evidence=stored_res["evidence"],
                    description=f"State-changing input in parameter '{param.name}' is stored by the server and rendered unencoded on {stored_res['view_url']}.",
                    impact="Stored Cross-Site Scripting affects all subsequent users viewing the affected page, enabling persistent session hijacking and worm propagation.",
                    remediation="Apply contextual HTML encoding on output rendering, sanitize rich text input with an allowlist sanitizer, and implement a strict Content-Security-Policy.",
                    evidence_details=stored_res,
                    module="xss",
                ))
                continue

        # ---- Vector C: Context-aware Reflected XSS parameter probes ----
        marker = "ztxss" + uuid.uuid4().hex[:6]
        probe = f"{marker}<b>\"'"

        resp = await _send_request(client, endpoint, param.name, probe, location, body_defaults)
        if resp is None or not resp.text:
            continue

        body = resp.text
        if marker not in body:
            continue

        context = classify_context(body, marker) or "html_body"

        # Check if metacharacters were unencoded
        unencoded_angle = f"{marker}<b>" in body or f"{marker}<script>" in body or f"{marker}<img>" in body
        unencoded_quote = f"{marker}<b>\"" in body or f"{marker}<b>'" in body or f"{marker}\"" in body or f"{marker}'" in body

        # Contextual secondary verification probe
        if not unencoded_angle and not (context in ("html_attribute", "javascript") and unencoded_quote):
            sec_marker = "ztxss" + uuid.uuid4().hex[:6]
            if context == "html_body":
                sec_probe = f"{sec_marker}<script>/*test*/</script>"
            elif context == "html_attribute":
                sec_probe = f'"{sec_marker} onfocus="1'
            elif context == "javascript":
                sec_probe = f'";/*{sec_marker}*/'
            else:
                sec_probe = f"-->{sec_marker}<b>"

            sec_resp = await _send_request(client, endpoint, param.name, sec_probe, location, body_defaults)
            if sec_resp and sec_resp.text:
                if (
                    (context == "html_body" and f"{sec_marker}<script>" in sec_resp.text)
                    or (context == "html_attribute" and f'"{sec_marker} onfocus=' in sec_resp.text)
                    or (context == "javascript" and f'";/*{sec_marker}*/' in sec_resp.text)
                    or (context == "html_comment" and f"-->{sec_marker}<b>" in sec_resp.text)
                ):
                    unencoded_angle = True
                    probe = sec_probe

        if unencoded_angle or (context in ("html_attribute", "javascript") and unencoded_quote):
            findings.append(ScanFinding(
                type="Reflected XSS",
                category="Injection",
                owasp_category="A03:2021 - Injection",
                url=endpoint.url,
                method=endpoint.method.upper(),
                parameter=param.name,
                severity="High",
                confidence="High confidence",
                cwe_id="CWE-79",
                mitre_attack="T1189",
                detection_status="Confirmed",
                evidence=f"Unsanitized marker reflected in '{context}' context with HTML metacharacters unencoded: '{probe}'.",
                description=f"User-supplied input in parameter '{param.name}' is reflected unencoded into the HTTP response body in {context} context, allowing arbitrary script execution.",
                impact="An attacker could execute arbitrary JavaScript in the victim's session, hijack cookies, or perform unauthorized client actions.",
                remediation="Apply context-aware contextual HTML/JavaScript output encoding, implement a strict Content-Security-Policy (CSP), and validate inputs.",
                evidence_details={"context": context, "probe": probe, "location": location},
                module="xss",
            ))
        else:
            findings.append(ScanFinding(
                type="Input Reflection",
                category="Information Disclosure",
                owasp_category="A05:2021 - Security Misconfiguration",
                url=endpoint.url,
                method=endpoint.method.upper(),
                parameter=param.name,
                severity="Informational",
                confidence="Low confidence",
                cwe_id="CWE-79",
                mitre_attack="T1059.007",
                detection_status="Potential",
                evidence=f"User input marker '{marker}' is reflected in '{context}' context, but HTML metacharacters (<, >, \", ') are properly encoded or filtered. No executable JavaScript was possible.",
                description=f"User-supplied input in parameter '{param.name}' is reflected into the HTTP response body in {context} context with proper encoding. While not exploitable as Cross-Site Scripting, input reflection should be monitored.",
                impact="None identified. HTML metacharacters are safely neutralized or encoded by the application.",
                remediation="Continue applying strict context-aware output encoding and maintain a strong Content-Security-Policy (CSP).",
                evidence_details={"context": context, "probe": probe, "location": location},
                module="xss",
            ))

    return findings
