"""
Severity, confidence, CWE, and correlation engine.

Severity = potential impact if the issue is real.
Confidence = how sure the scanner is that the issue is real.
They are kept separate because an automated tool can be wrong: a
High-severity / Medium-confidence finding still needs manual verification.

Rules (documented for auditability):
 - Injection classes (SQLi, Command Injection, SSTI) start at High / Critical.
 - XSS confirmed unencoded reflection: High; encoded reflection: Informational.
 - Exposed sensitive files: High (may contain secrets).
 - CSRF / open redirect / dir listing / info disclosure / weak CSP: Medium.
 - Missing hardening headers / cookie flags: Low-Medium depending on exposure.
 - Pure technology fingerprinting: Informational.
 - Heuristic or authorization checks (IDOR) require manual verification.
"""
import re
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse
from app.scanner.models import ScanFinding

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

SECURITY_HEADER_RULES: Dict[str, Dict[str, str]] = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy Header",
        "severity": "Medium",
        "cwe_id": "CWE-693",
        "mitre_attack": "T1562",
        "description": "Content-Security-Policy is missing across application responses, allowing injection attacks (e.g. Cross-Site Scripting, frame injection) to execute without defense-in-depth restrictions.",
        "impact": "Increases susceptibility to Cross-Site Scripting (XSS), clickjacking, and unauthorized resource injection.",
        "remediation": "Deploy a strict Content-Security-Policy (e.g., default-src 'self'; script-src 'self'; object-src 'none') to restrict untrusted sources.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "Medium",
        "cwe_id": "CWE-1021",
        "mitre_attack": "T1562",
        "description": "X-Frame-Options is missing, permitting web pages to be framed by external origins and exposing users to clickjacking UI redress attacks.",
        "impact": "Attackers can embed target interfaces in deceptive iframes to hijack user clicks and actions.",
        "remediation": "Send 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security Header",
        "severity": "Low",
        "cwe_id": "CWE-319",
        "mitre_attack": "T1562",
        "description": "HTTP Strict Transport Security (HSTS) is missing, leaving communication vulnerable to SSL-stripping and downgrade attacks on initial visit.",
        "impact": "Unencrypted HTTP connections can be intercepted or manipulated via man-in-the-middle attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "Low",
        "cwe_id": "CWE-693",
        "mitre_attack": "T1562",
        "description": "X-Content-Type-Options is missing, allowing browsers to MIME-sniff response bodies and execute non-executable file types as scripts.",
        "impact": "MIME-type confusion can lead to cross-site scripting when serving user-uploaded files.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": "Low",
        "cwe_id": "CWE-200",
        "mitre_attack": "T1592",
        "description": "Referrer-Policy is missing, which may inadvertently transmit sensitive URL paths and query parameters to third-party domains.",
        "impact": "Sensitive session IDs or token query strings may leak via HTTP Referer headers.",
        "remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": "Informational",
        "cwe_id": "CWE-693",
        "mitre_attack": "T1562",
        "description": "Permissions-Policy is missing, allowing browser features (geolocation, camera, microphone) to run without explicit site restrictions.",
        "impact": "Allows untrusted iframes or embedded third-party scripts to access browser device APIs if permission is granted.",
        "remediation": "Define a Permissions-Policy header explicitly disallowing unused browser features.",
    },
}

CWE_MITRE_MAP: Dict[str, Tuple[str, str]] = {
    "Missing Security Header": ("CWE-693", "T1562"),
    "Weak Content Security Policy": ("CWE-693", "T1562"),
    "SQL Injection": ("CWE-89", "T1190"),
    "Cross-Site Scripting (XSS)": ("CWE-79", "T1189"),
    "Cross-Site Request Forgery (CSRF)": ("CWE-352", "T1189"),
    "Open Redirect": ("CWE-601", "T1566"),
    "Command Injection": ("CWE-78", "T1059"),
    "Server-Side Template Injection (SSTI)": ("CWE-1336", "T1190"),
    "Path Traversal": ("CWE-22", "T1083"),
    "Exposed Sensitive File": ("CWE-538", "T1552"),
    "Sensitive File Exposure": ("CWE-538", "T1552"),
    "Directory Listing": ("CWE-548", "T1083"),
    "CORS Misconfiguration": ("CWE-942", "T1557"),
    "Clickjacking": ("CWE-1021", "T1189"),
    "Cookie Without HttpOnly": ("CWE-1004", "T1539"),
    "Cookie Without Secure": ("CWE-614", "T1557"),
    "Cookie Without SameSite": ("CWE-1275", "T1189"),
    "Technology Detection": ("CWE-200", "T1592"),
    "Information Disclosure": ("CWE-200", "T1592"),
}


def extract_header_name(parameter: Optional[str], evidence: Optional[str]) -> Optional[str]:
    """Extract canonical missing HTTP header name from parameter or evidence string."""
    if parameter:
        p = parameter.strip().lower()
        if p in SECURITY_HEADER_RULES or "policy" in p or "options" in p or "transport" in p or "security" in p:
            return p
    if evidence:
        m = re.search(r"['\"]([a-zA-Z0-9_-]+)['\"]", evidence)
        if m:
            h = m.group(1).lower()
            if h in SECURITY_HEADER_RULES:
                return h
        ev_lower = evidence.lower()
        for h in SECURITY_HEADER_RULES:
            if h in ev_lower:
                return h
    return (parameter or "").strip().lower() or None


def adjust_severity(f: ScanFinding) -> ScanFinding:
    ftype = f.type or ""
    if "header" in ftype.lower():
        hname = extract_header_name(f.parameter, f.evidence)
        if hname and hname in SECURITY_HEADER_RULES:
            f.severity = SECURITY_HEADER_RULES[hname]["severity"]
            return f

    if f.confidence == "Low confidence" and f.category != "Injection":
        idx = SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 0
        f.severity = SEVERITY_ORDER[max(0, idx - 1)]
    return f


def classify_finding_group(finding_type: str, category: str = "", severity: str = "") -> str:
    """
    Classify a finding into one of the three required ZeroTrace categories:
    1. critical_vulnerabilities ("Critical Security Vulnerabilities")
    2. other_vulnerabilities ("Other Security Vulnerabilities")
    3. security_configuration ("Security Configuration Issues")
    """
    ftype = (finding_type or "").lower()
    cat = (category or "").lower()
    sev = (severity or "").lower()

    # 1. Critical Security Vulnerabilities:
    # High-impact injection & bypass vulnerabilities
    if any(k in ftype for k in ("sql injection", "command injection", "template injection", "ssti", "code execution")):
        return "critical_vulnerabilities"
    if "path traversal" in ftype and sev in ("critical", "high"):
        return "critical_vulnerabilities"
    if "authentication bypass" in ftype or "auth bypass" in ftype:
        return "critical_vulnerabilities"

    # 3. Security Configuration Issues:
    # Framing, missing headers, cookies, info disclosure, tech detection, cors
    if any(k in ftype for k in (
        "clickjacking",
        "header",
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cookie",
        "information disclosure",
        "technology detection",
        "banner",
        "cors",
    )) or "configuration" in cat:
        return "security_configuration"

    # 2. Other Security Vulnerabilities:
    # XSS, CSRF, Open Redirect, Sensitive Files, Directory Listing, IDOR, etc.
    return "other_vulnerabilities"


def _dedup_key(f: ScanFinding) -> str:
    """Build canonical deduplication key so raw instances group under unique findings."""
    ftype = (f.type or "").strip()
    furl = (f.url or "").strip()
    fparam = (f.parameter or "").strip().lower()
    fevid = (f.evidence or "").strip()

    parsed = urlparse(furl) if furl else None
    path = parsed.path if parsed and parsed.path else furl

    # 1. Clickjacking Protection Missing -> Group site-wide into 1 unique finding
    if "clickjacking" in ftype.lower():
        return "config::clickjacking"

    # 2. Missing Security Headers -> Group site-wide by specific header name
    if "header" in ftype.lower() or "csp" in ftype.lower() or "content-security-policy" in ftype.lower():
        header_name = extract_header_name(fparam, fevid) or fparam or "generic"
        return f"header::{header_name.lower()}"

    # 3. CORS Misconfiguration -> Group site-wide
    if "cors" in ftype.lower():
        return "config::cors"

    # 4. Cookie Security Issues -> Group by cookie name & issue type
    if "cookie" in ftype.lower():
        return f"cookie::{ftype.lower()}::{fparam}"

    # 5. Technology Detection & Information Disclosure -> Group by fingerprint/evidence
    if ftype in ("Technology Detection", "Information Disclosure"):
        return f"config::{ftype.lower()}::{fevid.lower() or fparam}"

    # 6. Sensitive Files & Directory Listing -> Group by specific file path
    if ftype in ("Exposed Sensitive File", "Sensitive File Exposure", "Directory Listing"):
        return f"file::{ftype.lower()}::{path.lower()}"

    # 7. Injection & Endpoint Vulnerabilities (SQLi, XSS, Command Injection, SSTI, Path Traversal, etc.)
    # Group by vulnerability type, endpoint path, and parameter
    return f"vuln::{ftype.lower()}::{path.lower()}::{fparam}"


def correlate(findings: List[ScanFinding]) -> List[ScanFinding]:
    """
    De-duplicate repeated findings across endpoints, parameters, and pages.
    Group raw occurrences under unique findings, assign consistent CWE/MITRE IDs,
    and compute detection status (Confirmed, Potential, Requires Manual Verification).
    """
    groups: Dict[str, ScanFinding] = {}
    occurrences: Dict[str, List[Dict[str, Any]]] = {}
    affected_urls: Dict[str, List[str]] = {}

    for raw_f in findings:
        f = adjust_severity(raw_f)
        key = _dedup_key(f)

        # Standardize CWE and MITRE
        if not f.cwe_id or not f.mitre_attack:
            cwe, mitre = CWE_MITRE_MAP.get(f.type, ("CWE-200", "T1190"))
            f.cwe_id = f.cwe_id or cwe
            f.mitre_attack = f.mitre_attack or mitre

        # Standardize detection status
        if not f.detection_status:
            if "Potential" in f.type or "Heuristic" in f.type:
                f.detection_status = "Potential"
            elif f.confidence in ("Confirmed", "High confidence"):
                f.detection_status = "Confirmed"
            else:
                f.detection_status = "Requires Manual Verification"

        occurrence_item = {
            "url": f.url,
            "method": f.method,
            "parameter": f.parameter,
            "severity": f.severity,
            "evidence": f.evidence,
        }

        if key not in groups:
            f.raw_instances = 1
            groups[key] = f
            occurrences[key] = [occurrence_item]
            affected_urls[key] = [f.url] if f.url else []
        else:
            rep = groups[key]
            rep.raw_instances += 1
            occurrences[key].append(occurrence_item)
            if f.url and f.url not in affected_urls[key]:
                affected_urls[key].append(f.url)

            # Prefer higher confidence or confirmed status as representative
            rep_sev_idx = SEVERITY_ORDER.index(rep.severity) if rep.severity in SEVERITY_ORDER else 0
            cur_sev_idx = SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 0
            if cur_sev_idx > rep_sev_idx or (cur_sev_idx == rep_sev_idx and f.confidence in ("Confirmed", "High confidence")):
                rep.confidence = f.confidence
                rep.detection_status = f.detection_status
                if f.evidence and len(f.evidence) > len(rep.evidence or ""):
                    rep.evidence = f.evidence

    result = list(groups.values())

    # Attach occurrences list, affected URLs, and enforce consistent rule metadata
    for rep in result:
        key = _dedup_key(rep)
        rep.finding_group = classify_finding_group(rep.type, rep.category, rep.severity)
        hname = extract_header_name(rep.parameter, rep.evidence)
        if "header" in (rep.type or "").lower() and hname and hname in SECURITY_HEADER_RULES:
            rule = SECURITY_HEADER_RULES[hname]
            rep.parameter = hname
            rep.severity = rule["severity"]
            rep.description = rule["description"]
            rep.impact = rule["impact"]
            rep.remediation = rule["remediation"]
            rep.cwe_id = rule["cwe_id"]
            rep.mitre_attack = rule["mitre_attack"]

        aff_list = affected_urls.get(key, [])
        rep.evidence_details = {
            "unique_key": key,
            "finding_group": rep.finding_group,
            "raw_instances": rep.raw_instances,
            "affected_urls": aff_list,
            "total_affected_endpoints": len(aff_list),
            "occurrences": occurrences.get(key, [])[:100],
        }

    # Cross-module correlation:
    # If SQLi error disclosure and SQLi finding share the same URL => raise confidence to High
    disclosure_urls = {f.url for f in result if "Disclosure" in f.type or "Information" in f.type}
    for f in result:
        if f.type == "SQL Injection" and f.url in disclosure_urls and f.confidence == "Medium confidence":
            f.confidence = "High confidence"
            f.detection_status = "Confirmed"

    return result
