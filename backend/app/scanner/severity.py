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
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
from app.scanner.models import ScanFinding

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

CWE_MITRE_MAP: Dict[str, Tuple[str, str]] = {
    "SQL Injection": ("CWE-89", "T1190"),
    "Reflected XSS": ("CWE-79", "T1059.007"),
    "Stored XSS": ("CWE-79", "T1059.007"),
    "DOM XSS": ("CWE-79", "T1059.007"),
    "Input Reflection": ("CWE-79", "T1059.007"),
    "Command Injection": ("CWE-78", "T1059"),
    "Server-Side Template Injection": ("CWE-1336", "T1190"),
    "Potential CSRF": ("CWE-352", "T1566"),
    "CSRF": ("CWE-352", "T1566"),
    "Open Redirect": ("CWE-601", "T1566.002"),
    "Missing Security Header": ("CWE-693", "T1562"),
    "Insecure Cookie Configuration": ("CWE-614", "T1539"),
    "Directory Listing": ("CWE-548", "T1083"),
    "Exposed Sensitive File": ("CWE-552", "T1552"),
    "Sensitive File Exposure": ("CWE-552", "T1552"),
    "Potential Information Disclosure": ("CWE-200", "T1592"),
    "Technology Detection": ("CWE-200", "T1592"),
    "CORS Misconfiguration": ("CWE-942", "T1190"),
    "Clickjacking Protection Missing": ("CWE-1021", "T1190"),
    "Path Traversal": ("CWE-22", "T1083"),
    "Authentication Security Weakness": ("CWE-287", "T1078"),
    "Insecure Direct Object Reference (IDOR)": ("CWE-639", "T1190"),
    "GraphQL Security Weakness": ("CWE-200", "T1592"),
}


def adjust_severity(f: ScanFinding) -> ScanFinding:
    if f.confidence == "Low confidence" and f.category != "Injection":
        idx = SEVERITY_ORDER.index(f.severity)
        f.severity = SEVERITY_ORDER[max(0, idx - 1)]
    return f


def _dedup_key(f: ScanFinding) -> str:
    """Build canonical deduplication key so raw instances group under unique findings."""
    ftype = f.type or ""
    furl = f.url or ""
    fparam = (f.parameter or "").strip().lower()
    fevid = (f.evidence or "").strip().lower()

    parsed = urlparse(furl) if furl else None
    path = parsed.path if parsed and parsed.path else furl

    if ftype == "Missing Security Header":
        header_name = fparam if fparam else fevid.split(":")[0].strip()
        return f"header::{header_name.lower()}"

    if "Cookie" in ftype:
        return f"cookie::{ftype.lower()}::{fparam}"

    if ftype == "Technology Detection":
        return f"tech::{fevid or fparam}"

    if ftype in ("Exposed Sensitive File", "Sensitive File Exposure", "Directory Listing"):
        return f"file::{ftype.lower()}::{path}"

    return f"vuln::{ftype.lower()}::{path.lower()}::{fparam}"


def correlate(findings: List[ScanFinding]) -> List[ScanFinding]:
    """
    De-duplicate repeated findings across endpoints, parameters, and pages.
    Group raw occurrences under unique findings, assign CWE/MITRE IDs,
    and compute detection status (Confirmed, Potential, Requires Manual Verification).
    """
    groups: Dict[str, ScanFinding] = {}
    occurrences: Dict[str, List[Dict[str, Any]]] = {}

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
            "evidence": f.evidence,
        }

        if key not in groups:
            f.raw_instances = 1
            groups[key] = f
            occurrences[key] = [occurrence_item]
        else:
            rep = groups[key]
            rep.raw_instances += 1
            occurrences[key].append(occurrence_item)

            # Prefer higher severity or higher confidence as representative
            rep_sev_idx = SEVERITY_ORDER.index(rep.severity) if rep.severity in SEVERITY_ORDER else 0
            cur_sev_idx = SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 0
            if cur_sev_idx > rep_sev_idx or (cur_sev_idx == rep_sev_idx and f.confidence in ("Confirmed", "High confidence")):
                rep.severity = f.severity
                rep.confidence = f.confidence
                rep.detection_status = f.detection_status
                rep.url = f.url
                rep.parameter = f.parameter or rep.parameter
                rep.evidence = f.evidence

    result = list(groups.values())

    # Attach occurrences list to evidence_details
    for rep in result:
        key = _dedup_key(rep)
        rep.evidence_details = {
            "unique_key": key,
            "raw_instances": rep.raw_instances,
            "occurrences": occurrences.get(key, [])[:50],  # cap to 50 for safety/storage
        }

    # Cross-module correlation:
    # If SQLi error disclosure and SQLi finding share the same URL => raise confidence to High
    disclosure_urls = {f.url for f in result if "Disclosure" in f.type or "Information" in f.type}
    for f in result:
        if f.type == "SQL Injection" and f.url in disclosure_urls and f.confidence == "Medium confidence":
            f.confidence = "High confidence"
            f.detection_status = "Confirmed"

    return result
