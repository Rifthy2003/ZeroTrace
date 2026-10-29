"""
Severity/confidence engine.

Severity = potential impact if the issue is real.
Confidence = how sure the scanner is that the issue is real.
They are kept separate because an automated tool can be wrong: a
High-severity / Medium-confidence finding still needs manual verification.

Rules (documented for auditability):
 - Injection classes (SQLi) start at High: direct data compromise potential.
 - XSS confirmed unencoded reflection: High; encoded reflection: Informational.
 - Exposed sensitive files: High (may contain secrets).
 - CSRF / open redirect / dir listing / info disclosure / weak CSP: Medium.
 - Missing hardening headers / cookie flags: Low-Medium depending on exposure.
 - Pure technology fingerprinting: Informational.
Severity is only lowered (never raised) by correlation when confidence is Low
and the class is not injection.
"""
from typing import List
from app.scanner.models import ScanFinding

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


def adjust_severity(f: ScanFinding) -> ScanFinding:
    if f.confidence == "Low confidence" and f.category != "Injection":
        idx = SEVERITY_ORDER.index(f.severity)
        f.severity = SEVERITY_ORDER[max(0, idx - 1)]
    return f


def correlate(findings: List[ScanFinding]) -> List[ScanFinding]:
    """De-duplicate identical findings and raise confidence when multiple
    modules flag the same URL+parameter."""
    seen = {}
    for f in findings:
        key = (f.type, f.url, f.parameter, f.evidence)
        if key not in seen:
            seen[key] = adjust_severity(f)

    result = list(seen.values())

    # Correlation: SQLi error disclosure + SQLi finding on same URL => higher confidence
    disclosure_urls = {f.url for f in result if f.type == "Potential Information Disclosure"}
    for f in result:
        if f.type == "SQL Injection" and f.url in disclosure_urls and f.confidence == "Medium confidence":
            f.confidence = "High confidence"
    return result
