"""
Unit tests for vulnerability finding deduplication, canonical grouping,
and consistent severity assignment in ZeroTrace.
"""
import uuid
from datetime import datetime
import pytest
from app.scanner.models import ScanFinding
from app.scanner.severity import (
    correlate,
    adjust_severity,
    extract_header_name,
    SECURITY_HEADER_RULES,
)
from app.services.remediation import generate_finding_fingerprint
from app.models.finding import Finding, Severity, Confidence
from app.api.scans import group_scan_findings


def make_scan_finding(
    type="Missing Security Header",
    category="Security Misconfiguration",
    url="https://example.com/",
    method="GET",
    severity="Medium",
    confidence="Confirmed",
    evidence="Sample evidence",
    description="Sample description",
    impact="Sample impact",
    remediation="Sample remediation",
    parameter=None,
):
    return ScanFinding(
        type=type,
        category=category,
        url=url,
        method=method,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        description=description,
        impact=impact,
        remediation=remediation,
        parameter=parameter,
    )


def make_db_finding(
    type="Missing Security Header",
    category="Security Misconfiguration",
    url="https://example.com/",
    method="GET",
    severity=Severity.MEDIUM,
    confidence=Confidence.CONFIRMED,
    parameter=None,
    evidence="Sample evidence",
):
    return Finding(
        id=str(uuid.uuid4()),
        scan_id=str(uuid.uuid4()),
        type=type,
        category=category,
        url=url,
        method=method,
        parameter=parameter,
        severity=severity,
        confidence=confidence,
        status="open",
        evidence=evidence,
        timestamp=datetime.utcnow(),
        raw_instances=1,
    )


def test_extract_header_name():
    # From parameter
    assert extract_header_name("Content-Security-Policy", None) == "content-security-policy"
    assert extract_header_name("x-frame-options", None) == "x-frame-options"

    # From evidence string
    assert extract_header_name(None, "Response did not include a 'strict-transport-security' header.") == "strict-transport-security"
    assert extract_header_name(None, 'Response did not include a "permissions-policy" header.') == "permissions-policy"
    assert extract_header_name("", "Missing x-content-type-options header in response") == "x-content-type-options"


def test_security_header_severities():
    expected = {
        "content-security-policy": "Medium",
        "x-frame-options": "Medium",
        "strict-transport-security": "Low",
        "x-content-type-options": "Low",
        "referrer-policy": "Low",
        "permissions-policy": "Informational",
    }
    for header, sev in expected.items():
        assert SECURITY_HEADER_RULES[header]["severity"] == sev

        sf = make_scan_finding(
            type="Missing Security Header",
            category="Security Misconfiguration",
            url="https://example.com/",
            parameter=header,
            severity="Low",  # Intentionally pass wrong severity
            confidence="Confirmed",
        )
        adjusted = adjust_severity(sf)
        assert adjusted.severity == sev


def test_correlate_groups_same_header_across_urls():
    urls = [
        "https://example.com/",
        "https://example.com/login",
        "https://example.com/dashboard",
        "https://example.com/settings",
    ]
    raw_findings = []
    for u in urls:
        raw_findings.append(make_scan_finding(
            type="Missing Security Header",
            category="Security Misconfiguration",
            url=u,
            parameter="content-security-policy",
            severity="Medium",
            confidence="Confirmed",
            evidence="Response did not include a 'content-security-policy' header.",
        ))

    consolidated = correlate(raw_findings)
    assert len(consolidated) == 1
    f = consolidated[0]
    assert f.type == "Missing Security Header"
    assert f.parameter == "content-security-policy"
    assert f.severity == "Medium"
    assert getattr(f, "raw_instances", 1) == 4
    details = getattr(f, "evidence_details", {})
    assert len(details.get("affected_urls", [])) == 4
    assert len(details.get("occurrences", [])) == 4


def test_correlate_keeps_different_headers_separate():
    headers = [
        ("content-security-policy", "Medium"),
        ("x-frame-options", "Medium"),
        ("strict-transport-security", "Low"),
        ("x-content-type-options", "Low"),
        ("referrer-policy", "Low"),
        ("permissions-policy", "Informational"),
    ]
    raw_findings = []
    for h, sev in headers:
        for path in ["/", "/login", "/profile"]:
            raw_findings.append(make_scan_finding(
                type="Missing Security Header",
                category="Security Misconfiguration",
                url=f"https://example.com{path}",
                parameter=h,
                severity=sev,
                confidence="Confirmed",
                evidence=f"Response did not include a '{h}' header.",
            ))

    consolidated = correlate(raw_findings)
    assert len(consolidated) == 6
    params = {f.parameter for f in consolidated}
    assert params == {h for h, _ in headers}

    for f in consolidated:
        assert getattr(f, "raw_instances", 1) == 3
        details = getattr(f, "evidence_details", {})
        assert len(details.get("affected_urls", [])) == 3


def test_injection_findings_stay_scoped_to_parameter_and_endpoint():
    f1 = make_scan_finding(
        type="SQL Injection",
        category="Injection",
        url="https://example.com/search",
        parameter="q",
        method="GET",
        severity="Critical",
        confidence="Confirmed",
    )
    f2 = make_scan_finding(
        type="SQL Injection",
        category="Injection",
        url="https://example.com/search",
        parameter="category",
        method="GET",
        severity="Critical",
        confidence="Confirmed",
    )
    f3 = make_scan_finding(
        type="SQL Injection",
        category="Injection",
        url="https://example.com/login",
        parameter="username",
        method="POST",
        severity="Critical",
        confidence="Confirmed",
    )

    consolidated = correlate([f1, f2, f3])
    # Different parameters and endpoints must NOT be collapsed together
    assert len(consolidated) == 3


def test_group_scan_findings_historical_consolidation():
    # Simulate historical rows in DB where parameter was None and severities varied
    mock_db_findings = []
    urls = ["https://example.com/page1", "https://example.com/page2", "https://example.com/page3"]
    for u in urls:
        f = make_db_finding(
            type="Missing Security Header",
            category="Security Misconfiguration",
            url=u,
            method="GET",
            parameter=None,  # Historical record missing parameter
            severity=Severity.INFORMATIONAL,  # Historical inconsistent severity
            confidence=Confidence.CONFIRMED,
            evidence="Response did not include a 'content-security-policy' header.",
        )
        mock_db_findings.append(f)

    grouped = group_scan_findings(mock_db_findings)
    assert len(grouped) == 1
    res = grouped[0]
    assert res.parameter == "content-security-policy"
    assert res.severity == "Medium"  # Standardized canonical severity
    assert res.raw_instances == 3
    assert len(res.evidence_details["affected_urls"]) == 3
    assert res.evidence_details["total_affected_endpoints"] == 3


def test_fingerprint_generation_scoping():
    fp_csp_root = generate_finding_fingerprint(
        target_url="https://example.com",
        finding_type="Missing Security Header",
        url="https://example.com/",
        parameter="content-security-policy",
        method="GET",
        evidence="Response did not include a 'content-security-policy' header.",
    )
    fp_csp_login = generate_finding_fingerprint(
        target_url="https://example.com",
        finding_type="Missing Security Header",
        url="https://example.com/login",
        parameter="content-security-policy",
        method="GET",
        evidence="Response did not include a 'content-security-policy' header.",
    )
    fp_xfo_root = generate_finding_fingerprint(
        target_url="https://example.com",
        finding_type="Missing Security Header",
        url="https://example.com/",
        parameter="x-frame-options",
        method="GET",
        evidence="Response did not include a 'x-frame-options' header.",
    )

    # Same missing header across different URLs must share host-wide fingerprint
    assert fp_csp_root == fp_csp_login
    # Different missing headers must have distinct fingerprints
    assert fp_csp_root != fp_xfo_root
