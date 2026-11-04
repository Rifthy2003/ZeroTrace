import pytest
from unittest.mock import AsyncMock, MagicMock
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter, ScanFinding
from app.scanner.scanners.xss import scan as xss_scan
from app.scanner.severity import correlate, classify_finding_group
from app.services.security_posture import calculate_security_posture, _matches_module_finding
from app.models.finding import Severity, Confidence


@pytest.mark.asyncio
async def test_xss_scanner_confirmed_executable_reflection():
    """Requirement 1, 8, 9: Actual executable XSS reflection produces confirmed High severity finding."""
    endpoint = DiscoveredEndpoint(
        url="http://example.com/search",
        method="GET",
        parameters=[DiscoveredParameter(name="q", location="query", sample_value="test")],
    )

    client = AsyncMock()

    # When scanner probes with marker + probe, response reflects unencoded HTML metacharacters (<, >, ", ')
    def mock_get(url):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(url).query)
        val = qs.get("q", [""])[0]
        resp = MagicMock()
        resp.text = f"<html><body>Search results for: {val}</body></html>"
        resp.headers = {"content-type": "text/html; charset=utf-8"}
        return resp

    client.get.side_effect = mock_get

    findings = await xss_scan(endpoint, client)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "Reflected XSS"
    assert f.severity == "High"
    assert f.confidence == "High confidence"
    assert f.detection_status == "Confirmed"
    assert f.cwe_id == "CWE-79"
    assert f.module == "xss"
    assert "Unsanitized marker reflected" in f.evidence
    assert _matches_module_finding(f, "xss") is True


@pytest.mark.asyncio
async def test_xss_scanner_safe_input_reflection_informational():
    """Requirement 1, 8: Safe reflection with proper HTML encoding produces Input Reflection Informational."""
    endpoint = DiscoveredEndpoint(
        url="http://example.com/catalog",
        method="GET",
        parameters=[DiscoveredParameter(name="courseId", location="query", sample_value="173")],
    )

    client = AsyncMock()

    # When scanner probes, response safely HTML-encodes metacharacters or reflects safely
    def mock_get(url):
        from urllib.parse import urlparse, parse_qs
        import html
        qs = parse_qs(urlparse(url).query)
        val = qs.get("q", qs.get("courseId", [""]))[0]
        encoded = html.escape(val, quote=True)
        resp = MagicMock()
        resp.text = f"<html><body>Course: {encoded}</body></html>"
        resp.headers = {"content-type": "text/html; charset=utf-8"}
        return resp

    client.get.side_effect = mock_get

    findings = await xss_scan(endpoint, client)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "Input Reflection"
    assert f.severity == "Informational"
    assert f.confidence == "Low confidence"
    assert f.detection_status == "Potential"
    assert f.cwe_id == "CWE-79"
    assert f.module == "xss"
    assert "properly encoded or filtered" in f.evidence
    # Safe input reflection must NOT match confirmed XSS vulnerability module count
    assert _matches_module_finding(f, "xss") is False


def test_deduplication_and_correlation_preserves_module_and_counts():
    """Requirement 2, 3, 7: Normalization, deduplication and fingerprinting preserves module tag and raw instances."""
    findings = [
        ScanFinding(
            type="Input Reflection",
            category="Information Disclosure",
            owasp_category="A05:2021 - Security Misconfiguration",
            url="http://example.com/catalog?courseId=173",
            method="GET",
            parameter="courseId",
            severity="Informational",
            confidence="Low confidence",
            cwe_id="CWE-79",
            mitre_attack="T1059.007",
            detection_status="Potential",
            evidence="Encoded reflection",
            description="Input reflected safely",
            impact="None",
            remediation="Maintain encoding",
            module="xss",
        ),
        ScanFinding(
            type="Input Reflection",
            category="Information Disclosure",
            owasp_category="A05:2021 - Security Misconfiguration",
            url="http://example.com/catalog?courseId=174",
            method="GET",
            parameter="courseId",
            severity="Informational",
            confidence="Low confidence",
            cwe_id="CWE-79",
            mitre_attack="T1059.007",
            detection_status="Potential",
            evidence="Encoded reflection",
            description="Input reflected safely",
            impact="None",
            remediation="Maintain encoding",
            module="xss",
        ),
    ]

    correlated = correlate(findings)
    assert len(correlated) == 1
    unique_f = correlated[0]
    assert unique_f.type == "Input Reflection"
    assert unique_f.raw_instances == 2
    assert unique_f.module == "xss"
    assert unique_f.finding_group == "other_vulnerabilities"


def test_security_posture_module_matrix_safe_reflection_not_counted_as_xss():
    """Requirement 7, 8, 10: Module coverage table does not count Input Reflection as confirmed XSS."""
    class FakeScan:
        id = "scan-xss-test-1"
        target_id = "target-1"
        status = "completed"
        created_at = None
        started_at = None
        completed_at = None
        target = MagicMock(base_url="https://training.wso2.com/plus/catalog?courseId=173", hostname="training.wso2.com")
        coverage_summary = {
            "modules_total": 4,
            "modules_tested": 4,
            "endpoints_tested": 18,
            "parameters_tested": 59,
            "module_matrix": [
                {
                    "module": "xss",
                    "name": "Cross-Site Scripting (XSS)",
                    "status": "Tested",
                    "findings_count": 1,  # Legacy or raw count before fix
                    "endpoints_tested": 18,
                    "parameters_tested": 59,
                    "reason": "Tested parameters across 18 endpoint(s)",
                },
                {
                    "module": "sql_injection",
                    "name": "SQL Injection",
                    "status": "Tested",
                    "findings_count": 0,
                    "endpoints_tested": 18,
                    "parameters_tested": 59,
                    "reason": "Tested parameters across 18 endpoint(s)",
                },
            ],
        }
        route_summary = {
            "routes_discovered": ["https://training.wso2.com/plus/catalog?courseId=173"],
            "routes_tested": ["https://training.wso2.com/plus/catalog?courseId=173"],
        }
        config = MagicMock(max_depth=3, max_urls=50, modules=["xss", "sql_injection"])

    class FakeFinding:
        def __init__(self, f_id, f_type, sev, conf, det_status, url, param, cat="Information Disclosure"):
            self.id = f_id
            self.type = f_type
            self.finding_type = f_type
            self.severity = sev
            self.confidence = conf
            self.detection_status = det_status
            self.url = url
            self.parameter = param
            self.category = cat
            self.evidence = "Properly encoded marker"
            self.remediation = "Maintain encoding"
            self.method = "GET"
            self.cwe_id = "CWE-79"

    findings = [
        FakeFinding(
            "f1", "Input Reflection", Severity.INFORMATIONAL, Confidence.LOW, "Potential",
            "https://training.wso2.com/plus/catalog?courseId=173", "courseId"
        )
    ]

    posture = calculate_security_posture(FakeScan(), findings)

    # In posture coverage_summary module_matrix:
    xss_row = next(r for r in posture["coverage"]["coverage_summary"]["module_matrix"] if r["module"] == "xss")
    assert xss_row["findings_count"] == 0, "Input reflection must NOT count as confirmed XSS vulnerability in module matrix"
    assert "safe input reflection(s) observed with proper encoding; no confirmed XSS" in xss_row["reason"]

    # Unique issues count remains 1 (Input Reflection Informational)
    assert posture["unique_counts"]["informational"] == 1
    assert posture["unique_counts"]["high"] == 0
    assert posture["unique_confirmed_count"] == 0
    assert posture["unique_manual_verification_count"] == 1


def test_security_posture_module_matrix_with_confirmed_xss():
    """Requirement 9: With confirmed XSS, module findings count shows 1 and score reflects penalty."""
    class FakeScan:
        id = "scan-xss-test-2"
        target_id = "target-1"
        status = "completed"
        created_at = None
        started_at = None
        completed_at = None
        target = MagicMock(base_url="https://vulnerable.local/search", hostname="vulnerable.local")
        coverage_summary = {
            "modules_total": 4,
            "modules_tested": 4,
            "endpoints_tested": 5,
            "parameters_tested": 10,
            "module_matrix": [
                {
                    "module": "xss",
                    "name": "Cross-Site Scripting (XSS)",
                    "status": "Tested",
                    "findings_count": 0,
                    "endpoints_tested": 5,
                    "parameters_tested": 10,
                }
            ],
        }
        route_summary = {"routes_discovered": ["https://vulnerable.local/search"], "routes_tested": ["https://vulnerable.local/search"]}
        config = MagicMock(max_depth=3, max_urls=50, modules=["xss"])

    class FakeFinding:
        def __init__(self, f_id, f_type, sev, conf, det_status, url, param, cat="Injection"):
            self.id = f_id
            self.type = f_type
            self.finding_type = f_type
            self.severity = sev
            self.confidence = conf
            self.detection_status = det_status
            self.url = url
            self.parameter = param
            self.category = cat
            self.evidence = "Unencoded script tags executed"
            self.remediation = "Use context-aware encoding"
            self.method = "GET"
            self.cwe_id = "CWE-79"

    findings = [
        FakeFinding(
            "f2", "Reflected XSS", Severity.HIGH, Confidence.CONFIRMED, "Confirmed",
            "https://vulnerable.local/search", "q"
        )
    ]

    posture = calculate_security_posture(FakeScan(), findings)

    xss_row = next(r for r in posture["coverage"]["coverage_summary"]["module_matrix"] if r["module"] == "xss")
    assert xss_row["findings_count"] == 1
    assert posture["unique_counts"]["high"] == 1
    assert posture["unique_confirmed_count"] == 1
    assert posture["score"] < 100.0  # High confirmed XSS applies penalty
