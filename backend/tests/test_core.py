import pytest
from app.core.ssrf_protection import validate_target_url, UnsafeTargetError
from app.core.logging_config import redact
from app.scanner.crawler import normalize_url
from app.scanner.models import DiscoveredEndpoint, ScanFinding
from app.scanner.scanners import security_headers, cookie_security, information_disclosure, csrf, xss
from app.scanner.severity import correlate, adjust_severity


def test_blocks_loopback():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://127.0.0.1:8000", allow_private=False)


def test_blocks_metadata():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://169.254.169.254/latest", allow_private=True)


def test_blocks_bad_scheme():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("file:///etc/passwd")


def test_allows_private_when_enabled():
    assert validate_target_url("http://127.0.0.1:9000", allow_private=True)


def test_normalize_url():
    assert normalize_url("http://a.com/x/#frag") == "http://a.com/x"
    assert normalize_url("http://a.com") == "http://a.com/"


def test_redaction():
    assert "hunter2" not in redact("password=hunter2")


def test_security_headers_missing():
    ep = DiscoveredEndpoint(url="http://t/", response_headers={})
    types = [f.type for f in security_headers.scan(ep)]
    assert types.count("Missing Security Header") == 6


def test_security_headers_present():
    h = {"Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "x", "X-Content-Type-Options": "nosniff",
         "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}
    assert security_headers.scan(DiscoveredEndpoint(url="http://t/", response_headers=h)) == []


def test_cookie_flags():
    ep = DiscoveredEndpoint(url="http://t/", response_headers={"set-cookie": "sid=abc"})
    f = cookie_security.scan(ep)
    assert f and "sid" in f[0].evidence and "abc" not in f[0].evidence


def test_secure_cookie_ok():
    ep = DiscoveredEndpoint(url="http://t/", response_headers={"set-cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"})
    assert cookie_security.scan(ep) == []


def test_info_disclosure_split():
    ep = DiscoveredEndpoint(url="http://t/", response_headers={"Server": "nginx/1.2"},
                            body_snippet="Traceback (most recent call last)")
    types = {f.type for f in information_disclosure.scan(ep)}
    assert types == {"Technology Detection", "Potential Information Disclosure"}


def test_csrf_missing_token():
    html = "<form method='post'><input name='x'></form>"
    f = csrf.scan(DiscoveredEndpoint(url="http://t/"), html)
    assert f and f[0].type == "Potential CSRF"


def test_csrf_with_token():
    html = "<form method='post'><input name='csrf_token' value='" + "a" * 40 + "'><input name='x'></form>"
    assert csrf.scan(DiscoveredEndpoint(url="http://t/"), html) == []


def test_xss_context():
    assert xss.classify_context("<p>MARK</p>", "MARK") == "html_body"
    assert xss.classify_context("<script>var a='MARK'", "MARK") == "javascript"
    assert xss.classify_context("<a href=\"MARK", "MARK") == "html_attribute"
    assert xss.classify_context("nothing", "MARK") is None


def test_severity_lowered_for_low_confidence():
    f = ScanFinding("CSRF", "Broken Access Control", "u", "POST", "Medium", "Low confidence", "e", "d", "i", "r")
    assert adjust_severity(f).severity == "Low"


def test_correlation_dedup():
    a = ScanFinding("T", "C", "u", "GET", "High", "Confirmed", "e", "d", "i", "r")
    b = ScanFinding("T", "C", "u", "GET", "High", "Confirmed", "e", "d", "i", "r")
    assert len(correlate([a, b])) == 1
