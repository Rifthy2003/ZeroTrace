import pytest
from app.core.ssrf_protection import validate_target_url, validate_redirect_url, UnsafeTargetError
from app.core.logging_config import redact
from app.scanner.crawler import normalize_url
from app.scanner.models import DiscoveredEndpoint, ScanFinding
from app.scanner.scanners import security_headers, cookie_security, information_disclosure, csrf, xss
from app.scanner.severity import correlate, adjust_severity


def test_blocks_loopback():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://127.0.0.1:8000", allow_private=False, allow_local_dev=False)


def test_blocks_metadata():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://169.254.169.254/latest", allow_private=True)


def test_blocks_bad_scheme():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("file:///etc/passwd")


def test_allows_private_when_enabled():
    assert validate_target_url("http://127.0.0.1:9000", allow_private=True)


def test_local_dev_target_disabled_by_default():
    """Local development targets must be blocked by default with a clear error."""
    with pytest.raises(UnsafeTargetError) as exc_info:
        validate_target_url("http://localhost:49704/", allow_local_dev=False, allow_private=False)
    assert "local development target" in str(exc_info.value).lower()
    assert "disabled by default" in str(exc_info.value).lower()

    with pytest.raises(UnsafeTargetError) as exc_info2:
        validate_target_url("http://host.docker.internal:49704/", allow_local_dev=False, allow_private=False)
    assert "local development target" in str(exc_info2.value).lower()


def test_local_dev_target_allowed_when_enabled():
    """When allow_local_dev=True, host.docker.internal on any user-selected port is permitted, and localhost rewrites to host.docker.internal."""
    for port in (49704, 5173, 3000, 8000, 8080):
        # localhost:<port> rewrites to host.docker.internal:<port> for container reachability
        res_loc = validate_target_url(f"http://localhost:{port}/", allow_local_dev=True, allow_private=False)
        assert res_loc == f"http://host.docker.internal:{port}/"

        # 127.0.0.1:<port> rewrites to host.docker.internal:<port>
        res_ip = validate_target_url(f"http://127.0.0.1:{port}/app", allow_local_dev=True, allow_private=False)
        assert res_ip == f"http://host.docker.internal:{port}/app"

        # host.docker.internal:<port> directly is permitted
        res_host = validate_target_url(f"http://host.docker.internal:{port}/", allow_local_dev=True, allow_private=False)
        assert res_host == f"http://host.docker.internal:{port}/"


def test_local_dev_target_rejects_invalid_port():
    """Rejects out-of-range ports."""
    with pytest.raises(UnsafeTargetError) as exc_info:
        validate_target_url("http://host.docker.internal:70000/", allow_local_dev=True, allow_private=False)
    assert "invalid" in str(exc_info.value).lower()


def test_local_dev_target_blocks_other_private_and_metadata_targets():
    """Local dev mode does NOT open up arbitrary private networks or cloud metadata."""
    # Other private network targets must still be blocked
    with pytest.raises(UnsafeTargetError) as exc_priv:
        validate_target_url("http://10.0.0.1:49704/", allow_local_dev=True, allow_private=False)
    assert "private/internal address" in str(exc_priv.value).lower()

    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://192.168.1.1:49704/", allow_local_dev=True, allow_private=False)

    # Cloud metadata is strictly blocked
    with pytest.raises(UnsafeTargetError) as exc_meta:
        validate_target_url("http://169.254.169.254/latest", allow_local_dev=True, allow_private=False)
    assert "cloud metadata" in str(exc_meta.value).lower()


def test_validate_redirect_url_safe_and_unsafe():
    """Redirects are validated and unexpected address changes are rejected."""
    base_local = "http://host.docker.internal:49704/login"

    # Safe relative redirect
    assert validate_redirect_url(base_local, "/home", allow_local_dev=True) == "http://host.docker.internal:49704/home"

    # Safe same-origin absolute redirect
    assert validate_redirect_url(base_local, "http://host.docker.internal:49704/dashboard", allow_local_dev=True) == "http://host.docker.internal:49704/dashboard"

    # Unsafe: local dev target redirecting to cloud metadata
    with pytest.raises(UnsafeTargetError) as exc_meta:
        validate_redirect_url(base_local, "http://169.254.169.254/latest", allow_local_dev=True)
    assert "cloud metadata" in str(exc_meta.value).lower()

    # Unsafe: local dev target redirecting to a different port
    with pytest.raises(UnsafeTargetError) as exc_port:
        validate_redirect_url(base_local, "http://host.docker.internal:80/secret", allow_local_dev=True)
    assert "unexpected address or port change" in str(exc_port.value).lower()

    # Unsafe: local dev target redirecting to external or other private network
    with pytest.raises(UnsafeTargetError) as exc_ext:
        validate_redirect_url(base_local, "http://192.168.1.1/admin", allow_local_dev=True)
    assert "unexpected address" in str(exc_ext.value).lower() or "unexpected destination" in str(exc_ext.value).lower()

    # Unsafe: external target redirecting to internal/local dev target
    with pytest.raises(UnsafeTargetError) as exc_internal:
        validate_redirect_url("https://example.com/login", "http://host.docker.internal:49704/", allow_local_dev=True)
    assert "local development host is blocked" in str(exc_internal.value).lower()



def test_normalize_url():
    assert normalize_url("http://a.com/x/#frag") == "http://a.com/x"
    assert normalize_url("http://a.com") == "http://a.com/"
    # Preserves SPA hash routes like /#/welcome, /#/login, /#!/dashboard
    assert normalize_url("http://localhost:50091/#/welcome") == "http://host.docker.internal:50091/#/welcome" or normalize_url("http://a.com/#/welcome") == "http://a.com/#/welcome"
    assert normalize_url("http://a.com/#/login/") == "http://a.com/#/login"


@pytest.mark.asyncio
async def test_sensitive_files_rejects_spa_fallback_false_positives():
    """Generic HTTP 200 SPA fallback HTML must not be reported as sensitive file exposure."""
    from app.scanner.scanners import sensitive_files
    import httpx

    # Simulate an SPA server returning HTTP 200 with index.html for all paths
    spa_html = "<!DOCTYPE html><html><head><title>Hela Govi</title><script src='flutter_bootstrap.js'></script></head><body></body></html>"

    def handler(request: httpx.Request):
        return httpx.Response(200, text=spa_html, headers={"Content-Type": "text/html; charset=utf-8"})

    transport = httpx.MockTransport(handler)
    client = sensitive_files.SafeHTTPClient()
    client._client = httpx.AsyncClient(transport=transport)

    findings = await sensitive_files.scan("http://target.local/", client)
    await client.close()
    assert len(findings) == 0, "Generic SPA fallback pages should not produce any findings"


@pytest.mark.asyncio
async def test_sensitive_files_accepts_genuine_env_and_git_config():
    """Real .env and .git/config with authentic structure must be reported."""
    from app.scanner.scanners import sensitive_files
    import httpx

    real_env = "DATABASE_URL=postgresql://user:pass@db/prod\nSECRET_KEY=abcdef123456\nPORT=8000"
    real_git = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n[remote \"origin\"]\n\turl = git@github.com:org/repo.git"

    def handler(request: httpx.Request):
        path = request.url.path
        if path == "/__zerotrace_fallback_canary_404__":
            return httpx.Response(404, text="Not Found")
        if path == "/.env":
            return httpx.Response(200, text=real_env, headers={"Content-Type": "text/plain"})
        if path == "/.git/config":
            return httpx.Response(200, text=real_git, headers={"Content-Type": "text/plain"})
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    client = sensitive_files.SafeHTTPClient()
    client._client = httpx.AsyncClient(transport=transport)

    findings = await sensitive_files.scan("http://target.local/", client)
    await client.close()
    types = [f.url for f in findings]
    assert any("/.env" in u for u in types)
    assert any("/.git/config" in u for u in types)


@pytest.mark.asyncio
async def test_browser_crawler_route_discovery_and_auth_tracking():
    """BrowserCrawler extracts SPA routes and tracks auth requirements."""
    from app.scanner.browser_crawler import BrowserCrawler

    crawler = BrowserCrawler("http://example.local/", max_urls=10)
    # Test route extraction from JS
    js_sample = '''routes: new IdentityMap.from(T, ["/", () => Splash(), "/welcome", () => Welcome(), "/login", () => Login()]);
    settings.name === "/home";
    path: "/dashboard";'''
    extracted = crawler._extract_routes_from_text(js_sample)
    assert "/#/welcome" in extracted
    assert "/#/login" in extracted
    assert "/#/home" in extracted
    assert "/#/dashboard" in extracted

    # Test auth classification
    assert crawler._check_auth_required("/#/home", "http://example.local/#/home", "") is True
    assert crawler._check_auth_required("/#/dashboard", "http://example.local/#/dashboard", "") is True
    assert crawler._check_auth_required("/#/welcome", "http://example.local/#/welcome", "") is False
    assert crawler._check_auth_required("/#/login", "http://example.local/#/login", "") is False


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
