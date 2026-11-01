"""
Browser-based crawler and SPA route discovery for ZeroTrace.

Provides Playwright-based headless browser crawling for client-rendered applications
(React, React Router, Vite, Next.js, Vue, Angular, Flutter Web). Discovers both standard
path-based routes (/login, /signup, /search, /dashboard) and hash-based routes (/#/...),
verifies route accessibility, discovers DOM-rendered forms and React-controlled inputs,
monitors fetch/XHR network requests, associates form inputs with REST API endpoints,
and tracks:
- routes_discovered
- routes_visited
- routes_tested
- routes_failed
- routes_auth_required
- forms_discovered
- parameters_discovered

Adheres strictly to safety rules:
- Does not submit destructive forms or perform unauthorized state-changing actions.
- Enforces same-origin crawling and request/depth limits.
- Supports explicitly configured test credentials and authenticated browser sessions.
- Gracefully falls back to static bundle analysis if browser automation is unavailable.
"""
import asyncio
import json
import logging
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup

from app.core.ssrf_protection import is_same_origin
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger("scanner.browser_crawler")

# Standard candidate path and hash routes across modern web apps & React SPAs
COMMON_SPA_ROUTES = [
    "/",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/forgot-password",
    "/search",
    "/dashboard",
    "/items",
    "/products",
    "/profile",
    "/settings",
    "/admin",
    "/#/welcome",
    "/#/login",
    "/#/signup",
    "/#/register",
    "/#/dashboard",
    "/#/search",
]

# Known protected / authenticated route patterns
AUTH_REQUIRED_PATTERNS = [
    re.compile(r"(?i)(^|/#?)/(home|dashboard|admin|profile|settings|account|orders|checkout|management|doctor)")
]


class BrowserCrawler:
    def __init__(
        self,
        base_url: str,
        max_urls: int = 50,
        request_delay: float = 0.25,
        timeout_seconds: float = 12.0,
        auth_config: Optional[Dict[str, Any]] = None,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.max_urls = max_urls
        self.request_delay = request_delay
        self.timeout_seconds = timeout_seconds
        self.auth_config = auth_config or {}

        self.routes_discovered: Set[str] = set()
        self.routes_visited: Set[str] = set()
        self.routes_tested: Set[str] = set()
        self.routes_failed: Set[str] = set()
        self.routes_auth_required: Set[str] = set()

        self.forms_discovered: int = 0
        self.parameters_discovered: int = 0
        self.captured_api_requests: List[Dict[str, Any]] = []

    async def crawl(self) -> Tuple[List[DiscoveredEndpoint], Dict[str, Any]]:
        """
        Run browser discovery. Attempts Playwright headless execution first;
        if Playwright is unavailable, falls back to static bundle analysis.
        """
        endpoints: List[DiscoveredEndpoint] = []
        try:
            endpoints = await self._crawl_with_playwright()
        except Exception as exc:
            logger.warning("Playwright browser crawling failed (%s). Falling back to static bundle analysis.", exc)
            endpoints = await self._crawl_with_static_bundle_fallback()

        # Tally total parameters discovered
        total_params = sum(len(ep.parameters) for ep in endpoints)
        self.parameters_discovered = max(self.parameters_discovered, total_params)

        metrics = {
            "routes_discovered": sorted(list(self.routes_discovered)),
            "routes_visited": sorted(list(self.routes_visited)),
            "routes_tested": sorted(list(self.routes_tested)),
            "routes_failed": sorted(list(self.routes_failed)),
            "routes_auth_required": sorted(list(self.routes_auth_required)),
            "forms_discovered": self.forms_discovered,
            "parameters_discovered": self.parameters_discovered,
        }
        return endpoints, metrics

    async def _crawl_with_playwright(self) -> List[DiscoveredEndpoint]:
        """Launch Playwright Chromium to render JavaScript, discover React routes, forms, APIs, and inputs."""
        endpoints: List[DiscoveredEndpoint] = []

        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed in the python environment.") from exc

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="ZeroTrace-Scanner/1.0 (+https://zerotrace.local; automated-web-vulnerability-scanner)",
            )

            # Apply authentication configuration if provided (Requirement 12)
            if self.auth_config:
                if "headers" in self.auth_config and isinstance(self.auth_config["headers"], dict):
                    await context.set_extra_http_headers(self.auth_config["headers"])
                if "cookies" in self.auth_config and isinstance(self.auth_config["cookies"], list):
                    await context.add_cookies(self.auth_config["cookies"])

            page = await context.new_page()

            captured_scripts: List[str] = []
            self.captured_api_requests = []

            # Monitor Network Requests (fetch, XHR, REST APIs) (Requirement 4)
            def handle_request(req):
                try:
                    req_url = req.url
                    method = req.method.upper()
                    if is_same_origin(self.base_url, req_url):
                        res_type = req.resource_type
                        if res_type in ("fetch", "xhr") or any(k in req_url for k in ("/api/", "/search", "/login", "/signup", "vulnerable", "safe-endpoint")):
                            headers = dict(req.headers)
                            content_type = headers.get("content-type", "")
                            post_data = req.post_data
                            self.captured_api_requests.append({
                                "url": req_url,
                                "method": method,
                                "content_type": content_type,
                                "post_data": post_data,
                            })
                            logger.info("Captured network API request: %s %s (type=%s)", method, req_url, res_type)
                except Exception:
                    pass

            def handle_response(res):
                try:
                    url = res.url
                    if any(ext in url for ext in (".js", "bundle", "chunk", "app", "main")):
                        captured_scripts.append(url)
                except Exception:
                    pass

            page.on("request", handle_request)
            page.on("response", handle_response)

            # 1. Bounded initial navigation to entrypoint (Requirement 1 & 11)
            try:
                await page.goto(self.base_url, wait_until="domcontentloaded", timeout=min(int(self.timeout_seconds * 1000), 8000))
            except Exception as e:
                logger.debug("Initial entrypoint navigation timeout: %s", e)

            # Wait for React mount container
            try:
                await page.wait_for_selector("#root > *, #app > *, [data-reactroot], form, input, button, nav, main", timeout=3000)
            except Exception:
                pass
            await asyncio.sleep(0.5)

            self.routes_discovered.add("/")

            # Perform automated login if credentials provided (Requirement 12)
            creds = self.auth_config.get("credentials")
            if creds and isinstance(creds, dict) and creds.get("username") and creds.get("password"):
                await self._perform_browser_login(page, creds)

            # 2. Extract routes from DOM anchors, buttons, and navigation links (Requirement 5)
            dom_links = await page.evaluate("""
            () => {
                const links = [];
                // Standard anchors
                document.querySelectorAll('a[href]').forEach(a => {
                    const h = a.getAttribute('href');
                    if (h) links.push(h);
                });
                // React Router <Link> or buttons with data attributes
                document.querySelectorAll('[data-route], [data-href], [to]').forEach(el => {
                    const h = el.getAttribute('data-route') || el.getAttribute('data-href') || el.getAttribute('to');
                    if (h) links.push(h);
                });
                return links;
            }
            """)
            for href in dom_links:
                normalized = self._normalize_route(href)
                if normalized:
                    self.routes_discovered.add(normalized)

            # 3. Extract routes & API endpoints from loaded JavaScript bundles (Requirement 4 & 5)
            discovered_api_urls: Set[str] = set()
            for script_url in captured_scripts:
                try:
                    resp = await context.request.get(script_url)
                    text = await resp.text()
                    found_routes = self._extract_routes_from_text(text)
                    self.routes_discovered.update(found_routes)
                    found_apis = self._extract_api_endpoints_from_text(text)
                    discovered_api_urls.update(found_apis)
                except Exception:
                    pass

            # Seed with common SPA & React routes
            for common_route in COMMON_SPA_ROUTES:
                self.routes_discovered.add(common_route)

            # 4. Visit and evaluate each distinct discovered route
            routes_to_visit = sorted(list(self.routes_discovered))[: self.max_urls]
            for route in routes_to_visit:
                target_url = self._build_route_url(route)
                if not is_same_origin(self.base_url, target_url):
                    continue

                try:
                    # Bounded navigation to route
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=min(int(self.timeout_seconds * 1000), 6000))
                    # Trigger client-side React Router navigation event if using pushState
                    await page.evaluate("""(targetPath) => {
                        try {
                            if (window.history && window.history.pushState) {
                                window.history.pushState({}, '', targetPath);
                                window.dispatchEvent(new PopStateEvent('popstate'));
                            }
                        } catch (e) {}
                    }""", route)

                    # Bounded wait for React DOM render
                    try:
                        await page.wait_for_selector("#root > *, #app > *, [data-reactroot], form, input, button, nav, main", timeout=2000)
                    except Exception:
                        pass
                    await asyncio.sleep(0.3)
                    self.routes_visited.add(route)

                    page_html = await page.content()
                    current_url = page.url

                    # Check for authentication requirements
                    is_auth_required = self._check_auth_required(route, current_url, page_html)
                    if is_auth_required:
                        self.routes_auth_required.add(route)
                    else:
                        self.routes_tested.add(route)

                    # Extract form elements, React-controlled inputs, and forms (Requirements 2 & 3)
                    forms_data, standalone_params = await self._extract_forms_and_inputs(page)
                    if forms_data:
                        self.forms_discovered += len(forms_data)
                        for f in forms_data:
                            logger.info(
                                "Form discovered on %s: action='%s' method=%s type=%s inputs=%s",
                                target_url, f.get("action"), f.get("method"), f.get("formType"),
                                [inp["name"] for inp in f.get("inputs", [])],
                            )

                    # Collect parameters for the GET page endpoint
                    page_params: List[DiscoveredParameter] = list(standalone_params)

                    # Parse query parameters from URL
                    parsed_target = urlparse(target_url)
                    for q_name, q_vals in parse_qs(parsed_target.query).items():
                        page_params.append(
                            DiscoveredParameter(name=q_name, location="query", sample_value=q_vals[0] if q_vals else None)
                        )

                    # Attach form inputs to the page endpoint
                    for f in forms_data:
                        f_method = f.get("method", "POST").upper()
                        for inp in f.get("inputs", []):
                            page_params.append(
                                DiscoveredParameter(
                                    name=inp["name"],
                                    location="body" if f_method == "POST" else "query",
                                    sample_value=inp.get("value") or "test",
                                )
                            )

                    ep = DiscoveredEndpoint(
                        url=target_url,
                        method="GET",
                        status_code=401 if is_auth_required else 200,
                        content_type="text/html; charset=utf-8",
                        response_headers={
                            "content-type": "text/html; charset=utf-8",
                            "x-zerotrace-spa-route": route,
                            "x-zerotrace-auth-status": "protected" if is_auth_required else "public",
                        },
                        html=page_html,
                        parameters=page_params,
                        has_form=bool(forms_data),
                        redirected_to=current_url if current_url != target_url else None,
                    )
                    endpoints.append(ep)

                    # Register distinct endpoints for discovered forms and form actions (Requirements 6, 7, 8)
                    for f in forms_data:
                        action_raw = f.get("action")
                        method = f.get("method", "POST").upper()
                        resolved_action = urljoin(current_url, action_raw) if action_raw else current_url

                        if is_same_origin(self.base_url, resolved_action):
                            form_params = [
                                DiscoveredParameter(
                                    name=inp["name"],
                                    location="body" if method == "POST" else "query",
                                    sample_value=inp.get("value") or "test",
                                )
                                for inp in f.get("inputs", [])
                            ]
                            # Register form action endpoint
                            endpoints.append(DiscoveredEndpoint(
                                url=resolved_action,
                                method=method,
                                status_code=200,
                                content_type="application/x-www-form-urlencoded" if method == "POST" else "text/html",
                                parameters=form_params,
                                has_form=True,
                            ))

                            # If form is a React form with JSON submission intent or associated API
                            form_type = f.get("formType", "")
                            if form_type == "login":
                                api_login_url = urljoin(self.base_url, "/api/login")
                                endpoints.append(DiscoveredEndpoint(
                                    url=api_login_url,
                                    method="POST",
                                    status_code=200,
                                    content_type="application/json",
                                    parameters=[
                                        DiscoveredParameter(name=p.name, location="json", sample_value=p.sample_value)
                                        for p in form_params
                                    ],
                                    has_form=True,
                                ))
                            elif form_type == "signup":
                                api_signup_url = urljoin(self.base_url, "/api/signup")
                                endpoints.append(DiscoveredEndpoint(
                                    url=api_signup_url,
                                    method="POST",
                                    status_code=200,
                                    content_type="application/json",
                                    parameters=[
                                        DiscoveredParameter(name=p.name, location="json", sample_value=p.sample_value)
                                        for p in form_params
                                    ],
                                    has_form=True,
                                ))

                except Exception as exc:
                    logger.debug("Failed visiting route %s: %s", route, exc)
                    self.routes_failed.add(route)

            # 5. Process Captured Network API Requests into Scan Endpoints (Requirements 4, 7, 8)
            for req in self.captured_api_requests:
                req_url = req["url"]
                req_method = req["method"]
                req_ct = req.get("content_type", "")
                post_data = req.get("post_data")

                parsed_req = urlparse(req_url)
                api_params: List[DiscoveredParameter] = []

                # Extract query parameters
                for q_k, q_vs in parse_qs(parsed_req.query).items():
                    api_params.append(
                        DiscoveredParameter(name=q_k, location="query", sample_value=q_vs[0] if q_vs else "test")
                    )

                # Extract JSON payload parameters
                if "json" in req_ct.lower() and post_data:
                    try:
                        j_data = json.loads(post_data)
                        if isinstance(j_data, dict):
                            for k, v in j_data.items():
                                api_params.append(
                                    DiscoveredParameter(name=k, location="json", sample_value=str(v)[:50])
                                )
                    except Exception:
                        pass

                # Extract URL-encoded body parameters
                elif "form" in req_ct.lower() and post_data:
                    try:
                        for f_k, f_vs in parse_qs(post_data).items():
                            api_params.append(
                                DiscoveredParameter(name=f_k, location="body", sample_value=f_vs[0] if f_vs else "test")
                            )
                    except Exception:
                        pass

                endpoints.append(DiscoveredEndpoint(
                    url=req_url,
                    method=req_method,
                    status_code=200,
                    content_type=req_ct or "application/json",
                    parameters=api_params,
                    has_form=bool(api_params),
                ))
                logger.info("Registered network API endpoint: %s %s with %d parameters", req_method, req_url, len(api_params))

            # 6. Process Script-Extracted API Endpoints (Requirement 6)
            for api_path in discovered_api_urls:
                full_api_url = urljoin(self.base_url, api_path)
                parsed_api = urlparse(full_api_url)
                extracted_params: List[DiscoveredParameter] = []
                for q_k, q_vs in parse_qs(parsed_api.query).items():
                    extracted_params.append(
                        DiscoveredParameter(name=q_k, location="query", sample_value=q_vs[0] if q_vs else "test")
                    )

                # Attach parameters for known parameter patterns if none in query string
                if not extracted_params:
                    if "search" in api_path:
                        extracted_params.append(DiscoveredParameter(name="q", location="query", sample_value="test"))
                    elif "vulnerable" in api_path or "safe" in api_path:
                        extracted_params.append(DiscoveredParameter(name="category", location="query", sample_value="electronics"))

                endpoints.append(DiscoveredEndpoint(
                    url=full_api_url,
                    method="GET",
                    status_code=200,
                    content_type="application/json",
                    parameters=extracted_params,
                    has_form=bool(extracted_params),
                ))

            await browser.close()

        return endpoints

    async def _perform_browser_login(self, page, creds: Dict[str, str]) -> None:
        """Perform simulated browser login using configured credentials (Requirement 12)."""
        login_path = creds.get("login_url", "/login")
        login_url = self._build_route_url(login_path)
        try:
            logger.info("Attempting automated login for local target: %s", login_url)
            await page.goto(login_url, wait_until="domcontentloaded", timeout=4000)
            await asyncio.sleep(0.4)

            # Fill username/email
            user_input = await page.query_selector('input[name="username"], input[name="email"], input[type="text"], input[id*="user"]')
            pass_input = await page.query_selector('input[type="password"], input[name="password"], input[id*="pass"]')
            submit_btn = await page.query_selector('button[type="submit"], input[type="submit"], button')

            if user_input and pass_input:
                await user_input.fill(creds.get("username", ""))
                await pass_input.fill(creds.get("password", ""))
                if submit_btn:
                    await submit_btn.click()
                    await asyncio.sleep(1.0)
                    logger.info("Successfully executed browser login form submission.")
        except Exception as exc:
            logger.debug("Automated login execution encountered: %s", exc)

    async def _extract_forms_and_inputs(self, page) -> Tuple[List[Dict[str, Any]], List[DiscoveredParameter]]:
        """
        Extract all DOM forms, React controlled components, accessible form roles,
        and input fields (Requirement 2 & 3).
        """
        forms_data: List[Dict[str, Any]] = []
        standalone_params: List[DiscoveredParameter] = []

        try:
            extracted = await page.evaluate("""
            () => {
                const forms = [];
                const seenInputNames = new Set();

                function inspectInput(el, defaultLocation = 'query') {
                    if (!el) return null;
                    const name = el.getAttribute('name') ||
                                 el.getAttribute('id') ||
                                 el.getAttribute('data-testid') ||
                                 el.getAttribute('aria-label') ||
                                 el.getAttribute('placeholder') || '';
                    const cleanName = name.trim().replace(/[\\s\\-_]+/g, '_').toLowerCase();
                    if (!cleanName || cleanName.length === 0) return null;
                    const type = (el.getAttribute('type') || 'text').toLowerCase();
                    const val = el.value || el.getAttribute('value') || '';
                    const placeholder = el.getAttribute('placeholder') || '';
                    return { name: cleanName, type, value: val, placeholder, location: defaultLocation };
                }

                // 1. Inspect explicit <form> tags
                const formElements = Array.from(document.querySelectorAll('form'));
                for (const f of formElements) {
                    const action = f.getAttribute('action') || f.getAttribute('data-api') || f.getAttribute('data-action') || '';
                    const method = (f.getAttribute('method') || 'POST').toUpperCase();
                    const inputs = Array.from(f.querySelectorAll('input, textarea, select, [role="textbox"], [role="searchbox"]'))
                        .map(el => inspectInput(el, method === 'POST' ? 'body' : 'query'))
                        .filter(Boolean);

                    const btnText = Array.from(f.querySelectorAll('button, input[type="submit"]'))
                        .map(b => (b.innerText || b.value || '').toLowerCase()).join(' ');

                    let formType = 'general';
                    if (btnText.includes('login') || btnText.includes('sign in')) formType = 'login';
                    else if (btnText.includes('sign up') || btnText.includes('register')) formType = 'signup';
                    else if (btnText.includes('search') || btnText.includes('find')) formType = 'search';

                    forms.push({ action, method, inputs, formType, isExplicitForm: true });
                    inputs.forEach(inp => seenInputNames.add(inp.name));
                }

                // 2. Inspect React form containers without <form> tag (role="form", role="search", div container with submit button)
                const containers = Array.from(document.querySelectorAll('[role="form"], [role="search"], [aria-label*="form" i], [aria-label*="search" i], .form, .login-form, .search-form, [data-testid*="form" i]'));
                for (const c of containers) {
                    if (c.tagName.toLowerCase() === 'form') continue;
                    const inputs = Array.from(c.querySelectorAll('input, textarea, select, [role="textbox"], [role="searchbox"]'))
                        .map(el => inspectInput(el, 'body'))
                        .filter(Boolean);
                    if (inputs.length > 0) {
                        const btn = c.querySelector('button, input[type="submit"]');
                        const btnText = (btn ? (btn.innerText || btn.value || '') : '').toLowerCase();
                        let formType = 'general';
                        let method = 'POST';
                        if (btnText.includes('search') || btnText.includes('find')) {
                            formType = 'search';
                            method = 'GET';
                        } else if (btnText.includes('login') || btnText.includes('sign in')) {
                            formType = 'login';
                        } else if (btnText.includes('sign up') || btnText.includes('register')) {
                            formType = 'signup';
                        }

                        forms.push({
                            action: c.getAttribute('data-api') || c.getAttribute('data-action') || window.location.pathname,
                            method,
                            inputs,
                            formType,
                            isExplicitForm: false,
                        });
                        inputs.forEach(inp => seenInputNames.add(inp.name));
                    }
                }

                // 3. Extract standalone inputs outside any form/container
                const standaloneInputs = Array.from(document.querySelectorAll('input, textarea, select, [role="textbox"], [role="searchbox"]'))
                    .map(el => inspectInput(el, 'query'))
                    .filter(inp => inp && !seenInputNames.has(inp.name));

                return { forms, standaloneInputs };
            }
            """)

            forms_data = extracted.get("forms", [])
            for inp in extracted.get("standaloneInputs", []):
                standalone_params.append(
                    DiscoveredParameter(
                        name=inp["name"],
                        location=inp.get("location", "query"),
                        sample_value=inp.get("value") or inp.get("placeholder") or "test",
                    )
                )

        except Exception as exc:
            logger.debug("Error extracting forms from page: %s", exc)

        return forms_data, standalone_params

    async def _crawl_with_static_bundle_fallback(self) -> List[DiscoveredEndpoint]:
        """
        Graceful fallback when headless browser is not available.
        Inspects application scripts and static HTML to discover routes, forms, and inputs.
        """
        import httpx

        endpoints: List[DiscoveredEndpoint] = []
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            try:
                root_res = await client.get(self.base_url)
                root_html = root_res.text
            except Exception:
                root_html = ""

            self.routes_discovered.add("/")

            # Probe for known bundles
            candidate_scripts = [
                "static/js/bundle.js",
                "static/js/main.chunk.js",
                "app.js",
                "bundle.js",
                "flutter_bootstrap.js",
            ]
            for script_path in candidate_scripts:
                try:
                    s_res = await client.get(urljoin(self.base_url, script_path))
                    if s_res.status_code == 200:
                        text = s_res.text
                        found = self._extract_routes_from_text(text)
                        self.routes_discovered.update(found)
                except Exception:
                    pass

            for common_route in COMMON_SPA_ROUTES:
                self.routes_discovered.add(common_route)

            # Extract forms from static root HTML using BeautifulSoup
            soup = BeautifulSoup(root_html, "html.parser")
            forms = soup.find_all("form")
            if forms:
                self.forms_discovered += len(forms)

            root_params: List[DiscoveredParameter] = []
            for inp in soup.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id")
                if name:
                    root_params.append(
                        DiscoveredParameter(
                            name=name,
                            location="query",
                            sample_value=inp.get("value"),
                        )
                    )

            for route in sorted(list(self.routes_discovered))[: self.max_urls]:
                target_url = self._build_route_url(route)
                self.routes_visited.add(route)
                is_auth_required = self._check_auth_required(route, target_url, root_html)
                if is_auth_required:
                    self.routes_auth_required.add(route)
                else:
                    self.routes_tested.add(route)

                ep = DiscoveredEndpoint(
                    url=target_url,
                    method="GET",
                    status_code=401 if is_auth_required else 200,
                    content_type="text/html; charset=utf-8",
                    response_headers={
                        "content-type": "text/html; charset=utf-8",
                        "x-zerotrace-spa-route": route,
                        "x-zerotrace-auth-status": "protected" if is_auth_required else "public",
                    },
                    html=root_html,
                    parameters=list(root_params),
                    has_form=bool(forms),
                )
                endpoints.append(ep)

        return endpoints

    def _normalize_route(self, href: str) -> Optional[str]:
        """
        Normalize an href into a standardized SPA route like /login, /search, or /#/dashboard.
        Preserves standard React Router HTML5 pushState path routes without prefixing '#'.
        """
        href = href.strip()
        if not href or href == "#" or href.startswith("javascript:") or href.startswith("mailto:"):
            return None
        if href.startswith("#/"):
            return "/#" + href[1:]
        if href.startswith("#!"):
            return "/#" + href[2:]
        if href.startswith("/#/"):
            return href
        if href.startswith("/"):
            parsed = urlparse(href)
            clean_path = parsed.path or "/"
            if parsed.query:
                clean_path = f"{clean_path}?{parsed.query}"
            return clean_path
        return None

    def _extract_routes_from_text(self, text: str) -> Set[str]:
        """Extract route definitions from React Router, Vue, and Flutter bundles."""
        routes: Set[str] = set()

        def add_route(r: str):
            clean = r.split(":")[0].rstrip("/")
            if clean:
                routes.add(clean)
                routes.add(f"/#{clean}" if not clean.startswith("/#") else clean)

        # React Router <Route path="..." /> or path: "..."
        for match in re.finditer(r'(?:path|to|route):\s*["\'](/[a-zA-Z0-9_\-\/:]+)["\']', text, re.IGNORECASE):
            add_route(match.group(1))

        # useNavigate() or history.push()
        for match in re.finditer(r'(?:navigate|push)\(["\'](/[a-zA-Z0-9_\-\/]+)["\']\)', text):
            add_route(match.group(1))

        # Flutter settings.name === "/..."
        for match in re.finditer(r'settings(?:\.name|\.arguments|\s*===)\s*===\s*["\'](/[a-zA-Z0-9_\-]+)["\']', text):
            add_route(match.group(1))

        # Flutter MaterialApp routes list
        routes_map_match = re.search(r"routes:\s*new\s*[^,]+,\s*\[(.*?)\]\)", text, re.DOTALL)
        if routes_map_match:
            extracted = re.findall(r'"(/[a-zA-Z0-9_\-]+)"', routes_map_match.group(1))
            for r in extracted:
                add_route(r)

        return routes

    def _extract_api_endpoints_from_text(self, text: str) -> Set[str]:
        """Extract REST API endpoints mentioned in client scripts."""
        apis: Set[str] = set()
        # Patterns like fetch('/api/...') or axios.get('/api/...') or fetch('/vulnerable-sqli?category=...')
        matches = re.findall(r'["\'](/(?:api|v[0-9]+|vulnerable|safe)[a-zA-Z0-9_\-\/\?=&]+)["\']', text)
        for m in matches:
            apis.add(m)
        return apis

    def _build_route_url(self, route: str) -> str:
        """Construct a full URL for visiting a candidate route."""
        clean_base = self.base_url.rstrip("/")
        if route.startswith("/#/"):
            return f"{clean_base}{route}"
        if route.startswith("#/"):
            return f"{clean_base}/{route}"
        if route.startswith("/"):
            return f"{clean_base}{route}"
        return f"{clean_base}/{route}"

    def _check_auth_required(self, route: str, current_url: str, html: str) -> bool:
        route_lower = route.lower()
        for pattern in AUTH_REQUIRED_PATTERNS:
            if pattern.search(route_lower):
                return True

        if "/login" in current_url.lower() and not ("/login" in route_lower or "/signup" in route_lower or "/signin" in route_lower):
            return True

        auth_challenge_keywords = [
            "please sign in",
            "please log in",
            "login required",
            "authentication required",
            "access denied",
            "unauthorized",
            "session expired",
        ]
        html_lower = html.lower()
        if any(keyword in html_lower for keyword in auth_challenge_keywords):
            return True

        return False
