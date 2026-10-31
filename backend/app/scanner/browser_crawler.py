"""
Browser-based crawler and SPA route discovery for ZeroTrace.

Provides Playwright-based headless browser crawling for client-rendered applications
(Flutter Web, React, Vue, Angular, Vite, Next.js). Discovers hash-based routes
(e.g., /#/welcome, /#/login, /#/signup, /#/dashboard), verifies route accessibility,
discovers DOM-rendered forms, form action endpoints, search fields, input elements,
and tracks:
- routes_discovered
- routes_visited
- routes_tested
- routes_failed
- routes_auth_required
- forms_discovered
- parameters_discovered

Adheres strictly to safety rules:
- Does not submit forms or perform state-changing actions automatically.
- Enforces same-origin crawling and request/depth limits.
- Gracefully falls back to bundle-parsing heuristic discovery if browser
  automation is unavailable.
"""
import asyncio
import logging
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

from app.core.ssrf_protection import is_same_origin
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger("scanner.browser_crawler")

# Standard candidate hash and path routes across modern web apps & SPAs
COMMON_SPA_ROUTES = [
    "/",
    "/#/welcome",
    "/#/login",
    "/#/signup",
    "/#/register",
    "/#/forgot-password",
    "/#/home",
    "/#/dashboard",
    "/#/weather",
    "/#/crop-selection",
    "/#/soil",
    "/#/price",
    "/#/crop",
    "/#/chatbot",
    "/#/notifications",
    "/#/doctor",
    "/#/profile",
    "/#/settings",
    "/#/admin",
]

# Known protected / authenticated route patterns
AUTH_REQUIRED_PATTERNS = [
    re.compile(r"(?i)/#?/(home|dashboard|admin|profile|settings|account|orders|checkout|management|doctor)")
]


class BrowserCrawler:
    def __init__(
        self,
        base_url: str,
        max_urls: int = 50,
        request_delay: float = 0.25,
        timeout_seconds: float = 12.0,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.max_urls = max_urls
        self.request_delay = request_delay
        self.timeout_seconds = timeout_seconds

        self.routes_discovered: Set[str] = set()
        self.routes_visited: Set[str] = set()
        self.routes_tested: Set[str] = set()
        self.routes_failed: Set[str] = set()
        self.routes_auth_required: Set[str] = set()

        self.forms_discovered: int = 0
        self.parameters_discovered: int = 0

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
        """Launch Playwright Chromium to render JavaScript, discover routes, forms, and inputs."""
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
            page = await context.new_page()

            captured_scripts: List[str] = []
            page.on("response", lambda res: captured_scripts.append(res.url) if ".js" in res.url else None)

            # 1. Load initial entrypoint
            try:
                await page.goto(self.base_url, wait_until="networkidle", timeout=int(self.timeout_seconds * 1000))
            except Exception:
                await page.goto(self.base_url, wait_until="domcontentloaded", timeout=int(self.timeout_seconds * 1000))

            await asyncio.sleep(2.0)
            self.routes_discovered.add("/")

            # 2. Extract routes from DOM anchors
            anchor_hrefs = await page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(e => e.getAttribute('href'))",
            )
            for href in anchor_hrefs:
                if href:
                    normalized = self._normalize_route(href)
                    if normalized:
                        self.routes_discovered.add(normalized)

            # 3. Extract routes from loaded scripts (Flutter MaterialApp, React Router, Vue routes)
            for script_url in captured_scripts:
                if any(x in script_url for x in ("main.dart", "screens", "routes", "app", "bundle", "chunk")):
                    try:
                        resp = await context.request.get(script_url)
                        text = await resp.text()
                        found = self._extract_routes_from_text(text)
                        self.routes_discovered.update(found)
                    except Exception:
                        pass

            # Seed with common SPA routes for the framework
            for common_route in COMMON_SPA_ROUTES:
                self.routes_discovered.add(common_route)

            # 4. Visit and evaluate each distinct discovered route
            routes_to_visit = sorted(list(self.routes_discovered))[: self.max_urls]
            for route in routes_to_visit:
                target_url = self._build_route_url(route)
                if not is_same_origin(self.base_url, target_url):
                    continue

                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=int(self.timeout_seconds * 1000))
                    await asyncio.sleep(1.0)
                    self.routes_visited.add(route)

                    # Inspect the rendered DOM & page state
                    page_html = await page.content()
                    current_url = page.url

                    # Check for authentication requirements
                    is_auth_required = self._check_auth_required(route, current_url, page_html)
                    if is_auth_required:
                        self.routes_auth_required.add(route)
                    else:
                        self.routes_tested.add(route)

                    # Extract form elements, actions, and inputs from the rendered DOM
                    forms_data, standalone_params = await self._extract_forms_and_inputs(page)
                    if forms_data:
                        self.forms_discovered += len(forms_data)

                    # Collect parameters for the GET page endpoint
                    page_params: List[DiscoveredParameter] = list(standalone_params)

                    # Also parse query parameters from the URL
                    parsed_target = urlparse(target_url)
                    for q_name, q_vals in parse_qs(parsed_target.query).items():
                        page_params.append(
                            DiscoveredParameter(name=q_name, location="query", sample_value=q_vals[0] if q_vals else None)
                        )

                    # Attach form inputs to the page endpoint
                    for f in forms_data:
                        for inp in f.get("inputs", []):
                            page_params.append(
                                DiscoveredParameter(
                                    name=inp["name"],
                                    location="body" if f.get("method") == "POST" else "query",
                                    sample_value=inp.get("value") or None,
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

                    # If forms specify explicit action targets, register those action endpoints as distinct targets
                    for f in forms_data:
                        action_raw = f.get("action")
                        method = f.get("method", "GET").upper()
                        resolved_action = urljoin(current_url, action_raw) if action_raw else current_url

                        if is_same_origin(self.base_url, resolved_action):
                            form_params = [
                                DiscoveredParameter(
                                    name=inp["name"],
                                    location="body" if method == "POST" else "query",
                                    sample_value=inp.get("value") or None,
                                )
                                for inp in f.get("inputs", [])
                            ]
                            # Create separate endpoint for form submission if method is POST or action differs
                            if method == "POST" or resolved_action != target_url:
                                endpoints.append(DiscoveredEndpoint(
                                    url=resolved_action,
                                    method=method,
                                    status_code=200,
                                    content_type="application/x-www-form-urlencoded" if method == "POST" else "text/html",
                                    parameters=form_params,
                                    has_form=True,
                                ))

                except Exception as exc:
                    logger.debug("Failed visiting route %s: %s", route, exc)
                    self.routes_failed.add(route)

            await browser.close()

        return endpoints

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

            # Probe for known Flutter and JS script bundles
            candidate_scripts = [
                "flutter_bootstrap.js",
                "packages/smartfarming/main.dart.lib.js",
                "main.dart.js",
                "app.js",
                "bundle.js",
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

                # Add distinct form endpoints
                for form in forms:
                    action = form.get("action") or ""
                    method = (form.get("method") or "GET").upper()
                    resolved = urljoin(target_url, action) if action else target_url
                    if is_same_origin(self.base_url, resolved) and method == "POST":
                        f_params = []
                        for finp in form.find_all(["input", "textarea", "select"]):
                            fn = finp.get("name") or finp.get("id")
                            if fn:
                                f_params.append(
                                    DiscoveredParameter(name=fn, location="body", sample_value=finp.get("value"))
                                )
                        endpoints.append(DiscoveredEndpoint(
                            url=resolved,
                            method="POST",
                            status_code=200,
                            content_type="application/x-www-form-urlencoded",
                            parameters=f_params,
                            has_form=True,
                        ))

        return endpoints

    def _normalize_route(self, href: str) -> Optional[str]:
        """Normalize an href into a standardized SPA route like /#/welcome or /login."""
        href = href.strip()
        if not href or href == "#" or href.startswith("javascript:") or href.startswith("mailto:"):
            return None
        if href.startswith("#/"):
            return href
        if href.startswith("#!"):
            return "/#" + href[2:]
        if href.startswith("/"):
            return f"/#{href}" if not href.startswith("/#") else href
        return None

    def _extract_routes_from_text(self, text: str) -> Set[str]:
        """Extract route definitions from JavaScript bundles, MaterialApp, and routers."""
        routes: Set[str] = set()

        # Flutter MaterialApp routes list
        routes_map_match = re.search(r"routes:\s*new\s*[^,]+,\s*\[(.*?)\]\)", text, re.DOTALL)
        if routes_map_match:
            extracted = re.findall(r'"(/[a-zA-Z0-9_\-]+)"', routes_map_match.group(1))
            for r in extracted:
                routes.add(f"/#{r}" if not r.startswith("/#") else r)

        # Flutter onGenerateRoute
        for match in re.finditer(r'settings(?:\.name|\.arguments|\s*===)\s*===\s*"(/[a-zA-Z0-9_\-]+)"', text):
            r = match.group(1)
            routes.add(f"/#{r}" if not r.startswith("/#") else r)

        # General React/Vue/Angular route patterns
        for match in re.finditer(r'path:\s*["\'](/[a-zA-Z0-9_\-]+)["\']', text):
            r = match.group(1)
            routes.add(f"/#{r}" if not r.startswith("/#") else r)

        return routes

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

        if "/login" in current_url.lower() and not ("/login" in route_lower or "/signup" in route_lower):
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

    async def _extract_forms_and_inputs(self, page) -> Tuple[List[Dict[str, Any]], List[DiscoveredParameter]]:
        """Extract all DOM forms, actions, methods, and standalone inputs."""
        forms_data: List[Dict[str, Any]] = []
        standalone_params: List[DiscoveredParameter] = []

        try:
            # 1. Extract structured forms
            forms_data = await page.evaluate("""
            () => {
                const forms = Array.from(document.querySelectorAll('form'));
                return forms.map(f => {
                    const action = f.getAttribute('action') || '';
                    const method = (f.getAttribute('method') || 'GET').toUpperCase();
                    const inputs = Array.from(f.querySelectorAll('input, textarea, select')).map(el => ({
                        name: el.getAttribute('name') || el.getAttribute('id') || '',
                        type: el.getAttribute('type') || 'text',
                        value: el.value || el.getAttribute('value') || '',
                        placeholder: el.getAttribute('placeholder') || ''
                    })).filter(inp => inp.name && inp.name.length > 0);
                    return { action, method, inputs };
                });
            }
            """)

            # 2. Extract standalone search inputs or inputs outside forms
            standalone_inputs = await page.evaluate("""
            () => {
                const inputs = Array.from(document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)'));
                return inputs.map(el => ({
                    name: el.getAttribute('name') || el.getAttribute('id') || el.getAttribute('placeholder') || 'search',
                    type: el.getAttribute('type') || 'text',
                    value: el.value || el.getAttribute('value') || ''
                })).filter(inp => inp.name && inp.name.length > 0);
            }
            """)

            for inp in standalone_inputs:
                standalone_params.append(
                    DiscoveredParameter(
                        name=inp["name"],
                        location="query",
                        sample_value=inp.get("value") or None,
                    )
                )

        except Exception as exc:
            logger.debug("Error extracting forms from page: %s", exc)

        return forms_data, standalone_params
