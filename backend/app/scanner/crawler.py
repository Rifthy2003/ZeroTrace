"""
Controlled, same-origin asynchronous crawler with Single Page Application (SPA) support.

Responsible for discovering pages, hash-based routes (e.g. /#/welcome, /#/login),
forms, POST endpoints, and parameters within configured depth/URL/rate limits.
Integrates Playwright-based browser discovery for client-rendered applications
(Flutter Web, React, Vue, Angular) and server-rendered HTTP endpoints.
"""
import json
import logging
import re
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse, parse_qs
from typing import Set, List, Dict, Tuple, Optional, Any

from bs4 import BeautifulSoup

from app.core.rate_limiter import AsyncRateLimiter
from app.core.ssrf_protection import is_same_origin, validate_redirect_url, UnsafeTargetError
from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter
from app.scanner.browser_crawler import BrowserCrawler

logger = logging.getLogger("scanner.crawler")


def normalize_url(url: str, preserve_hash_routes: bool = True) -> str:
    """
    Normalize URLs for de-duplication while preserving SPA hash routes (e.g., /#/welcome).
    Traditional client-side in-page anchor fragments (#section) are stripped,
    while route fragments beginning with '#/' or '#!' are preserved.
    """
    parsed = urlparse(url)
    fragment = parsed.fragment or ""
    has_spa_route = fragment.startswith("/") or fragment.startswith("!/") or ("/" in fragment and len(fragment) > 2)

    if not (preserve_hash_routes and has_spa_route):
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        fragment = ""

    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    if fragment and has_spa_route:
        frag_clean = fragment.rstrip("/")
        normalized = parsed._replace(path=path, fragment=frag_clean).geturl()
    else:
        normalized = parsed._replace(path=path, fragment="").geturl()

    return normalized


class Crawler:
    def __init__(
        self,
        start_url: str,
        max_depth: int = 2,
        max_urls: int = 50,
        request_delay: float = 0.25,
        allow_external: bool = False,
        enable_browser_discovery: bool = True,
        transport: Any = None,
    ):
        self.start_url = normalize_url(start_url)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.allow_external = allow_external
        self.enable_browser_discovery = enable_browser_discovery

        self.rate_limiter = AsyncRateLimiter(request_delay)
        self.client = SafeHTTPClient(request_delay, transport=transport)

        self.visited: Set[str] = set()
        self.http_visited: Set[str] = set()
        self.endpoints: List[DiscoveredEndpoint] = []
        self.total_forms_discovered = 0
        self.total_parameters_discovered = 0
        self.route_metrics: Dict[str, Any] = {
            "routes_discovered": [],
            "routes_visited": [],
            "routes_tested": [],
            "routes_failed": [],
            "routes_auth_required": [],
            "forms_discovered": 0,
            "parameters_discovered": 0,
        }

    async def crawl(self, on_endpoint_discovered=None) -> List[DiscoveredEndpoint]:
        # 1. Optional Playwright-based browser discovery for SPAs & client-side routes
        if self.enable_browser_discovery:
            try:
                browser_crawler = BrowserCrawler(
                    base_url=self.start_url,
                    max_urls=self.max_urls,
                    request_delay=self.rate_limiter.delay_seconds,
                )
                spa_endpoints, metrics = await browser_crawler.crawl()
                self.route_metrics.update(metrics)
                self.total_forms_discovered += metrics.get("forms_discovered", 0)

                for ep in spa_endpoints:
                    norm_ep_url = normalize_url(ep.url)
                    ep_key = f"{ep.method}:{norm_ep_url}"
                    if ep_key not in self.visited:
                        self.visited.add(ep_key)
                        self.endpoints.append(ep)
                        self.total_parameters_discovered += len(ep.parameters)
                        if on_endpoint_discovered:
                            await on_endpoint_discovered(ep)
            except Exception as exc:
                logger.warning("Browser discovery encountered an issue: %s. Continuing with HTTP crawler.", exc)

        # 2. Standard HTTP crawling for server-rendered routes and static endpoints
        queue = deque([(self.start_url, 0)])

        while queue and len(self.endpoints) < self.max_urls:
            url, depth = queue.popleft()
            norm_url = normalize_url(url)
            http_key = f"GET:{norm_url}"

            # Skip if we already performed full HTTP parse on this exact URL
            if http_key in self.http_visited or depth > self.max_depth:
                continue
            self.http_visited.add(http_key)

            await self.rate_limiter.wait()
            endpoint, links, form_endpoints = await self._fetch_and_parse(url)
            if endpoint is None:
                continue

            # Only append if not already present from browser crawler
            if http_key not in self.visited:
                self.visited.add(http_key)
                self.endpoints.append(endpoint)
                self.total_parameters_discovered += len(endpoint.parameters)
                if on_endpoint_discovered:
                    await on_endpoint_discovered(endpoint)
            else:
                # Merge discovered parameters into existing endpoint
                existing = next((e for e in self.endpoints if e.url == endpoint.url and e.method == "GET"), None)
                if existing:
                    existing_names = {p.name for p in existing.parameters}
                    for p in endpoint.parameters:
                        if p.name not in existing_names:
                            existing.parameters.append(p)
                            existing_names.add(p.name)
                            self.total_parameters_discovered += 1
                    if endpoint.has_form:
                        existing.has_form = True

            # Register discovered form action endpoints (e.g. POST forms)
            for f_ep in form_endpoints:
                f_key = f"{f_ep.method}:{normalize_url(f_ep.url)}"
                if f_key not in self.visited and len(self.endpoints) < self.max_urls:
                    self.visited.add(f_key)
                    self.endpoints.append(f_ep)
                    self.total_parameters_discovered += len(f_ep.parameters)
                    if on_endpoint_discovered:
                        await on_endpoint_discovered(f_ep)

            if depth < self.max_depth:
                for link in links:
                    norm_link = normalize_url(link)
                    link_key = f"GET:{norm_link}"
                    if link_key not in self.http_visited:
                        queue.append((norm_link, depth + 1))

        await self.client.close()

        # Update final metrics
        self.route_metrics["forms_discovered"] = self.total_forms_discovered
        self.route_metrics["parameters_discovered"] = sum(len(e.parameters) for e in self.endpoints)

        return self.endpoints

    async def _fetch_and_parse(self, url: str) -> Tuple[Optional[DiscoveredEndpoint], List[str], List[DiscoveredEndpoint]]:
        response = await self.client.get(url)
        if response is None:
            logger.info("Timeout or connection error fetching %s", url)
            return None, [], []

        content_type = response.headers.get("content-type", "")
        links: List[str] = []
        form_endpoints: List[DiscoveredEndpoint] = []
        endpoint = DiscoveredEndpoint(
            url=url,
            method="GET",
            status_code=response.status_code,
            content_type=content_type,
            response_headers=dict(response.headers),
        )

        # Validate and record redirect target without following unsafe redirects automatically.
        if response.status_code in (301, 302, 303, 307, 308):
            raw_loc = response.headers.get("location")
            if raw_loc:
                try:
                    safe_loc = validate_redirect_url(url, raw_loc)
                    endpoint.redirected_to = safe_loc
                    if not self.allow_external and is_same_origin(self.start_url, safe_loc):
                        links.append(normalize_url(safe_loc))
                except UnsafeTargetError as exc:
                    logger.warning("Blocked unsafe redirect from %s to %s: %s", url, raw_loc, exc)
                    endpoint.redirected_to = f"[BLOCKED UNSAFE REDIRECT: {raw_loc}]"

        # 1. Query string parameters
        parsed = urlparse(url)
        for name, values in parse_qs(parsed.query).items():
            endpoint.parameters.append(
                DiscoveredParameter(name=name, location="query", sample_value=values[0] if values else None)
            )

        # 2. JSON Response / API Parameter Discovery
        if "application/json" in content_type:
            try:
                data = json.loads(response.text)
                if isinstance(data, dict):
                    for k, v in data.items():
                        endpoint.parameters.append(
                            DiscoveredParameter(name=k, location="json", sample_value=str(v)[:50])
                        )
                elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                    for k, v in data[0].items():
                        endpoint.parameters.append(
                            DiscoveredParameter(name=k, location="json", sample_value=str(v)[:50])
                        )
            except Exception:
                pass

        # 3. HTML Forms and Link Extraction
        if "text/html" in content_type:
            body = response.text[:200_000]
            endpoint.body_snippet = body[:2000]
            endpoint.html = body
            soup = BeautifulSoup(body, "html.parser")
            form_endpoints = self._extract_forms(soup, url, endpoint)
            extracted_links = await self._extract_links_from_html(body, url)
            links.extend(extracted_links)

            # Discover API endpoints mentioned in JavaScript
            api_matches = re.findall(r'["\'](/(?:api|v[0-9]+)/[a-zA-Z0-9_\-\/]+)["\']', body)
            for api_path in api_matches:
                api_full = urljoin(url, api_path)
                if is_same_origin(self.start_url, api_full):
                    links.append(normalize_url(api_full))

        return endpoint, list(dict.fromkeys(links)), form_endpoints

    def _extract_forms(self, soup: BeautifulSoup, base_url: str, endpoint: DiscoveredEndpoint) -> List[DiscoveredEndpoint]:
        forms = soup.find_all("form")
        form_endpoints: List[DiscoveredEndpoint] = []
        if forms:
            endpoint.has_form = True
            self.total_forms_discovered += len(forms)

        for form in forms:
            f_action = form.get("action") or ""
            f_method = (form.get("method") or "GET").upper()
            resolved_action = urljoin(base_url, f_action) if f_action else base_url

            form_params: List[DiscoveredParameter] = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name") or input_tag.get("id")
                if not name:
                    continue
                location = "body" if f_method == "POST" else "query"
                val = input_tag.get("value")
                p = DiscoveredParameter(name=name, location=location, sample_value=val)
                # Attach to current page endpoint
                if not any(ep_p.name == name for ep_p in endpoint.parameters):
                    endpoint.parameters.append(p)
                form_params.append(p)

            # Create distinct endpoint for form actions if same origin
            if is_same_origin(self.start_url, resolved_action):
                norm_action = normalize_url(resolved_action)
                if norm_action != normalize_url(base_url) or f_method != endpoint.method:
                    form_endpoints.append(DiscoveredEndpoint(
                        url=norm_action,
                        method=f_method,
                        content_type="application/x-www-form-urlencoded" if f_method == "POST" else "text/html",
                        parameters=form_params,
                        has_form=True,
                    ))

        return form_endpoints

    async def _extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href")
            if not href or href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("#"):
                continue
            absolute = urljoin(base_url, href)
            if not self.allow_external and not is_same_origin(self.start_url, absolute):
                continue
            links.append(normalize_url(absolute))
        return list(dict.fromkeys(links))
