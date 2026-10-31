"""
Controlled, same-origin asynchronous crawler with Single Page Application (SPA) support.

Responsible for discovering pages, hash-based routes (e.g. /#/welcome, /#/login),
forms, and parameters within configured depth/URL/rate limits.
Integrates Playwright-based browser discovery for client-rendered applications
(Flutter Web, React, Vue, Angular) and falls back cleanly to static crawling.
"""
import logging
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse, parse_qs
from typing import Set, List, Dict, Tuple, Optional

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
    ):
        self.start_url = normalize_url(start_url)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.allow_external = allow_external
        self.enable_browser_discovery = enable_browser_discovery

        self.rate_limiter = AsyncRateLimiter(request_delay)
        self.client = SafeHTTPClient(request_delay)

        self.visited: Set[str] = set()
        self.endpoints: List[DiscoveredEndpoint] = []
        self.route_metrics: Dict[str, List[str]] = {
            "routes_discovered": [],
            "routes_visited": [],
            "routes_tested": [],
            "routes_failed": [],
            "routes_auth_required": [],
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
                self.route_metrics = metrics

                for ep in spa_endpoints:
                    norm_ep_url = normalize_url(ep.url)
                    if norm_ep_url not in self.visited:
                        self.visited.add(norm_ep_url)
                        self.endpoints.append(ep)
                        if on_endpoint_discovered:
                            await on_endpoint_discovered(ep)
            except Exception as exc:
                logger.warning("Browser discovery encountered an issue: %s. Continuing with HTTP crawler.", exc)

        # 2. Standard HTTP crawling for server-rendered routes and static endpoints
        queue = deque([(self.start_url, 0)])

        while queue and len(self.visited) < self.max_urls:
            url, depth = queue.popleft()
            url = normalize_url(url)

            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)

            await self.rate_limiter.wait()
            endpoint, links = await self._fetch_and_parse(url)
            if endpoint is None:
                continue

            self.endpoints.append(endpoint)
            if on_endpoint_discovered:
                await on_endpoint_discovered(endpoint)

            if depth < self.max_depth:
                for link in links:
                    norm_link = normalize_url(link)
                    if norm_link not in self.visited:
                        queue.append((norm_link, depth + 1))

        await self.client.close()
        return self.endpoints

    async def _fetch_and_parse(self, url: str):
        response = await self.client.get(url)
        if response is None:
            logger.info("Timeout or connection error fetching %s", url)
            return None, []

        content_type = response.headers.get("content-type", "")
        links: List[str] = []
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

        # Query string parameters
        parsed = urlparse(url)
        for name, values in parse_qs(parsed.query).items():
            endpoint.parameters.append(
                DiscoveredParameter(name=name, location="query", sample_value=values[0] if values else None)
            )

        if "text/html" in content_type:
            body = response.text[:200_000]
            endpoint.body_snippet = body[:2000]
            endpoint.html = body
            soup = BeautifulSoup(body, "html.parser")
            self._extract_forms(soup, url, endpoint)
            extracted_links = await self._extract_links_from_html(body, url)
            links.extend(extracted_links)

        return endpoint, list(dict.fromkeys(links))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str, endpoint: DiscoveredEndpoint) -> None:
        forms = soup.find_all("form")
        if forms:
            endpoint.has_form = True
        for form in forms:
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if not name:
                    continue
                location = "body" if form.get("method", "get").lower() == "post" else "query"
                endpoint.parameters.append(
                    DiscoveredParameter(name=name, location=location, sample_value=input_tag.get("value"))
                )

    async def _extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href")
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            absolute = urljoin(base_url, href)
            if not self.allow_external and not is_same_origin(self.start_url, absolute):
                continue
            links.append(normalize_url(absolute))
        return list(dict.fromkeys(links))
