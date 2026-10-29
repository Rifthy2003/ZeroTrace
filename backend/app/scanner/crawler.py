"""
Controlled, same-origin asynchronous crawler.

Responsible only for discovering pages, forms, and parameters within the
configured depth/URL/rate limits. Does not perform any vulnerability testing
itself — that is left to the scanner modules that run afterwards.
"""
import logging
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse, parse_qs
from typing import Set, List

from bs4 import BeautifulSoup

from app.core.rate_limiter import AsyncRateLimiter
from app.core.ssrf_protection import is_same_origin
from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger("scanner.crawler")


def normalize_url(url: str) -> str:
    """Strip fragments and trailing slashes (except root) for de-duplication."""
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    normalized = parsed._replace(path=path).geturl()
    return normalized


class Crawler:
    def __init__(
        self,
        start_url: str,
        max_depth: int = 2,
        max_urls: int = 50,
        request_delay: float = 0.25,
        allow_external: bool = False,
    ):
        self.start_url = normalize_url(start_url)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.allow_external = allow_external

        self.rate_limiter = AsyncRateLimiter(request_delay)
        self.client = SafeHTTPClient(request_delay)

        self.visited: Set[str] = set()
        self.endpoints: List[DiscoveredEndpoint] = []

    async def crawl(self, on_endpoint_discovered=None) -> List[DiscoveredEndpoint]:
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
                    if link not in self.visited:
                        queue.append((link, depth + 1))

        await self.client.close()
        return self.endpoints

    async def _fetch_and_parse(self, url: str):
        response = await self.client.get(url)
        if response is None:
            logger.info(f"Timeout or connection error fetching {url}")
            return None, []

        content_type = response.headers.get("content-type", "")
        endpoint = DiscoveredEndpoint(
            url=url,
            method="GET",
            status_code=response.status_code,
            content_type=content_type,
            response_headers=dict(response.headers),
        )

        # Record redirect target without following it automatically.
        if response.status_code in (301, 302, 303, 307, 308):
            endpoint.redirected_to = response.headers.get("location")

        # Query string parameters
        parsed = urlparse(url)
        for name, values in parse_qs(parsed.query).items():
            endpoint.parameters.append(
                DiscoveredParameter(name=name, location="query", sample_value=values[0] if values else None)
            )

        links: List[str] = []
        if "text/html" in content_type:
            body = response.text[:200_000]
            endpoint.body_snippet = body[:2000]
            endpoint.html = body
            soup = BeautifulSoup(body, "html.parser")
            self._extract_forms(soup, url, endpoint)
            links = await self._extract_links_from_html(body, url)

        return endpoint, links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str, endpoint: DiscoveredEndpoint) -> None:
        forms = soup.find_all("form")
        if forms:
            endpoint.has_form = True
        for form in forms:
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if not name:
                    continue
                endpoint.parameters.append(
                    DiscoveredParameter(
                        name=name,
                        location="form",
                        sample_value=input_tag.get("value"),
                    )
                )

    async def _extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            absolute = urljoin(base_url, a["href"])
            if not self.allow_external and not is_same_origin(self.start_url, absolute):
                continue
            if absolute.startswith(("http://", "https://")):
                links.append(normalize_url(absolute))
        return links
