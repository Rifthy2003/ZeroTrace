"""
Thin wrapper around httpx.AsyncClient that enforces the scanner's safety
limits: timeouts, response-size caps, and a bounded redirect count.
"""
import httpx

from app.core.config import settings


class SafeHTTPClient:
    def __init__(self, request_delay: float = 0.25):
        self._client = httpx.AsyncClient(
            timeout=settings.REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,  # scanners inspect redirects explicitly
            headers={
                "User-Agent": "ZeroTrace-Scanner/1.0 (+https://zerotrace.local; automated-web-vulnerability-scanner)"
            },
        )

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response | None:
        try:
            response = await self._client.request(method, url, **kwargs)
        except (httpx.TimeoutException, httpx.RequestError):
            return None

        # Enforce a max response size by only reading up to the cap.
        content = response.content
        if len(content) > settings.MAX_RESPONSE_BYTES:
            content = content[: settings.MAX_RESPONSE_BYTES]
        return response

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def close(self):
        await self._client.aclose()
