"""
Simple async rate limiter used by the crawler and scanner modules to throttle
outbound requests to the target — both to be a good citizen and to avoid
looking like a denial-of-service attempt.
"""
import asyncio
import time


class AsyncRateLimiter:
    def __init__(self, delay_seconds: float):
        self.delay_seconds = max(0.0, delay_seconds)
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def wait(self) -> None:
        if self.delay_seconds <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            remaining = self.delay_seconds - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_call = time.monotonic()
