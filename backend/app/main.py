import time
from contextlib import asynccontextmanager
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import scans
from app.core.config import settings
from app.core.logging_config import configure_logging
from app.database.session import init_db

configure_logging()
@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(lifespan=lifespan, title=settings.APP_NAME, version="1.0.0",
              description="Authorized defensive web vulnerability assessment platform. Scan only systems you own or have written permission to test.")
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])

_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    # Only throttle scan creation (the expensive operation).
    if request.method == "POST" and request.url.path == "/api/scans":
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        q = _hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= settings.API_RATE_LIMIT_PER_MINUTE:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        q.append(now)
    return await call_next(request)



app.include_router(scans.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
