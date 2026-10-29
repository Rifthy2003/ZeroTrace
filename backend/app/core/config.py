"""
Application configuration.

All security-relevant defaults (SSRF protection, rate limiting, crawl limits)
live here so they are easy to audit in one place.
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "Automated Web Vulnerability Scanner"
    ENV: str = "development"

    DATABASE_URL: str = "sqlite:///./scanner.db"

    # --- Safety / SSRF protection -------------------------------------------------
    # When False (default), the scanner refuses to target private/loopback/link-local
    # addresses. Only flip this on for an isolated local lab (e.g. the bundled
    # vulnerable-test-app) and never in a shared/production deployment.
    ALLOW_PRIVATE_NETWORK_TARGETS: bool = False

    # Hard ceiling on crawl size regardless of what the user requests.
    MAX_CRAWL_DEPTH_LIMIT: int = 5
    MAX_URLS_LIMIT: int = 500

    # Networking safety
    REQUEST_TIMEOUT_SECONDS: float = 10.0
    MAX_RESPONSE_BYTES: int = 2_000_000
    DEFAULT_REQUEST_DELAY_SECONDS: float = 0.25
    MAX_REDIRECTS: int = 5

    # Rate limiting for the API itself
    API_RATE_LIMIT_PER_MINUTE: int = 30

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    SECRET_KEY: str = "change-me-in-production"

    class Config:
        env_file = ".env"


settings = Settings()
