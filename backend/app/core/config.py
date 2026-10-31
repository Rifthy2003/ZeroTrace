"""
Application configuration.

All security-relevant defaults (SSRF protection, rate limiting, crawl limits)
live here so they are easy to audit in one place.
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "ZeroTrace — Automated Web Vulnerability Scanner"
    ENV: str = "development"

    DATABASE_URL: str = "sqlite:///./scanner.db"

    # --- Safety / SSRF protection -------------------------------------------------
    # When False (default), the scanner refuses to target private/loopback/link-local
    # addresses. Keep False in production deployments.
    ALLOW_PRIVATE_NETWORK_TARGETS: bool = False

    # Dedicated local-development testing option for scanning host-running projects from Docker.
    # Disabled by default. When explicitly enabled, permits authorized host targets
    # (host.docker.internal, localhost, 127.0.0.1) on user-selected ports,
    # preserving DNS resolution, resolved-IP checks, redirect validation,
    # and SSRF protection for all other destinations.
    ALLOW_LOCAL_DEV_TARGET: bool = False
    LOCAL_DEV_ALLOWED_HOSTS: List[str] = ["host.docker.internal", "localhost", "127.0.0.1"]

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
        extra = "ignore"


settings = Settings()
