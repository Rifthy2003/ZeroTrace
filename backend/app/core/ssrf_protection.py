"""
SSRF / target-safety validation.

Before the crawler or any scanner module ever makes a request to a
user-supplied target, the URL and its resolved IP address are checked here.
This is a defensive control: it exists to stop the scanner from being
pointed at internal infrastructure, cloud metadata endpoints, or other
unauthorized hosts.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from app.core.config import settings

ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata endpoints are always blocked, even in local-lab mode,
# because they are never a legitimate authorized-scan target.
BLOCKED_HOSTS = {
    "169.254.169.254",  # AWS/GCP/Azure metadata
    "metadata.google.internal",
}


class UnsafeTargetError(ValueError):
    """Raised when a target URL fails safety validation."""


def _is_private_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_target_url(url: str, allow_private: bool | None = None) -> str:
    """
    Validate a target URL for scheme, host, and (optionally) private-network
    restrictions. Returns the normalized URL or raises UnsafeTargetError.
    """
    if allow_private is None:
        allow_private = settings.ALLOW_PRIVATE_NETWORK_TARGETS

    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(f"Unsupported scheme: {parsed.scheme!r}. Use http or https.")

    if not parsed.hostname:
        raise UnsafeTargetError("URL has no hostname.")

    hostname = parsed.hostname.lower()

    if hostname in BLOCKED_HOSTS:
        raise UnsafeTargetError("This host is blocked (cloud metadata endpoint).")

    if not allow_private:
        try:
            # If the hostname is already an IP literal, this resolves instantly.
            resolved_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
        except socket.gaierror as exc:
            raise UnsafeTargetError(f"Could not resolve host: {hostname}") from exc

        for ip_str in resolved_ips:
            try:
                if _is_private_ip(ip_str):
                    raise UnsafeTargetError(
                        f"Target resolves to a private/internal address ({ip_str}). "
                        "Enable ALLOW_PRIVATE_NETWORK_TARGETS only for local lab testing."
                    )
            except ValueError:
                # Not a parseable IP (shouldn't happen from getaddrinfo) — be safe and reject.
                raise UnsafeTargetError(f"Could not validate resolved address: {ip_str}")

    return url


def is_same_origin(base_url: str, candidate_url: str) -> bool:
    b = urlparse(base_url)
    c = urlparse(candidate_url)
    return (b.scheme, b.hostname, b.port) == (c.scheme, c.hostname, c.port)
