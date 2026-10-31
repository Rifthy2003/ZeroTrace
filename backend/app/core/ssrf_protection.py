"""
SSRF / target-safety validation.

Before the crawler or any scanner module ever makes a request to a
user-supplied target, the URL and its resolved IP address are checked here.
This is a defensive control: it exists to stop the scanner from being
pointed at internal infrastructure, cloud metadata endpoints, or other
unauthorized hosts.

Includes support for authorized Windows-host local development testing
(host.docker.internal, localhost, 127.0.0.1) across user-selected target ports,
while strictly preserving DNS resolution, resolved-IP checks, and redirect destination validation.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

from app.core.config import settings

ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata endpoints are always blocked in all modes.
BLOCKED_HOSTS = {
    "169.254.169.254",  # AWS/GCP/Azure/OpenStack metadata
    "169.254.169.253",
    "metadata.google.internal",
    "instance-data",
}

CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local (cloud metadata)
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]


class UnsafeTargetError(ValueError):
    """Raised when a target URL fails safety validation."""


def _is_cloud_metadata(ip_str: str) -> bool:
    """Return True if ip_str is a cloud metadata address."""
    if ip_str in BLOCKED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in CLOUD_METADATA_NETWORKS)
    except ValueError:
        return True


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


def validate_target_url(
    url: str,
    allow_private: bool | None = None,
    allow_local_dev: bool | None = None,
) -> str:
    """
    Validate a target URL for scheme, host, port, and network restrictions.
    
    Modes:
    1. Default (Production): Refuses all private/loopback/link-local addresses and cloud metadata.
    2. Local Development (ALLOW_LOCAL_DEV_TARGET=True):
       Permits authorized Windows-host development targets (host.docker.internal,
       localhost, 127.0.0.1) on any user-selected port.
       Preserves DNS resolution and resolved-IP verification.
       Rewrites localhost/127.0.0.1 to host.docker.internal preserving the target port
       so containerized scans reach the Windows host development server.
       Rejects all unapproved private IPs and cloud metadata.
    3. Private network override (ALLOW_PRIVATE_NETWORK_TARGETS=True):
       Allows private network targets for isolated environments, while strictly blocking metadata.

    Returns the normalized target URL or raises UnsafeTargetError.
    """
    if allow_private is None:
        allow_private = settings.ALLOW_PRIVATE_NETWORK_TARGETS
    if allow_local_dev is None:
        allow_local_dev = settings.ALLOW_LOCAL_DEV_TARGET

    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(f"Unsupported scheme: {parsed.scheme!r}. Use http or https.")

    if not parsed.hostname:
        raise UnsafeTargetError("URL has no hostname.")

    hostname = parsed.hostname.lower()
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeTargetError(f"Invalid target port in URL: {exc}") from exc

    # 1. Cloud metadata is ALWAYS blocked across all modes
    if hostname in BLOCKED_HOSTS:
        raise UnsafeTargetError("This host is blocked (cloud metadata endpoint).")

    is_local_dev_host = hostname in settings.LOCAL_DEV_ALLOWED_HOSTS

    # 2. Local development target handling
    if is_local_dev_host:
        if not allow_local_dev and not allow_private:
            raise UnsafeTargetError(
                f"Target '{hostname}' is a local development target. Local development testing is "
                f"disabled by default. Enable ALLOW_LOCAL_DEV_TARGET=true in your environment to "
                f"permit scanning authorized host targets on custom ports."
            )

        if allow_local_dev and not allow_private:
            if port < 1 or port > 65535:
                raise UnsafeTargetError(f"Target port {port} is invalid. Port must be between 1 and 65535.")

            # Preserve DNS resolution and resolved-IP validation for local development target
            try:
                resolved_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
            except socket.gaierror as exc:
                raise UnsafeTargetError(f"Could not resolve host: {hostname}") from exc

            for ip_str in resolved_ips:
                if _is_cloud_metadata(ip_str):
                    raise UnsafeTargetError(
                        f"Resolved address {ip_str} is a blocked cloud metadata endpoint."
                    )
                # Verify that it resolves to a valid host gateway, private bridge, or loopback IP
                if not _is_private_ip(ip_str):
                    raise UnsafeTargetError(
                        f"Authorized local target '{hostname}' unexpectedly resolved to public IP {ip_str}."
                    )

            # Rewrite localhost / 127.0.0.1 to host.docker.internal so container requests reach the Windows host
            if hostname in ("localhost", "127.0.0.1"):
                netloc = f"host.docker.internal:{port}"
                return parsed._replace(netloc=netloc).geturl()

            return url

    # 3. Standard / External targets and private network restrictions
    if not allow_private:
        try:
            resolved_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
        except socket.gaierror as exc:
            raise UnsafeTargetError(f"Could not resolve host: {hostname}") from exc

        for ip_str in resolved_ips:
            if _is_cloud_metadata(ip_str):
                raise UnsafeTargetError(
                    f"Target resolves to a blocked cloud metadata address ({ip_str})."
                )
            if _is_private_ip(ip_str):
                raise UnsafeTargetError(
                    f"Target resolves to a private/internal address ({ip_str}). "
                    f"Unapproved private network destinations are blocked. "
                    f"To scan your local host development applications, enable ALLOW_LOCAL_DEV_TARGET=true."
                )
    else:
        # allow_private is True: still reject cloud metadata
        try:
            resolved_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
            for ip_str in resolved_ips:
                if _is_cloud_metadata(ip_str):
                    raise UnsafeTargetError("This host is blocked (cloud metadata endpoint).")
        except socket.gaierror:
            pass

    return url


def validate_redirect_url(
    current_url: str,
    redirect_target: str,
    allow_private: bool | None = None,
    allow_local_dev: bool | None = None,
) -> str:
    """
    Validate every redirect destination and reject unexpected address changes.
    Enforces SSRF protection on redirect locations:
    - Resolves relative URLs against current_url.
    - Validates scheme and hostname.
    - Blocks cloud metadata and unapproved private destinations.
    - For local development targets, ensures redirect remains strictly on the authorized
      local development host and selected port.
    - Rejects unexpected host, port, or scheme transitions.
    """
    if allow_private is None:
        allow_private = settings.ALLOW_PRIVATE_NETWORK_TARGETS
    if allow_local_dev is None:
        allow_local_dev = settings.ALLOW_LOCAL_DEV_TARGET

    dest_url = urljoin(current_url, redirect_target)
    parsed_curr = urlparse(current_url)
    parsed_dest = urlparse(dest_url)

    curr_host = (parsed_curr.hostname or "").lower()
    dest_host = (parsed_dest.hostname or "").lower()
    try:
        curr_port = parsed_curr.port or (443 if parsed_curr.scheme == "https" else 80)
        dest_port = parsed_dest.port or (443 if parsed_dest.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeTargetError(f"Invalid port in redirect URL: {exc}") from exc

    # 1. Scheme check
    if parsed_dest.scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(
            f"Unsafe redirect scheme: {parsed_dest.scheme!r}. Only http and https are permitted."
        )

    # 2. Cloud metadata block
    if dest_host in BLOCKED_HOSTS:
        raise UnsafeTargetError("Redirect destination is a blocked cloud metadata endpoint.")

    # 3. If current URL is an authorized local development target:
    # Redirect MUST remain on the authorized host and preserve the selected port!
    is_curr_local_dev = curr_host in settings.LOCAL_DEV_ALLOWED_HOSTS
    is_dest_local_dev = dest_host in settings.LOCAL_DEV_ALLOWED_HOSTS

    if is_curr_local_dev:
        if not is_dest_local_dev or dest_port != curr_port:
            raise UnsafeTargetError(
                f"Unsafe redirect: unexpected address or port change from {current_url} to {dest_url} "
                f"(redirects must remain on the authorized host and port {curr_port})."
            )
        return validate_target_url(dest_url, allow_private=allow_private, allow_local_dev=allow_local_dev)

    # 4. If current URL is an external target:
    # Redirect cannot change address to an internal/private or local development target.
    if is_dest_local_dev:
        raise UnsafeTargetError(
            f"Unsafe redirect destination: redirect from external target to local development host is blocked: {dest_url}"
        )

    if not is_same_origin(current_url, dest_url) and not allow_private:
        # Verify dest_url does not resolve to private address or metadata
        try:
            validate_target_url(dest_url, allow_private=False, allow_local_dev=False)
        except UnsafeTargetError as exc:
            raise UnsafeTargetError(
                f"Unsafe redirect destination: unexpected private/unapproved address: {dest_url}"
            ) from exc

    return validate_target_url(dest_url, allow_private=allow_private, allow_local_dev=allow_local_dev)


def is_same_origin(base_url: str, candidate_url: str) -> bool:
    b = urlparse(base_url)
    c = urlparse(candidate_url)
    b_port = b.port or (443 if b.scheme == "https" else 80)
    c_port = c.port or (443 if c.scheme == "https" else 80)
    b_host = (b.hostname or "").lower()
    c_host = (c.hostname or "").lower()

    # For containerized local development targets, treat host.docker.internal and localhost as matching origin if port matches
    if b_host in settings.LOCAL_DEV_ALLOWED_HOSTS and c_host in settings.LOCAL_DEV_ALLOWED_HOSTS:
        return b.scheme == c.scheme and b_port == c_port

    return (b.scheme, b_host, b_port) == (c.scheme, c_host, c_port)
