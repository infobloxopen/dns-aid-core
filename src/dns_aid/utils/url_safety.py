"""
URL safety validation for DNS-AID.

Prevents SSRF attacks by enforcing HTTPS-only and blocking
requests to private/loopback/link-local IP addresses.
"""

from __future__ import annotations

import ipaddress
import os
import socket

import structlog

logger = structlog.get_logger(__name__)


class UnsafeURLError(ValueError):
    """Raised when a URL fails safety validation."""


def validate_fetch_url(url: str) -> str:
    """
    Validate that a URL is safe to fetch.

    Enforces:
    - HTTPS scheme only (no http://, file://, etc.)
    - Resolved IP must not be private, loopback, or link-local
    - Allows override via DNS_AID_FETCH_ALLOWLIST env var

    Args:
        url: The URL to validate.

    Returns:
        The validated URL (unchanged).

    Raises:
        UnsafeURLError: If the URL fails validation.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)

    # Enforce HTTPS
    if parsed.scheme != "https":
        raise UnsafeURLError(f"Only HTTPS URLs are allowed, got scheme '{parsed.scheme}': {url}")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURLError(f"URL has no hostname: {url}")

    # Check allowlist
    allowlist = _get_allowlist()
    if allowlist and hostname in allowlist:
        logger.debug("URL hostname in allowlist, skipping IP check", hostname=hostname)
        return url

    # Resolve hostname and check IP addresses
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURLError(f"Cannot resolve hostname '{hostname}': {e}") from e

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise UnsafeURLError(
                f"URL resolves to non-public IP {ip_str} (hostname '{hostname}'): {url}"
            )

    return url


def _get_allowlist() -> set[str]:
    """Get the fetch allowlist from environment variable."""
    raw = os.environ.get("DNS_AID_FETCH_ALLOWLIST", "")
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}
