# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

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


class ResponseTooLargeError(ValueError):
    """Raised when a response exceeds the configured size limit."""


async def safe_fetch_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    max_redirects: int = 0,
) -> bytes | None:
    """Fetch a URL with streaming size enforcement.

    Reads the response body in chunks and aborts the connection if the
    cumulative size exceeds *max_bytes*.  This prevents a malicious
    server from forcing an OOM — the oversized payload never fully
    lands in memory.

    ``Content-Length`` is checked first as a fast-path reject, but
    is not trusted (it can be spoofed or absent with chunked encoding).
    The byte-counted stream read is the authoritative guard.

    Returns the raw bytes on success, *None* on HTTP errors (non-200).

    Raises:
        ResponseTooLargeError: If the response exceeds *max_bytes*.
    """
    import httpx

    kwargs: dict = {"timeout": timeout, "follow_redirects": follow_redirects}
    if max_redirects:
        kwargs["max_redirects"] = max_redirects

    async with httpx.AsyncClient(**kwargs) as client, client.stream("GET", url) as resp:
        if resp.status_code != 200:
            return None

        # Fast-path: reject via Content-Length header if present.
        # Not authoritative (can be spoofed/absent) — stream read is.
        cl = resp.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > max_bytes:
            logger.warning(
                "Response Content-Length exceeds limit — aborting",
                url=url,
                content_length=int(cl),
                limit=max_bytes,
            )
            raise ResponseTooLargeError(
                f"Content-Length {cl} exceeds {max_bytes} byte limit: {url}"
            )

        # Stream with byte counting — the real guard.
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes(chunk_size=8192):
            total += len(chunk)
            if total > max_bytes:
                logger.warning(
                    "Response exceeded size limit mid-stream — aborting",
                    url=url,
                    bytes_read=total,
                    limit=max_bytes,
                )
                raise ResponseTooLargeError(
                    f"Response exceeded {max_bytes} byte limit at {total} bytes: {url}"
                )
            chunks.append(chunk)

        return b"".join(chunks)


def _get_allowlist() -> set[str]:
    """Get the fetch allowlist from environment variable."""
    raw = os.environ.get("DNS_AID_FETCH_ALLOWLIST", "")
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}
