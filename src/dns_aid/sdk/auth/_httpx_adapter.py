# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Bridge dns-aid AuthHandler implementations to httpx.Auth.

The official MCP Python SDK's `streamablehttp_client` accepts
``auth: httpx.Auth | None``. dns-aid's existing AuthHandler interface
(in ``base.py``) exposes an async ``apply(request)`` method instead.
This adapter wraps the latter so it can be passed to the former.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import httpx

from dns_aid.sdk.auth.base import AuthHandler


class _DnsAidHttpxAuth(httpx.Auth):
    """Wrap a dns-aid ``AuthHandler`` so it satisfies the ``httpx.Auth`` protocol."""

    requires_request_body = False  # httpx.Auth instance attribute (overridden per-class)

    def __init__(self, handler: AuthHandler) -> None:
        self._handler = handler

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """Apply credentials to *request* and yield it once.

        dns-aid AuthHandlers are stateless per-request (no challenge/response
        flow). A single yield is correct; httpx will not re-enter for retries.
        """
        request = await self._handler.apply(request)
        yield request


def to_httpx_auth(handler: AuthHandler | None) -> httpx.Auth | None:
    """Convert a dns-aid ``AuthHandler`` (or ``None``) into an ``httpx.Auth``.

    Returns ``None`` when *handler* is ``None`` so callers can pass the
    result directly to ``streamablehttp_client(auth=...)``.
    """
    return _DnsAidHttpxAuth(handler) if handler is not None else None
