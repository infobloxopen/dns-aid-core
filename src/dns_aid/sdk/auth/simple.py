# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Simple auth handlers: Noop, API key, Bearer token."""

from __future__ import annotations

import httpx

from dns_aid.sdk.auth.base import AuthHandler


class NoopAuthHandler(AuthHandler):
    """Pass-through — no authentication applied."""

    @property
    def auth_type(self) -> str:
        return "none"

    def __repr__(self) -> str:
        return "NoopAuthHandler()"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        return request


class ApiKeyAuthHandler(AuthHandler):
    """Inject an API key into a header or query parameter.

    Args:
        api_key: The API key value.
        header_name: Header to inject into (default ``X-API-Key``).
        location: ``"header"`` (default) or ``"query"``.
        query_param: Query parameter name when *location* is ``"query"``
            (default ``api_key``).
    """

    def __init__(
        self,
        api_key: str,
        *,
        header_name: str = "X-API-Key",
        location: str = "header",
        query_param: str = "api_key",
    ) -> None:
        self._api_key = api_key
        self._header_name = header_name
        self._location = location
        self._query_param = query_param

    @property
    def auth_type(self) -> str:
        return "api_key"

    def __repr__(self) -> str:
        return f"ApiKeyAuthHandler(header={self._header_name!r}, location={self._location!r})"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        if self._location == "query":
            # Append API key as query parameter
            url = request.url.copy_merge_params({self._query_param: self._api_key})
            request.url = url
        else:
            request.headers[self._header_name] = self._api_key
        return request


class BearerAuthHandler(AuthHandler):
    """Set ``Authorization: Bearer <token>`` header.

    Args:
        token: The bearer token value.
        header_name: Header name (default ``Authorization``).
    """

    def __init__(
        self,
        token: str,
        *,
        header_name: str = "Authorization",
    ) -> None:
        self._token = token
        self._header_name = header_name

    @property
    def auth_type(self) -> str:
        return "bearer"

    def __repr__(self) -> str:
        return f"BearerAuthHandler(header={self._header_name!r})"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        request.headers[self._header_name] = f"Bearer {self._token}"
        return request
