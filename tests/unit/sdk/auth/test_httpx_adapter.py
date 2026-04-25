# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dns-aid AuthHandler -> httpx.Auth adapter."""

from __future__ import annotations

import httpx
import pytest

from dns_aid.sdk.auth._httpx_adapter import _DnsAidHttpxAuth, to_httpx_auth
from dns_aid.sdk.auth.base import AuthHandler


class _RecordingHandler(AuthHandler):
    """Test double that records calls and stamps a header."""

    def __init__(self) -> None:
        self.call_count = 0
        self.last_request: httpx.Request | None = None

    @property
    def auth_type(self) -> str:
        return "test-recording"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        self.call_count += 1
        self.last_request = request
        request.headers["X-Test-Auth"] = "applied"
        return request


def test_to_httpx_auth_returns_none_for_none_handler() -> None:
    assert to_httpx_auth(None) is None


def test_to_httpx_auth_wraps_real_handler() -> None:
    handler = _RecordingHandler()
    adapter = to_httpx_auth(handler)
    assert isinstance(adapter, httpx.Auth)
    assert isinstance(adapter, _DnsAidHttpxAuth)


@pytest.mark.asyncio
async def test_async_auth_flow_invokes_apply_exactly_once() -> None:
    handler = _RecordingHandler()
    adapter = _DnsAidHttpxAuth(handler)

    request = httpx.Request("POST", "https://example.com/mcp")

    flow = adapter.async_auth_flow(request)
    yielded = await flow.__anext__()

    assert handler.call_count == 1
    assert yielded is request

    # The flow should terminate after a single yield (no challenge/response loop).
    with pytest.raises(StopAsyncIteration):
        await flow.__anext__()


@pytest.mark.asyncio
async def test_async_auth_flow_propagates_request_modifications() -> None:
    handler = _RecordingHandler()
    adapter = _DnsAidHttpxAuth(handler)

    request = httpx.Request("GET", "https://example.com/mcp")
    assert "X-Test-Auth" not in request.headers

    flow = adapter.async_auth_flow(request)
    yielded = await flow.__anext__()

    assert yielded.headers.get("X-Test-Auth") == "applied"
    assert handler.last_request is yielded


def test_requires_request_body_is_false() -> None:
    """httpx.Auth contract: handlers that don't read the body must declare so."""
    assert _DnsAidHttpxAuth.requires_request_body is False
