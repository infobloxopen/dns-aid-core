# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for simple auth handlers: Noop, ApiKey, Bearer."""

from __future__ import annotations

import pytest
import httpx

from dns_aid.sdk.auth.simple import (
    ApiKeyAuthHandler,
    BearerAuthHandler,
    NoopAuthHandler,
)


@pytest.fixture
def _build_request() -> httpx.Request:
    """Build a sample POST request for testing."""
    return httpx.Request(
        "POST",
        "https://agent.example.com/mcp",
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        headers={"Content-Type": "application/json"},
    )


class TestNoopAuthHandler:
    @pytest.mark.asyncio
    async def test_passthrough(self, _build_request: httpx.Request) -> None:
        handler = NoopAuthHandler()
        result = await handler.apply(_build_request)
        assert result is _build_request
        assert "Authorization" not in result.headers

    def test_auth_type(self) -> None:
        assert NoopAuthHandler().auth_type == "none"


class TestApiKeyAuthHandler:
    @pytest.mark.asyncio
    async def test_header_injection(self, _build_request: httpx.Request) -> None:
        handler = ApiKeyAuthHandler(api_key="sk-test-123")
        result = await handler.apply(_build_request)
        assert result.headers["X-API-Key"] == "sk-test-123"

    @pytest.mark.asyncio
    async def test_custom_header_name(self, _build_request: httpx.Request) -> None:
        handler = ApiKeyAuthHandler(api_key="my-key", header_name="X-Custom-Auth")
        result = await handler.apply(_build_request)
        assert result.headers["X-Custom-Auth"] == "my-key"

    @pytest.mark.asyncio
    async def test_query_param_injection(self, _build_request: httpx.Request) -> None:
        handler = ApiKeyAuthHandler(
            api_key="qk-456",
            location="query",
            query_param="key",
        )
        result = await handler.apply(_build_request)
        assert "key=qk-456" in str(result.url)

    def test_auth_type(self) -> None:
        assert ApiKeyAuthHandler(api_key="x").auth_type == "api_key"


class TestBearerAuthHandler:
    @pytest.mark.asyncio
    async def test_authorization_header(self, _build_request: httpx.Request) -> None:
        handler = BearerAuthHandler(token="eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9")
        result = await handler.apply(_build_request)
        assert result.headers["Authorization"] == "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"

    @pytest.mark.asyncio
    async def test_custom_header_name(self, _build_request: httpx.Request) -> None:
        handler = BearerAuthHandler(token="tok", header_name="X-Bearer")
        result = await handler.apply(_build_request)
        assert result.headers["X-Bearer"] == "Bearer tok"

    def test_auth_type(self) -> None:
        assert BearerAuthHandler(token="x").auth_type == "bearer"
