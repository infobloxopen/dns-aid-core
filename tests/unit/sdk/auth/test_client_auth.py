# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: AgentClient.invoke() with auth handlers."""

from __future__ import annotations

import json

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth.simple import BearerAuthHandler
from dns_aid.sdk.client import AgentClient


def _make_agent(
    auth_type: str | None = None,
    auth_config: dict | None = None,
) -> AgentRecord:
    return AgentRecord(
        name="test-agent",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        auth_type=auth_type,
        auth_config=auth_config,
    )


def _mock_transport_capturing_headers():
    """Return a transport that captures request headers and returns a valid MCP response."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        body = {"jsonrpc": "2.0", "result": {"tools": []}, "id": 1}
        return httpx.Response(
            200,
            json=body,
            headers={"Content-Type": "application/json"},
            request=request,
        )

    return httpx.MockTransport(handler), captured


class TestClientAuthIntegration:
    @pytest.mark.asyncio
    async def test_invoke_with_bearer_credentials(self) -> None:
        """invoke() resolves Bearer auth from agent metadata + credentials."""
        agent = _make_agent(auth_type="bearer")
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                credentials={"token": "my-secret-token"},
            )

        assert result.success
        assert captured["headers"]["authorization"] == "Bearer my-secret-token"

    @pytest.mark.asyncio
    async def test_invoke_with_api_key_credentials(self) -> None:
        """invoke() resolves API key auth from agent metadata + credentials."""
        agent = _make_agent(
            auth_type="api_key",
            auth_config={"header_name": "X-Custom-Key"},
        )
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                credentials={"api_key": "sk-test-123"},
            )

        assert result.success
        assert captured["headers"]["x-custom-key"] == "sk-test-123"

    @pytest.mark.asyncio
    async def test_invoke_with_explicit_auth_handler(self) -> None:
        """Explicit auth_handler overrides agent metadata."""
        agent = _make_agent(auth_type="api_key")  # metadata says api_key
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        # Override with a bearer handler
        handler = BearerAuthHandler(token="override-token")

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                auth_handler=handler,
            )

        assert result.success
        assert captured["headers"]["authorization"] == "Bearer override-token"

    @pytest.mark.asyncio
    async def test_invoke_no_auth_when_type_none(self) -> None:
        """No auth applied when agent auth_type is 'none'."""
        agent = _make_agent(auth_type="none")
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.success
        assert "authorization" not in captured["headers"]

    @pytest.mark.asyncio
    async def test_invoke_no_auth_when_no_credentials(self) -> None:
        """Auth skipped when agent requires it but no credentials provided."""
        agent = _make_agent(auth_type="bearer")
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.success
        assert "authorization" not in captured["headers"]

    @pytest.mark.asyncio
    async def test_invoke_no_auth_when_no_auth_type(self) -> None:
        """No auth applied when agent has no auth_type field."""
        agent = _make_agent()  # auth_type=None
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.success
        assert "authorization" not in captured["headers"]
