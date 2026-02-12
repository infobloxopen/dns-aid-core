# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for MCP protocol handler."""

from __future__ import annotations

import json

import httpx
import pytest

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.mcp import MCPProtocolHandler


@pytest.fixture
def handler() -> MCPProtocolHandler:
    return MCPProtocolHandler()


class TestMCPProtocolHandler:
    def test_protocol_name(self, handler: MCPProtocolHandler) -> None:
        assert handler.protocol_name == "mcp"

    @pytest.mark.asyncio
    async def test_successful_tools_list(self, handler: MCPProtocolHandler) -> None:
        """Test successful tools/list invocation."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": json.dumps({"tools": ["ping", "traceroute"]})}]
            },
            "id": 1,
        }
        mock_response = httpx.Response(
            200,
            json=rpc_response,
            headers={"x-cost-units": "0.5", "x-cost-currency": "USD"},
        )

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/list",
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.status == InvocationStatus.SUCCESS
        assert raw.data == {"tools": ["ping", "traceroute"]}
        assert raw.http_status_code == 200
        assert raw.cost_units == 0.5
        assert raw.cost_currency == "USD"
        assert raw.invocation_latency_ms > 0
        assert raw.response_size_bytes is not None
        assert raw.response_size_bytes > 0

    @pytest.mark.asyncio
    async def test_successful_tools_call(self, handler: MCPProtocolHandler) -> None:
        """Test successful tools/call invocation."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": json.dumps({"result": "pong"})}]},
            "id": 1,
        }
        mock_response = httpx.Response(200, json=rpc_response)

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/call",
                arguments={"name": "ping", "arguments": {"host": "1.1.1.1"}},
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.data == {"result": "pong"}

    @pytest.mark.asyncio
    async def test_rpc_error(self, handler: MCPProtocolHandler) -> None:
        """Test JSON-RPC error response."""
        rpc_response = {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": 1,
        }
        mock_response = httpx.Response(200, json=rpc_response)

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="unknown/method",
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is False
        assert raw.status == InvocationStatus.ERROR
        assert raw.error_type == "RPCError"
        assert "Method not found" in (raw.error_message or "")

    @pytest.mark.asyncio
    async def test_http_error(self, handler: MCPProtocolHandler) -> None:
        """Test non-200 HTTP response."""
        mock_response = httpx.Response(503, text="Service Unavailable")

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/list",
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is False
        assert raw.status == InvocationStatus.ERROR
        assert raw.http_status_code == 503
        assert "503" in (raw.error_message or "")

    @pytest.mark.asyncio
    async def test_timeout(self, handler: MCPProtocolHandler) -> None:
        """Test timeout handling."""

        def raise_timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Read timed out")

        transport = httpx.MockTransport(raise_timeout)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/list",
                arguments=None,
                timeout=0.1,
            )

        assert raw.success is False
        assert raw.status == InvocationStatus.TIMEOUT
        assert raw.error_type == "TimeoutError"
        assert raw.invocation_latency_ms > 0

    @pytest.mark.asyncio
    async def test_connection_refused(self, handler: MCPProtocolHandler) -> None:
        """Test connection refused handling."""

        def raise_connect_error(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(raise_connect_error)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/list",
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is False
        assert raw.status == InvocationStatus.REFUSED
        assert raw.error_type == "ConnectError"

    @pytest.mark.asyncio
    async def test_invalid_json_response(self, handler: MCPProtocolHandler) -> None:
        """Test handling of non-JSON response body."""
        mock_response = httpx.Response(
            200,
            content=b"not json",
            headers={"content-type": "text/plain"},
        )

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/list",
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is False
        assert raw.status == InvocationStatus.ERROR
        assert raw.error_type == "JSONDecodeError"

    @pytest.mark.asyncio
    async def test_plain_text_content(self, handler: MCPProtocolHandler) -> None:
        """Test MCP response with plain text (non-JSON) content."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": "Hello, I am an agent"}]},
            "id": 1,
        }
        mock_response = httpx.Response(200, json=rpc_response)

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/call",
                arguments={"name": "greet"},
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.data == "Hello, I am an agent"

    @pytest.mark.asyncio
    async def test_null_result(self, handler: MCPProtocolHandler) -> None:
        """Test MCP response with null result."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": None,
            "id": 1,
        }
        mock_response = httpx.Response(200, json=rpc_response)

        transport = httpx.MockTransport(lambda req: mock_response)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method="tools/call",
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.data is None

    @pytest.mark.asyncio
    async def test_default_method(self, handler: MCPProtocolHandler) -> None:
        """Test that method defaults to tools/list when None."""
        captured_request = {}

        def capture_request(request: httpx.Request) -> httpx.Response:
            captured_request["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "result": {"content": []}, "id": 1},
            )

        transport = httpx.MockTransport(capture_request)
        async with httpx.AsyncClient(transport=transport) as client:
            await handler.invoke(
                client=client,
                endpoint="https://mcp.example.com/rpc",
                method=None,
                arguments=None,
                timeout=5.0,
            )

        assert captured_request["body"]["method"] == "tools/list"
