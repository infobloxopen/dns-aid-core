# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.core.invoke — shared invocation functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.core.invoke import (
    InvokeResult,
    _build_agent_record_from_endpoint,
    _invoke_raw_a2a,
    build_a2a_message_params,
    extract_a2a_response_text,
    extract_mcp_content,
    normalize_endpoint,
    send_a2a_message,
)

# ---------------------------------------------------------------------------
# Pure utility tests
# ---------------------------------------------------------------------------


class TestNormalizeEndpoint:
    def test_adds_https(self):
        assert normalize_endpoint("example.com") == "https://example.com"

    def test_strips_trailing_slash(self):
        assert normalize_endpoint("https://example.com/") == "https://example.com"

    def test_preserves_http(self):
        assert normalize_endpoint("http://localhost:8080") == "http://localhost:8080"

    def test_preserves_path(self):
        assert normalize_endpoint("https://example.com/mcp") == "https://example.com/mcp"


class TestBuildA2AMessageParams:
    def test_structure(self):
        params = build_a2a_message_params("Hello")
        assert "message" in params
        msg = params["message"]
        assert msg["role"] == "user"
        assert msg["parts"] == [{"kind": "text", "text": "Hello"}]
        assert "messageId" in msg  # UUID generated

    def test_unique_message_ids(self):
        p1 = build_a2a_message_params("a")
        p2 = build_a2a_message_params("b")
        assert p1["message"]["messageId"] != p2["message"]["messageId"]


class TestExtractA2AResponseText:
    def test_artifacts_parts(self):
        data = {
            "result": {
                "artifacts": [
                    {
                        "parts": [
                            {"kind": "text", "text": "Hello"},
                            {"kind": "text", "text": "World"},
                        ]
                    }
                ]
            }
        }
        assert extract_a2a_response_text(data) == "Hello\nWorld"

    def test_direct_parts(self):
        data = {"result": {"parts": [{"kind": "text", "text": "Direct"}]}}
        assert extract_a2a_response_text(data) == "Direct"

    def test_content_array(self):
        data = {"result": {"content": [{"text": "Content"}]}}
        assert extract_a2a_response_text(data) == "Content"

    def test_content_string(self):
        data = {"result": {"content": ["Plain string"]}}
        assert extract_a2a_response_text(data) == "Plain string"

    def test_empty_result(self):
        assert extract_a2a_response_text({}) is None
        assert extract_a2a_response_text({"result": {}}) is None


class TestExtractMCPContent:
    def test_content_array_json(self):
        result = {"result": {"content": [{"text": '{"key": "value"}'}]}}
        assert extract_mcp_content(result) == {"key": "value"}

    def test_content_array_plain_text(self):
        result = {"result": {"content": [{"text": "just text"}]}}
        assert extract_mcp_content(result) == "just text"

    def test_passthrough(self):
        result = {"result": {"tools": [{"name": "t1"}]}}
        assert extract_mcp_content(result) == {"tools": [{"name": "t1"}]}

    def test_none_result(self):
        assert extract_mcp_content({}) is None
        assert extract_mcp_content({"result": None}) is None


class TestBuildAgentRecord:
    def test_simple_url(self):
        agent = _build_agent_record_from_endpoint("https://booking.example.com:443")
        assert agent.target_host == "booking.example.com"
        assert agent.port == 443
        assert agent.domain == "example.com"

    def test_url_with_path(self):
        agent = _build_agent_record_from_endpoint("https://mcp.example.com/mcp")
        assert agent.endpoint_override == "https://mcp.example.com/mcp"

    def test_protocol_mapping(self):
        from dns_aid.core.models import Protocol

        mcp = _build_agent_record_from_endpoint("https://h.com", protocol="mcp")
        assert mcp.protocol == Protocol.MCP
        a2a = _build_agent_record_from_endpoint("https://h.com", protocol="a2a")
        assert a2a.protocol == Protocol.A2A


# ---------------------------------------------------------------------------
# Raw invocation tests (mocked httpx)
# ---------------------------------------------------------------------------


class TestInvokeRawA2A:
    @pytest.mark.asyncio
    async def test_success(self):
        mock_response = httpx.Response(
            200,
            json={"result": {"artifacts": [{"parts": [{"kind": "text", "text": "Hi"}]}]}},
            request=httpx.Request("POST", "https://agent.example.com"),
        )

        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is True
        assert isinstance(result.data, dict)

    @pytest.mark.asyncio
    async def test_timeout(self):
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.TimeoutException("timed out")
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 5.0)

        assert result.success is False
        assert "5" in result.error

    @pytest.mark.asyncio
    async def test_http_403(self):
        mock_response = httpx.Response(
            403,
            text="Forbidden",
            request=httpx.Request("POST", "https://agent.example.com"),
        )

        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is False
        assert "403" in result.error


# NOTE: TestInvokeRawMCP and TestCallMCPToolNoSDK / TestListMCPToolsNoSDK were
# removed when MCP transport was unified onto the modern Streamable HTTP path
# (feature 001-mcp-streamable-http). The legacy `_invoke_raw_mcp` helper has
# been deleted; the _sdk_available toggle no longer gates MCP. Modern transport
# behavior is covered by tests/unit/sdk/protocols/test_mcp_streamable.py and
# legacy fallback by tests/unit/sdk/test_mcp_handler.py.


# ---------------------------------------------------------------------------
# Public API tests (A2A no-SDK path retained — A2A is out of scope for the
# transport unification; its raw helper still exists.)
# ---------------------------------------------------------------------------


class TestSendA2AMessageNoSDK:
    @pytest.mark.asyncio
    async def test_extracts_response_text(self):
        mock_response = httpx.Response(
            200,
            json={
                "result": {"artifacts": [{"parts": [{"kind": "text", "text": "I am an agent"}]}]}
            },
            request=httpx.Request("POST", "https://a.example.com"),
        )

        with (
            patch("dns_aid.core.invoke._sdk_available", False),
            patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient,
        ):
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await send_a2a_message("https://a.example.com", "Hello")

        assert result.success is True
        assert result.data["response_text"] == "I am an agent"


# NOTE: TestCallMCPToolNoSDK / TestListMCPToolsNoSDK removed alongside the
# deletion of `_invoke_raw_mcp` and the `_sdk_available` toggle gating MCP.
# Coverage of the modern path lives in tests/unit/sdk/protocols/test_mcp_streamable.py
# and the legacy fallback in tests/unit/sdk/test_mcp_handler.py.


class TestInvokeResult:
    def test_defaults(self):
        r = InvokeResult(success=True)
        assert r.data is None
        assert r.error is None
        assert r.telemetry is None

    def test_with_telemetry(self):
        r = InvokeResult(
            success=True,
            data={"key": "val"},
            telemetry={"latency_ms": 42.0, "status": "success"},
        )
        assert r.telemetry["latency_ms"] == 42.0
