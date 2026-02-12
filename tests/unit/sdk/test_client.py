# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for AgentClient."""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

from dns_aid.core.models import AgentRecord
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.models import InvocationStatus


@pytest.fixture
def config() -> SDKConfig:
    return SDKConfig(timeout_seconds=5.0, caller_id="test-agent")


class TestAgentClient:
    @pytest.mark.asyncio
    async def test_context_manager(self, config: SDKConfig) -> None:
        """Test that client opens and closes cleanly."""
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
        assert client._http_client is None

    @pytest.mark.asyncio
    async def test_invoke_without_context_manager_raises(
        self, config: SDKConfig, sample_mcp_agent: AgentRecord
    ) -> None:
        """Test that invoke raises if not used as context manager."""
        client = AgentClient(config=config)
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.invoke(sample_mcp_agent, method="tools/list")

    @pytest.mark.asyncio
    async def test_invoke_mcp_success(
        self, config: SDKConfig, sample_mcp_agent: AgentRecord
    ) -> None:
        """Test successful MCP invocation through the client."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": json.dumps({"tools": ["ping"]})}]},
            "id": 1,
        }
        mock_resp = httpx.Response(200, json=rpc_response)
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with AgentClient(config=config) as client:
            # Replace the internal httpx client with our mock
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)

            result = await client.invoke(sample_mcp_agent, method="tools/list")

        assert result.success is True
        assert result.data == {"tools": ["ping"]}
        assert result.signal.status == InvocationStatus.SUCCESS
        assert result.signal.agent_fqdn == sample_mcp_agent.fqdn
        assert result.signal.protocol == "mcp"
        assert result.signal.method == "tools/list"
        assert result.signal.caller_id == "test-agent"
        assert result.signal.invocation_latency_ms > 0

    @pytest.mark.asyncio
    async def test_invoke_mcp_error(self, config: SDKConfig, sample_mcp_agent: AgentRecord) -> None:
        """Test MCP invocation with server error."""
        mock_resp = httpx.Response(500, text="Internal Server Error")
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)

            result = await client.invoke(sample_mcp_agent, method="tools/call")

        assert result.success is False
        assert result.signal.status == InvocationStatus.ERROR
        assert result.signal.http_status_code == 500

    @pytest.mark.asyncio
    async def test_invoke_mcp_timeout(
        self, config: SDKConfig, sample_mcp_agent: AgentRecord
    ) -> None:
        """Test MCP invocation timeout."""

        def raise_timeout(req: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out")

        transport = httpx.MockTransport(raise_timeout)

        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)

            result = await client.invoke(sample_mcp_agent, method="tools/list")

        assert result.success is False
        assert result.signal.status == InvocationStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_unsupported_protocol(self, config: SDKConfig) -> None:
        """Test that unsupported protocol raises ValueError."""
        from dns_aid.core.models import AgentRecord, Protocol

        # Create an agent with a protocol not registered in handlers
        agent = AgentRecord(
            name="test",
            domain="example.com",
            protocol=Protocol.MCP,  # We'll override the protocol string
            target_host="example.com",
            port=443,
        )
        async with AgentClient(config=config) as client:
            # Temporarily remove MCP handler to test unsupported path
            from dns_aid.sdk.client import _HANDLERS

            saved = _HANDLERS.copy()
            _HANDLERS.clear()
            try:
                with pytest.raises(ValueError, match="Unsupported protocol"):
                    await client.invoke(agent, method="test")
            finally:
                _HANDLERS.update(saved)

    @pytest.mark.asyncio
    async def test_collector_records_signals(
        self, config: SDKConfig, sample_mcp_agent: AgentRecord
    ) -> None:
        """Test that the collector accumulates signals across invocations."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": '"ok"'}]},
            "id": 1,
        }
        mock_resp = httpx.Response(200, json=rpc_response)
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)

            await client.invoke(sample_mcp_agent, method="tools/list")
            await client.invoke(sample_mcp_agent, method="tools/call")

        assert len(client.collector.signals) == 2
        assert client.collector.signals[0].method == "tools/list"
        assert client.collector.signals[1].method == "tools/call"

    @pytest.mark.asyncio
    async def test_scorecard_from_collector(
        self, config: SDKConfig, sample_mcp_agent: AgentRecord
    ) -> None:
        """Test scorecard computation from collector."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": '"ok"'}]},
            "id": 1,
        }
        mock_resp = httpx.Response(200, json=rpc_response)
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)

            for _ in range(5):
                await client.invoke(sample_mcp_agent, method="tools/call")

        sc = client.collector.scorecard(sample_mcp_agent.fqdn)
        assert sc.total_invocations == 5
        assert sc.success_count == 5
        assert sc.success_rate == 100.0
        assert sc.composite_score > 0

    @pytest.mark.asyncio
    async def test_custom_timeout_override(
        self, config: SDKConfig, sample_mcp_agent: AgentRecord
    ) -> None:
        """Test per-call timeout override."""

        def capture(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "result": None, "id": 1},
            )

        transport = httpx.MockTransport(capture)

        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport, timeout=1.0)

            result = await client.invoke(sample_mcp_agent, method="tools/list", timeout=1.0)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_config_from_env(self) -> None:
        """Test SDK config from environment variables."""
        env = {
            "DNS_AID_SDK_TIMEOUT": "10",
            "DNS_AID_SDK_CALLER_ID": "env-caller",
            "DNS_AID_SDK_CONSOLE_SIGNALS": "true",
        }
        with patch.dict("os.environ", env, clear=False):
            config = SDKConfig.from_env()
        assert config.timeout_seconds == 10.0
        assert config.caller_id == "env-caller"
        assert config.console_signals is True

    def test_register_handler(self) -> None:
        """Test custom handler registration."""
        from dns_aid.sdk.protocols.base import ProtocolHandler, RawResponse

        class DummyHandler(ProtocolHandler):
            @property
            def protocol_name(self) -> str:
                return "dummy"

            async def invoke(self, client, endpoint, method, arguments, timeout):
                return RawResponse(
                    success=True,
                    status=InvocationStatus.SUCCESS,
                    invocation_latency_ms=0,
                )

        AgentClient.register_handler("dummy", DummyHandler)
        # Verify it's registered
        from dns_aid.sdk.client import _HANDLERS

        assert "dummy" in _HANDLERS
        # Cleanup
        del _HANDLERS["dummy"]
