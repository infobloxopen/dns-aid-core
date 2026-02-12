# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the top-level dns_aid.invoke() and dns_aid.rank() convenience API."""

from __future__ import annotations

import json

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol


class TestTopLevelInvoke:
    @pytest.mark.asyncio
    async def test_invoke_one_liner(self, sample_mcp_agent: AgentRecord) -> None:
        """Test that dns_aid.invoke() works as a one-liner."""
        rpc_response = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": json.dumps({"tools": ["ping"]})}]},
            "id": 1,
        }
        mock_resp = httpx.Response(200, json=rpc_response)
        transport = httpx.MockTransport(lambda req: mock_resp)

        # Patch the internal http client after context manager opens
        from dns_aid.sdk import AgentClient, SDKConfig

        config = SDKConfig(timeout_seconds=5.0, caller_id="test")

        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(sample_mcp_agent, method="tools/list")

        # Verify the top-level API contract
        assert result.success is True
        assert result.data == {"tools": ["ping"]}
        assert result.signal.invocation_latency_ms > 0
        assert result.signal.agent_fqdn == sample_mcp_agent.fqdn
        assert result.signal.protocol == "mcp"
        assert result.signal.method == "tools/list"

    @pytest.mark.asyncio
    async def test_invoke_is_importable(self) -> None:
        """Test that invoke is importable from the top-level package."""
        import dns_aid

        assert hasattr(dns_aid, "invoke")
        assert callable(dns_aid.invoke)

    @pytest.mark.asyncio
    async def test_rank_is_importable(self) -> None:
        """Test that rank is importable from the top-level package."""
        import dns_aid

        assert hasattr(dns_aid, "rank")
        assert callable(dns_aid.rank)

    @pytest.mark.asyncio
    async def test_sdk_classes_importable_from_top_level(self) -> None:
        """Test that SDK classes are re-exported from dns_aid."""
        import dns_aid

        assert hasattr(dns_aid, "AgentClient")
        assert hasattr(dns_aid, "SDKConfig")
        assert hasattr(dns_aid, "InvocationResult")
        assert hasattr(dns_aid, "InvocationSignal")

    @pytest.mark.asyncio
    async def test_rank_with_mock_agents(self) -> None:
        """Test ranking multiple agents through AgentClient."""
        from dns_aid.sdk import AgentClient, SDKConfig

        rpc_fast = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": '"ok"'}]},
            "id": 1,
        }
        mock_resp = httpx.Response(200, json=rpc_fast)
        transport = httpx.MockTransport(lambda req: mock_resp)

        agent_a = AgentRecord(
            name="fast",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="fast.example.com",
            port=443,
        )
        agent_b = AgentRecord(
            name="slow",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="slow.example.com",
            port=443,
        )

        config = SDKConfig(timeout_seconds=5.0)
        async with AgentClient(config=config) as client:
            await client._http_client.aclose()
            client._http_client = httpx.AsyncClient(transport=transport)

            await client.invoke(agent_a, method="tools/list")
            await client.invoke(agent_b, method="tools/list")

            ranked = client.rank()

        assert len(ranked) == 2
        # Both should have scores since both succeeded
        assert all(r.composite_score > 0 for r in ranked)
