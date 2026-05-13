# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""SDK-level tests for ``verify_freshness_seconds`` opt-in re-verify.

Covers OWASP MAESTRO BV-9 (TOCTOU between verify and invoke):

- Fresh agent (or budget disabled) → no re-resolve, handler invoked
- Stale agent + match → fresh record adopted, handler invoked
- Stale agent + drift → invocation refused with StaleDiscoveryDrift
- Stale agent + re-resolve failure → invocation refused
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient, _reverify_agent
from dns_aid.sdk.models import InvocationStatus


def _make_agent(discovered_at: float | None, target_host: str = "mcp.example.com") -> AgentRecord:
    return AgentRecord(
        name="network",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host=target_host,
        port=443,
        capabilities=["ipam"],
        version="1.0.0",
        cap_sha256="abc",
        discovered_at=discovered_at,
    )


def _build_success_raw():
    from dns_aid.sdk.protocols.base import RawResponse

    return RawResponse(
        success=True,
        status=InvocationStatus.SUCCESS,
        data={},
        http_status_code=200,
        invocation_latency_ms=1.0,
        ttfb_ms=1.0,
        response_size_bytes=0,
        headers={},
    )


# ---------------------------------------------------------------------------
# _reverify_agent — pure helper
# ---------------------------------------------------------------------------


async def test_reverify_returns_fresh_when_essentials_match() -> None:
    cached = _make_agent(discovered_at=time.time() - 10)
    fresh = _make_agent(discovered_at=time.time())
    result = DiscoveryResult(
        query="_agents.example.com",
        domain="example.com",
        agents=[fresh],
    )
    with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=result)):
        out_agent, reason = await _reverify_agent(cached)
    assert reason is None
    assert out_agent is not None
    assert out_agent.target_host == "mcp.example.com"


async def test_reverify_detects_target_host_drift() -> None:
    cached = _make_agent(discovered_at=time.time() - 10, target_host="mcp.example.com")
    fresh = _make_agent(discovered_at=time.time(), target_host="attacker.example.com")
    result = DiscoveryResult(query="_agents.example.com", domain="example.com", agents=[fresh])
    with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=result)):
        out_agent, reason = await _reverify_agent(cached)
    assert out_agent is None
    assert reason is not None
    assert "drift" in reason.lower()


async def test_reverify_detects_cap_sha256_rotation_bv2() -> None:
    """Publisher rotated cap-doc and updated SVCB cap-sha256 (OWASP MAESTRO BV-2).

    Same target host and port, but cap_sha256 has changed — the rug-pull case
    where the agent advertises an entirely new capability document. Drift must
    be detected and the invocation refused; clients that previously cached the
    cap-doc cannot be silently steered to a new contract.
    """
    cached = _make_agent(discovered_at=time.time() - 10)  # cap_sha256='abc'
    fresh = _make_agent(discovered_at=time.time())
    fresh.cap_sha256 = "different-hash"  # publisher rotated
    result = DiscoveryResult(query="_agents.example.com", domain="example.com", agents=[fresh])
    with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=result)):
        out_agent, reason = await _reverify_agent(cached)
    assert out_agent is None
    assert reason is not None
    assert "drift" in reason.lower()


async def test_reverify_detects_missing_agent() -> None:
    cached = _make_agent(discovered_at=time.time() - 10)
    result = DiscoveryResult(query="_agents.example.com", domain="example.com", agents=[])
    with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=result)):
        out_agent, reason = await _reverify_agent(cached)
    assert out_agent is None
    assert reason is not None
    assert "missing" in reason.lower()


async def test_reverify_handles_resolver_exception() -> None:
    cached = _make_agent(discovered_at=time.time() - 10)
    with patch(
        "dns_aid.core.discoverer.discover",
        new=AsyncMock(side_effect=RuntimeError("simulated dns failure")),
    ):
        out_agent, reason = await _reverify_agent(cached)
    assert out_agent is None
    assert reason is not None
    assert "re-resolve failed" in reason


# ---------------------------------------------------------------------------
# AgentClient.invoke — freshness gating
# ---------------------------------------------------------------------------


async def test_disabled_freshness_skips_reverify() -> None:
    """verify_freshness_seconds=0 → never re-verifies (today's default)."""
    cached = _make_agent(discovered_at=time.time() - 1_000_000)  # very stale
    config = SDKConfig(verify_freshness_seconds=0)
    reverify_mock = AsyncMock()

    with (
        patch("dns_aid.sdk.client._reverify_agent", new=reverify_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())
        async with AgentClient(config=config) as client:
            await client.invoke(cached)

    reverify_mock.assert_not_called()


async def test_fresh_agent_skips_reverify() -> None:
    """Within budget → no re-verify even when feature is enabled."""
    cached = _make_agent(discovered_at=time.time())
    config = SDKConfig(verify_freshness_seconds=60)
    reverify_mock = AsyncMock()

    with (
        patch("dns_aid.sdk.client._reverify_agent", new=reverify_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())
        async with AgentClient(config=config) as client:
            await client.invoke(cached)

    reverify_mock.assert_not_called()


async def test_missing_discovered_at_skips_reverify() -> None:
    """Records constructed outside discover() (no timestamp) → backward-compatible passthrough."""
    cached = _make_agent(discovered_at=None)
    config = SDKConfig(verify_freshness_seconds=60)
    reverify_mock = AsyncMock()

    with (
        patch("dns_aid.sdk.client._reverify_agent", new=reverify_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())
        async with AgentClient(config=config) as client:
            await client.invoke(cached)

    reverify_mock.assert_not_called()


async def test_stale_agent_reverify_match_proceeds() -> None:
    """Stale + match → fresh record adopted, handler invoked."""
    cached = _make_agent(discovered_at=time.time() - 120)
    fresh = _make_agent(discovered_at=time.time())
    config = SDKConfig(verify_freshness_seconds=30)

    with (
        patch(
            "dns_aid.sdk.client._reverify_agent",
            new=AsyncMock(return_value=(fresh, None)),
        ),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())
        async with AgentClient(config=config) as client:
            result = await client.invoke(cached)

    handler.invoke.assert_awaited_once()
    assert result.success is True


async def test_stale_agent_reverify_drift_refuses() -> None:
    """Stale + drift → invocation refused, handler not called."""
    cached = _make_agent(discovered_at=time.time() - 120)
    config = SDKConfig(verify_freshness_seconds=30)

    with (
        patch(
            "dns_aid.sdk.client._reverify_agent",
            new=AsyncMock(return_value=(None, "essential fields drifted")),
        ),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())
        async with AgentClient(config=config) as client:
            result = await client.invoke(cached)

    handler.invoke.assert_not_called()
    assert result.success is False
    assert result.signal.status == InvocationStatus.REFUSED
    assert result.signal.error_type == "StaleDiscoveryDrift"
    assert "drifted" in (result.signal.error_message or "")


async def test_stale_agent_reverify_failure_refuses() -> None:
    """Stale + re-resolve failure → invocation refused."""
    cached = _make_agent(discovered_at=time.time() - 120)
    config = SDKConfig(verify_freshness_seconds=30)

    with (
        patch(
            "dns_aid.sdk.client._reverify_agent",
            new=AsyncMock(return_value=(None, "re-resolve failed: timeout")),
        ),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())
        async with AgentClient(config=config) as client:
            result = await client.invoke(cached)

    handler.invoke.assert_not_called()
    assert result.signal.error_type == "StaleDiscoveryDrift"
