# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""SDK-level tests for DANE preflight wiring in AgentClient.invoke().

Verifies that when prefer_dane / require_dane are set on SDKConfig, the
invocation path consults the DANE preflight before reaching the protocol
handler and refuses with a structured InvocationSignal on mismatch or
strict-mode absent.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core._dane import DanePreflightResult, DanePreflightStatus
from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient, _parse_target_port
from dns_aid.sdk.models import InvocationStatus

# ---------------------------------------------------------------------------
# _parse_target_port — URL parsing for the preflight host/port
# ---------------------------------------------------------------------------


def test_parse_target_port_https_explicit() -> None:
    assert _parse_target_port("https://agent.example.com:8443/path") == (
        "agent.example.com",
        8443,
    )


def test_parse_target_port_https_default() -> None:
    assert _parse_target_port("https://agent.example.com/") == ("agent.example.com", 443)


def test_parse_target_port_http_default() -> None:
    assert _parse_target_port("http://agent.example.com/") == ("agent.example.com", 80)


def test_parse_target_port_unknown_scheme_skipped() -> None:
    """Non-TLS / unknown schemes should yield (None, 0) so preflight is skipped."""
    assert _parse_target_port("mcp://agent.example.com/") == (None, 0)
    assert _parse_target_port("not-a-url") == (None, 0)


def test_parse_target_port_no_hostname() -> None:
    assert _parse_target_port("https://") == (None, 0)


# ---------------------------------------------------------------------------
# AgentClient — preflight gating
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_agent() -> AgentRecord:
    return AgentRecord(
        name="network",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=["ipam"],
        version="1.0.0",
    )


async def test_no_preflight_when_both_flags_off(mcp_agent: AgentRecord) -> None:
    """Default behavior (prefer_dane=False, require_dane=False) skips preflight entirely."""
    config = SDKConfig(prefer_dane=False, require_dane=False)
    preflight_mock = AsyncMock()

    with (
        patch("dns_aid.sdk.client.dane_preflight", new=preflight_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(
            return_value=type(
                "R",
                (),
                {
                    "success": True,
                    "status": InvocationStatus.SUCCESS,
                    "data": {},
                    "http_status_code": 200,
                    "error_type": None,
                    "error_message": None,
                    "invocation_latency_ms": 1.0,
                    "ttfb_ms": 1.0,
                    "response_size_bytes": 0,
                    "tls_version": None,
                    "cost_units": None,
                    "cost_currency": None,
                    "headers": {},
                },
            )()
        )
        async with AgentClient(config=config) as client:
            await client.invoke(mcp_agent)

    preflight_mock.assert_not_called()


async def test_prefer_dane_match_proceeds(mcp_agent: AgentRecord) -> None:
    """prefer_dane=True + TLSA matches → handler invoked normally."""
    config = SDKConfig(prefer_dane=True)
    preflight_mock = AsyncMock(
        return_value=DanePreflightResult(ok=True, status=DanePreflightStatus.MATCH)
    )

    with (
        patch("dns_aid.sdk.client.dane_preflight", new=preflight_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        raw = _build_success_raw()
        handler.invoke = AsyncMock(return_value=raw)

        async with AgentClient(config=config) as client:
            result = await client.invoke(mcp_agent)

    preflight_mock.assert_awaited_once()
    handler.invoke.assert_awaited_once()
    assert result.success is True


async def test_prefer_dane_absent_falls_back_to_webpki(mcp_agent: AgentRecord) -> None:
    """prefer_dane=True + TLSA absent → handler still invoked (WebPKI fallback)."""
    config = SDKConfig(prefer_dane=True, require_dane=False)
    preflight_mock = AsyncMock(
        return_value=DanePreflightResult(ok=True, status=DanePreflightStatus.ABSENT)
    )

    with (
        patch("dns_aid.sdk.client.dane_preflight", new=preflight_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())

        async with AgentClient(config=config) as client:
            result = await client.invoke(mcp_agent)

    preflight_mock.assert_awaited_once()
    handler.invoke.assert_awaited_once()
    assert result.success is True


async def test_prefer_dane_mismatch_refuses(mcp_agent: AgentRecord) -> None:
    """Mismatch is an attack signal — refused regardless of strictness."""
    config = SDKConfig(prefer_dane=True, require_dane=False)
    preflight_mock = AsyncMock(
        return_value=DanePreflightResult(ok=False, status=DanePreflightStatus.MISMATCH)
    )

    with (
        patch("dns_aid.sdk.client.dane_preflight", new=preflight_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())

        async with AgentClient(config=config) as client:
            result = await client.invoke(mcp_agent)

    preflight_mock.assert_awaited_once()
    handler.invoke.assert_not_called()
    assert result.success is False
    assert result.signal.status == InvocationStatus.REFUSED
    assert result.signal.error_type == "DANEMismatch"


async def test_require_dane_absent_refuses(mcp_agent: AgentRecord) -> None:
    """require_dane=True + TLSA absent → refused (no WebPKI fallback)."""
    config = SDKConfig(prefer_dane=True, require_dane=True)
    preflight_mock = AsyncMock(
        return_value=DanePreflightResult(ok=False, status=DanePreflightStatus.ABSENT)
    )

    with (
        patch("dns_aid.sdk.client.dane_preflight", new=preflight_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())

        async with AgentClient(config=config) as client:
            result = await client.invoke(mcp_agent)

    preflight_mock.assert_awaited_once()
    handler.invoke.assert_not_called()
    assert result.success is False
    assert result.signal.error_type == "DANEAbsent"


async def test_require_dane_error_refuses(mcp_agent: AgentRecord) -> None:
    """Strict mode: transient DANE lookup error → refuse rather than fall through."""
    config = SDKConfig(require_dane=True)
    preflight_mock = AsyncMock(
        return_value=DanePreflightResult(
            ok=False,
            status=DanePreflightStatus.ERROR,
            error="simulated",
        )
    )

    with (
        patch("dns_aid.sdk.client.dane_preflight", new=preflight_mock),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_build_success_raw())

        async with AgentClient(config=config) as client:
            result = await client.invoke(mcp_agent)

    handler.invoke.assert_not_called()
    assert result.signal.error_type == "DANEError"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_success_raw():
    """Build a minimal RawResponse-shaped object the post-invoke code can consume."""
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
