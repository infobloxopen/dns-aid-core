# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for SDK tests."""

from __future__ import annotations

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig


class _ModernTransportRejected:
    """Async context manager whose __aenter__ raises HTTP 406."""

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        raise httpx.HTTPStatusError(
            "modern transport rejected (simulated 406)",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(406),
        )

    async def __aexit__(self, *exc):  # type: ignore[no-untyped-def]
        return False


@pytest.fixture
def force_legacy_mcp_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the MCP handler to take the legacy fallback path on every call.

    Patches ``streamablehttp_client`` in ``dns_aid.sdk.protocols.mcp`` so
    that any attempt to use the modern Streamable HTTP transport raises
    HTTP 406 — which the handler classifies as a transport mismatch and
    falls back to the legacy plain JSON-RPC POST path.

    Use this fixture in any test that mocks MCP behavior with
    ``httpx.MockTransport`` (which simulates the legacy POST path), so the
    test continues to verify the legacy semantic now that it is reached
    via fallback rather than as the primary transport.
    """
    monkeypatch.setattr(
        "dns_aid.sdk.protocols.mcp.streamablehttp_client",
        lambda *args, **kwargs: _ModernTransportRejected(),
    )


@pytest.fixture
def sdk_config() -> SDKConfig:
    """Default SDK config for testing."""
    return SDKConfig(
        timeout_seconds=5.0,
        caller_id="test-caller",
        console_signals=False,
    )


@pytest.fixture
def sample_mcp_agent() -> AgentRecord:
    """A sample MCP agent record for testing."""
    return AgentRecord(
        name="network",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=["ipam", "dns"],
        version="1.0.0",
    )


@pytest.fixture
def sample_a2a_agent() -> AgentRecord:
    """A sample A2A agent record for testing."""
    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host="a2a.example.com",
        port=443,
        capabilities=["conversation"],
        version="1.0.0",
    )
