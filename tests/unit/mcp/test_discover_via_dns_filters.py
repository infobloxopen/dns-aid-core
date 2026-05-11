# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the extended ``discover_agents_via_dns`` MCP tool — Path A filter args.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from dns_aid.core.models import DiscoveryResult
from dns_aid.mcp.server import discover_agents_via_dns


def _empty_result() -> DiscoveryResult:
    return DiscoveryResult(
        query="_index._agents.example.com",
        domain="example.com",
        agents=[],
        dnssec_validated=False,
        cached=False,
        query_time_ms=1.0,
    )


def test_filter_args_propagate_to_discoverer() -> None:
    captured: dict[str, Any] = {}

    async def fake_discover(*args: Any, **kwargs: Any) -> DiscoveryResult:
        captured.update(kwargs)
        return _empty_result()

    with patch("dns_aid.core.discoverer.discover", new=fake_discover):
        result = discover_agents_via_dns(
            domain="example.com",
            protocol="mcp",
            capabilities=["payment-processing"],
            capabilities_any=["alt-payment"],
            auth_type="oauth2",
            intent="transaction",
            transport="mcp",
            realm="prod",
            min_dnssec=True,
            text_match="payment",
            require_signed=True,
            require_signature_algorithm=["ES256"],
        )

    assert result["domain"] == "example.com"
    assert captured["capabilities"] == ["payment-processing"]
    assert captured["capabilities_any"] == ["alt-payment"]
    assert captured["auth_type"] == "oauth2"
    assert captured["intent"] == "transaction"
    assert captured["transport"] == "mcp"
    assert captured["realm"] == "prod"
    assert captured["min_dnssec"] is True
    assert captured["text_match"] == "payment"
    assert captured["require_signed"] is True
    assert captured["require_signature_algorithm"] == ["ES256"]


def test_legacy_call_still_works() -> None:
    """Pre-existing tool invocations (no filter args) MUST produce identical behavior."""
    captured: dict[str, Any] = {}

    async def fake_discover(*args: Any, **kwargs: Any) -> DiscoveryResult:
        captured.update(kwargs)
        return _empty_result()

    with patch("dns_aid.core.discoverer.discover", new=fake_discover):
        result = discover_agents_via_dns(domain="example.com", protocol="mcp")

    assert result["domain"] == "example.com"
    # New kwargs default to None / False so legacy paths see no behavior change.
    assert captured["capabilities"] is None
    assert captured["require_signed"] is False
