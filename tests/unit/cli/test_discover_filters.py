# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the new Path A filter flags on ``dns-aid discover``.

Validates that every flag introduced by US2/US3 reaches the underlying ``discover()``
call with the right shape, AND that pre-existing flag combinations still produce the
same results (backwards-compat regression).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dns_aid.cli.main import app
from dns_aid.core.models import DiscoveryResult


def _empty_discovery_result() -> DiscoveryResult:
    return DiscoveryResult(
        query="_index._agents.example.com",
        domain="example.com",
        agents=[],
        dnssec_validated=False,
        cached=False,
        query_time_ms=1.5,
    )


runner = CliRunner()


class TestFilterFlagsReachDiscoverer:
    def test_every_filter_flag_arrives_at_discoverer(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*args: Any, **kwargs: Any) -> DiscoveryResult:
            captured.update(kwargs)
            return _empty_discovery_result()

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(
                app,
                [
                    "discover",
                    "example.com",
                    "--protocol",
                    "mcp",
                    "--capabilities",
                    "payment-processing",
                    "--capabilities",
                    "fraud-detection",
                    "--capabilities-any",
                    "alt-payment",
                    "--auth-type",
                    "oauth2",
                    "--intent",
                    "transaction",
                    "--transport",
                    "mcp",
                    "--realm",
                    "prod",
                    "--min-dnssec",
                    "--text-match",
                    "payments",
                    "--require-signed",
                    "--require-signature-algorithm",
                    "ES256",
                    "--require-signature-algorithm",
                    "Ed25519",
                ],
            )

        assert result.exit_code == 0, result.output
        assert captured["domain"] == "example.com"
        assert captured["protocol"] == "mcp"
        assert captured["capabilities"] == ["payment-processing", "fraud-detection"]
        assert captured["capabilities_any"] == ["alt-payment"]
        assert captured["auth_type"] == "oauth2"
        assert captured["intent"] == "transaction"
        assert captured["transport"] == "mcp"
        assert captured["realm"] == "prod"
        assert captured["min_dnssec"] is True
        assert captured["text_match"] == "payments"
        assert captured["require_signed"] is True
        assert captured["require_signature_algorithm"] == ["ES256", "Ed25519"]


class TestBackwardsCompat:
    """Pre-existing flags must continue to produce identical behavior."""

    def test_legacy_invocation_still_calls_discover(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*args: Any, **kwargs: Any) -> DiscoveryResult:
            captured.update(kwargs)
            return _empty_discovery_result()

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(
                app,
                ["discover", "example.com", "--protocol", "mcp", "--name", "payments"],
            )

        assert result.exit_code == 0
        assert captured["domain"] == "example.com"
        assert captured["protocol"] == "mcp"
        assert captured["name"] == "payments"
        # New filter kwargs default to None / False — nothing surprising threaded through.
        assert captured["capabilities"] is None
        assert captured["min_dnssec"] is False
        assert captured["require_signed"] is False


class TestInvalidCombination:
    def test_algorithm_without_require_signed_exits_64(self) -> None:
        # The discoverer raises ValueError; CLI maps to exit 64 (usage error).
        with patch(
            "dns_aid.core.discoverer.discover",
            new=AsyncMock(side_effect=ValueError("require_signed=True needed")),
        ):
            result = runner.invoke(
                app,
                [
                    "discover",
                    "example.com",
                    "--require-signature-algorithm",
                    "ES256",
                ],
            )
        assert result.exit_code == 64
