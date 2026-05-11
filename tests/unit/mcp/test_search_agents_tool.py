# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the ``search_agents`` MCP tool.

Validates:
- happy-path dispatch returns the SearchResponse serialized as a JSON-friendly dict
- every ``DirectoryError`` subclass converts to a structured ``{"success": False, ...}``
  envelope with the documented ``error`` discriminator (FR-017: never raises to MCP transport)
- argument propagation across SDK boundary
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.mcp.server import search_agents
from dns_aid.sdk.exceptions import (
    DirectoryAuthError,
    DirectoryConfigError,
    DirectoryRateLimitedError,
    DirectoryUnavailableError,
)
from dns_aid.sdk.search import (
    Provenance,
    SearchResponse,
    SearchResult,
    TrustAttestation,
)


def _make_response() -> SearchResponse:
    now = datetime.now(UTC)
    return SearchResponse(
        query="payments",
        results=[
            SearchResult(
                agent=AgentRecord(
                    name="payments",
                    domain="example.com",
                    protocol=Protocol.MCP,
                    target_host="payments.example.com",
                    port=443,
                    capabilities=["payment-processing"],
                ),
                score=39.4,
                trust=TrustAttestation(
                    security_score=87,
                    trust_score=83,
                    popularity_score=70,
                    trust_tier=2,
                    safety_status="active",
                    dnssec_valid=True,
                    dane_valid=False,
                    svcb_valid=True,
                    endpoint_reachable=True,
                    protocol_verified=True,
                    badges=["Verified", "DNSSEC"],
                ),
                provenance=Provenance(
                    discovery_level=2,
                    first_seen=now,
                    last_seen=now,
                    last_verified=now,
                ),
            )
        ],
        total=5,
        limit=20,
        offset=0,
    )


class TestHappyPath:
    def test_returns_serialized_search_response(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            return_value=_make_response(),
        ):
            result = search_agents(q="payments", protocol="mcp")

        assert result["success"] is True
        assert result["total"] == 5
        assert len(result["results"]) == 1
        assert result["results"][0]["agent"]["name"] == "payments"
        assert result["results"][0]["score"] == 39.4
        assert result["results"][0]["trust"]["trust_tier"] == 2
        assert result["results"][0]["trust"]["badges"] == ["Verified", "DNSSEC"]
        assert result["results"][0]["provenance"]["discovery_level"] == 2
        assert result["has_more"] is True

    def test_arguments_propagate_to_sdk(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_search(self: Any, *args: Any, **kwargs: Any) -> SearchResponse:
            captured.update(kwargs)
            return _make_response()

        with patch("dns_aid.sdk.client.AgentClient.search", new=fake_search):
            search_agents(
                q="payments",
                protocol="mcp",
                domain="example.com",
                capabilities=["payment-processing"],
                min_security_score=70,
                verified_only=True,
                intent="transaction",
                auth_type="oauth2",
                transport="streamable-http",
                realm="prod",
                limit=10,
                offset=20,
            )

        assert captured["q"] == "payments"
        assert captured["protocol"] == "mcp"
        assert captured["domain"] == "example.com"
        assert captured["capabilities"] == ["payment-processing"]
        assert captured["min_security_score"] == 70
        assert captured["verified_only"] is True
        assert captured["intent"] == "transaction"
        assert captured["auth_type"] == "oauth2"
        assert captured["transport"] == "streamable-http"
        assert captured["realm"] == "prod"
        assert captured["limit"] == 10
        assert captured["offset"] == 20


class TestErrorEnvelopes:
    """Errors MUST return structured envelopes — never raise to the MCP transport."""

    def test_config_error_returns_structured_envelope(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryConfigError(
                "no url",
                details={
                    "missing_field": "directory_api_url",
                    "env_var": "DNS_AID_SDK_DIRECTORY_API_URL",
                },
            ),
        ):
            result = search_agents(q="x")

        assert result["success"] is False
        assert result["error"] == "directory_not_configured"
        assert result["details"]["env_var"] == "DNS_AID_SDK_DIRECTORY_API_URL"
        assert "remediation" in result

    def test_unavailable_error_returns_structured_envelope(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryUnavailableError(
                "down", details={"directory_url": "https://x.example", "status_code": 503}
            ),
        ):
            result = search_agents(q="x")

        assert result["success"] is False
        assert result["error"] == "directory_unavailable"
        assert result["transient"] is True
        assert result["retry_recommended"] is True
        assert result["details"]["status_code"] == 503

    def test_rate_limited_returns_distinct_envelope(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryRateLimitedError(
                "slow",
                details={
                    "directory_url": "https://x.example",
                    "status_code": 429,
                    "retry_after_seconds": 30,
                },
            ),
        ):
            result = search_agents(q="x")

        # MUST surface as ``directory_rate_limited``, NOT ``directory_unavailable``,
        # so the AI agent can dispatch on the specific case.
        assert result["error"] == "directory_rate_limited"
        assert result["details"]["retry_after_seconds"] == 30

    def test_auth_error_returns_structured_envelope(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryAuthError(
                "bad token", details={"directory_url": "https://x.example", "status_code": 401}
            ),
        ):
            result = search_agents(q="x")

        assert result["success"] is False
        assert result["error"] == "directory_auth_failed"
        assert "remediation" in result
        assert result["details"]["status_code"] == 401
