# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the ``dns-aid search`` CLI subcommand.

Covers:
- flag parsing for every Path B filter
- output formatting (human + JSON)
- exit codes mapped from DirectoryError subclasses (sysexits.h)
- ``--directory-url`` per-invocation override
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dns_aid.cli.main import app
from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk.exceptions import (
    DirectoryAuthError,
    DirectoryConfigError,
    DirectoryRateLimitedError,
    DirectoryUnavailableError,
)
from dns_aid.sdk.search import (
    SearchResponse,
    SearchResult,
    TrustAttestation,
)


def _make_response(results: int = 1, total: int = 1, offset: int = 0) -> SearchResponse:
    return SearchResponse(
        query="payments",
        results=[
            SearchResult(
                agent=AgentRecord(
                    name=f"agent{i}",
                    domain="example.com",
                    protocol=Protocol.MCP,
                    target_host=f"agent{i}.example.com",
                    port=443,
                    capabilities=["payment-processing"],
                ),
                # Directory uses raw scores; CLI formatting handles >= 1.0.
                score=39.2 - (i * 0.1),
                trust=TrustAttestation(
                    security_score=80,
                    trust_score=75,
                    popularity_score=60,
                    trust_tier=2,
                    safety_status="active",
                    dnssec_valid=True,
                    dane_valid=False,
                    svcb_valid=True,
                    endpoint_reachable=True,
                    protocol_verified=True,
                    badges=["Verified"],
                ),
            )
            for i in range(results)
        ],
        total=total,
        limit=20,
        offset=offset,
    )


runner = CliRunner()


class TestHappyPath:
    def test_renders_human_table(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            return_value=_make_response(results=2, total=5),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "payments",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )

        assert result.exit_code == 0, result.output
        assert "agent0" in result.output
        assert "T2" in result.output
        # Pagination summary appears when more results exist.
        assert "Showing" in result.output
        assert "of 5 results" in result.output

    def test_json_output_serializes_response(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            return_value=_make_response(results=1, total=1),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "payments",
                    "--json",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )

        assert result.exit_code == 0
        # JSON envelope must include the whole SearchResponse shape.
        assert '"results"' in result.output
        assert '"total"' in result.output
        assert '"trust_tier"' in result.output

    def test_zero_results_exits_zero(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            return_value=_make_response(results=0, total=0),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "no-such-thing",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )

        assert result.exit_code == 0
        assert "No agents matched" in result.output


class TestFilterPropagation:
    def test_every_filter_flag_reaches_search(self) -> None:
        """Each CLI filter flag must arrive at AgentClient.search() with the right shape."""
        captured: dict[str, Any] = {}

        async def fake_search(self: Any, *args: Any, **kwargs: Any) -> SearchResponse:
            captured.update(kwargs)
            return _make_response(results=0, total=0)

        with patch("dns_aid.sdk.client.AgentClient.search", new=fake_search):
            result = runner.invoke(
                app,
                [
                    "search",
                    "payments",
                    "--protocol",
                    "mcp",
                    "--domain",
                    "example.com",
                    "--capabilities",
                    "payment-processing",
                    "--capabilities",
                    "fraud-detection",
                    "--intent",
                    "transaction",
                    "--auth-type",
                    "oauth2",
                    "--transport",
                    "streamable-http",
                    "--realm",
                    "prod",
                    "--min-security-score",
                    "70",
                    "--verified-only",
                    "--limit",
                    "10",
                    "--offset",
                    "20",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )

        assert result.exit_code == 0, result.output
        assert captured["q"] == "payments"
        assert captured["protocol"] == "mcp"
        assert captured["domain"] == "example.com"
        assert captured["capabilities"] == ["payment-processing", "fraud-detection"]
        assert captured["intent"] == "transaction"
        assert captured["auth_type"] == "oauth2"
        assert captured["transport"] == "streamable-http"
        assert captured["realm"] == "prod"
        assert captured["min_security_score"] == 70
        assert captured["verified_only"] is True
        assert captured["limit"] == 10
        assert captured["offset"] == 20


class TestExitCodes:
    def test_config_error_exits_78(self) -> None:
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
            result = runner.invoke(app, ["search", "x"])
        assert result.exit_code == 78

    def test_auth_error_exits_77(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryAuthError("bad token", details={"status_code": 401}),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "x",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 77

    def test_unavailable_exits_75(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryUnavailableError("down", details={"status_code": 503}),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "x",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 75

    def test_rate_limited_exits_75(self) -> None:
        # DirectoryRateLimitedError inherits from DirectoryUnavailableError.
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryRateLimitedError(
                "slow", details={"status_code": 429, "retry_after_seconds": 30}
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "x",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 75

    def test_json_error_envelope_on_failure(self) -> None:
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryUnavailableError(
                "down", details={"status_code": 503, "underlying": "HTTPStatusError"}
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "search",
                    "x",
                    "--json",
                    "--directory-url",
                    "https://directory.test.example",
                ],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 75
        assert '"error"' in result.output
        assert "DirectoryUnavailableError" in result.output


class TestLimitBounds:
    def test_limit_zero_rejected(self) -> None:
        result = runner.invoke(
            app,
            ["search", "x", "--limit", "0"],
            env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
        )
        # Typer enforces min=1 → exit 2 (usage error).
        assert result.exit_code != 0
