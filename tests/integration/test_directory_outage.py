# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Directory-outage isolation integration test (FR-005, SC-005, US4).

The contract under test is the zero-trust isolation guarantee: a directory
backend that flips between healthy and unreachable mid-session must NOT prevent
Path A discovery on the same client. Path B failures get bubbled up with a
typed exception, the directory URL stays configured, and a *subsequent* Path A
discovery on the same ``AgentClient`` instance proceeds normally.

The earlier suite (``tests/unit/sdk/test_path_isolation.py``) covers the
single-shot case — one Path B failure, one Path A success. This integration
test interleaves multiple Path B and Path A calls on the same client to flush
out subtler corruption modes (lingering cancelled tasks, half-closed connection
pools, stale auth state) that only surface with sustained traffic.
"""

from __future__ import annotations

import itertools
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.core.discoverer import discover
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.exceptions import (
    DirectoryRateLimitedError,
    DirectoryUnavailableError,
)


def _mock_response(status_code: int, *, body: Any = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = {}
    resp.json = MagicMock(return_value=body)
    resp.text = "" if body is None else str(body)
    return resp


def _empty_discovery() -> DiscoveryResult:
    return DiscoveryResult(
        query="_index._agents.example.com",
        domain="example.com",
        agents=[],
        dnssec_validated=False,
        cached=False,
        query_time_ms=1.0,
    )


@pytest.mark.asyncio
async def test_directory_outage_does_not_corrupt_path_a(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sustained Path B churn (5xx → 200 → 503 → 429) leaves Path A untouched."""
    monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
    config = SDKConfig(directory_api_url="https://directory.test.example/")

    # Cycle through a realistic outage pattern: transient 503, recovery, 429
    # backpressure, hard 502. ``itertools.cycle`` gives us a deterministic stream
    # that exhausts every error path the SDK maps to a typed exception.
    response_cycle = itertools.cycle(
        [
            _mock_response(503),
            _mock_response(
                200,
                body={
                    "query": "x",
                    "results": [],
                    "total": 0,
                    "limit": 20,
                    "offset": 0,
                },
            ),
            _mock_response(429, body=None),
            _mock_response(502),
        ]
    )

    async with AgentClient(config=config) as client:
        assert client._http_client is not None
        original_http_client = client._http_client

        async def cycling_get(url: str, params: Any = None, **kwargs: Any) -> MagicMock:
            return next(response_cycle)

        client._http_client.get = cycling_get  # type: ignore[method-assign]

        # Note: ``next(response_cycle)`` advances every call — including 429, which
        # the SDK raises as DirectoryRateLimitedError (a subclass of
        # DirectoryUnavailableError). Catching the parent covers all four cases.
        path_b_outcomes: list[type[Exception] | str] = []
        for _ in range(8):
            try:
                response = await client.search(q="x")
                path_b_outcomes.append("ok")
                # The successful body has total=0; pagination still parses cleanly.
                assert response.total == 0
            except DirectoryRateLimitedError:
                path_b_outcomes.append("rate_limited")
            except DirectoryUnavailableError:
                path_b_outcomes.append("unavailable")

        # Each cycle has a 1/4 chance of being "ok"; over 8 calls we should have
        # at least one of every outcome. Assert the *shape* of the outcome stream
        # rather than exact counts so cycle internals aren't load-bearing.
        assert "ok" in path_b_outcomes
        assert "unavailable" in path_b_outcomes
        assert "rate_limited" in path_b_outcomes

        # ── Critical invariant ── despite the churn, the http client must still
        # be the same instance, still open, still bound to the configured base URL.
        assert client._http_client is original_http_client
        assert client._http_client.is_closed is False
        assert client._config.directory_api_url == "https://directory.test.example/"

        # ── Path A must still work on the SAME process. The free ``discover()``
        # function is independent of AgentClient state, but a real caller will
        # call both on the same event loop, so we exercise that pattern here.
        with (
            patch(
                "dns_aid.core.discoverer._execute_discovery",
                new=AsyncMock(
                    return_value=[
                        AgentRecord(
                            name="payments",
                            domain="example.com",
                            protocol=Protocol.MCP,
                            target_host="payments.example.com",
                            port=443,
                            capabilities=["payment-processing"],
                        )
                    ]
                ),
            ),
            patch(
                "dns_aid.core.discoverer._apply_post_discovery",
                new=AsyncMock(return_value=False),
            ),
        ):
            path_a_result = await discover("example.com")

        assert path_a_result.domain == "example.com"
        assert {a.name for a in path_a_result.agents} == {"payments"}


@pytest.mark.asyncio
async def test_directory_recovery_after_extended_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    After a sustained Path B outage, the very next successful Path B call must
    return cleanly — no warm-up retries, no stale auth headers, no leaked state.
    """
    monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
    config = SDKConfig(directory_api_url="https://directory.test.example/")

    healthy_body = {
        "query": "x",
        "results": [],
        "total": 0,
        "limit": 20,
        "offset": 0,
    }

    # 5 consecutive failures then a recovery — what a real directory outage with
    # eventual repair looks like.
    responses = [_mock_response(503)] * 5 + [_mock_response(200, body=healthy_body)]
    iterator = iter(responses)

    async with AgentClient(config=config) as client:
        assert client._http_client is not None

        async def get(url: str, params: Any = None, **kwargs: Any) -> MagicMock:
            return next(iterator)

        client._http_client.get = get  # type: ignore[method-assign]

        for _ in range(5):
            with pytest.raises(DirectoryUnavailableError):
                await client.search(q="x")

        # Recovery: same client, no reset needed.
        recovered = await client.search(q="x")
        assert recovered.total == 0
        assert recovered.results == []
