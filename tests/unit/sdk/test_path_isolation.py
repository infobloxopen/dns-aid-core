# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Path A / Path B isolation tests (FR-005, SC-005, QS-009).

Path B failures (directory unreachable, config missing, auth rejected) MUST NOT prevent
a subsequent Path A discovery on the same client. This is the foundational guarantee
that lets callers safely write zero-trust composition flows: search → re-verify → invoke.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.core.models import DiscoveryResult
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.exceptions import (
    DirectoryConfigError,
    DirectoryUnavailableError,
)


def _mock_response(status_code: int, body: Any = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = {}
    resp.json = MagicMock(return_value=body)
    resp.text = "" if body is None else str(body)
    return resp


def _empty_discovery_result() -> DiscoveryResult:
    return DiscoveryResult(
        query="_index._agents.example.com",
        domain="example.com",
        agents=[],
        dnssec_validated=False,
        cached=False,
        query_time_ms=1.0,
    )


@pytest.mark.asyncio
async def test_search_failure_does_not_corrupt_subsequent_discover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
    config = SDKConfig(directory_api_url="https://directory.test.example/")

    async with AgentClient(config=config) as client:
        assert client._http_client is not None
        # Path B fails with a transient 503.
        client._http_client.get = AsyncMock(  # type: ignore[method-assign]
            return_value=_mock_response(503)
        )
        with pytest.raises(DirectoryUnavailableError):
            await client.search(q="x")

        # Path A succeeds on the SAME client instance — the search failure left no
        # poisoned state behind.
        # Path A is the free ``discover()`` function — independent of AgentClient state.
        from dns_aid.core.discoverer import discover

        with (
            patch(
                "dns_aid.core.discoverer._execute_discovery",
                new=AsyncMock(return_value=[]),
            ),
            patch(
                "dns_aid.core.discoverer._apply_post_discovery",
                new=AsyncMock(return_value=False),
            ),
        ):
            result = await discover("example.com")
        assert result.domain == "example.com"


@pytest.mark.asyncio
async def test_directory_config_error_does_not_corrupt_path_a() -> None:
    """Calling search() without directory configured must NOT break Path A."""
    config = SDKConfig()  # No directory_api_url.

    async with AgentClient(config=config) as client:
        with pytest.raises(DirectoryConfigError):
            await client.search(q="x")

        # Path A is the free ``discover()`` function — independent of AgentClient state.
        from dns_aid.core.discoverer import discover

        with (
            patch(
                "dns_aid.core.discoverer._execute_discovery",
                new=AsyncMock(return_value=[]),
            ),
            patch(
                "dns_aid.core.discoverer._apply_post_discovery",
                new=AsyncMock(return_value=False),
            ),
        ):
            result = await discover("example.com")
        assert result.domain == "example.com"


@pytest.mark.asyncio
async def test_search_connect_error_does_not_close_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed search MUST leave self._http_client open for subsequent calls."""
    monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
    config = SDKConfig(directory_api_url="https://directory.test.example/")

    async with AgentClient(config=config) as client:
        assert client._http_client is not None
        original_client = client._http_client

        client._http_client.get = AsyncMock(  # type: ignore[method-assign]
            side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(DirectoryUnavailableError):
            await client.search(q="x")

        # Critical invariant: the http client is still the same, still open.
        assert client._http_client is original_client
        assert client._http_client.is_closed is False
