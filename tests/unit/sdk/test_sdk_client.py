"""Tests for dns_aid.sdk.client module — uncovered paths."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.models import InvocationSignal, InvocationStatus


@pytest.fixture
def _config() -> SDKConfig:
    return SDKConfig(
        timeout_seconds=5.0,
        caller_id="test",
        telemetry_api_url="https://api.test.io",
    )


@pytest.fixture
def _signal() -> InvocationSignal:
    return InvocationSignal(
        agent_fqdn="_chat._a2a._agents.example.com",
        agent_endpoint="https://chat.example.com",
        protocol="a2a",
        invocation_latency_ms=42.0,
        status=InvocationStatus.SUCCESS,
    )


class TestAgentClientAsyncContext:
    """Tests for __aenter__ / __aexit__."""

    @pytest.mark.asyncio
    async def test_aexit_cleanup_no_client(self, _config: SDKConfig):
        """__aexit__ when _http_client is already None should not raise."""
        client = AgentClient(config=_config)
        # Never entered context → _http_client is None
        await client.__aexit__(None, None, None)
        # Should not raise

    @pytest.mark.asyncio
    async def test_aexit_closes_client(self, _config: SDKConfig):
        """__aexit__ should close the http client and set it to None."""
        async with AgentClient(config=_config) as client:
            assert client._http_client is not None
        assert client._http_client is None


class TestFetchRankings:
    """Tests for fetch_rankings method."""

    @pytest.mark.asyncio
    async def test_fetch_rankings_success(self, _config: SDKConfig):
        """Happy path: returns rankings from API."""
        response_data = {
            "rankings": [
                {"agent_fqdn": "_chat._a2a._agents.example.com", "composite_score": 95},
                {"agent_fqdn": "_other._mcp._agents.example.com", "composite_score": 80},
            ]
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = response_data
        mock_resp.raise_for_status = MagicMock()

        async with AgentClient(config=_config) as client:
            client._http_client.get = AsyncMock(return_value=mock_resp)
            rankings = await client.fetch_rankings()

        assert len(rankings) == 2
        assert rankings[0]["composite_score"] == 95

    @pytest.mark.asyncio
    async def test_fetch_rankings_no_telemetry_url(self):
        """No telemetry_api_url → returns empty list."""
        config = SDKConfig(timeout_seconds=5.0, telemetry_api_url=None)
        async with AgentClient(config=config) as client:
            rankings = await client.fetch_rankings()
        assert rankings == []

    @pytest.mark.asyncio
    async def test_fetch_rankings_http_error(self, _config: SDKConfig):
        """HTTP 500 → returns empty list."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=mock_resp
        )
        mock_resp.json.return_value = {}

        async with AgentClient(config=_config) as client:
            client._http_client.get = AsyncMock(return_value=mock_resp)
            rankings = await client.fetch_rankings()

        assert rankings == []

    @pytest.mark.asyncio
    async def test_fetch_rankings_with_fqdn_filter(self, _config: SDKConfig):
        """Rankings are filtered by provided FQDNs."""
        response_data = {
            "rankings": [
                {"agent_fqdn": "_chat._a2a._agents.example.com", "composite_score": 95},
                {"agent_fqdn": "_other._mcp._agents.example.com", "composite_score": 80},
            ]
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = response_data
        mock_resp.raise_for_status = MagicMock()

        async with AgentClient(config=_config) as client:
            client._http_client.get = AsyncMock(return_value=mock_resp)
            rankings = await client.fetch_rankings(
                fqdns=["_chat._a2a._agents.example.com"]
            )

        assert len(rankings) == 1
        assert rankings[0]["agent_fqdn"] == "_chat._a2a._agents.example.com"


class TestPushSignalHttpSync:
    """Tests for _push_signal_http_sync static method."""

    def test_push_signal_http_sync_success(self, _signal: InvocationSignal):
        """Successful push (status 200) logs ok."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("dns_aid.sdk.client.httpx.post", return_value=mock_resp) as mock_post:
            AgentClient._push_signal_http_sync(_signal, "https://api.test.io/signals")
            mock_post.assert_called_once()

    def test_push_signal_http_sync_rejected(self, _signal: InvocationSignal):
        """Status 400 logs a warning but does not raise."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"

        with patch("dns_aid.sdk.client.httpx.post", return_value=mock_resp):
            # Should not raise
            AgentClient._push_signal_http_sync(_signal, "https://api.test.io/signals")

    def test_push_signal_http_sync_exception(self, _signal: InvocationSignal):
        """Network error is silently caught."""
        with patch(
            "dns_aid.sdk.client.httpx.post",
            side_effect=httpx.ConnectError("refused"),
        ):
            # Should not raise
            AgentClient._push_signal_http_sync(_signal, "https://api.test.io/signals")
