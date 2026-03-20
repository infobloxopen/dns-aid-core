# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for OAuth2 client-credentials auth handler."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.sdk.auth.oauth2 import OAuth2AuthHandler


@pytest.fixture
def request_obj() -> httpx.Request:
    return httpx.Request(
        "POST",
        "https://agent.example.com/mcp",
        json={"method": "tools/list"},
    )


@pytest.fixture
def token_response() -> dict:
    return {
        "access_token": "eyJ0b2tlbiI6InRlc3QifQ",
        "token_type": "bearer",
        "expires_in": 3600,
    }


@pytest.fixture
def discovery_response() -> dict:
    return {
        "token_endpoint": "https://auth.example.com/oauth/token",
        "issuer": "https://auth.example.com",
    }


class TestOAuth2AuthHandler:
    def test_requires_token_url_or_discovery(self) -> None:
        with pytest.raises(ValueError, match="Either token_url or discovery_url"):
            OAuth2AuthHandler(
                client_id="id",
                client_secret="secret",
            )

    @pytest.mark.asyncio
    async def test_fetches_and_applies_token(
        self, request_obj: httpx.Request, token_response: dict
    ) -> None:
        mock_resp = httpx.Response(200, json=token_response)
        transport = httpx.MockTransport(lambda req: mock_resp)

        handler = OAuth2AuthHandler(
            client_id="my-client",
            client_secret="my-secret",
            token_url="https://auth.example.com/oauth/token",
        )

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await handler.apply(request_obj)

        assert result.headers["Authorization"] == "Bearer eyJ0b2tlbiI6InRlc3QifQ"

    @pytest.mark.asyncio
    async def test_caches_token(
        self, request_obj: httpx.Request, token_response: dict
    ) -> None:
        mock_resp = httpx.Response(200, json=token_response)

        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://auth.example.com/oauth/token",
        )

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await handler.apply(request_obj)
            await handler.apply(request_obj)

            # Token endpoint called only once (cached)
            assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_refreshes_expired_token(
        self, request_obj: httpx.Request
    ) -> None:
        resp1 = httpx.Response(200, json={
            "access_token": "token-1",
            "expires_in": 1,  # Expires almost immediately
        })
        resp2 = httpx.Response(200, json={
            "access_token": "token-2",
            "expires_in": 3600,
        })

        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://auth.example.com/oauth/token",
        )

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=[resp1, resp2])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            r1 = await handler.apply(request_obj)
            assert r1.headers["Authorization"] == "Bearer token-1"

            # Force expiry (token expires_in=1 minus 30s buffer = already expired)
            handler._expires_at = time.monotonic() - 1

            r2 = await handler.apply(request_obj)
            assert r2.headers["Authorization"] == "Bearer token-2"
            assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_oidc_discovery(
        self,
        request_obj: httpx.Request,
        token_response: dict,
        discovery_response: dict,
    ) -> None:
        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            discovery_url="https://auth.example.com/.well-known/openid-configuration",
        )

        mock_disc_resp = httpx.Response(200, json=discovery_response)
        mock_token_resp = httpx.Response(200, json=token_response)

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_disc_resp)
            mock_client.post = AsyncMock(return_value=mock_token_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await handler.apply(request_obj)

        assert result.headers["Authorization"].startswith("Bearer ")

    def test_auth_type(self) -> None:
        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://auth.example.com/token",
        )
        assert handler.auth_type == "oauth2"
