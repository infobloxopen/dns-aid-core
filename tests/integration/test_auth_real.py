# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for auth handlers against real HTTP endpoints.

These tests hit real services — they require network access and may
be slow. Skip with: pytest -m "not integration"

Tests:
1. Bearer handler → httpbin.org (verifies header arrives)
2. API key handler → httpbin.org (verifies header arrives)
3. OIDC discovery → Google's public .well-known endpoint
4. OAuth2 → real Okta/Cognito endpoint (requires env vars, skipped if absent)
"""

from __future__ import annotations

import os

import httpx
import pytest

from dns_aid.sdk.auth.oauth2 import OAuth2AuthHandler
from dns_aid.sdk.auth.simple import ApiKeyAuthHandler, BearerAuthHandler

pytestmark = pytest.mark.integration


class TestBearerRealEndpoint:
    """Verify Bearer token actually arrives at a real HTTP server."""

    @pytest.mark.asyncio
    async def test_bearer_header_reaches_httpbin(self) -> None:
        handler = BearerAuthHandler(token="test-token-abc123")

        async with httpx.AsyncClient() as client:
            request = client.build_request(
                "GET",
                "https://httpbin.org/headers",
            )
            request = await handler.apply(request)
            response = await client.send(request)

        assert response.status_code == 200
        data = response.json()
        # httpbin echoes back all headers
        assert data["headers"]["Authorization"] == "Bearer test-token-abc123"


class TestApiKeyRealEndpoint:
    """Verify API key actually arrives at a real HTTP server."""

    @pytest.mark.asyncio
    async def test_api_key_header_reaches_httpbin(self) -> None:
        handler = ApiKeyAuthHandler(api_key="sk-live-test", header_name="X-Api-Key")

        async with httpx.AsyncClient() as client:
            request = client.build_request(
                "GET",
                "https://httpbin.org/headers",
            )
            request = await handler.apply(request)
            response = await client.send(request)

        assert response.status_code == 200
        data = response.json()
        assert data["headers"]["X-Api-Key"] == "sk-live-test"

    @pytest.mark.asyncio
    async def test_api_key_query_reaches_httpbin(self) -> None:
        handler = ApiKeyAuthHandler(
            api_key="qk-test",
            location="query",
            query_param="api_key",
        )

        async with httpx.AsyncClient() as client:
            request = client.build_request(
                "GET",
                "https://httpbin.org/get",
            )
            request = await handler.apply(request)
            response = await client.send(request)

        assert response.status_code == 200
        data = response.json()
        assert data["args"]["api_key"] == "qk-test"


class TestOIDCDiscoveryReal:
    """Test OIDC discovery against Google's public endpoint."""

    @pytest.mark.asyncio
    async def test_google_oidc_discovery(self) -> None:
        """Verify we can parse a real OIDC discovery document."""
        handler = OAuth2AuthHandler(
            client_id="fake-id",  # Won't actually authenticate
            client_secret="fake-secret",
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        )

        # Just test discovery resolution, not actual token fetch
        token_url = await handler._discover_token_url()
        assert "token" in token_url
        assert token_url.startswith("https://")
        # Google's token endpoint
        assert "googleapis.com" in token_url or "google.com" in token_url


def _get_oauth_creds() -> tuple[str, str, str, str | None] | None:
    """Return (token_url, client_id, client_secret, scopes) or None."""
    token_url = os.getenv("DNS_AID_TEST_OAUTH_TOKEN_URL")
    client_id = os.getenv("DNS_AID_TEST_OAUTH_CLIENT_ID")
    client_secret = os.getenv("DNS_AID_TEST_OAUTH_CLIENT_SECRET")
    if not all([token_url, client_id, client_secret]):
        return None
    return (token_url, client_id, client_secret, os.getenv("DNS_AID_TEST_OAUTH_SCOPES"))


class TestOAuth2RealProvider:
    """Test OAuth2 against a real provider (AWS Cognito).

    Requires env vars:
        DNS_AID_TEST_OAUTH_TOKEN_URL — token endpoint
        DNS_AID_TEST_OAUTH_CLIENT_ID — client ID
        DNS_AID_TEST_OAUTH_CLIENT_SECRET — client secret
        DNS_AID_TEST_OAUTH_SCOPES — scopes (optional)

    Skip if not configured.
    """

    @pytest.mark.asyncio
    async def test_real_oauth2_token_fetch(self) -> None:
        creds = _get_oauth_creds()
        if not creds:
            pytest.skip("Set DNS_AID_TEST_OAUTH_* env vars to run")

        token_url, client_id, client_secret, scopes = creds
        handler = OAuth2AuthHandler(
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            scopes=scopes,
        )

        # Fetch real token and apply to request
        request = httpx.Request("POST", "https://agent.example.com/mcp")
        result = await handler.apply(request)

        auth_header = result.headers.get("authorization", "")
        assert auth_header.startswith("Bearer ")
        token = auth_header.split(" ", 1)[1]
        assert len(token) > 20  # Real JWTs are substantial

        # Verify caching — second call should NOT hit the token endpoint
        request2 = httpx.Request("POST", "https://agent.example.com/mcp")
        result2 = await handler.apply(request2)
        assert result2.headers["authorization"] == result.headers["authorization"]

    @pytest.mark.asyncio
    async def test_real_oauth2_token_reaches_httpbin(self) -> None:
        """Full round-trip: Cognito token → httpbin echoes it back."""
        creds = _get_oauth_creds()
        if not creds:
            pytest.skip("Set DNS_AID_TEST_OAUTH_* env vars to run")

        token_url, client_id, client_secret, scopes = creds
        handler = OAuth2AuthHandler(
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            scopes=scopes,
        )

        async with httpx.AsyncClient() as client:
            request = client.build_request("GET", "https://httpbin.org/headers")
            request = await handler.apply(request)
            response = await client.send(request)

        assert response.status_code == 200
        echoed = response.json()["headers"]["Authorization"]
        assert echoed.startswith("Bearer ")
        # Verify it's a real JWT (three dot-separated parts)
        token = echoed.split(" ", 1)[1]
        parts = token.split(".")
        assert len(parts) == 3, f"Expected JWT (3 parts), got {len(parts)} parts"

    @pytest.mark.asyncio
    async def test_real_oidc_discovery_to_token(self) -> None:
        """Full OIDC flow: discover token_url from Cognito, then fetch token.

        Requires DNS_AID_TEST_OAUTH_DISCOVERY_URL in addition to the
        standard OAuth env vars. Cognito discovery uses a pool-based URL:
        https://cognito-idp.{region}.amazonaws.com/{pool-id}/.well-known/openid-configuration
        """
        creds = _get_oauth_creds()
        discovery_url = os.getenv("DNS_AID_TEST_OAUTH_DISCOVERY_URL")
        if not creds or not discovery_url:
            pytest.skip(
                "Set DNS_AID_TEST_OAUTH_* + DNS_AID_TEST_OAUTH_DISCOVERY_URL to run"
            )

        _, client_id, client_secret, scopes = creds

        handler = OAuth2AuthHandler(
            client_id=client_id,
            client_secret=client_secret,
            discovery_url=discovery_url,
            scopes=scopes,
        )

        request = httpx.Request("POST", "https://agent.example.com/mcp")
        result = await handler.apply(request)

        auth_header = result.headers.get("authorization", "")
        assert auth_header.startswith("Bearer ")
        token = auth_header.split(" ", 1)[1]
        assert len(token.split(".")) == 3  # Real JWT
