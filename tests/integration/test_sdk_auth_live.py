# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Live SDK auth integration tests against real AWS infrastructure.

Tests every SDK auth pattern from the developer guide:
1. No auth (public agent)
2. Bearer token (httpbin echo)
3. API key (httpbin echo)
4. OAuth2 client-credentials (AWS Cognito)
5. SigV4 (API Gateway with IAM auth)
6. Explicit handler override
7. Auth enrichment from agent-card.json
8. Multi-agent with different auth types

Requires:
- Public agent: https://1ls9mi4dp2.execute-api.us-east-1.amazonaws.com
- SigV4 agent: https://lixqgn0ttl.execute-api.us-east-1.amazonaws.com
- AWS okta-sso profile configured

Run with:
    pytest tests/integration/test_sdk_auth_live.py -v
"""

from __future__ import annotations

import pytest

from dns_aid.core.a2a_card import fetch_agent_card
from dns_aid.core.discoverer import (
    _apply_agent_card,
    _apply_auth_from_metadata,
    _fetch_agent_json_auth,
)
from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth.simple import BearerAuthHandler
from dns_aid.sdk.client import AgentClient

pytestmark = [pytest.mark.integration, pytest.mark.live]

PUBLIC_HOST = "1ls9mi4dp2.execute-api.us-east-1.amazonaws.com"
SIGV4_HOST = "lixqgn0ttl.execute-api.us-east-1.amazonaws.com"


def _agent(host: str, name: str = "test", **kwargs: object) -> AgentRecord:
    return AgentRecord(
        name=name,
        domain="test.example.com",
        protocol=Protocol.A2A,
        target_host=host,
        port=443,
        **kwargs,
    )


def _a2a_payload(text: str) -> dict:
    return {
        "message": {
            "messageId": "live-test",
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
        }
    }


# ─────────────────────────────────────────────────────────
# 1. NO AUTH — public agent
# ─────────────────────────────────────────────────────────


class TestNoAuth:
    @pytest.mark.asyncio
    async def test_public_agent_no_credentials(self) -> None:
        """Invoke a public agent with no credentials — should succeed."""
        agent = _agent(PUBLIC_HOST, "public-test")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("hello public agent"),
            )

        assert result.success
        assert "[PUBLIC] Echo:" in str(result.data)


# ─────────────────────────────────────────────────────────
# 2. BEARER TOKEN — httpbin echo
# ─────────────────────────────────────────────────────────


class TestBearerAuth:
    @pytest.mark.asyncio
    async def test_bearer_token_reaches_endpoint(self) -> None:
        """Bearer token applied via SDK credentials reaches the endpoint."""
        agent = _agent(
            "httpbin.org",
            "bearer-test",
            auth_type="bearer",
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "bearer"},
                credentials={"token": "live-bearer-token-xyz"},
            )

        assert result.success
        data = result.data
        assert data["headers"]["Authorization"] == "Bearer live-bearer-token-xyz"


# ─────────────────────────────────────────────────────────
# 3. API KEY — httpbin echo
# ─────────────────────────────────────────────────────────


class TestApiKeyAuth:
    @pytest.mark.asyncio
    async def test_api_key_header_reaches_endpoint(self) -> None:
        """API key injected via SDK credentials reaches the endpoint."""
        agent = _agent(
            "httpbin.org",
            "apikey-test",
            auth_type="api_key",
            auth_config={"header_name": "X-Custom-Key"},
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "api_key"},
                credentials={"api_key": "sk-live-test-key"},
            )

        assert result.success
        assert result.data["headers"]["X-Custom-Key"] == "sk-live-test-key"


# ─────────────────────────────────────────────────────────
# 4. OAUTH2 — AWS Cognito
# ─────────────────────────────────────────────────────────


class TestOAuth2Auth:
    @pytest.mark.asyncio
    async def test_oauth2_token_applied_to_request(self) -> None:
        """OAuth2 client-credentials token fetched from Cognito and applied."""
        agent = _agent(
            "httpbin.org",
            "oauth2-test",
            auth_type="oauth2",
            auth_config={
                "oauth_discovery": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_NE34GkEdc/.well-known/openid-configuration",
            },
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "oauth2"},
                credentials={
                    "client_id": "17gid5tgiv7634o57kvo9ph6mm",
                    "client_secret": "l6s8jli2fk18jisb6gouoaho9rf9va82c3vg6m2fnu141qhrpe9",
                    "scopes": "dns-aid-api/invoke",
                },
            )

        assert result.success
        auth_header = result.data["headers"]["Authorization"]
        assert auth_header.startswith("Bearer ")
        # Verify it's a real JWT (3 dot-separated parts)
        token = auth_header.split(" ", 1)[1]
        assert len(token.split(".")) == 3


# ─────────────────────────────────────────────────────────
# 5. AWS SIGV4 — API Gateway with IAM auth
# ─────────────────────────────────────────────────────────


class TestSigV4Auth:
    @pytest.mark.asyncio
    async def test_sigv4_invoke_succeeds(self) -> None:
        """SigV4 signed request passes API Gateway IAM auth."""
        agent = _agent(
            SIGV4_HOST,
            "sigv4-test",
            auth_type="sigv4",
            auth_config={"region": "us-east-1", "service": "execute-api"},
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("SigV4 live test"),
                credentials={"profile_name": "okta-sso"},
            )

        assert result.success
        assert "Auth verified!" in str(result.data)

    @pytest.mark.asyncio
    async def test_sigv4_without_credentials_fails(self) -> None:
        """Request without SigV4 to IAM-protected endpoint returns error."""
        agent = _agent(SIGV4_HOST, "sigv4-noauth")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("should fail"),
            )

        assert not result.success
        assert result.signal.http_status_code == 403


# ─────────────────────────────────────────────────────────
# 6. EXPLICIT HANDLER OVERRIDE
# ─────────────────────────────────────────────────────────


class TestExplicitHandler:
    @pytest.mark.asyncio
    async def test_explicit_handler_overrides_metadata(self) -> None:
        """Explicit auth_handler ignores agent metadata auth_type."""
        agent = _agent(
            "httpbin.org",
            "override-test",
            auth_type="api_key",  # metadata says api_key
            endpoint_override="https://httpbin.org/post",
        )

        # But we override with bearer
        handler = BearerAuthHandler(token="explicit-override-token")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "override"},
                auth_handler=handler,
            )

        assert result.success
        assert result.data["headers"]["Authorization"] == "Bearer explicit-override-token"


# ─────────────────────────────────────────────────────────
# 7. AUTH ENRICHMENT FROM agent-card.json
# ─────────────────────────────────────────────────────────


class TestAuthEnrichment:
    @pytest.mark.asyncio
    async def test_auth_from_agent_card_json(self) -> None:
        """Auth populated from agent-card.json authentication.schemes."""
        agent = _agent(SIGV4_HOST, "enrich-card")

        card = await fetch_agent_card(f"https://{SIGV4_HOST}")
        assert card is not None
        assert card.authentication is not None
        assert "sigv4" in card.authentication.schemes

        _apply_agent_card(agent, card)

        assert agent.auth_type == "sigv4"
        assert agent.auth_config == {"schemes": ["sigv4"]}

    @pytest.mark.asyncio
    async def test_auth_from_agent_json_fallback(self) -> None:
        """Auth populated from agent.json when agent-card.json has no auth."""
        agent = _agent(SIGV4_HOST, "enrich-native")

        auth_data = await _fetch_agent_json_auth(SIGV4_HOST)
        assert auth_data is not None
        assert auth_data["type"] == "sigv4"

        _apply_auth_from_metadata(agent, {"auth": auth_data})

        assert agent.auth_type == "sigv4"
        assert agent.auth_config["region"] == "us-east-1"
        assert agent.auth_config["service"] == "execute-api"

    @pytest.mark.asyncio
    async def test_enrichment_then_invoke(self) -> None:
        """Full flow: enrich from agent-card.json → invoke with credentials."""
        agent = _agent(SIGV4_HOST, "enrich-invoke")

        # Enrich
        card = await fetch_agent_card(f"https://{SIGV4_HOST}")
        _apply_agent_card(agent, card)
        assert agent.auth_type == "sigv4"

        # Override with richer config from agent.json
        auth_data = await _fetch_agent_json_auth(SIGV4_HOST)
        _apply_auth_from_metadata(agent, {"auth": auth_data})

        # Invoke
        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("enrichment + invoke"),
                credentials={"profile_name": "okta-sso"},
            )

        assert result.success
        assert "Auth verified!" in str(result.data)


# ─────────────────────────────────────────────────────────
# 8. MULTI-AGENT WITH DIFFERENT AUTH
# ─────────────────────────────────────────────────────────


class TestMultiAgent:
    @pytest.mark.asyncio
    async def test_different_auth_per_agent(self) -> None:
        """Multiple agents with different auth types — SDK handles each."""
        agents = [
            _agent(PUBLIC_HOST, "public"),
            _agent(
                "httpbin.org",
                "bearer-agent",
                auth_type="bearer",
                endpoint_override="https://httpbin.org/post",
            ),
            _agent(
                SIGV4_HOST,
                "sigv4-agent",
                auth_type="sigv4",
                auth_config={"region": "us-east-1", "service": "execute-api"},
            ),
        ]

        credentials_map = {
            "public": None,
            "bearer-agent": {"token": "multi-test-token"},
            "sigv4-agent": {"profile_name": "okta-sso"},
        }

        results = {}
        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            for agent in agents:
                result = await client.invoke(
                    agent,
                    method="message/send" if agent.name != "bearer-agent" else None,
                    arguments=(
                        _a2a_payload(f"hello {agent.name}")
                        if agent.name != "bearer-agent"
                        else {"test": agent.name}
                    ),
                    credentials=credentials_map[agent.name],
                )
                results[agent.name] = result

        # All should succeed
        assert results["public"].success, "Public agent failed"
        assert results["bearer-agent"].success, "Bearer agent failed"
        assert results["sigv4-agent"].success, "SigV4 agent failed"

        # Verify correct auth was applied
        assert "[PUBLIC] Echo:" in str(results["public"].data)
        assert results["bearer-agent"].data["headers"]["Authorization"] == "Bearer multi-test-token"
        assert "Auth verified!" in str(results["sigv4-agent"].data)
