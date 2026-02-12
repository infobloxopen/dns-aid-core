# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for A2A Agent Card parsing and fetching."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.a2a_card import (
    A2AAgentCard,
    A2AAuthentication,
    A2ASkill,
    fetch_agent_card,
    fetch_agent_card_from_domain,
)


class TestA2ASkill:
    """Tests for A2ASkill dataclass."""

    def test_from_dict_full(self) -> None:
        """Test parsing a full skill dict."""
        data = {
            "id": "process-payment",
            "name": "Process Payment",
            "description": "Handles credit card payments",
            "inputModes": ["text", "data"],
            "outputModes": ["text"],
            "tags": ["payment", "finance"],
        }
        skill = A2ASkill.from_dict(data)

        assert skill.id == "process-payment"
        assert skill.name == "Process Payment"
        assert skill.description == "Handles credit card payments"
        assert skill.input_modes == ["text", "data"]
        assert skill.output_modes == ["text"]
        assert skill.tags == ["payment", "finance"]

    def test_from_dict_minimal(self) -> None:
        """Test parsing a minimal skill dict."""
        data = {"id": "ping", "name": "Ping"}
        skill = A2ASkill.from_dict(data)

        assert skill.id == "ping"
        assert skill.name == "Ping"
        assert skill.description is None
        assert skill.input_modes == ["text"]
        assert skill.output_modes == ["text"]
        assert skill.tags == []


class TestA2AAuthentication:
    """Tests for A2AAuthentication dataclass."""

    def test_from_dict_full(self) -> None:
        """Test parsing full auth dict."""
        data = {
            "schemes": ["oauth2", "api_key"],
            "credentials": "https://example.com/.well-known/oauth",
        }
        auth = A2AAuthentication.from_dict(data)

        assert auth.schemes == ["oauth2", "api_key"]
        assert auth.credentials == "https://example.com/.well-known/oauth"

    def test_from_dict_empty(self) -> None:
        """Test parsing empty auth dict."""
        auth = A2AAuthentication.from_dict({})

        assert auth.schemes == []
        assert auth.credentials is None


class TestA2AAgentCard:
    """Tests for A2AAgentCard dataclass."""

    def test_from_dict_full(self) -> None:
        """Test parsing a full Agent Card."""
        data = {
            "name": "Payment Agent",
            "description": "Handles payment processing",
            "url": "https://payment.example.com",
            "version": "2.0.0",
            "provider": {
                "organization": "Example Corp",
                "url": "https://example.com",
            },
            "skills": [
                {"id": "pay", "name": "Pay"},
                {"id": "refund", "name": "Refund"},
            ],
            "authentication": {
                "schemes": ["oauth2"],
            },
            "defaultInputModes": ["text", "data"],
            "defaultOutputModes": ["text"],
            "customField": "custom value",
        }
        card = A2AAgentCard.from_dict(data)

        assert card.name == "Payment Agent"
        assert card.description == "Handles payment processing"
        assert card.url == "https://payment.example.com"
        assert card.version == "2.0.0"
        assert card.provider is not None
        assert card.provider.organization == "Example Corp"
        assert card.provider.url == "https://example.com"
        assert len(card.skills) == 2
        assert card.skills[0].id == "pay"
        assert card.skills[1].id == "refund"
        assert card.authentication is not None
        assert card.authentication.schemes == ["oauth2"]
        assert card.default_input_modes == ["text", "data"]
        assert card.default_output_modes == ["text"]
        assert card.metadata == {"customField": "custom value"}

    def test_from_dict_minimal(self) -> None:
        """Test parsing a minimal Agent Card."""
        data = {"name": "Simple Agent", "url": "https://agent.example.com"}
        card = A2AAgentCard.from_dict(data)

        assert card.name == "Simple Agent"
        assert card.url == "https://agent.example.com"
        assert card.version == "1.0.0"
        assert card.description is None
        assert card.provider is None
        assert card.skills == []
        assert card.authentication is None
        assert card.default_input_modes == ["text"]
        assert card.default_output_modes == ["text"]

    def test_skill_ids(self) -> None:
        """Test skill_ids property."""
        card = A2AAgentCard(
            name="Test",
            url="https://test.com",
            skills=[
                A2ASkill(id="skill-1", name="Skill 1"),
                A2ASkill(id="skill-2", name="Skill 2"),
            ],
        )
        assert card.skill_ids == ["skill-1", "skill-2"]

    def test_skill_names(self) -> None:
        """Test skill_names property."""
        card = A2AAgentCard(
            name="Test",
            url="https://test.com",
            skills=[
                A2ASkill(id="s1", name="First Skill"),
                A2ASkill(id="s2", name="Second Skill"),
            ],
        )
        assert card.skill_names == ["First Skill", "Second Skill"]

    def test_to_capabilities(self) -> None:
        """Test converting skills to DNS-AID capabilities."""
        card = A2AAgentCard(
            name="Test",
            url="https://test.com",
            skills=[
                A2ASkill(id="payment", name="Payment"),
                A2ASkill(id="refund", name="Refund"),
            ],
        )
        assert card.to_capabilities() == ["payment", "refund"]


class TestFetchAgentCard:
    """Tests for fetch_agent_card function."""

    @pytest.mark.asyncio
    async def test_fetch_success(self) -> None:
        """Test successful Agent Card fetch."""
        mock_card_data = {
            "name": "Test Agent",
            "url": "https://agent.example.com",
            "skills": [{"id": "ping", "name": "Ping"}],
        }

        with patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u):
            with patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_card_data

                mock_instance = AsyncMock()
                mock_instance.get.return_value = mock_response
                mock_instance.__aenter__.return_value = mock_instance
                mock_instance.__aexit__.return_value = None

                mock_client.return_value = mock_instance

                card = await fetch_agent_card("https://agent.example.com")

        assert card is not None
        assert card.name == "Test Agent"
        assert len(card.skills) == 1
        assert card.skills[0].id == "ping"

    @pytest.mark.asyncio
    async def test_fetch_adds_https(self) -> None:
        """Test that https:// is added if missing."""
        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client,
        ):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"name": "Test", "url": "https://x.com"}

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            await fetch_agent_card("agent.example.com")

            # Verify the URL was constructed correctly
            call_args = mock_instance.get.call_args[0][0]
            assert call_args == "https://agent.example.com/.well-known/agent.json"

    @pytest.mark.asyncio
    async def test_fetch_404(self) -> None:
        """Test fetch returns None on 404."""
        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client,
        ):
            mock_response = MagicMock()
            mock_response.status_code = 404

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_timeout(self) -> None:
        """Test fetch returns None on timeout."""
        import httpx

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client,
        ):
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = httpx.TimeoutException("timeout")
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_connect_error(self) -> None:
        """Test fetch returns None on connection error."""
        import httpx

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client,
        ):
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = httpx.ConnectError("failed")
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_invalid_json(self) -> None:
        """Test fetch returns None on invalid JSON."""
        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client,
        ):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = "not an object"

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            card = await fetch_agent_card("https://agent.example.com")

        assert card is None


class TestFetchAgentCardFromDomain:
    """Tests for fetch_agent_card_from_domain function."""

    @pytest.mark.asyncio
    async def test_constructs_url_correctly(self) -> None:
        """Test that domain is converted to full URL."""
        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.a2a_card.httpx.AsyncClient") as mock_client,
        ):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"name": "Test", "url": "https://x.com"}

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            await fetch_agent_card_from_domain("example.com")

            call_args = mock_instance.get.call_args[0][0]
            assert call_args == "https://example.com/.well-known/agent.json"
