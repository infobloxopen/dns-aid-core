# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for A2A discovery bridge."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.a2a.bridge import (
    AgentCard,
    AgentCardSkill,
    MAX_DNS_LABEL_LENGTH,
    _sanitize_dns_label,
    _validate_endpoint,
    discover_a2a_agents,
    fetch_agent_card,
    publish_a2a_agent,
    to_agent_card,
    unpublish_a2a_agent,
)
from dns_aid.core.models import AgentRecord, DiscoveryResult


class TestAgentCardSkill:
    """Tests for AgentCardSkill dataclass."""

    def test_defaults(self) -> None:
        skill = AgentCardSkill(id="search", name="Search")
        assert skill.id == "search"
        assert skill.name == "Search"
        assert skill.description == ""
        assert skill.tags == []
        assert skill.examples == []

    def test_all_fields(self) -> None:
        skill = AgentCardSkill(
            id="search",
            name="Search",
            description="Full-text search",
            tags=["search", "retrieval"],
            examples=["find papers about AI"],
        )
        assert skill.description == "Full-text search"
        assert skill.tags == ["search", "retrieval"]
        assert skill.examples == ["find papers about AI"]


class TestAgentCard:
    """Tests for AgentCard dataclass."""

    def test_defaults(self) -> None:
        card = AgentCard(name="test")
        assert card.name == "test"
        assert card.description == ""
        assert card.url == ""
        assert card.skills == []
        assert card.raw == {}

    def test_from_dict(self) -> None:
        data = {
            "name": "Research Agent",
            "description": "A research assistant",
            "url": "https://research.example.com",
            "version": "2.0.0",
            "skills": [
                {
                    "id": "search",
                    "name": "Search",
                    "description": "Search for papers",
                    "tags": ["search"],
                    "examples": ["find papers"],
                }
            ],
            "provider": {"organization": "Example Corp"},
            "documentationUrl": "https://docs.example.com",
            "capabilities": {"streaming": True},
        }
        card = AgentCard.from_dict(data)
        assert card.name == "Research Agent"
        assert card.description == "A research assistant"
        assert card.url == "https://research.example.com"
        assert card.version == "2.0.0"
        assert len(card.skills) == 1
        assert card.skills[0].id == "search"
        assert card.skills[0].tags == ["search"]
        assert card.provider == "Example Corp"
        assert card.documentation_url == "https://docs.example.com"
        assert card.capabilities == {"streaming": True}

    def test_from_dict_minimal(self) -> None:
        data = {"name": "Simple Agent"}
        card = AgentCard.from_dict(data)
        assert card.name == "Simple Agent"
        assert card.skills == []
        assert card.provider == ""

    def test_from_dict_string_provider(self) -> None:
        data = {"name": "Test", "provider": "Acme Inc"}
        card = AgentCard.from_dict(data)
        assert card.provider == "Acme Inc"

    def test_from_dict_malformed_skills_raises(self) -> None:
        """skills as a string should raise TypeError, not iterate chars."""
        data = {"name": "Bad", "skills": "not-a-list"}
        with pytest.raises(TypeError, match="Expected 'skills' to be a list"):
            AgentCard.from_dict(data)

    def test_from_dict_non_dict_skill_entries_skipped(self) -> None:
        """Non-dict entries inside the skills list are skipped."""
        data = {"name": "Test", "skills": [42, "string", {"id": "real", "name": "Real"}]}
        card = AgentCard.from_dict(data)
        assert len(card.skills) == 1
        assert card.skills[0].id == "real"

    def test_to_dict(self) -> None:
        card = AgentCard(
            name="Test Agent",
            description="A test agent",
            url="https://test.example.com",
            version="1.0.0",
            skills=[
                AgentCardSkill(
                    id="summarize",
                    name="Summarize",
                    description="Summarize text",
                )
            ],
            provider="Test Corp",
        )
        result = card.to_dict()
        assert result["name"] == "Test Agent"
        assert result["description"] == "A test agent"
        assert result["url"] == "https://test.example.com"
        assert len(result["skills"]) == 1
        assert result["skills"][0]["id"] == "summarize"
        assert result["provider"] == {"organization": "Test Corp"}

    def test_to_dict_minimal(self) -> None:
        card = AgentCard(name="Simple")
        result = card.to_dict()
        assert result["name"] == "Simple"
        assert "skills" not in result
        assert "provider" not in result

    def test_roundtrip(self) -> None:
        original = {
            "name": "Roundtrip Agent",
            "description": "Testing roundtrip",
            "url": "https://rt.example.com",
            "version": "1.0.0",
            "skills": [
                {"id": "test", "name": "Test", "description": "Test skill"}
            ],
            "provider": {"organization": "Test"},
        }
        card = AgentCard.from_dict(original)
        result = card.to_dict()
        assert result["name"] == original["name"]
        assert result["description"] == original["description"]
        assert result["url"] == original["url"]
        assert len(result["skills"]) == len(original["skills"])


class TestValidateEndpoint:
    """Tests for _validate_endpoint."""

    def test_valid_hostname(self) -> None:
        _validate_endpoint("api.example.com")

    def test_rejects_slash(self) -> None:
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_endpoint("evil.com/../../bypass")

    def test_rejects_at_sign(self) -> None:
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_endpoint("evil.com@attacker.com")

    def test_rejects_hash(self) -> None:
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_endpoint("evil.com#fragment")

    def test_rejects_question_mark(self) -> None:
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_endpoint("evil.com?query=1")


class TestSanitizeDnsLabel:
    """Tests for _sanitize_dns_label."""

    def test_simple_name(self) -> None:
        assert _sanitize_dns_label("my-agent") == "my-agent"

    def test_spaces_to_hyphens(self) -> None:
        assert _sanitize_dns_label("My Agent") == "my-agent"

    def test_underscores_to_hyphens(self) -> None:
        assert _sanitize_dns_label("my_agent") == "my-agent"

    def test_removes_special_chars(self) -> None:
        assert _sanitize_dns_label("my.agent!v2") == "myagentv2"

    def test_strips_hyphens(self) -> None:
        assert _sanitize_dns_label("-agent-") == "agent"

    def test_lowercase(self) -> None:
        assert _sanitize_dns_label("MyAgent") == "myagent"

    def test_empty_returns_agent(self) -> None:
        assert _sanitize_dns_label("") == "agent"

    def test_special_only_returns_agent(self) -> None:
        assert _sanitize_dns_label("!!!") == "agent"

    def test_truncates_to_63_chars(self) -> None:
        long_name = "a" * 100
        result = _sanitize_dns_label(long_name)
        assert len(result) <= MAX_DNS_LABEL_LENGTH


class TestToAgentCard:
    """Tests for to_agent_card conversion."""

    def test_converts_basic_agent(self) -> None:
        agent = AgentRecord(
            name="search-agent",
            domain="example.com",
            protocol="a2a",
            target_host="search.example.com",
            port=443,
            capabilities=["search", "summarize"],
            version="1.0.0",
            description="A search agent",
        )
        card = to_agent_card(agent)
        assert card.name == "search-agent"
        assert card.description == "A search agent"
        assert card.version == "1.0.0"
        assert len(card.skills) == 2
        assert card.skills[0].id == "search"
        assert card.skills[1].id == "summarize"

    def test_converts_agent_without_capabilities(self) -> None:
        agent = AgentRecord(
            name="simple",
            domain="example.com",
            protocol="a2a",
            target_host="simple.example.com",
        )
        card = to_agent_card(agent)
        assert card.name == "simple"
        assert card.skills == []

    def test_includes_endpoint_url(self) -> None:
        agent = AgentRecord(
            name="test",
            domain="example.com",
            protocol="a2a",
            target_host="test.example.com",
            port=8080,
        )
        card = to_agent_card(agent)
        assert "test.example.com" in card.url
        assert "8080" in card.url


class TestDiscoverA2aAgents:
    """Tests for discover_a2a_agents."""

    @pytest.mark.asyncio
    async def test_filters_by_a2a_protocol(self) -> None:
        mock_agent = AgentRecord(
            name="a2a-agent",
            domain="example.com",
            protocol="a2a",
            target_host="a2a.example.com",
        )
        mock_result = DiscoveryResult(
            query="_agents.example.com",
            domain="example.com",
            agents=[mock_agent],
        )

        with patch(
            "dns_aid.a2a.bridge.discover", new_callable=AsyncMock
        ) as mock_discover:
            mock_discover.return_value = mock_result

            agents = await discover_a2a_agents("example.com")

        assert len(agents) == 1
        assert agents[0].name == "a2a-agent"
        mock_discover.assert_awaited_once_with(
            domain="example.com",
            protocol="a2a",
            require_dnssec=False,
        )


class TestFetchAgentCard:
    """Tests for fetch_agent_card."""

    @pytest.mark.asyncio
    async def test_fetches_card_https(self) -> None:
        card_data = {
            "name": "Remote Agent",
            "description": "A remote agent",
            "url": "https://remote.example.com",
            "version": "1.0.0",
        }

        mock_response = MagicMock()
        mock_response.json.return_value = card_data
        mock_response.raise_for_status = MagicMock()

        with patch("dns_aid.a2a.bridge.httpx") as mock_httpx, \
             patch("dns_aid.a2a.bridge.validate_fetch_url"):
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient.return_value = mock_client

            card = await fetch_agent_card("remote.example.com")

        assert card.name == "Remote Agent"
        assert card.description == "A remote agent"

    @pytest.mark.asyncio
    async def test_defaults_to_https_for_non_443(self) -> None:
        """Non-443 ports should still use HTTPS by default."""
        card_data = {"name": "Test"}

        mock_response = MagicMock()
        mock_response.json.return_value = card_data
        mock_response.raise_for_status = MagicMock()

        with patch("dns_aid.a2a.bridge.httpx") as mock_httpx, \
             patch("dns_aid.a2a.bridge.validate_fetch_url"):
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient.return_value = mock_client

            await fetch_agent_card("test.example.com", port=8080)

        # Should be HTTPS, not HTTP
        mock_client.get.assert_awaited_once()
        url_called = mock_client.get.call_args[0][0]
        assert url_called.startswith("https://")

    @pytest.mark.asyncio
    async def test_allow_http_enables_cleartext(self) -> None:
        """allow_http=True for non-443 ports should use HTTP."""
        card_data = {"name": "Test"}

        mock_response = MagicMock()
        mock_response.json.return_value = card_data
        mock_response.raise_for_status = MagicMock()

        with patch("dns_aid.a2a.bridge.httpx") as mock_httpx, \
             patch("dns_aid.a2a.bridge.validate_fetch_url"):
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient.return_value = mock_client

            await fetch_agent_card(
                "test.example.com", port=8080, allow_http=True
            )

        url_called = mock_client.get.call_args[0][0]
        assert url_called.startswith("http://")

    @pytest.mark.asyncio
    async def test_rejects_unsafe_endpoint(self) -> None:
        with pytest.raises(ValueError, match="unsafe characters"):
            await fetch_agent_card("evil.com/../../bypass")

    @pytest.mark.asyncio
    async def test_uses_shared_client(self) -> None:
        card_data = {"name": "Shared"}
        mock_response = MagicMock()
        mock_response.json.return_value = card_data
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch("dns_aid.a2a.bridge.validate_fetch_url"):
            card = await fetch_agent_card(
                "test.example.com", client=mock_client
            )

        assert card.name == "Shared"
        mock_client.get.assert_awaited_once()


class TestPublishA2aAgent:
    """Tests for publish_a2a_agent."""

    @pytest.mark.asyncio
    async def test_publishes_card(self) -> None:
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {"success": True}

        card = AgentCard(
            name="My Agent",
            description="A helpful agent",
            url="https://agent.example.com",
            version="1.0.0",
            skills=[
                AgentCardSkill(id="search", name="Search"),
                AgentCardSkill(id="summarize", name="Summarize"),
            ],
        )

        with patch(
            "dns_aid.a2a.bridge.publish", new_callable=AsyncMock
        ) as mock_publish:
            mock_publish.return_value = mock_result

            result = await publish_a2a_agent(
                card,
                domain="agents.example.com",
                endpoint="agent.example.com",
            )

        assert result["success"] is True
        call_kwargs = mock_publish.call_args.kwargs
        assert call_kwargs["name"] == "my-agent"
        assert call_kwargs["protocol"] == "a2a"
        assert call_kwargs["capabilities"] == ["search", "summarize"]
        assert call_kwargs["description"] == "A helpful agent"

    @pytest.mark.asyncio
    async def test_uses_explicit_name(self) -> None:
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {"success": True}

        card = AgentCard(
            name="My Agent",
            url="https://agent.example.com",
        )

        with patch(
            "dns_aid.a2a.bridge.publish", new_callable=AsyncMock
        ) as mock_publish:
            mock_publish.return_value = mock_result

            await publish_a2a_agent(
                card,
                domain="agents.example.com",
                name="custom-name",
                endpoint="agent.example.com",
            )

        call_kwargs = mock_publish.call_args.kwargs
        assert call_kwargs["name"] == "custom-name"

    @pytest.mark.asyncio
    async def test_extracts_endpoint_from_url(self) -> None:
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {"success": True}

        card = AgentCard(
            name="Test",
            url="https://agent.example.com:8080/api",
        )

        with patch(
            "dns_aid.a2a.bridge.publish", new_callable=AsyncMock
        ) as mock_publish:
            mock_publish.return_value = mock_result

            await publish_a2a_agent(
                card, domain="agents.example.com"
            )

        call_kwargs = mock_publish.call_args.kwargs
        assert call_kwargs["endpoint"] == "agent.example.com"
        assert call_kwargs["port"] == 8080

    @pytest.mark.asyncio
    async def test_raises_without_endpoint(self) -> None:
        card = AgentCard(name="No URL Agent")

        with pytest.raises(ValueError, match="endpoint"):
            await publish_a2a_agent(
                card, domain="agents.example.com"
            )

    @pytest.mark.asyncio
    async def test_raises_with_both_backend_and_backend_name(self) -> None:
        card = AgentCard(name="Test", url="https://test.example.com")

        with pytest.raises(ValueError, match="Specify either"):
            await publish_a2a_agent(
                card,
                domain="agents.example.com",
                endpoint="test.example.com",
                backend=MagicMock(),
                backend_name="mock",
            )


class TestUnpublishA2aAgent:
    """Tests for unpublish_a2a_agent."""

    @pytest.mark.asyncio
    async def test_unpublishes(self) -> None:
        with patch(
            "dns_aid.a2a.bridge.unpublish", new_callable=AsyncMock
        ) as mock_unpublish:
            mock_unpublish.return_value = True

            result = await unpublish_a2a_agent(
                name="my-agent",
                domain="agents.example.com",
            )

        assert result is True
        call_kwargs = mock_unpublish.call_args.kwargs
        assert call_kwargs["name"] == "my-agent"
        assert call_kwargs["protocol"] == "a2a"

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        with patch(
            "dns_aid.a2a.bridge.unpublish", new_callable=AsyncMock
        ) as mock_unpublish:
            mock_unpublish.return_value = False

            result = await unpublish_a2a_agent(
                name="missing",
                domain="agents.example.com",
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_raises_with_both_backend_and_backend_name(self) -> None:
        with pytest.raises(ValueError, match="Specify either"):
            await unpublish_a2a_agent(
                name="test",
                domain="agents.example.com",
                backend=MagicMock(),
                backend_name="mock",
            )
