# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for SvcParam schema registry."""

from dns_aid.core.schema_registry import (
    REGISTRY,
    from_a2a_agent_card,
    from_langserve_route,
    from_langsmith_project,
)


class TestSchemaRegistry:
    """Tests for the global schema registry."""

    def test_registry_has_all_svcparams(self):
        """All DNS-AID SvcParam keys are registered."""
        expected = {
            "alpn", "port", "cap_uri", "cap_sha256", "bap",
            "policy_uri", "realm", "sig", "connect_class",
            "connect_meta", "enroll_uri",
        }
        assert set(REGISTRY.field_names()) == expected

    def test_lookup_by_field_name(self):
        entry = REGISTRY.lookup("cap_uri")
        assert entry is not None
        assert entry.svcparam_name == "cap"
        assert "langserve" in entry.sources[0]

    def test_lookup_by_svcparam_name(self):
        entry = REGISTRY.lookup_by_svcparam("bap")
        assert entry is not None
        assert entry.field_name == "bap"

    def test_lookup_missing_returns_none(self):
        assert REGISTRY.lookup("nonexistent") is None

    def test_bap_serializer(self):
        entry = REGISTRY.lookup("bap")
        assert entry.serializer(["a2a/1", "mcp/1"]) == "a2a/1,mcp/1"
        assert entry.serializer("a2a/1") == "a2a/1"


class TestFromLangserveRoute:
    """Tests for LangServe route adapter."""

    def test_basic_conversion(self):
        result = from_langserve_route(
            path="/my-agent",
            protocol="a2a",
            endpoint="api.example.com",
        )
        assert result["name"] == "my-agent"
        assert result["protocol"].value == "a2a"
        assert result["endpoint"] == "api.example.com"
        assert result["port"] == 443

    def test_nested_path(self):
        result = from_langserve_route(
            path="/api/v1/chat",
            protocol="mcp",
            endpoint="mcp.example.com",
        )
        assert result["name"] == "api-v1-chat"

    def test_empty_path(self):
        result = from_langserve_route(
            path="",
            protocol="https",
            endpoint="api.example.com",
        )
        assert result["name"] == "default"

    def test_none_values_excluded(self):
        result = from_langserve_route(
            path="/agent",
            protocol="a2a",
            endpoint="api.example.com",
        )
        assert "capabilities" not in result
        assert "cap_uri" not in result


class TestFromA2aAgentCard:
    """Tests for A2A agent card adapter."""

    def test_with_skills(self):
        class MockSkill:
            def __init__(self, id):
                self.id = id

        class MockCard:
            name = "Payment Agent"
            version = "2.0.0"
            description = "Handles payments"
            skills = [MockSkill("pay"), MockSkill("refund")]

            def to_capabilities(self):
                return ["pay", "refund"]

        result = from_a2a_agent_card(MockCard(), endpoint="pay.example.com")
        assert result["name"] == "payment-agent"
        assert result["protocol"].value == "a2a"
        assert result["capabilities"] == ["pay", "refund"]
        assert result["version"] == "2.0.0"

    def test_name_sanitization(self):
        class MockCard:
            name = "My Agent (v2)!"
            version = "1.0.0"
            description = None
            skills = []

            def to_capabilities(self):
                return []

        result = from_a2a_agent_card(MockCard(), endpoint="a.example.com")
        # Special chars replaced with hyphens, stripped
        assert all(c.isalnum() or c == "-" for c in result["name"])


class TestFromLangsmithProject:
    """Tests for LangSmith project adapter."""

    def test_basic_project(self):
        project = {
            "name": "My Chat Bot",
            "description": "A helpful chatbot",
        }
        result = from_langsmith_project(
            project,
            domain="agents.example.com",
            endpoint="api.example.com",
        )
        assert result["name"] == "my-chat-bot"
        assert result["domain"] == "agents.example.com"
        assert result["protocol"] == "https"
        assert result["description"] == "A helpful chatbot"

    def test_metadata_overrides(self):
        project = {
            "name": "agent",
            "metadata": {
                "protocol": "a2a",
                "capabilities": ["search", "summarize"],
                "realm": "production",
                "cap_uri": "https://example.com/cap.json",
            },
        }
        result = from_langsmith_project(
            project,
            domain="agents.example.com",
            endpoint="api.example.com",
        )
        assert result["protocol"] == "a2a"
        assert result["capabilities"] == ["search", "summarize"]
        assert result["realm"] == "production"
        assert result["cap_uri"] == "https://example.com/cap.json"

    def test_name_sanitization(self):
        project = {"name": "My Agent (Test)"}
        result = from_langsmith_project(
            project,
            domain="example.com",
            endpoint="api.example.com",
        )
        assert all(c.isalnum() or c == "-" for c in result["name"])
