# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for PolicyDocument schema."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from dns_aid.sdk.policy.schema import (
    RULE_ENFORCEMENT_LAYERS,
    AvailabilityConfig,
    CELRule,
    PolicyDocument,
    PolicyEnforcementLayer,
    PolicyRules,
    RateLimitConfig,
)

# =============================================================================
# PolicyDocument tests
# =============================================================================


class TestPolicyDocument:
    """Test PolicyDocument parsing and validation."""

    def test_valid_document_parses(self) -> None:
        """A fully populated valid document should parse correctly."""
        doc = PolicyDocument(
            version="1.0",
            agent="_network._mcp._agents.example.com",
            rules=PolicyRules(
                required_protocols=["mcp", "a2a"],
                required_auth_types=["oauth2"],
                require_dnssec=True,
                require_mutual_tls=False,
                min_tls_version="1.3",
                required_caller_trust_score=0.7,
                rate_limits=RateLimitConfig(max_per_minute=60, max_per_hour=1000),
                max_payload_bytes=1048576,
                allowed_caller_domains=["*.infoblox.com", "trusted.example.com"],
                blocked_caller_domains=["evil.example.com"],
                allowed_methods=["tools/list", "tools/call"],
                allowed_intents=["query", "configure"],
                geo_restrictions=["US", "EU"],
                availability=AvailabilityConfig(hours="08:00-22:00", timezone="US/Eastern"),
                data_classification="confidential",
                consent_required=True,
            ),
        )
        assert doc.version == "1.0"
        assert doc.agent == "_network._mcp._agents.example.com"
        assert doc.rules.require_dnssec is True
        assert doc.rules.min_tls_version == "1.3"
        assert doc.rules.data_classification == "confidential"
        assert doc.rules.rate_limits is not None
        assert doc.rules.rate_limits.max_per_minute == 60

    def test_invalid_tls_version_rejected(self) -> None:
        """TLS version '1.0' should be rejected."""
        with pytest.raises(ValidationError, match="Invalid TLS version"):
            PolicyRules(min_tls_version="1.0")

    def test_invalid_tls_version_11_rejected(self) -> None:
        """TLS version '1.1' should be rejected."""
        with pytest.raises(ValidationError, match="Invalid TLS version"):
            PolicyRules(min_tls_version="1.1")

    def test_invalid_data_classification_rejected(self) -> None:
        """Data classification 'secret' should be rejected."""
        with pytest.raises(ValidationError, match="Invalid classification"):
            PolicyRules(data_classification="secret")

    def test_unsupported_version_rejected(self) -> None:
        """Policy version '2.0' should be rejected."""
        with pytest.raises(ValidationError, match="Unsupported policy version"):
            PolicyDocument(
                version="2.0",
                agent="_test._mcp._agents.example.com",
            )

    def test_empty_rules_defaults(self) -> None:
        """Empty rules (all defaults) should parse correctly."""
        doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
        )
        assert doc.rules.require_dnssec is False
        assert doc.rules.require_mutual_tls is False
        assert doc.rules.consent_required is False
        assert doc.rules.required_protocols is None
        assert doc.rules.required_auth_types is None
        assert doc.rules.min_tls_version is None
        assert doc.rules.required_caller_trust_score is None
        assert doc.rules.rate_limits is None
        assert doc.rules.max_payload_bytes is None
        assert doc.rules.allowed_caller_domains is None
        assert doc.rules.blocked_caller_domains is None
        assert doc.rules.allowed_methods is None
        assert doc.rules.allowed_intents is None
        assert doc.rules.geo_restrictions is None
        assert doc.rules.availability is None
        assert doc.rules.data_classification is None

    def test_all_16_rules_parse(self) -> None:
        """All 16 rule fields should parse with valid values."""
        rules = PolicyRules(
            required_protocols=["mcp"],
            required_auth_types=["bearer"],
            require_dnssec=True,
            require_mutual_tls=True,
            min_tls_version="1.2",
            required_caller_trust_score=0.5,
            rate_limits=RateLimitConfig(max_per_minute=10),
            max_payload_bytes=65536,
            allowed_caller_domains=["example.com"],
            blocked_caller_domains=["bad.com"],
            allowed_methods=["tools/list"],
            allowed_intents=["query"],
            geo_restrictions=["US"],
            availability=AvailabilityConfig(hours="09:00-17:00"),
            data_classification="public",
            consent_required=True,
        )
        assert rules.required_protocols == ["mcp"]
        assert rules.required_auth_types == ["bearer"]
        assert rules.require_dnssec is True
        assert rules.require_mutual_tls is True
        assert rules.min_tls_version == "1.2"
        assert rules.required_caller_trust_score == 0.5
        assert rules.rate_limits.max_per_minute == 10
        assert rules.max_payload_bytes == 65536
        assert rules.allowed_caller_domains == ["example.com"]
        assert rules.blocked_caller_domains == ["bad.com"]
        assert rules.allowed_methods == ["tools/list"]
        assert rules.allowed_intents == ["query"]
        assert rules.geo_restrictions == ["US"]
        assert rules.availability.hours == "09:00-17:00"
        assert rules.data_classification == "public"
        assert rules.consent_required is True

    def test_valid_data_classifications(self) -> None:
        """All four valid classifications should be accepted."""
        for classification in ("public", "internal", "confidential", "restricted"):
            rules = PolicyRules(data_classification=classification)
            assert rules.data_classification == classification

    def test_valid_tls_versions(self) -> None:
        """Both valid TLS versions should be accepted."""
        for version in ("1.2", "1.3"):
            rules = PolicyRules(min_tls_version=version)
            assert rules.min_tls_version == version


# =============================================================================
# RULE_ENFORCEMENT_LAYERS tests
# =============================================================================


class TestRuleEnforcementLayers:
    """Test that RULE_ENFORCEMENT_LAYERS covers all 16 rules."""

    def test_has_entries_for_all_16_rules(self) -> None:
        """RULE_ENFORCEMENT_LAYERS should have entries for all 16 rules."""
        expected_rules = {
            "required_protocols",
            "required_auth_types",
            "require_dnssec",
            "require_mutual_tls",
            "min_tls_version",
            "required_caller_trust_score",
            "rate_limits",
            "max_payload_bytes",
            "allowed_caller_domains",
            "blocked_caller_domains",
            "allowed_methods",
            "allowed_intents",
            "geo_restrictions",
            "availability",
            "data_classification",
            "consent_required",
        }
        assert set(RULE_ENFORCEMENT_LAYERS.keys()) == expected_rules
        assert len(RULE_ENFORCEMENT_LAYERS) == 16

    def test_all_values_are_valid_layers(self) -> None:
        """All enforcement layer values should be valid PolicyEnforcementLayer members."""
        for rule, layers in RULE_ENFORCEMENT_LAYERS.items():
            assert len(layers) > 0, f"Rule {rule} has no enforcement layers"
            for layer in layers:
                assert isinstance(layer, PolicyEnforcementLayer)

    def test_dns_layer_rules(self) -> None:
        """Only specific rules should be enforceable at the DNS layer."""
        dns_rules = [
            rule
            for rule, layers in RULE_ENFORCEMENT_LAYERS.items()
            if PolicyEnforcementLayer.DNS in layers
        ]
        assert set(dns_rules) == {"required_protocols", "geo_restrictions"}


# =============================================================================
# PolicyEnforcementLayer tests
# =============================================================================


class TestPolicyEnforcementLayer:
    """Test PolicyEnforcementLayer enum."""

    def test_values(self) -> None:
        assert PolicyEnforcementLayer.DNS == "layer0"
        assert PolicyEnforcementLayer.CALLER == "layer1"
        assert PolicyEnforcementLayer.TARGET == "layer2"


# =============================================================================
# Config model tests
# =============================================================================


class TestRateLimitConfig:
    """Test RateLimitConfig model."""

    def test_defaults(self) -> None:
        config = RateLimitConfig()
        assert config.max_per_minute is None
        assert config.max_per_hour is None

    def test_populated(self) -> None:
        config = RateLimitConfig(max_per_minute=60, max_per_hour=3600)
        assert config.max_per_minute == 60
        assert config.max_per_hour == 3600


class TestAvailabilityConfig:
    """Test AvailabilityConfig model."""

    def test_with_defaults(self) -> None:
        config = AvailabilityConfig(hours="08:00-22:00")
        assert config.hours == "08:00-22:00"
        assert config.timezone == "UTC"

    def test_custom_timezone(self) -> None:
        config = AvailabilityConfig(hours="09:00-17:00", timezone="US/Eastern")
        assert config.timezone == "US/Eastern"


# =============================================================================
# CELRule tests
# =============================================================================


class TestCELRule:
    """Test CELRule schema validation."""

    def test_valid_deny_rule(self) -> None:
        rule = CELRule(
            id="test-deny",
            expression="request.caller_trust_score >= 0.7",
            effect="deny",
            message="Trust too low",
        )
        assert rule.id == "test-deny"
        assert rule.effect == "deny"

    def test_valid_warn_rule(self) -> None:
        rule = CELRule(
            id="test-warn",
            expression="request.protocol == 'mcp'",
            effect="warn",
            message="Non-MCP protocol",
        )
        assert rule.effect == "warn"

    def test_invalid_effect_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CEL rule effect"):
            CELRule(id="bad", expression="true", effect="block")

    def test_expression_max_length(self) -> None:
        with pytest.raises(ValidationError):
            CELRule(id="long", expression="x" * 2049)

    def test_valid_enforcement_layers(self) -> None:
        rule = CELRule(
            id="layered",
            expression="true",
            enforcement_layers=["layer1", "layer2"],
        )
        assert rule.enforcement_layers == ["layer1", "layer2"]

    def test_invalid_enforcement_layer_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Invalid enforcement layer"):
            CELRule(id="bad", expression="true", enforcement_layers=["layer99"])

    def test_none_enforcement_layers_means_all(self) -> None:
        rule = CELRule(id="all", expression="true")
        assert rule.enforcement_layers is None


class TestPolicyVersion11:
    """Test version 1.1 acceptance for CEL rules."""

    def test_version_11_accepted(self) -> None:
        doc = PolicyDocument(
            version="1.1",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(
                cel_rules=[
                    CELRule(id="r1", expression="request.caller_trust_score >= 0.5"),
                ]
            ),
        )
        assert doc.version == "1.1"
        assert len(doc.rules.cel_rules) == 1

    def test_version_20_still_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Unsupported policy version"):
            PolicyDocument(version="2.0", agent="_test._mcp._agents.example.com")
