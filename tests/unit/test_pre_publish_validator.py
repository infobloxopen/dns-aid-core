# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for pre-publish record validator."""

import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.core.pre_publish_validator import validate_record


def _make_agent(**kwargs) -> AgentRecord:
    """Create an AgentRecord with sensible defaults."""
    defaults = {
        "name": "chat",
        "domain": "example.com",
        "protocol": Protocol.A2A,
        "target_host": "api.example.com",
    }
    defaults.update(kwargs)
    return AgentRecord(**defaults)


class TestValidateRecord:
    """Tests for validate_record."""

    def test_valid_record_no_errors(self):
        agent = _make_agent()
        errors = validate_record(agent)
        assert errors == []

    def test_valid_record_with_all_fields(self):
        agent = _make_agent(
            capabilities=["search", "summarize"],
            version="2.0.0",
            description="A chat agent",
            cap_uri="https://api.example.com/.well-known/agent-cap.json",
            bap=["a2a/1"],
            policy_uri="https://example.com/policy",
            realm="production",
        )
        errors = validate_record(agent)
        assert errors == []


class TestFqdnValidation:
    """Tests for FQDN length validation."""

    def test_long_fqdn(self):
        agent = _make_agent(name="a" * 63, domain="b" * 63 + "." + "c" * 63 + "." + "d" * 63)
        errors = validate_record(agent)
        fqdn_errors = [e for e in errors if e.field == "fqdn"]
        assert any("exceeds" in e.message for e in fqdn_errors)


class TestTtlValidation:
    """Tests for TTL bounds checking."""

    def test_ttl_below_minimum_rejected_by_model(self):
        """Pydantic model itself rejects ttl < 30."""
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            _make_agent(ttl=29)

    def test_ttl_above_maximum_rejected_by_model(self):
        """Pydantic model itself rejects ttl > 86400."""
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            _make_agent(ttl=86401)

    def test_ttl_at_minimum(self):
        agent = _make_agent(ttl=30)
        errors = validate_record(agent)
        ttl_errors = [e for e in errors if e.field == "ttl"]
        assert len(ttl_errors) == 0

    def test_ttl_at_maximum(self):
        agent = _make_agent(ttl=86400)
        errors = validate_record(agent)
        ttl_errors = [e for e in errors if e.field == "ttl"]
        assert len(ttl_errors) == 0


class TestUriValidation:
    """Tests for URI format validation."""

    def test_valid_https_uri(self):
        agent = _make_agent(cap_uri="https://example.com/cap.json")
        errors = validate_record(agent)
        assert all(e.field != "cap_uri" for e in errors)

    def test_uri_no_scheme(self):
        agent = _make_agent(cap_uri="example.com/cap.json")
        errors = validate_record(agent)
        cap_errors = [e for e in errors if e.field == "cap_uri"]
        assert len(cap_errors) == 1
        assert "no scheme" in cap_errors[0].message

    def test_urn_uri_valid(self):
        agent = _make_agent(cap_uri="urn:dns-aid:cap:example")
        errors = validate_record(agent)
        assert all(e.field != "cap_uri" for e in errors)

    def test_unusual_scheme_warns(self):
        agent = _make_agent(cap_uri="ftp://example.com/cap.json")
        errors = validate_record(agent)
        cap_errors = [e for e in errors if e.field == "cap_uri"]
        assert len(cap_errors) == 1
        assert cap_errors[0].severity == "warning"

    def test_http_cap_uri_warns_cleartext(self):
        agent = _make_agent(cap_uri="http://example.com/cap.json")
        errors = validate_record(agent)
        cap_errors = [e for e in errors if e.field == "cap_uri"]
        assert len(cap_errors) == 1
        assert cap_errors[0].severity == "warning"
        assert "cleartext" in cap_errors[0].message.lower()

    def test_http_policy_uri_warns_cleartext(self):
        agent = _make_agent(policy_uri="http://example.com/policy")
        errors = validate_record(agent)
        policy_errors = [e for e in errors if e.field == "policy_uri"]
        assert len(policy_errors) == 1
        assert policy_errors[0].severity == "warning"
        assert "cleartext" in policy_errors[0].message.lower()


class TestCapabilityValidation:
    """Tests for capability string format."""

    def test_valid_capabilities(self):
        agent = _make_agent(capabilities=["search", "dns/lookup", "network.ipam"])
        errors = validate_record(agent)
        assert all(e.field != "capabilities" for e in errors)

    def test_invalid_capability_chars(self):
        agent = _make_agent(capabilities=["valid", "has spaces"])
        errors = validate_record(agent)
        cap_errors = [e for e in errors if e.field == "capabilities"]
        assert len(cap_errors) == 1
        assert "has spaces" in cap_errors[0].message

    def test_empty_capability(self):
        agent = _make_agent(capabilities=["valid", ""])
        errors = validate_record(agent)
        cap_errors = [e for e in errors if e.field == "capabilities"]
        assert len(cap_errors) == 1
        assert "Empty" in cap_errors[0].message


class TestBapValidation:
    """Tests for BAP protocol format."""

    def test_valid_bap(self):
        agent = _make_agent(bap=["a2a/1", "mcp/1"])
        errors = validate_record(agent)
        assert all(e.field != "bap" for e in errors)

    def test_bap_without_version(self):
        agent = _make_agent(bap=["a2a"])
        errors = validate_record(agent)
        assert all(e.field != "bap" for e in errors)

    def test_invalid_bap(self):
        agent = _make_agent(bap=["A2A/1"])  # uppercase
        errors = validate_record(agent)
        bap_errors = [e for e in errors if e.field == "bap"]
        assert len(bap_errors) == 1


class TestProtocolValidation:
    """Tests for protocol/ALPN validation."""

    def test_valid_protocols(self):
        for proto in [Protocol.A2A, Protocol.MCP, Protocol.HTTPS]:
            agent = _make_agent(protocol=proto)
            errors = validate_record(agent)
            assert all(e.field != "protocol" for e in errors)
