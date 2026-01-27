"""Tests for DNS-AID data models."""

import pytest
from pydantic import ValidationError

from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol, VerifyResult


class TestAgentRecord:
    """Tests for AgentRecord model."""

    def test_create_basic_agent(self):
        """Test creating a basic agent record."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        assert agent.name == "chat"
        assert agent.domain == "example.com"
        assert agent.protocol == Protocol.A2A
        assert agent.target_host == "chat.example.com"
        assert agent.port == 443  # default

    def test_fqdn_generation(self):
        """Test FQDN is generated correctly per DNS-AID spec."""
        agent = AgentRecord(
            name="network-specialist",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
        )

        # Format: _{name}._{protocol}._agents.{domain}
        assert agent.fqdn == "_network-specialist._mcp._agents.example.com"

    def test_endpoint_url(self):
        """Test endpoint URL generation."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
            port=8443,
        )

        assert agent.endpoint_url == "https://chat.example.com:8443"

    def test_svcb_target(self):
        """Test SVCB target has trailing dot."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        assert agent.svcb_target == "chat.example.com."

    def test_svcb_params(self):
        """Test SVCB parameters generation."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=8443,
            ipv4_hint="192.0.2.1",
        )

        params = agent.to_svcb_params()

        assert params["alpn"] == "mcp"
        assert params["port"] == "8443"
        assert params["ipv4hint"] == "192.0.2.1"
        # BANDAID compliance: mandatory param must be set
        assert params["mandatory"] == "alpn,port"

    def test_svcb_params_with_bandaid_custom_params(self):
        """Test SVCB params include BANDAID custom params when set."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            cap_sha256="abc123base64url",
            bap=["mcp/1", "a2a/1"],
            policy_uri="https://example.com/agent-policy",
            realm="production",
        )

        params = agent.to_svcb_params()

        assert params["cap"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert params["cap-sha256"] == "abc123base64url"
        assert params["bap"] == "mcp/1,a2a/1"
        assert params["policy"] == "https://example.com/agent-policy"
        assert params["realm"] == "production"
        # Standard params still present
        assert params["alpn"] == "mcp"
        assert params["port"] == "443"

    def test_svcb_params_without_bandaid_params(self):
        """Test SVCB params exclude BANDAID custom params when None/empty."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        params = agent.to_svcb_params()

        assert "cap" not in params
        assert "cap-sha256" not in params
        assert "bap" not in params
        assert "policy" not in params
        assert "realm" not in params
        # Standard params present
        assert params["alpn"] == "a2a"
        assert params["port"] == "443"

    def test_svcb_params_partial_bandaid_params(self):
        """Test SVCB params with only some BANDAID params set."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            realm="demo",
            # cap_sha256, bap, and policy_uri not set
        )

        params = agent.to_svcb_params()

        assert params["cap"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert params["realm"] == "demo"
        assert "cap-sha256" not in params
        assert "bap" not in params
        assert "policy" not in params

    def test_svcb_params_cap_sha256_without_cap_uri(self):
        """Test cap-sha256 can be set independently (unlikely but valid)."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_sha256="dGVzdGhhc2g",
        )

        params = agent.to_svcb_params()

        assert params["cap-sha256"] == "dGVzdGhhc2g"
        assert "cap" not in params

    def test_txt_values(self):
        """Test TXT record values generation."""
        agent = AgentRecord(
            name="network",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            capabilities=["ipam", "dns", "vpn"],
            version="2.0.0",
            description="Network agent",
        )

        values = agent.to_txt_values()

        assert "capabilities=ipam,dns,vpn" in values
        assert "version=2.0.0" in values
        assert "description=Network agent" in values

    def test_name_validation_lowercase(self):
        """Test that name is normalized to lowercase."""
        agent = AgentRecord(
            name="MyAgent",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="agent.example.com",
        )

        assert agent.name == "myagent"

    def test_domain_validation_removes_trailing_dot(self):
        """Test that domain removes trailing dot."""
        agent = AgentRecord(
            name="chat",
            domain="example.com.",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        assert agent.domain == "example.com"

    def test_invalid_name_rejected(self):
        """Test that invalid DNS label names are rejected."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="invalid_name",  # Underscores not allowed in DNS labels
                domain="example.com",
                protocol=Protocol.A2A,
                target_host="agent.example.com",
            )

    def test_invalid_port_rejected(self):
        """Test that invalid port numbers are rejected."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.A2A,
                target_host="chat.example.com",
                port=70000,  # Invalid port
            )


class TestProtocol:
    """Tests for Protocol enum."""

    def test_protocol_values(self):
        """Test protocol enum values."""
        assert Protocol.A2A.value == "a2a"
        assert Protocol.MCP.value == "mcp"
        assert Protocol.HTTPS.value == "https"

    def test_protocol_from_string(self):
        """Test creating protocol from string."""
        assert Protocol("a2a") == Protocol.A2A
        assert Protocol("mcp") == Protocol.MCP


class TestDiscoveryResult:
    """Tests for DiscoveryResult model."""

    def test_count_property(self):
        """Test agents count property."""
        result = DiscoveryResult(
            query="_index._agents.example.com",
            domain="example.com",
            agents=[],
        )

        assert result.count == 0

    def test_with_agents(self, sample_agent):
        """Test discovery result with agents."""
        result = DiscoveryResult(
            query="_index._agents.example.com",
            domain="example.com",
            agents=[sample_agent],
            dnssec_validated=True,
            query_time_ms=45.5,
        )

        assert result.count == 1
        assert result.dnssec_validated is True
        assert result.query_time_ms == 45.5


class TestVerifyResult:
    """Tests for VerifyResult model."""

    def test_security_score_all_pass(self):
        """Test security score when all checks pass."""
        result = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=True,
            endpoint_reachable=True,
        )

        assert result.security_score == 100
        assert result.security_rating == "Excellent"

    def test_security_score_no_dane(self):
        """Test security score without DANE."""
        result = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=False,  # No DANE
            endpoint_reachable=True,
        )

        assert result.security_score == 85
        assert result.security_rating == "Excellent"

    def test_security_score_minimal(self):
        """Test security score with minimal checks."""
        result = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=False,
        )

        assert result.security_score == 20
        assert result.security_rating == "Poor"
