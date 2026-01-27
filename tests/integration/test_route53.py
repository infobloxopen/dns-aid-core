"""
Integration tests for Route 53 backend.

These tests require AWS credentials and a real Route 53 zone.
Set environment variables:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - DNS_AID_TEST_ZONE (e.g., "highvelocitynetworking.com")

Run with: pytest tests/integration/test_route53.py -v
"""

import os

import pytest

# Skip all tests if no test zone configured
pytestmark = pytest.mark.skipif(
    not os.environ.get("DNS_AID_TEST_ZONE"), reason="DNS_AID_TEST_ZONE not set"
)


@pytest.fixture
def test_zone() -> str:
    """Get test zone from environment."""
    return os.environ["DNS_AID_TEST_ZONE"]


@pytest.fixture
def route53_backend():
    """Create Route 53 backend."""
    from dns_aid.backends.route53 import Route53Backend

    return Route53Backend()


class TestRoute53Backend:
    """Integration tests for Route 53 backend."""

    @pytest.mark.asyncio
    async def test_zone_exists(self, route53_backend, test_zone):
        """Test zone existence check."""
        exists = await route53_backend.zone_exists(test_zone)
        assert exists is True

    @pytest.mark.asyncio
    async def test_zone_not_exists(self, route53_backend):
        """Test zone non-existence."""
        exists = await route53_backend.zone_exists("nonexistent-zone-12345.com")
        assert exists is False

    @pytest.mark.asyncio
    async def test_list_zones(self, route53_backend, test_zone):
        """Test listing zones."""
        zones = await route53_backend.list_zones()

        assert len(zones) > 0

        zone_names = [z["name"] for z in zones]
        assert test_zone in zone_names

    @pytest.mark.asyncio
    async def test_create_and_delete_svcb_record(self, route53_backend, test_zone):
        """Test creating and deleting SVCB record."""
        # Create record
        name = "_test-agent._mcp._agents"

        fqdn = await route53_backend.create_svcb_record(
            zone=test_zone,
            name=name,
            priority=1,
            target=f"mcp.{test_zone}.",
            params={"alpn": "mcp", "port": "443"},
            ttl=300,
        )

        assert fqdn == f"{name}.{test_zone}"

        # List and verify
        found = False
        async for record in route53_backend.list_records(test_zone, name_pattern="_test-agent"):
            if record["type"] == "SVCB":
                found = True
                break

        assert found, "SVCB record not found after creation"

        # Delete record
        deleted = await route53_backend.delete_record(
            zone=test_zone,
            name=name,
            record_type="SVCB",
        )

        assert deleted is True

    @pytest.mark.asyncio
    async def test_create_and_delete_txt_record(self, route53_backend, test_zone):
        """Test creating and deleting TXT record."""
        name = "_test-agent._mcp._agents"

        fqdn = await route53_backend.create_txt_record(
            zone=test_zone,
            name=name,
            values=["capabilities=test,demo", "version=1.0.0"],
            ttl=300,
        )

        assert fqdn == f"{name}.{test_zone}"

        # Delete record
        deleted = await route53_backend.delete_record(
            zone=test_zone,
            name=name,
            record_type="TXT",
        )

        assert deleted is True

    @pytest.mark.asyncio
    async def test_publish_agent(self, route53_backend, test_zone):
        """Test full agent publish workflow."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="integration-test",
            domain=test_zone,
            protocol=Protocol.MCP,
            target_host=f"mcp.{test_zone}",
            port=443,
            capabilities=["test", "integration"],
            ttl=300,
        )

        # Publish
        records = await route53_backend.publish_agent(agent)

        assert len(records) == 2
        assert any("SVCB" in r for r in records)
        assert any("TXT" in r for r in records)

        # Cleanup
        record_name = f"_{agent.name}._{agent.protocol.value}._agents"
        await route53_backend.delete_record(test_zone, record_name, "SVCB")
        await route53_backend.delete_record(test_zone, record_name, "TXT")
