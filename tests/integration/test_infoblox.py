# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for Infoblox BloxOne backend.

These tests require Infoblox API credentials and a real BloxOne zone.
Set environment variables:
  - INFOBLOX_API_KEY (BloxOne API key)
  - INFOBLOX_TEST_ZONE (e.g., "dns-test.com")
  - INFOBLOX_DNS_VIEW (optional, default: "default")

Run with: pytest tests/integration/test_infoblox.py -v

Note: These tests verify records via API, not DNS queries (dig),
since BloxOne zones may not be publicly resolvable.
"""

import os
import uuid

import pytest

# Live backend tests — run with: pytest -m live
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.environ.get("INFOBLOX_API_KEY") or not os.environ.get("INFOBLOX_TEST_ZONE"),
        reason="INFOBLOX_API_KEY or INFOBLOX_TEST_ZONE not set",
    ),
]


@pytest.fixture
def test_zone() -> str:
    """Get test zone from environment."""
    return os.environ["INFOBLOX_TEST_ZONE"]


@pytest.fixture
def api_key() -> str:
    """Get API key from environment."""
    return os.environ["INFOBLOX_API_KEY"]


@pytest.fixture
def dns_view() -> str:
    """Get DNS view from environment (default: 'default')."""
    return os.environ.get("INFOBLOX_DNS_VIEW", "default")


@pytest.fixture
async def infoblox_backend(api_key, dns_view):
    """Create Infoblox BloxOne backend with configured DNS view."""
    from dns_aid.backends.infoblox import InfobloxBloxOneBackend

    backend = InfobloxBloxOneBackend(api_key=api_key, dns_view=dns_view)
    yield backend
    await backend.close()


@pytest.fixture
def unique_name() -> str:
    """Generate unique record name to avoid conflicts."""
    short_id = str(uuid.uuid4())[:8]
    return f"_inttest-{short_id}._mcp._agents"


class TestInfobloxBloxOneBackend:
    """Integration tests for Infoblox BloxOne backend."""

    @pytest.mark.asyncio
    async def test_zone_exists(self, infoblox_backend, test_zone):
        """Test zone existence check."""
        exists = await infoblox_backend.zone_exists(test_zone)
        assert exists is True

    @pytest.mark.asyncio
    async def test_zone_not_exists(self, infoblox_backend):
        """Test zone non-existence."""
        exists = await infoblox_backend.zone_exists("nonexistent-zone-xyz123.invalid")
        assert exists is False

    @pytest.mark.asyncio
    async def test_list_zones(self, infoblox_backend, test_zone):
        """Test listing zones."""
        zones = await infoblox_backend.list_zones()

        assert len(zones) > 0

        zone_names = [z["name"] for z in zones]
        assert test_zone in zone_names

    @pytest.mark.asyncio
    async def test_create_verify_delete_svcb_record(self, infoblox_backend, test_zone, unique_name):
        """Test SVCB record lifecycle: create, verify via API, delete."""
        # Create SVCB record
        fqdn = await infoblox_backend.create_svcb_record(
            zone=test_zone,
            name=unique_name,
            priority=1,  # Note: BloxOne ignores this, always uses 0
            target=f"mcp.{test_zone}.",
            params={"alpn": "mcp", "port": "443"},  # Stored in TXT instead
            ttl=300,
        )

        expected_fqdn = f"{unique_name}.{test_zone}"
        assert fqdn == expected_fqdn

        # Verify record exists via API (not dig)
        found_svcb = False
        async for record in infoblox_backend.list_records(test_zone, name_pattern=unique_name):
            if record["type"] == "SVCB":
                found_svcb = True
                assert record["fqdn"] == expected_fqdn
                break

        assert found_svcb, f"SVCB record not found via API: {expected_fqdn}"

        # Delete record
        deleted = await infoblox_backend.delete_record(
            zone=test_zone,
            name=unique_name,
            record_type="SVCB",
        )
        assert deleted is True

        # Verify deletion via API
        found_after_delete = False
        async for record in infoblox_backend.list_records(test_zone, name_pattern=unique_name):
            if record["type"] == "SVCB":
                found_after_delete = True
                break

        assert not found_after_delete, "SVCB record still exists after deletion"

    @pytest.mark.asyncio
    async def test_create_verify_delete_txt_record(self, infoblox_backend, test_zone, unique_name):
        """Test TXT record lifecycle: create, verify via API, delete."""
        # Create TXT record
        fqdn = await infoblox_backend.create_txt_record(
            zone=test_zone,
            name=unique_name,
            values=["capabilities=test,integration", "version=1.0.0"],
            ttl=300,
        )

        expected_fqdn = f"{unique_name}.{test_zone}"
        assert fqdn == expected_fqdn

        # Verify record exists via API
        found_txt = False
        async for record in infoblox_backend.list_records(test_zone, name_pattern=unique_name):
            if record["type"] == "TXT":
                found_txt = True
                assert record["fqdn"] == expected_fqdn
                # Verify capabilities are in the record
                values_str = " ".join(record["values"])
                assert "capabilities" in values_str
                break

        assert found_txt, f"TXT record not found via API: {expected_fqdn}"

        # Delete record
        deleted = await infoblox_backend.delete_record(
            zone=test_zone,
            name=unique_name,
            record_type="TXT",
        )
        assert deleted is True

    @pytest.mark.asyncio
    async def test_full_dnsaid_publish_workflow(self, infoblox_backend, test_zone, unique_name):
        """Test complete DNS-AID publish: SVCB + TXT records."""
        from dns_aid.core.models import AgentRecord, Protocol

        # Create agent record
        agent = AgentRecord(
            name=f"inttest-{str(uuid.uuid4())[:8]}",
            domain=test_zone,
            protocol=Protocol.MCP,
            target_host=f"mcp.{test_zone}",
            port=443,
            capabilities=["integration", "test", "bloxone"],
            version="1.0.0",
            ttl=300,
        )

        # Publish using backend's publish_agent method
        records_created = await infoblox_backend.publish_agent(agent)

        assert len(records_created) == 2
        assert any("SVCB" in r for r in records_created)
        assert any("TXT" in r for r in records_created)

        # Verify both records via API
        record_name = f"_{agent.name}._{agent.protocol.value}._agents"

        found_svcb = False
        found_txt = False

        async for record in infoblox_backend.list_records(test_zone, name_pattern=agent.name):
            if record["type"] == "SVCB":
                found_svcb = True
            elif record["type"] == "TXT":
                found_txt = True

        assert found_svcb, "SVCB record not found after publish_agent"
        assert found_txt, "TXT record not found after publish_agent"

        # Cleanup
        await infoblox_backend.delete_record(test_zone, record_name, "SVCB")
        await infoblox_backend.delete_record(test_zone, record_name, "TXT")

    @pytest.mark.asyncio
    async def test_list_records_filter_by_type(self, infoblox_backend, test_zone):
        """Test listing records filtered by type."""
        # List only TXT records
        txt_count = 0
        async for record in infoblox_backend.list_records(test_zone, record_type="TXT"):
            assert record["type"] == "TXT"
            txt_count += 1
            if txt_count >= 5:  # Limit iterations
                break

        # Test passes if we can filter (even if no TXT records exist)

    @pytest.mark.asyncio
    async def test_delete_nonexistent_record(self, infoblox_backend, test_zone):
        """Test deleting a record that doesn't exist."""
        deleted = await infoblox_backend.delete_record(
            zone=test_zone,
            name="_nonexistent-record-xyz._mcp._agents",
            record_type="SVCB",
        )
        assert deleted is False


class TestInfobloxBloxOneAPIVerification:
    """Tests that verify API behavior matches expectations."""

    @pytest.mark.asyncio
    async def test_svcb_priority_is_always_zero(self, infoblox_backend, test_zone, unique_name):
        """
        Verify BloxOne SVCB always uses priority 0 (alias mode).

        This is a known BloxOne limitation documented in their UI:
        "Only Alias Mode SVCB Resource Records are currently supported.
        SvcPriority is always 0."
        """
        # Create with priority=1
        await infoblox_backend.create_svcb_record(
            zone=test_zone,
            name=unique_name,
            priority=1,  # We specify 1...
            target=f"mcp.{test_zone}.",
            params={},
            ttl=300,
        )

        # Verify the record has priority 0 in dns_rdata
        async for record in infoblox_backend.list_records(test_zone, name_pattern=unique_name):
            if record["type"] == "SVCB":
                # dns_rdata format: "0 mcp.dns-test.com."
                # The 0 indicates alias mode (priority 0)
                values_str = " ".join(record["values"])
                assert values_str.startswith("0 "), f"Expected priority 0, got: {values_str}"
                break

        # Cleanup
        await infoblox_backend.delete_record(test_zone, unique_name, "SVCB")
