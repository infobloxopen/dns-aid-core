# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for Infoblox NIOS (on-premises) backend.

These tests require NIOS WAPI credentials and a real NIOS zone.
Set environment variables:
  - NIOS_HOST (Grid Master hostname)
  - NIOS_USERNAME (WAPI username)
  - NIOS_PASSWORD (WAPI password)
  - NIOS_TEST_ZONE (e.g., "dns-test.com")
  - NIOS_DNS_VIEW (optional, default: "default")
  - NIOS_VERIFY_SSL (optional, default: "true")
  - NIOS_WAPI_VERSION (optional, default: "2.13.7")

Run with: pytest tests/integration/test_nios.py -v

Mutation tests (create/delete) additionally require:
  - NIOS_MUTATION_TESTS=1
"""

import os
import uuid

import pytest

# Live backend tests — run with: pytest -m live
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.environ.get("NIOS_HOST")
        or not os.environ.get("NIOS_USERNAME")
        or not os.environ.get("NIOS_PASSWORD")
        or not os.environ.get("NIOS_TEST_ZONE"),
        reason="NIOS_HOST, NIOS_USERNAME, NIOS_PASSWORD, or NIOS_TEST_ZONE not set",
    ),
]


@pytest.fixture
def test_zone() -> str:
    """Get test zone from environment."""
    return os.environ["NIOS_TEST_ZONE"]


@pytest.fixture
async def nios_backend():
    """Create NIOS backend from environment variables."""
    from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend

    backend = InfobloxNIOSBackend()
    yield backend
    await backend.close()


@pytest.fixture
def unique_name() -> str:
    """Generate unique record name to avoid conflicts."""
    short_id = str(uuid.uuid4())[:8]
    return f"_inttest-{short_id}._mcp._agents"


class TestInfobloxNIOSReadOnly:
    """Read-only integration tests for NIOS backend."""

    async def test_zone_exists(self, nios_backend, test_zone):
        """Test zone existence check."""
        exists = await nios_backend.zone_exists(test_zone)
        assert exists is True

    async def test_zone_exists_with_trailing_dot(self, nios_backend, test_zone):
        """Test zone existence with trailing dot."""
        exists = await nios_backend.zone_exists(f"{test_zone}.")
        assert exists is True

    async def test_zone_not_exists(self, nios_backend):
        """Test zone non-existence."""
        exists = await nios_backend.zone_exists("nonexistent-zone-xyz123.invalid")
        assert exists is False

    async def test_list_zones(self, nios_backend, test_zone):
        """Test listing zones."""
        zones = await nios_backend.list_zones()

        assert len(zones) > 0
        zone_names = [z["name"] for z in zones]
        assert test_zone.rstrip(".") in zone_names


class TestInfobloxNIOSMutation:
    """Mutation integration tests (create/delete) for NIOS backend."""

    pytestmark = pytest.mark.skipif(
        not os.environ.get("NIOS_MUTATION_TESTS"),
        reason="NIOS_MUTATION_TESTS not set (set to 1 to enable)",
    )

    async def test_create_verify_delete_svcb(self, nios_backend, test_zone, unique_name):
        """Test SVCB record lifecycle: create, verify via API, delete."""
        try:
            fqdn = await nios_backend.create_svcb_record(
                zone=test_zone,
                name=unique_name,
                priority=1,
                target=f"live-target.{test_zone}",
                params={
                    "mandatory": "alpn,port",
                    "alpn": "mcp",
                    "port": "443",
                    "realm": "live-test",
                },
                ttl=120,
            )

            assert unique_name in fqdn

            # Verify via get_record
            record = await nios_backend.get_record(test_zone, unique_name, "SVCB")
            assert record is not None
            assert record["type"] == "SVCB"
        finally:
            await nios_backend.delete_record(test_zone, unique_name, "SVCB")

    async def test_create_verify_delete_txt(self, nios_backend, test_zone, unique_name):
        """Test TXT record lifecycle: create, verify via API, delete."""
        try:
            fqdn = await nios_backend.create_txt_record(
                zone=test_zone,
                name=unique_name,
                values=["capabilities=live-test", "version=0.0.1"],
                ttl=120,
            )

            assert unique_name in fqdn

            # Verify via get_record
            record = await nios_backend.get_record(test_zone, unique_name, "TXT")
            assert record is not None
            assert record["type"] == "TXT"
        finally:
            await nios_backend.delete_record(test_zone, unique_name, "TXT")

    async def test_full_dnsaid_publish_workflow(self, nios_backend, test_zone):
        """Test complete DNS-AID publish: SVCB + TXT records."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name=f"inttest-{str(uuid.uuid4())[:8]}",
            domain=test_zone,
            protocol=Protocol.MCP,
            target_host=f"mcp.{test_zone}",
            port=443,
            capabilities=["integration", "test", "nios"],
            version="1.0.0",
            ttl=120,
        )

        record_name = f"_{agent.name}._{agent.protocol.value}._agents"

        try:
            records_created = await nios_backend.publish_agent(agent)

            assert len(records_created) == 2
            assert any("SVCB" in r for r in records_created)
            assert any("TXT" in r for r in records_created)
        finally:
            await nios_backend.delete_record(test_zone, record_name, "SVCB")
            await nios_backend.delete_record(test_zone, record_name, "TXT")

    async def test_delete_nonexistent_record(self, nios_backend, test_zone):
        """Test deleting a record that doesn't exist."""
        deleted = await nios_backend.delete_record(
            zone=test_zone,
            name="_nonexistent-record-xyz._mcp._agents",
            record_type="SVCB",
        )
        assert deleted is False
