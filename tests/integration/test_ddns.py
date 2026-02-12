# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for DDNS backend using Docker BIND9.

These tests require a running BIND9 container. Start it with:
    cd tests/integration/bind && docker-compose up -d

Run tests with:
    pytest tests/integration/test_ddns.py -v

Environment:
    DDNS_TEST_ENABLED=1 - Enable DDNS integration tests
"""

import asyncio
import os
import subprocess

import pytest

# Live backend tests — run with: pytest -m live
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("DDNS_TEST_ENABLED"), reason="DDNS_TEST_ENABLED not set"),
]

# Test configuration matching bind/named.conf
DDNS_SERVER = "127.0.0.1"
DDNS_PORT = 15353
DDNS_ZONE = "test.dns-aid.local"
DDNS_KEY_NAME = "dns-aid-key"
DDNS_KEY_SECRET = "c2VjcmV0a2V5Zm9yZG5zYWlkdGVzdGluZzEyMzQ1Ng=="
DDNS_KEY_ALGORITHM = "hmac-sha256"


@pytest.fixture(scope="module")
def bind_container():
    """Ensure BIND container is running."""
    # Check if container is running
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", "name=dns-aid-bind9"],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        pytest.skip(
            "BIND container not running. Start with: cd tests/integration/bind && docker-compose up -d"
        )

    yield

    # Don't stop container - let user manage it


@pytest.fixture
def ddns_backend(bind_container):
    """Create DDNS backend for testing."""
    from dns_aid.backends.ddns import DDNSBackend

    return DDNSBackend(
        server=DDNS_SERVER,
        port=DDNS_PORT,
        key_name=DDNS_KEY_NAME,
        key_secret=DDNS_KEY_SECRET,
        key_algorithm=DDNS_KEY_ALGORITHM,
    )


class TestDDNSBackend:
    """Integration tests for DDNSBackend."""

    @pytest.mark.asyncio
    async def test_zone_exists(self, ddns_backend):
        """Test zone existence check."""
        # Our test zone should exist
        assert await ddns_backend.zone_exists(DDNS_ZONE)

        # Non-existent zone should not exist
        assert not await ddns_backend.zone_exists("nonexistent.zone.local")

    @pytest.mark.asyncio
    async def test_create_and_delete_svcb_record(self, ddns_backend):
        """Test creating and deleting SVCB record."""
        name = "_test-agent._mcp._agents"

        try:
            # Create SVCB record
            fqdn = await ddns_backend.create_svcb_record(
                zone=DDNS_ZONE,
                name=name,
                priority=1,
                target="agent.test.dns-aid.local.",
                params={"alpn": "mcp", "port": "443", "mandatory": "alpn,port"},
                ttl=300,
            )

            assert fqdn == f"{name}.{DDNS_ZONE}"

            # Verify record exists by querying DNS
            await asyncio.sleep(1)  # Give BIND time to update

            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DDNS_SERVER]
            resolver.port = DDNS_PORT

            answers = resolver.resolve(fqdn, "SVCB")
            assert len(answers) > 0

            # Check record content
            rdata = str(answers[0])
            assert "agent.test.dns-aid.local" in rdata
            assert "alpn" in rdata

        finally:
            # Cleanup
            await ddns_backend.delete_record(DDNS_ZONE, name, "SVCB")

    @pytest.mark.asyncio
    async def test_create_and_delete_txt_record(self, ddns_backend):
        """Test creating and deleting TXT record."""
        name = "_test-agent._mcp._agents"

        try:
            # Create TXT record
            fqdn = await ddns_backend.create_txt_record(
                zone=DDNS_ZONE,
                name=name,
                values=["capabilities=chat,code-review", "version=1.0.0"],
                ttl=300,
            )

            assert fqdn == f"{name}.{DDNS_ZONE}"

            # Verify record exists
            await asyncio.sleep(1)

            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DDNS_SERVER]
            resolver.port = DDNS_PORT

            answers = resolver.resolve(fqdn, "TXT")
            assert len(answers) > 0

            # Check TXT values
            txt_values = [str(rdata) for rdata in answers]
            txt_combined = " ".join(txt_values)
            assert "capabilities" in txt_combined

        finally:
            # Cleanup
            await ddns_backend.delete_record(DDNS_ZONE, name, "TXT")

    @pytest.mark.asyncio
    async def test_full_agent_publish_flow(self, ddns_backend):
        """Test full agent publish flow via DDNS."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="ddns-test-agent",
            domain=DDNS_ZONE,
            protocol=Protocol.MCP,
            target_host="mcp.test.dns-aid.local",
            port=443,
            capabilities=["ddns-test", "integration"],
            ttl=300,
        )

        try:
            # Publish agent
            records = await ddns_backend.publish_agent(agent)

            assert len(records) == 2
            assert any("SVCB" in r for r in records)
            assert any("TXT" in r for r in records)

            # Verify via DNS query
            await asyncio.sleep(1)

            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DDNS_SERVER]
            resolver.port = DDNS_PORT

            fqdn = f"_ddns-test-agent._mcp._agents.{DDNS_ZONE}"

            # Check SVCB
            svcb_answers = resolver.resolve(fqdn, "SVCB")
            assert len(svcb_answers) > 0

            # Check TXT
            txt_answers = resolver.resolve(fqdn, "TXT")
            assert len(txt_answers) > 0

        finally:
            # Cleanup
            name = "_ddns-test-agent._mcp._agents"
            await ddns_backend.delete_record(DDNS_ZONE, name, "SVCB")
            await ddns_backend.delete_record(DDNS_ZONE, name, "TXT")

    @pytest.mark.asyncio
    async def test_update_existing_record(self, ddns_backend):
        """Test updating an existing record (replace behavior)."""
        name = "_update-test._mcp._agents"

        try:
            # Create initial record
            await ddns_backend.create_svcb_record(
                zone=DDNS_ZONE,
                name=name,
                priority=1,
                target="old.test.dns-aid.local.",
                params={"alpn": "mcp", "port": "443"},
                ttl=300,
            )

            await asyncio.sleep(1)

            # Update with new target
            await ddns_backend.create_svcb_record(
                zone=DDNS_ZONE,
                name=name,
                priority=1,
                target="new.test.dns-aid.local.",
                params={"alpn": "mcp", "port": "8443"},
                ttl=300,
            )

            await asyncio.sleep(1)

            # Verify only new record exists
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DDNS_SERVER]
            resolver.port = DDNS_PORT

            fqdn = f"{name}.{DDNS_ZONE}"
            answers = resolver.resolve(fqdn, "SVCB")

            # Should have exactly 1 record with new target
            assert len(answers) == 1
            rdata = str(answers[0])
            assert "new.test.dns-aid.local" in rdata
            assert "old.test.dns-aid.local" not in rdata

        finally:
            await ddns_backend.delete_record(DDNS_ZONE, name, "SVCB")
