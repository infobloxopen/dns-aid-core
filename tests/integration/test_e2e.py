"""
End-to-end integration tests for DNS-AID.

Tests the full cycle: publish → discover → verify → delete
using real DNS infrastructure.

Set environment variables:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - DNS_AID_TEST_ZONE (e.g., "highvelocitynetworking.com")

Run with: pytest tests/integration/test_e2e.py -v

Note: DNS propagation can take 5-15 seconds. Tests include retry logic.
"""

import asyncio
import contextlib
import os
import uuid

import pytest

# DNS propagation settings
# Route 53 changes can take 10-60 seconds to propagate globally
DNS_PROPAGATION_WAIT = 10  # Initial wait in seconds
DNS_RETRY_ATTEMPTS = 5  # Number of retry attempts
DNS_RETRY_DELAY = 5  # Delay between retries in seconds

# Live backend tests — run with: pytest -m live
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("DNS_AID_TEST_ZONE"), reason="DNS_AID_TEST_ZONE not set"),
]


@pytest.fixture
def test_zone() -> str:
    """Get test zone from environment."""
    return os.environ["DNS_AID_TEST_ZONE"]


@pytest.fixture
def unique_agent_name() -> str:
    """Generate unique agent name to avoid conflicts."""
    short_id = str(uuid.uuid4())[:8]
    return f"e2e-test-{short_id}"


class TestEndToEndWorkflow:
    """End-to-end integration tests for the complete DNS-AID workflow."""

    @pytest.mark.asyncio
    async def test_publish_discover_verify_delete(self, test_zone, unique_agent_name):
        """
        Test the complete DNS-AID workflow:
        1. Publish an agent to DNS
        2. Wait for DNS propagation
        3. Discover the agent via DNS query
        4. Verify the agent's DNS records
        5. Delete the agent from DNS
        6. Confirm agent is no longer discoverable
        """
        import dns_aid
        from dns_aid.backends.route53 import Route53Backend

        backend = Route53Backend()
        fqdn = f"_{unique_agent_name}._mcp._agents.{test_zone}"

        try:
            # --- Step 1: Publish ---
            publish_result = await dns_aid.publish(
                name=unique_agent_name,
                domain=test_zone,
                protocol="mcp",
                endpoint=f"mcp.{test_zone}",
                port=443,
                capabilities=["e2e-test", "integration"],
                ttl=300,
                backend=backend,
            )

            assert publish_result.success, f"Publish failed: {publish_result}"
            assert publish_result.agent.fqdn == fqdn
            assert len(publish_result.records_created) == 2  # SVCB + TXT

            # --- Step 2: Wait for DNS propagation ---
            await asyncio.sleep(DNS_PROPAGATION_WAIT)

            # --- Step 3: Discover (with retry) ---
            found_agent = None
            for _ in range(DNS_RETRY_ATTEMPTS):
                discovery_result = await dns_aid.discover(
                    domain=test_zone,
                    protocol="mcp",
                    name=unique_agent_name,
                )

                for agent in discovery_result.agents:
                    if agent.name == unique_agent_name:
                        found_agent = agent
                        break

                if found_agent:
                    break
                await asyncio.sleep(DNS_RETRY_DELAY)

            assert found_agent is not None, (
                f"Agent {unique_agent_name} not discovered after {DNS_RETRY_ATTEMPTS} attempts"
            )
            assert found_agent.protocol.value == "mcp"
            assert found_agent.port == 443

            # --- Step 4: Verify (with retry) ---
            verify_result = None
            for _ in range(DNS_RETRY_ATTEMPTS):
                verify_result = await dns_aid.verify(fqdn)
                if verify_result.record_exists:
                    break
                await asyncio.sleep(DNS_RETRY_DELAY)

            assert verify_result.record_exists, "Verify: record should exist"
            assert verify_result.svcb_valid, "Verify: SVCB should be valid"
            assert verify_result.security_score > 0, "Verify: security score should be > 0"

            # --- Step 5: Delete ---
            deleted = await dns_aid.unpublish(
                name=unique_agent_name,
                domain=test_zone,
                protocol="mcp",
                backend=backend,
            )

            assert deleted, "Delete failed"

            # Note: We don't verify deletion via DNS query because DNS caching
            # means records may still resolve for up to TTL seconds after deletion.
            # The Route 53 delete operation succeeded (logged above).

        except Exception:
            # Cleanup on failure
            with contextlib.suppress(Exception):
                await dns_aid.unpublish(
                    name=unique_agent_name, domain=test_zone, protocol="mcp", backend=backend
                )
            raise

    @pytest.mark.asyncio
    async def test_discover_multiple_protocols(self, test_zone, unique_agent_name):
        """
        Test discovering agents with different protocols.
        Publishes both MCP and A2A agents, discovers each separately.
        """
        import dns_aid
        from dns_aid.backends.route53 import Route53Backend

        backend = Route53Backend()
        mcp_name = f"{unique_agent_name}-mcp"
        a2a_name = f"{unique_agent_name}-a2a"

        try:
            # Publish MCP agent
            await dns_aid.publish(
                name=mcp_name,
                domain=test_zone,
                protocol="mcp",
                endpoint=f"mcp.{test_zone}",
                capabilities=["chat"],
                backend=backend,
            )

            # Publish A2A agent
            await dns_aid.publish(
                name=a2a_name,
                domain=test_zone,
                protocol="a2a",
                endpoint=f"a2a.{test_zone}",
                capabilities=["assistant"],
                backend=backend,
            )

            await asyncio.sleep(DNS_PROPAGATION_WAIT)

            # Discover MCP only (with retry)
            mcp_found = False
            for _ in range(DNS_RETRY_ATTEMPTS):
                mcp_results = await dns_aid.discover(
                    domain=test_zone,
                    protocol="mcp",
                    name=mcp_name,
                )
                if any(a.name == mcp_name for a in mcp_results.agents):
                    mcp_found = True
                    break
                await asyncio.sleep(DNS_RETRY_DELAY)

            assert mcp_found, f"MCP agent {mcp_name} not discovered"

            # Discover A2A only (with retry)
            a2a_found = False
            for _ in range(DNS_RETRY_ATTEMPTS):
                a2a_results = await dns_aid.discover(
                    domain=test_zone,
                    protocol="a2a",
                    name=a2a_name,
                )
                if any(a.name == a2a_name for a in a2a_results.agents):
                    a2a_found = True
                    break
                await asyncio.sleep(DNS_RETRY_DELAY)

            assert a2a_found, f"A2A agent {a2a_name} not discovered"

        finally:
            # Cleanup both agents
            with contextlib.suppress(Exception):
                await dns_aid.unpublish(
                    name=mcp_name, domain=test_zone, protocol="mcp", backend=backend
                )
            with contextlib.suppress(Exception):
                await dns_aid.unpublish(
                    name=a2a_name, domain=test_zone, protocol="a2a", backend=backend
                )

    @pytest.mark.asyncio
    async def test_verify_security_scoring(self, test_zone, unique_agent_name):
        """
        Test that security scoring works correctly.
        Verifies score components are calculated.
        """
        import dns_aid
        from dns_aid.backends.route53 import Route53Backend

        backend = Route53Backend()

        try:
            # Publish agent
            await dns_aid.publish(
                name=unique_agent_name,
                domain=test_zone,
                protocol="mcp",
                endpoint=f"mcp.{test_zone}",
                backend=backend,
            )

            await asyncio.sleep(DNS_PROPAGATION_WAIT)

            # Verify and check scoring (with retry)
            fqdn = f"_{unique_agent_name}._mcp._agents.{test_zone}"
            result = None
            for _ in range(DNS_RETRY_ATTEMPTS):
                result = await dns_aid.verify(fqdn)
                if result.record_exists:
                    break
                await asyncio.sleep(DNS_RETRY_DELAY)

            # Check all score components are present
            assert result.record_exists is True, "Record should exist"
            assert result.svcb_valid is True, "SVCB should be valid"
            assert isinstance(result.dnssec_valid, bool)
            assert result.dane_valid is None or isinstance(result.dane_valid, bool)
            assert isinstance(result.endpoint_reachable, bool)

            # Score should be calculated
            assert 0 <= result.security_score <= 100
            assert result.security_rating in ["Excellent", "Good", "Fair", "Poor", "Critical"]

        finally:
            with contextlib.suppress(Exception):
                await dns_aid.unpublish(
                    name=unique_agent_name,
                    domain=test_zone,
                    protocol="mcp",
                    backend=backend,
                )

    @pytest.mark.asyncio
    async def test_capabilities_roundtrip(self, test_zone, unique_agent_name):
        """
        Test that capabilities are correctly stored and retrieved.
        """
        import dns_aid
        from dns_aid.backends.route53 import Route53Backend

        backend = Route53Backend()
        capabilities = ["chat", "code-review", "agent-discovery", "testing"]

        try:
            # Publish with capabilities
            await dns_aid.publish(
                name=unique_agent_name,
                domain=test_zone,
                protocol="a2a",
                endpoint=f"agent.{test_zone}",
                capabilities=capabilities,
                backend=backend,
            )

            await asyncio.sleep(DNS_PROPAGATION_WAIT)

            # Discover and verify capabilities (with retry)
            agent = None
            for _ in range(DNS_RETRY_ATTEMPTS):
                result = await dns_aid.discover(
                    domain=test_zone,
                    protocol="a2a",
                    name=unique_agent_name,
                )
                for a in result.agents:
                    if a.name == unique_agent_name:
                        agent = a
                        break
                if agent:
                    break
                await asyncio.sleep(DNS_RETRY_DELAY)

            assert agent is not None, f"Agent {unique_agent_name} not discovered"

            # All capabilities should be present
            for cap in capabilities:
                assert cap in agent.capabilities, f"Missing capability: {cap}"

        finally:
            with contextlib.suppress(Exception):
                await dns_aid.unpublish(
                    name=unique_agent_name,
                    domain=test_zone,
                    protocol="a2a",
                    backend=backend,
                )
