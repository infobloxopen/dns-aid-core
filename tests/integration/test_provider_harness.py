# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Hermetic end-to-end tests for provider discovery bootstrap flows."""

from __future__ import annotations

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk.publishers.harness import DiscoveryValidationHarness


@pytest.mark.asyncio
async def test_apphub_harness_bootstraps_from_published_records(dns_bridge):
    backend = MockBackend(zones=["example.com"])
    dns_bridge.backend = backend

    agent = AgentRecord(
        name="inventory-api",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="psc.inventory.internal",
        connect_class="apphub-psc",
        connect_meta=(
            "apphub.googleapis.com/projects/test-project/locations/global/services/inventory-api"
        ),
        enroll_uri="https://psc.inventory.internal/.well-known/agent-connect",
    )
    await backend.publish_agent(agent)
    dns_bridge.set_endpoint_reachable(
        "psc.inventory.internal",
        json_data={"enrollment": "ok", "service": "inventory-api"},
    )

    harness = DiscoveryValidationHarness(
        apphub_connect_meta_validator=lambda value: value.endswith("/inventory-api")
    )

    with dns_bridge.patch_all():
        results = await harness.bootstrap("example.com", protocol="mcp", name="inventory-api")

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].connect_class == "apphub-psc"
    assert results[0].details["enrollment"]["service"] == "inventory-api"


@pytest.mark.asyncio
async def test_lattice_harness_bootstraps_overlay_path(dns_bridge):
    backend = MockBackend(zones=["example.com"])
    dns_bridge.backend = backend

    agent = AgentRecord(
        name="orders-api",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="orders.service.internal",
        connect_class="lattice",
        connect_meta="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123",
        enroll_uri="https://orders.service.internal/.well-known/agent-connect",
    )
    await backend.publish_agent(agent)
    dns_bridge.set_endpoint_reachable(
        "orders.service.internal",
        json_data={"overlay": "required"},
    )

    async def lattice_lookup(arn: str):
        return {"arn": arn, "overlay_required": True}

    harness = DiscoveryValidationHarness(lattice_lookup=lattice_lookup)

    with dns_bridge.patch_all():
        results = await harness.bootstrap("example.com", protocol="mcp", name="orders-api")

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].direct_connect_attempted is False
    assert results[0].connect_class == "lattice"
    assert results[0].details["lattice_record"]["overlay_required"] is True
