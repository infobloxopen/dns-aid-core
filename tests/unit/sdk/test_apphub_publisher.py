# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AppHub publisher."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.sdk.publishers.apphub import AppHubPublisher
from dns_aid.sdk.publishers.models import (
    AppHubPublisherConfig,
    AppHubServiceRef,
    AppHubServiceSnapshot,
)


def _config() -> AppHubPublisherConfig:
    return AppHubPublisherConfig(
        project_id="test-project",
        location="us-central1",
        domain="example.com",
        protocol="mcp",
    )


def _publisher(backend: MockBackend | None = None) -> AppHubPublisher:
    return AppHubPublisher(
        _config(),
        backend=backend or MockBackend(zones=["example.com"]),
        token_provider=lambda: ("token", None),
    )


def _apphub_snapshot(
    *,
    agent_name: str = "inventory-api",
    capabilities: list[str] | None = None,
    enrollment_base_url: str = "https://psc.inventory.internal",
    functional_type: str = "AGENT",
) -> AppHubServiceSnapshot:
    return AppHubServiceSnapshot(
        discovered_service_name=(
            "projects/test-project/locations/us-central1/discoveredServices/inventory-api"
        ),
        agent_name=agent_name,
        service_uri="https://psc.inventory.internal",
        canonical_service_name=(
            "apphub.googleapis.com/projects/test-project/locations/global/services/inventory-api"
        ),
        functional_type=functional_type,
        capabilities=capabilities or [],
        enrollment_base_url=enrollment_base_url,
        metadata={},
    )


class TestAppHubPublisher:
    """AppHub publisher behavior with mock DNS and API responses."""

    @pytest.mark.asyncio
    async def test_publish_resolves_service_and_populates_connect_fields(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend)

        api_response = {
            "name": "projects/test-project/locations/us-central1/discoveredServices/inventory-api",
            "serviceReference": {"uri": "https://psc.inventory.internal"},
            "serviceProperties": {
                "functionalType": {"type": "AGENT"},
                "extendedMetadata": {
                    "apphub.googleapis.com/agentProperties": {
                        "metadata": {
                            "a2a": {"capabilities": ["search", "invoke"]},
                            "serviceName": "Inventory API",
                        }
                    },
                    "apphub.googleapis.com/agentConnect": {
                        "metadata": {
                            "serviceName": (
                                "apphub.googleapis.com/projects/test-project/locations/global/"
                                "services/inventory-api"
                            ),
                            "pscBaseUrl": "https://psc.inventory.internal",
                        }
                    },
                },
            },
        }

        with patch.object(publisher, "_request", AsyncMock(return_value=api_response)) as mock_request:
            result = await publisher.publish(AppHubServiceRef(name="inventory-api"))

        assert result.success is True
        mock_request.assert_awaited_once_with(
            "GET",
            "/v1/projects/test-project/locations/us-central1/discoveredServices/inventory-api",
        )

        record_name = "_inventory-api._mcp._agents"
        svcb = backend.get_svcb_record("example.com", record_name)
        txt_values = backend.get_txt_record("example.com", record_name)

        assert svcb is not None
        assert svcb["target"] == "psc.inventory.internal."
        assert svcb["params"]["key65406"] == "apphub-psc"
        assert (
            svcb["params"]["key65407"]
            == "apphub.googleapis.com/projects/test-project/locations/global/services/inventory-api"
        )
        assert (
            svcb["params"]["key65408"]
            == "https://psc.inventory.internal/.well-known/agent-connect"
        )
        assert txt_values is not None
        assert "capabilities=search,invoke" in txt_values

    @pytest.mark.asyncio
    async def test_publish_without_capabilities_metadata_keeps_record_valid(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend)

        result = await publisher.publish(_apphub_snapshot(capabilities=[]))

        assert result.success is True
        txt_values = backend.get_txt_record("example.com", "_inventory-api._mcp._agents")
        assert txt_values is not None
        assert not any(value.startswith("capabilities=") for value in txt_values)
        assert "version=1.0.0" in txt_values

    @pytest.mark.asyncio
    async def test_sync_updates_endpoint_on_next_cycle(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend)

        first = _apphub_snapshot(
            capabilities=["search"],
            enrollment_base_url="https://psc-v1.inventory.internal",
        )
        second = _apphub_snapshot(
            capabilities=["search"],
            enrollment_base_url="https://psc-v2.inventory.internal",
        )

        with patch.object(
            publisher,
            "_list_discovered_services",
            AsyncMock(side_effect=[[first], [second]]),
        ):
            first_result = await publisher.sync()
            second_result = await publisher.sync()

        assert first_result.published == 1
        assert second_result.updated == 1

        svcb = backend.get_svcb_record("example.com", "_inventory-api._mcp._agents")
        assert svcb is not None
        assert svcb["target"] == "psc-v2.inventory.internal."
        assert (
            svcb["params"]["key65408"]
            == "https://psc-v2.inventory.internal/.well-known/agent-connect"
        )

    @pytest.mark.asyncio
    async def test_sync_removes_deleted_or_detached_services(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend)

        active = _apphub_snapshot(capabilities=["search"])
        detached = _apphub_snapshot(functional_type="APPLICATION")

        with patch.object(
            publisher,
            "_list_discovered_services",
            AsyncMock(side_effect=[[active], [detached], []]),
        ):
            published = await publisher.sync()
            detached_result = await publisher.sync()
            deleted_result = await publisher.sync()

        assert published.published == 1
        assert detached_result.unpublished == 1
        assert deleted_result.unpublished == 0
        assert backend.get_svcb_record("example.com", "_inventory-api._mcp._agents") is None
