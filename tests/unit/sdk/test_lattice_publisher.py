# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the VPC Lattice publisher."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.sdk.publishers.lattice import LatticePublisher
from dns_aid.sdk.publishers.models import (
    LatticePublisherConfig,
    LatticeServiceRef,
    LatticeServiceSnapshot,
    SyncResult,
)


def _config(*, name_overrides: dict[str, str] | None = None) -> LatticePublisherConfig:
    return LatticePublisherConfig(
        domain="example.com",
        protocol="mcp",
        stable_tag_key="stable",
        dynamic_ttl=30,
        stable_ttl=300,
        name_overrides=name_overrides or {},
    )


def _publisher(
    *,
    backend: MockBackend | None = None,
    client: MagicMock | None = None,
    name_overrides: dict[str, str] | None = None,
) -> LatticePublisher:
    return LatticePublisher(
        _config(name_overrides=name_overrides),
        backend=backend or MockBackend(zones=["example.com"]),
        client=client,
    )


def _service_response(dns_name: str = "orders.service.internal") -> dict[str, str | dict[str, str]]:
    return {
        "id": "svc-123",
        "name": "Orders API",
        "arn": "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123",
        "dnsEntry": {"domainName": dns_name},
        "status": "ACTIVE",
    }


def _snapshot(dns_name: str = "orders.service.internal") -> LatticeServiceSnapshot:
    return LatticeServiceSnapshot(
        service_id="svc-123",
        service_name="orders-api",
        service_arn="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123",
        dns_name=dns_name,
        tags={},
        status="ACTIVE",
    )


class TestLatticePublisher:
    """VPC Lattice publisher behavior with mock DNS and boto3 stubs."""

    @pytest.mark.asyncio
    async def test_publish_uses_stable_tag_ttl(self):
        backend = MockBackend(zones=["example.com"])
        client = MagicMock()
        client.get_service.return_value = _service_response()
        client.list_tags_for_resource.return_value = {"tags": {"stable": "true"}}
        publisher = _publisher(backend=backend, client=client)

        result = await publisher.publish(LatticeServiceRef(service_id="svc-123"))

        assert result.success is True
        client.get_service.assert_called_once_with(serviceIdentifier="svc-123")
        svcb = backend.get_svcb_record("example.com", "_orders-api._mcp._agents")
        assert svcb is not None
        assert svcb["ttl"] == 300
        assert svcb["params"]["key65406"] == "lattice"
        assert (
            svcb["params"]["key65407"]
            == "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
        )

    @pytest.mark.asyncio
    async def test_publish_without_stable_tag_uses_dynamic_ttl(self):
        backend = MockBackend(zones=["example.com"])
        client = MagicMock()
        client.get_service.return_value = _service_response()
        client.list_tags_for_resource.return_value = {"tags": {}}
        publisher = _publisher(backend=backend, client=client)

        result = await publisher.publish(LatticeServiceRef(service_id="svc-123"))

        assert result.success is True
        svcb = backend.get_svcb_record("example.com", "_orders-api._mcp._agents")
        assert svcb is not None
        assert svcb["ttl"] == 30

    @pytest.mark.asyncio
    async def test_sync_replaces_changed_fqdn_atomically(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend=backend)

        first = _snapshot("orders-v1.service.internal")
        second = _snapshot("orders-v2.service.internal")

        with patch.object(
            publisher,
            "_list_services",
            AsyncMock(side_effect=[[first], [second]]),
        ):
            first_result = await publisher.sync()
            second_result = await publisher.sync()

        assert first_result.published == 1
        assert second_result.updated == 1

        svcb = backend.get_svcb_record("example.com", "_orders-api._mcp._agents")
        assert svcb is not None
        assert svcb["target"] == "orders-v2.service.internal."
        assert len(backend.records["example.com"]["_orders-api._mcp._agents"]["SVCB"]) == 1

    @pytest.mark.asyncio
    async def test_sync_removes_deleted_services(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend=backend)

        with patch.object(
            publisher,
            "_list_services",
            AsyncMock(side_effect=[[_snapshot()], []]),
        ):
            published = await publisher.sync()
            deleted = await publisher.sync()

        assert published.published == 1
        assert deleted.unpublished == 1
        assert backend.get_svcb_record("example.com", "_orders-api._mcp._agents") is None

    @pytest.mark.asyncio
    async def test_concurrent_publish_is_idempotent(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend=backend)

        snapshot = _snapshot()
        results = await asyncio.gather(
            publisher.publish(snapshot),
            publisher.publish(snapshot),
        )

        assert all(result.success for result in results)
        assert len(backend.records["example.com"]["_orders-api._mcp._agents"]["SVCB"]) == 1
        assert len(backend.records["example.com"]["_orders-api._mcp._agents"]["TXT"]) == 1

    @pytest.mark.asyncio
    async def test_sync_republishes_after_zone_records_are_deleted(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend=backend)
        snapshot = _snapshot()

        with patch.object(
            publisher,
            "_list_services",
            AsyncMock(side_effect=[[snapshot], [snapshot]]),
        ):
            first_result = await publisher.sync()
            backend.clear()
            second_result = await publisher.sync()

        assert first_result.published == 1
        assert second_result.published == 1
        assert len(backend.records["example.com"]["_orders-api._mcp._agents"]["SVCB"]) == 1

    @pytest.mark.asyncio
    async def test_list_services_uses_summary_without_get_service_when_dns_present(self):
        client = MagicMock()
        client.list_services.return_value = {"items": [_service_response()]}
        client.list_tags_for_resource.return_value = {"tags": {}}
        publisher = _publisher(client=client)

        snapshots = await publisher._list_services()

        assert len(snapshots) == 1
        client.get_service.assert_not_called()
        client.list_tags_for_resource.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_reports_name_collisions_without_override(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(backend=backend)

        first = LatticeServiceSnapshot(
            service_id="svc-123",
            service_name="orders-api",
            service_arn="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123",
            dns_name="orders-a.service.internal",
            tags=(),
            status="ACTIVE",
        )
        second = LatticeServiceSnapshot(
            service_id="svc-456",
            service_name="orders-api",
            service_arn="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-456",
            dns_name="orders-b.service.internal",
            tags=(),
            status="ACTIVE",
        )

        with patch.object(publisher, "_list_services", AsyncMock(return_value=[first, second])):
            result = await publisher.sync()

        assert result.published == 0
        assert result.errors
        assert "name collision" in result.errors[0]
        assert backend.get_svcb_record("example.com", "_orders-api._mcp._agents") is None

    @pytest.mark.asyncio
    async def test_name_override_allows_colliding_services_to_publish(self):
        backend = MockBackend(zones=["example.com"])
        publisher = _publisher(
            backend=backend,
            name_overrides={
                "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-456": "orders-api-west"
            },
        )

        first = publisher._snapshot_from_api(_service_response("orders-a.service.internal"), {})
        second = publisher._snapshot_from_api(
            {
                "id": "svc-456",
                "name": "Orders API",
                "arn": "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-456",
                "dnsEntry": {"domainName": "orders-b.service.internal"},
                "status": "ACTIVE",
            },
            {},
        )

        with patch.object(publisher, "_list_services", AsyncMock(return_value=[first, second])):
            result = await publisher.sync()

        assert result.published == 2
        assert backend.get_svcb_record("example.com", "_orders-api._mcp._agents") is not None
        assert backend.get_svcb_record("example.com", "_orders-api-west._mcp._agents") is not None

    @pytest.mark.asyncio
    async def test_handle_eventbridge_event_routes_tag_updates_to_publish(self):
        publisher = _publisher()

        with patch.object(
            publisher,
            "publish",
            AsyncMock(return_value=MagicMock(success=True)),
        ) as mock_publish:
            await publisher.handle_eventbridge_event(
                {
                    "detail": {
                        "eventName": "TagResource",
                        "requestParameters": {
                            "serviceArn": (
                                "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
                            )
                        },
                    }
                }
            )

        ref = mock_publish.await_args.args[0]
        assert isinstance(ref, LatticeServiceRef)
        assert ref.service_arn == "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"

    @pytest.mark.asyncio
    async def test_handle_eventbridge_delete_falls_back_to_sync(self):
        publisher = _publisher()

        with patch.object(
            publisher,
            "sync",
            AsyncMock(return_value=SyncResult(unpublished=1)),
        ) as mock_sync:
            result = await publisher.handle_eventbridge_event(
                {"detail": {"eventName": "DeleteService"}}
            )

        assert result.unpublished == 1
        mock_sync.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_main_async_times_out_on_stdin_and_falls_back_to_startup_sync(self):
        publisher = _publisher()

        async def _timeout_read(coro, timeout):
            coro.close()
            raise TimeoutError

        with (
            patch("dns_aid.sdk.publishers.lattice.LatticePublisher.from_env", return_value=publisher),
            patch("dns_aid.sdk.publishers.lattice.sys.stdin.isatty", return_value=False),
            patch("dns_aid.sdk.publishers.lattice.asyncio.wait_for", side_effect=_timeout_read),
            patch(
                "dns_aid.sdk.publishers.lattice.run_startup_sync",
                AsyncMock(return_value=SyncResult(unchanged=1)),
            ) as mock_startup_sync,
        ):
            from dns_aid.sdk.publishers.lattice import main_async

            result = await main_async()

        assert result.unchanged == 1
        mock_startup_sync.assert_awaited_once_with(publisher)
