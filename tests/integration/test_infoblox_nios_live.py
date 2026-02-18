# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import uuid

import pytest

from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend
from tests.live_targets import (
    LiveNiosTarget,
    live_mutation_tests_enabled,
    live_tests_enabled,
    load_live_nios_targets,
)

pytestmark = [pytest.mark.live]


def _require_live_targets() -> list[LiveNiosTarget]:
    if not live_tests_enabled():
        pytest.skip("Live tests disabled. Set DNS_AID_LIVE_TESTS=1 to enable.")

    targets = load_live_nios_targets()
    if not targets:
        pytest.skip(
            "No live NIOS targets configured. "
            "Create tests/live_targets.json (see tests/live_targets.example.json)."
        )
    return targets


@pytest.mark.asyncio
async def test_live_nios_read_only_connectivity() -> None:
    targets = _require_live_targets()

    for target in targets:
        backend = InfobloxNIOSBackend(
            host=target.host,
            username=target.username,
            password=target.password,
            wapi_version=target.wapi_version,
            verify_ssl=target.verify_ssl,
            dns_view=target.dns_view,
            timeout=target.timeout,
        )
        try:
            zones = await backend.list_zones()
            assert isinstance(zones, list)

            if target.test_zone:
                assert await backend.zone_exists(target.test_zone)
                assert await backend.zone_exists(f"{target.test_zone}.")
        finally:
            await backend.close()


@pytest.mark.asyncio
async def test_live_nios_create_delete_cycle() -> None:
    targets = _require_live_targets()
    if not live_mutation_tests_enabled():
        pytest.skip("Mutation tests disabled. Set DNS_AID_LIVE_MUTATION_TESTS=1 to enable.")

    exercised_targets = 0
    for target in targets:
        if not target.test_zone:
            continue

        exercised_targets += 1
        backend = InfobloxNIOSBackend(
            host=target.host,
            username=target.username,
            password=target.password,
            wapi_version=target.wapi_version,
            verify_ssl=target.verify_ssl,
            dns_view=target.dns_view,
            timeout=target.timeout,
        )

        suffix = uuid.uuid4().hex[:8]
        record_name = f"_live-nios-{suffix}._mcp._agents"
        zone = target.test_zone

        try:
            await backend.create_svcb_record(
                zone=zone,
                name=record_name,
                priority=1,
                target=f"live-target.{zone}",
                params={
                    "mandatory": "alpn,port",
                    "alpn": "mcp",
                    "port": "443",
                    "realm": "live-test",
                },
                ttl=120,
            )
            await backend.create_txt_record(
                zone=zone,
                name=record_name,
                values=["capabilities=live-test", "version=0.0.1"],
                ttl=120,
            )

            svcb = await backend.get_record(zone, record_name, "SVCB")
            txt = await backend.get_record(zone, record_name, "TXT")
            assert svcb is not None
            assert txt is not None
        finally:
            await backend.delete_record(zone, record_name, "SVCB")
            await backend.delete_record(zone, record_name, "TXT")
            await backend.close()

    if exercised_targets == 0:
        pytest.skip(
            "No targets with test_zone configured for mutation tests. "
            "Set 'test_zone' in tests/live_targets.json."
        )
