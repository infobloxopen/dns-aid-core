# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Hermetic discovery validation harness for provider-managed connection flows."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from pydantic import BaseModel, Field

import dns_aid
from dns_aid.core.models import AgentRecord


class DiscoveryBootstrapResult(BaseModel):
    """Outcome of a full discovery and provider-specific bootstrap attempt."""

    agent_name: str
    domain: str
    connect_class: str | None = None
    connect_meta: str | None = None
    enroll_uri: str | None = None
    success: bool = False
    direct_connect_attempted: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None


class DiscoveryValidationHarness:
    """Bootstrap discovered DNS-AID agents using only the published records."""

    def __init__(
        self,
        *,
        lattice_lookup: Callable[[str], Awaitable[dict[str, Any] | None]] | None = None,
        apphub_connect_meta_validator: Callable[[str], bool] | None = None,
    ) -> None:
        self._lattice_lookup = lattice_lookup
        self._apphub_connect_meta_validator = apphub_connect_meta_validator

    async def bootstrap(
        self,
        domain: str,
        *,
        protocol: str | None = None,
        name: str | None = None,
    ) -> list[DiscoveryBootstrapResult]:
        discovery = await dns_aid.discover(
            domain,
            protocol=protocol,
            name=name,
            enrich_endpoints=False,
        )
        results = []
        for agent in discovery.agents:
            results.append(await self._bootstrap_agent(domain, agent))
        return results

    async def _bootstrap_agent(self, domain: str, agent: AgentRecord) -> DiscoveryBootstrapResult:
        if agent.connect_class == "apphub-psc":
            return await self._bootstrap_apphub(domain, agent)
        if agent.connect_class == "lattice":
            return await self._bootstrap_lattice(domain, agent)
        return DiscoveryBootstrapResult(
            agent_name=agent.name,
            domain=domain,
            connect_class=agent.connect_class,
            connect_meta=agent.connect_meta,
            enroll_uri=agent.enroll_uri,
            success=True,
            direct_connect_attempted=True,
            details={"endpoint_url": agent.endpoint_url},
            message="Direct agent bootstrap path",
        )

    async def _bootstrap_apphub(self, domain: str, agent: AgentRecord) -> DiscoveryBootstrapResult:
        if not agent.enroll_uri:
            return DiscoveryBootstrapResult(
                agent_name=agent.name,
                domain=domain,
                connect_class=agent.connect_class,
                connect_meta=agent.connect_meta,
                success=False,
                message="Missing enroll_uri for AppHub bootstrap",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(agent.enroll_uri)
            response.raise_for_status()
            payload = response.json()

        meta_valid = True
        if self._apphub_connect_meta_validator and agent.connect_meta:
            meta_valid = self._apphub_connect_meta_validator(agent.connect_meta)

        return DiscoveryBootstrapResult(
            agent_name=agent.name,
            domain=domain,
            connect_class=agent.connect_class,
            connect_meta=agent.connect_meta,
            enroll_uri=agent.enroll_uri,
            success=meta_valid,
            direct_connect_attempted=False,
            details={"enrollment": payload},
            message="AppHub enrollment bootstrap completed" if meta_valid else "AppHub connect_meta validation failed",
        )

    async def _bootstrap_lattice(self, domain: str, agent: AgentRecord) -> DiscoveryBootstrapResult:
        if not agent.enroll_uri:
            return DiscoveryBootstrapResult(
                agent_name=agent.name,
                domain=domain,
                connect_class=agent.connect_class,
                connect_meta=agent.connect_meta,
                success=False,
                message="Missing enroll_uri for lattice bootstrap",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(agent.enroll_uri)
            response.raise_for_status()
            payload = response.json()

        lattice_record = None
        if self._lattice_lookup and agent.connect_meta:
            lattice_record = await self._lattice_lookup(agent.connect_meta)

        success = lattice_record is not None or self._lattice_lookup is None
        return DiscoveryBootstrapResult(
            agent_name=agent.name,
            domain=domain,
            connect_class=agent.connect_class,
            connect_meta=agent.connect_meta,
            enroll_uri=agent.enroll_uri,
            success=success,
            direct_connect_attempted=False,
            details={"enrollment": payload, "lattice_record": lattice_record},
            message="Lattice overlay bootstrap completed" if success else "Lattice ARN lookup failed",
        )
