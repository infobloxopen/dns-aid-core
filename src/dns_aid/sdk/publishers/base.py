# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Base abstractions for provider-managed record publishers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from dns_aid.backends.base import DNSBackend
from dns_aid.core.models import AgentRecord, Protocol, PublishResult
from dns_aid.core.publisher import unpublish
from dns_aid.sdk.publishers._helpers import parse_published_state
from dns_aid.sdk.publishers.models import PublishedAgentState, SyncResult

TService = TypeVar("TService")


class AgentRecordPublisher(ABC, Generic[TService]):
    """Abstract interface for provider-managed agent record publishing."""

    @abstractmethod
    async def publish(self, service: TService) -> PublishResult:
        """Publish or update DNS-AID records for the given provider service."""

    @abstractmethod
    async def unpublish(self, service: TService) -> bool:
        """Remove DNS-AID records for the given provider service."""

    @abstractmethod
    async def sync(self) -> SyncResult:
        """Reconcile provider state against authoritative DNS."""


class BaseAgentRecordPublisher(AgentRecordPublisher[TService], Generic[TService]):
    """Shared DNS mutation helpers for provider-backed publishers."""

    def __init__(self, backend: DNSBackend, domain: str, protocol: str | Protocol) -> None:
        self.backend = backend
        self.domain = domain.rstrip(".")
        self.protocol = protocol if isinstance(protocol, Protocol) else Protocol(protocol.lower())

    async def _publish_agent_record(self, agent: AgentRecord) -> PublishResult:
        if not await self.backend.zone_exists(agent.domain):
            return PublishResult(
                agent=agent,
                records_created=[],
                zone=agent.domain,
                backend=self.backend.name,
                success=False,
                message=f"Zone '{agent.domain}' does not exist or is not accessible",
            )

        try:
            records = await self.backend.publish_agent(agent)
        except Exception as exc:
            return PublishResult(
                agent=agent,
                records_created=[],
                zone=agent.domain,
                backend=self.backend.name,
                success=False,
                message=f"Failed to publish: {exc}",
            )

        return PublishResult(
            agent=agent,
            records_created=records,
            zone=agent.domain,
            backend=self.backend.name,
            success=True,
            message="Agent published successfully",
        )

    async def _unpublish_agent_name(self, agent_name: str) -> bool:
        return await unpublish(
            name=agent_name,
            domain=self.domain,
            protocol=self.protocol,
            backend=self.backend,
        )

    async def _list_published_states(
        self,
        *,
        connect_class: str | None = None,
    ) -> dict[str, PublishedAgentState]:
        states: dict[str, PublishedAgentState] = {}

        async for record in self.backend.list_records(self.domain, name_pattern="._agents", record_type="SVCB"):
            svcb_record = record
            if not record.get("values"):
                svcb_record = await self.backend.get_record(self.domain, record["name"], "SVCB") or record
            txt_record = await self.backend.get_record(self.domain, record["name"], "TXT")
            txt_values = txt_record["values"] if txt_record else []
            state = parse_published_state(svcb_record, txt_values)
            if state is None:
                continue
            if connect_class and state.connect_class != connect_class:
                continue
            states[f"{state.name}:{state.protocol}"] = state
        return states
