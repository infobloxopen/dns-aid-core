# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""AWS VPC Lattice-backed DNS-AID record publisher."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from dns_aid.backends.base import DNSBackend
from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend
from dns_aid.core.models import AgentRecord
from dns_aid.sdk.publishers._helpers import is_truthy_tag, normalize_agent_name
from dns_aid.sdk.publishers.base import BaseAgentRecordPublisher
from dns_aid.sdk.publishers.models import (
    LatticePublisherConfig,
    LatticeServiceRef,
    LatticeServiceSnapshot,
    PublishedAgentState,
    SyncResult,
)


class LatticePublisher(BaseAgentRecordPublisher[LatticeServiceRef | LatticeServiceSnapshot | str]):
    """Publisher that reconciles VPC Lattice services into authoritative DNS."""

    def __init__(
        self,
        config: LatticePublisherConfig,
        *,
        backend: DNSBackend | None = None,
        client: Any | None = None,
    ) -> None:
        self.config = config
        self._client = client
        dns_backend = backend or InfobloxNIOSBackend()
        super().__init__(dns_backend, config.domain, config.protocol)

    @classmethod
    def from_env(
        cls,
        *,
        backend: DNSBackend | None = None,
        client: Any | None = None,
    ) -> LatticePublisher:
        return cls(
            LatticePublisherConfig(
                domain=os.environ["LATTICE_DOMAIN"],
                protocol=os.environ.get("LATTICE_PROTOCOL", "mcp"),
                stable_tag_key=os.environ.get("LATTICE_STABLE_TAG_KEY", "stable"),
                stable_tag_values=[
                    item.strip()
                    for item in os.environ.get("LATTICE_STABLE_TAG_VALUES", "1,true,yes,stable").split(",")
                    if item.strip()
                ],
                dynamic_ttl=int(os.environ.get("LATTICE_DYNAMIC_TTL", "30")),
                stable_ttl=int(os.environ.get("LATTICE_STABLE_TTL", "300")),
            ),
            backend=backend,
            client=client,
        )

    def _get_client(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("vpc-lattice")
        return self._client

    async def _resolve_ref(self, service: LatticeServiceRef | str) -> LatticeServiceSnapshot:
        ref = service if isinstance(service, LatticeServiceRef) else LatticeServiceRef(service_id=service)
        identifier = ref.service_arn or ref.service_id or ref.service_name
        if not identifier:
            raise ValueError("Lattice service reference must include a service identifier")

        client = self._get_client()
        data = client.get_service(serviceIdentifier=identifier)
        tags = {}
        service_arn = data.get("arn")
        if service_arn:
            tags_response = client.list_tags_for_resource(resourceArn=service_arn)
            tags = dict(tags_response.get("tags", {}))
        return self._snapshot_from_api(data, tags)

    def _snapshot_from_api(self, data: dict[str, Any], tags: dict[str, str]) -> LatticeServiceSnapshot:
        dns_name = (
            data.get("dnsEntry", {}).get("domainName")
            or data.get("customDomainName")
            or ""
        )
        if not dns_name:
            raise ValueError("VPC Lattice service is missing a DNS name")

        return LatticeServiceSnapshot(
            service_id=data["id"],
            service_name=normalize_agent_name(data["name"]),
            service_arn=data["arn"],
            dns_name=dns_name,
            tags=tags,
            status=data.get("status"),
        )

    async def _resolve_service(self, service: LatticeServiceRef | LatticeServiceSnapshot | str) -> LatticeServiceSnapshot:
        if isinstance(service, LatticeServiceSnapshot):
            return service
        return await self._resolve_ref(service)

    def _ttl_for_snapshot(self, snapshot: LatticeServiceSnapshot) -> int:
        value = snapshot.tags.get(self.config.stable_tag_key)
        if is_truthy_tag(value, self.config.stable_tag_values):
            return self.config.stable_ttl
        return self.config.dynamic_ttl

    def _build_agent(self, snapshot: LatticeServiceSnapshot) -> AgentRecord:
        return AgentRecord(
            name=snapshot.service_name,
            domain=self.domain,
            protocol=self.protocol,
            target_host=snapshot.target_host,
            ttl=self._ttl_for_snapshot(snapshot),
            connect_class="lattice",
            connect_meta=snapshot.service_arn,
            enroll_uri=f"https://{snapshot.target_host}/.well-known/agent-connect",
        )

    @staticmethod
    def _matches_state(state: PublishedAgentState, agent: AgentRecord) -> bool:
        return (
            state.protocol == agent.protocol.value
            and state.target_host == agent.target_host
            and state.ttl == agent.ttl
            and state.connect_class == agent.connect_class
            and state.connect_meta == agent.connect_meta
            and state.enroll_uri == agent.enroll_uri
        )

    async def _list_services(self) -> list[LatticeServiceSnapshot]:
        client = self._get_client()
        next_token: str | None = None
        snapshots: list[LatticeServiceSnapshot] = []

        while True:
            params: dict[str, Any] = {"maxResults": 100}
            if next_token:
                params["nextToken"] = next_token

            response = client.list_services(**params)
            for summary in response.get("items", []):
                snapshot = await self._resolve_ref(LatticeServiceRef(service_id=summary["id"]))
                snapshots.append(snapshot)

            next_token = response.get("nextToken")
            if not next_token:
                break

        return snapshots

    async def publish(self, service: LatticeServiceRef | LatticeServiceSnapshot | str):
        snapshot = await self._resolve_service(service)
        return await self._publish_agent_record(self._build_agent(snapshot))

    async def unpublish(self, service: LatticeServiceRef | LatticeServiceSnapshot | str) -> bool:
        try:
            snapshot = await self._resolve_service(service)
            return await self._unpublish_agent_name(snapshot.service_name)
        except Exception:
            candidates: set[str] = set()
            if isinstance(service, LatticeServiceRef):
                candidates.update(filter(None, [service.service_id, service.service_arn, service.service_name]))
            else:
                candidates.add(str(service))

            current_states = await self._list_published_states(connect_class="lattice")
            for state in current_states.values():
                if state.connect_meta in candidates or state.name in candidates:
                    return await self._unpublish_agent_name(state.name)
            return False

    async def sync(self) -> SyncResult:
        result = SyncResult()
        current_states = await self._list_published_states(connect_class="lattice")
        desired_snapshots = await self._list_services()

        for snapshot in desired_snapshots:
            agent = self._build_agent(snapshot)
            key = f"{agent.name}:{agent.protocol.value}"
            current = current_states.pop(key, None)

            if current and self._matches_state(current, agent):
                result.unchanged += 1
                continue

            publish_result = await self._publish_agent_record(agent)
            if not publish_result.success:
                result.errors.append(publish_result.message or f"Failed to publish {agent.name}")
            elif current:
                result.updated += 1
            else:
                result.published += 1

        for stale in current_states.values():
            deleted = await self._unpublish_agent_name(stale.name)
            if deleted:
                result.unpublished += 1
            else:
                result.errors.append(f"Failed to unpublish stale lattice record {stale.name}")

        return result

    @staticmethod
    def _extract_service_identifier(event: dict[str, Any]) -> LatticeServiceRef | None:
        detail = event.get("detail", {})
        request_parameters = detail.get("requestParameters", {}) if isinstance(detail, dict) else {}
        response_elements = detail.get("responseElements", {}) if isinstance(detail, dict) else {}

        service_arn = (
            response_elements.get("arn")
            or request_parameters.get("resourceArn")
            or request_parameters.get("serviceArn")
        )
        service_id = (
            response_elements.get("id")
            or request_parameters.get("serviceIdentifier")
            or request_parameters.get("serviceId")
        )
        service_name = (
            response_elements.get("name")
            or request_parameters.get("name")
            or request_parameters.get("serviceName")
        )

        if not any((service_id, service_arn, service_name)):
            return None
        return LatticeServiceRef(service_id=service_id, service_arn=service_arn, service_name=service_name)

    async def handle_eventbridge_event(self, event: dict[str, Any]):
        detail = event.get("detail", {})
        event_name = detail.get("eventName", "") if isinstance(detail, dict) else ""

        if event_name == "DeleteService":
            return await self.sync()

        if event_name in {"CreateService", "UpdateService", "TagResource", "UntagResource"}:
            ref = self._extract_service_identifier(event)
            if ref is not None:
                return await self.publish(ref)

        return await self.sync()


async def run_startup_sync(publisher: LatticePublisher) -> SyncResult:
    """Run a single startup reconciliation cycle."""
    return await publisher.sync()


async def main_async() -> SyncResult | Any:
    publisher = LatticePublisher.from_env()
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            return await publisher.handle_eventbridge_event(json.loads(raw))
    return await run_startup_sync(publisher)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":  # pragma: no cover
    main()
