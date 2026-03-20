# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""AWS VPC Lattice-backed DNS-AID record publisher."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable
from typing import Any

from dns_aid.backends.base import DNSBackend
from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend
from dns_aid.core.models import AgentRecord, PublishResult
from dns_aid.sdk.publishers._helpers import is_truthy_tag, normalize_agent_name
from dns_aid.sdk.publishers.base import BaseAgentRecordPublisher
from dns_aid.sdk.publishers.models import (
    LatticePublisherConfig,
    LatticeServiceRef,
    LatticeServiceSnapshot,
    PublishedAgentState,
    SyncResult,
)

_BotocoreBotoCoreError: type[Exception] = Exception
_BotocoreClientError: type[Exception] = Exception

try:  # pragma: no cover - optional dependency
    from botocore.exceptions import BotoCoreError as ImportedBotocoreBotoCoreError
    from botocore.exceptions import ClientError as ImportedBotocoreClientError
except ImportError:  # pragma: no cover - exercised when boto3 extra is absent
    pass
else:  # pragma: no cover - trivial assignment
    _BotocoreBotoCoreError = ImportedBotocoreBotoCoreError
    _BotocoreClientError = ImportedBotocoreClientError


_LATTICE_RUNTIME_ERRORS = (
    ValueError,
    RuntimeError,
    _BotocoreBotoCoreError,
    _BotocoreClientError,
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
        self._sync_lock = asyncio.Lock()
        dns_backend = backend or InfobloxNIOSBackend()
        super().__init__(dns_backend, config.domain, config.protocol)

    @classmethod
    def from_env(
        cls,
        *,
        backend: DNSBackend | None = None,
        client: Any | None = None,
    ) -> LatticePublisher:
        raw_name_overrides = os.environ.get("LATTICE_NAME_OVERRIDES_JSON", "{}")
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
                name_overrides=json.loads(raw_name_overrides) if raw_name_overrides.strip() else {},
            ),
            backend=backend,
            client=client,
        )

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("vpc-lattice")
        return self._client

    async def _call_client(self, method_name: str, **kwargs: Any) -> Any:
        client = self._get_client()
        method: Callable[..., Any] = getattr(client, method_name)
        return await asyncio.to_thread(method, **kwargs)

    async def _list_tags(self, service_arn: str | None) -> dict[str, str]:
        if not service_arn:
            return {}
        tags_response = await self._call_client("list_tags_for_resource", resourceArn=service_arn)
        tags = tags_response.get("tags", {})
        return {
            str(key): str(value)
            for key, value in tags.items()
            if isinstance(key, str) and isinstance(value, str)
        }

    def _configured_name_override(self, *identifiers: str | None) -> str | None:
        for identifier in identifiers:
            if not identifier:
                continue
            override = self.config.name_overrides.get(identifier)
            if override:
                return normalize_agent_name(override)
        return None

    async def _resolve_ref(self, service: LatticeServiceRef | str) -> LatticeServiceSnapshot:
        ref = service if isinstance(service, LatticeServiceRef) else LatticeServiceRef(service_id=service)
        identifier = ref.service_arn or ref.service_id or ref.service_name
        if not identifier:
            raise ValueError("Lattice service reference must include a service identifier")

        data = await self._call_client("get_service", serviceIdentifier=identifier)
        tags = await self._list_tags(data.get("arn"))
        return self._snapshot_from_api(data, tags)

    def _snapshot_from_api(self, data: dict[str, Any], tags: dict[str, str]) -> LatticeServiceSnapshot:
        dns_entry = data.get("dnsEntry", {})
        dns_name = (dns_entry.get("domainName") if isinstance(dns_entry, dict) else None) or data.get(
            "customDomainName"
        ) or ""
        if not dns_name:
            raise ValueError("VPC Lattice service is missing a DNS name")

        service_id = data.get("id")
        service_arn = data.get("arn")
        raw_name = data.get("name")
        if not isinstance(service_id, str) or not service_id:
            raise ValueError("VPC Lattice service is missing an id")
        if not isinstance(service_arn, str) or not service_arn:
            raise ValueError("VPC Lattice service is missing an ARN")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("VPC Lattice service is missing a name")

        service_name = self._configured_name_override(service_arn, service_id, raw_name)
        if service_name is None:
            service_name = normalize_agent_name(raw_name)

        return LatticeServiceSnapshot(
            service_id=service_id,
            service_name=service_name,
            service_arn=service_arn,
            dns_name=dns_name,
            tags=tuple(sorted(tags.items())),
            status=data.get("status"),
        )

    async def _resolve_service(
        self,
        service: LatticeServiceRef | LatticeServiceSnapshot | str,
    ) -> LatticeServiceSnapshot:
        if isinstance(service, LatticeServiceSnapshot):
            return service
        return await self._resolve_ref(service)

    def _ttl_for_snapshot(self, snapshot: LatticeServiceSnapshot) -> int:
        value = snapshot.tag_map.get(self.config.stable_tag_key)
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
        next_token: str | None = None
        snapshots: list[LatticeServiceSnapshot] = []

        while True:
            params: dict[str, Any] = {"maxResults": 100}
            if next_token:
                params["nextToken"] = next_token

            response = await self._call_client("list_services", **params)
            for summary in response.get("items", []):
                if not isinstance(summary, dict):
                    continue
                service_id = summary.get("id")
                if not isinstance(service_id, str) or not service_id:
                    continue

                tags = await self._list_tags(summary.get("arn"))
                try:
                    snapshot = self._snapshot_from_api(summary, tags)
                except ValueError:
                    snapshot = await self._resolve_ref(LatticeServiceRef(service_id=service_id))
                snapshots.append(snapshot)

            next_token = response.get("nextToken")
            if not next_token:
                break

        return snapshots

    async def _ensure_name_is_unique(self, agent_name: str, connect_meta: str) -> bool:
        current_states = await self._list_published_states(connect_class="lattice")
        state = current_states.get(f"{agent_name}:{self.protocol.value}")
        return state is None or state.connect_meta == connect_meta

    def _publish_collision_result(self, agent: AgentRecord) -> PublishResult:
        return PublishResult(
            agent=agent,
            records_created=[],
            zone=agent.domain,
            backend=self.backend.name,
            success=False,
            message=f"Agent name collision for {agent.name}; add an explicit name override",
        )

    async def publish(self, service: LatticeServiceRef | LatticeServiceSnapshot | str):
        snapshot = await self._resolve_service(service)
        agent = self._build_agent(snapshot)
        async with self._sync_lock:
            if not await self._ensure_name_is_unique(agent.name, snapshot.service_arn):
                return self._publish_collision_result(agent)
            return await self._publish_agent_record(agent)

    async def unpublish(self, service: LatticeServiceRef | LatticeServiceSnapshot | str) -> bool:
        try:
            snapshot = await self._resolve_service(service)
            return await self._unpublish_agent_name(snapshot.service_name)
        except _LATTICE_RUNTIME_ERRORS:
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
        async with self._sync_lock:
            result = SyncResult()
            current_states = await self._list_published_states(connect_class="lattice")
            desired_snapshots = await self._list_services()

            desired_agents: list[tuple[LatticeServiceSnapshot, AgentRecord]] = []
            collisions: set[str] = set()
            seen_connect_meta: dict[str, str] = {}

            for snapshot in desired_snapshots:
                agent = self._build_agent(snapshot)
                key = f"{agent.name}:{agent.protocol.value}"
                previous_connect_meta = seen_connect_meta.get(key)
                if previous_connect_meta and previous_connect_meta != snapshot.service_arn:
                    collisions.add(key)
                    result.errors.append(
                        f"Agent name collision for {agent.name}; add an explicit name override"
                    )
                    continue
                seen_connect_meta[key] = snapshot.service_arn
                desired_agents.append((snapshot, agent))

            for snapshot, agent in desired_agents:
                key = f"{agent.name}:{agent.protocol.value}"
                if key in collisions:
                    continue

                current = current_states.get(key)
                if current and current.connect_meta not in {snapshot.service_arn, None}:
                    result.errors.append(
                        f"Existing lattice record for {agent.name} belongs to {current.connect_meta}; add an explicit name override"
                    )
                    current_states.pop(key, None)
                    continue

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
        try:
            raw = await asyncio.wait_for(asyncio.to_thread(sys.stdin.read), timeout=5.0)
        except TimeoutError:
            raw = ""
        raw = raw.strip()
        if raw:
            return await publisher.handle_eventbridge_event(json.loads(raw))
    return await run_startup_sync(publisher)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":  # pragma: no cover
    main()
