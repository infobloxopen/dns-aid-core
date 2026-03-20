# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""GCP AppHub-backed DNS-AID record publisher."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import os
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from dns_aid.backends.base import DNSBackend
from dns_aid.backends.cloud_dns import CloudDNSBackend
from dns_aid.core.models import AgentRecord, PublishResult
from dns_aid.sdk.publishers._helpers import (
    coerce_capabilities,
    get_nested_value,
    normalize_agent_name,
)
from dns_aid.sdk.publishers.base import BaseAgentRecordPublisher
from dns_aid.sdk.publishers.models import (
    AppHubPublisherConfig,
    AppHubServiceRef,
    AppHubServiceSnapshot,
    PublishedAgentState,
    SyncResult,
)
from dns_aid.utils.google_auth import GoogleAccessTokenProvider

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_APPHUB_RUNTIME_ERRORS = (ValueError, RuntimeError, httpx.HTTPError)


class AppHubPublisher(BaseAgentRecordPublisher[AppHubServiceRef | AppHubServiceSnapshot | str]):
    """Publisher that reconciles AppHub discovered services into Cloud DNS."""

    def __init__(
        self,
        config: AppHubPublisherConfig,
        *,
        backend: DNSBackend | None = None,
        token_provider: Callable[[], tuple[str, str | None] | Any] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        default_provider = GoogleAccessTokenProvider(_SCOPES)
        self._token_provider = token_provider or default_provider.get_token
        self._http_client = http_client
        self._client_loop_id: int | None = None
        self._sync_lock = asyncio.Lock()

        dns_backend = backend or CloudDNSBackend(
            project_id=config.project_id,
            managed_zone=config.managed_zone,
            token_provider=self._token_provider,
        )
        super().__init__(dns_backend, config.domain, config.protocol)

    @classmethod
    def from_env(cls, *, backend: DNSBackend | None = None) -> AppHubPublisher:
        raw_name_overrides = os.environ.get("APPHUB_NAME_OVERRIDES_JSON", "{}")
        return cls(
            AppHubPublisherConfig(
                project_id=os.environ["GOOGLE_CLOUD_PROJECT"],
                location=os.environ["APPHUB_LOCATION"],
                domain=os.environ["APPHUB_DOMAIN"],
                protocol=os.environ.get("APPHUB_PROTOCOL", "mcp"),
                managed_zone=os.environ.get("CLOUD_DNS_MANAGED_ZONE"),
                capabilities_metadata_key=os.environ.get(
                    "APPHUB_CAPABILITIES_METADATA_KEY",
                    "apphub.googleapis.com/agentProperties",
                ),
                capabilities_metadata_path=os.environ.get(
                    "APPHUB_CAPABILITIES_METADATA_PATH",
                    "a2a.capabilities",
                ),
                service_name_metadata_key=os.environ.get(
                    "APPHUB_SERVICE_NAME_METADATA_KEY",
                    "apphub.googleapis.com/agentProperties",
                ),
                service_name_metadata_path=os.environ.get(
                    "APPHUB_SERVICE_NAME_METADATA_PATH",
                    "serviceName",
                ),
                connect_meta_metadata_key=os.environ.get(
                    "APPHUB_CONNECT_META_METADATA_KEY",
                    "apphub.googleapis.com/agentConnect",
                ),
                connect_meta_metadata_path=os.environ.get(
                    "APPHUB_CONNECT_META_METADATA_PATH",
                    "serviceName",
                ),
                enrollment_metadata_key=os.environ.get(
                    "APPHUB_ENROLLMENT_METADATA_KEY",
                    "apphub.googleapis.com/agentConnect",
                ),
                enrollment_metadata_path=os.environ.get(
                    "APPHUB_ENROLLMENT_METADATA_PATH",
                    "pscBaseUrl",
                ),
                poll_interval_seconds=int(os.environ.get("APPHUB_POLL_INTERVAL_SECONDS", "300")),
                name_overrides=(
                    json.loads(raw_name_overrides)
                    if raw_name_overrides.strip()
                    else {}
                ),
            ),
            backend=backend,
        )

    async def _get_http_client(self) -> httpx.AsyncClient:
        current_loop_id = id(asyncio.get_running_loop())

        if self._http_client is not None and self._client_loop_id not in (None, current_loop_id):
            with contextlib.suppress(Exception):
                await self._http_client.aclose()
            self._http_client = None
            self._client_loop_id = None

        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url="https://apphub.googleapis.com",
                timeout=30.0,
                follow_redirects=False,
            )
            self._client_loop_id = current_loop_id

        return self._http_client

    async def close(self) -> None:
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
        self._http_client = None
        self._client_loop_id = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        client = await self._get_http_client()
        last_error: httpx.HTTPError | None = None

        for attempt in range(3):
            try:
                result = self._token_provider()
                if inspect.isawaitable(result):
                    token, _ = await result
                else:
                    token, _ = result
                response = await client.request(
                    method=method,
                    url=path,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 2 or not self._is_retryable_http_error(exc):
                    raise
                await asyncio.sleep(0.5 * (2**attempt))

        if last_error is not None:  # pragma: no cover - defensive fallback
            raise last_error
        return {}

    @staticmethod
    def _is_retryable_http_error(exc: httpx.HTTPError) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in _RETRYABLE_STATUS_CODES
        return isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError))

    @staticmethod
    def _unwrap_extended_metadata_entry(entry: Any) -> Any:
        if isinstance(entry, dict):
            for key in ("metadata", "details", "value", "json", "data"):
                if key in entry:
                    return entry[key]
        return entry

    def _extract_extended_metadata_value(
        self,
        extended_metadata: dict[str, Any],
        metadata_key: str,
        path: str,
    ) -> Any | None:
        entry = self._unwrap_extended_metadata_entry(extended_metadata.get(metadata_key))
        return get_nested_value(entry, path)

    def _derive_enrollment_base_url(
        self,
        service_uri: str | None,
        extended_metadata: dict[str, Any],
    ) -> str | None:
        configured = self._extract_extended_metadata_value(
            extended_metadata,
            self.config.enrollment_metadata_key,
            self.config.enrollment_metadata_path,
        )
        if isinstance(configured, str) and configured.strip():
            return configured.rstrip("/")

        if service_uri:
            parsed = urlparse(service_uri)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        return None

    def _configured_name_override(self, *identifiers: str | None) -> str | None:
        for identifier in identifiers:
            if not identifier:
                continue
            override = self.config.name_overrides.get(identifier)
            if override:
                return normalize_agent_name(override)
        return None

    def _derive_agent_name(
        self,
        discovered_service_name: str,
        service_uri: str | None,
        canonical_service_name: str | None,
        extended_metadata: dict[str, Any],
    ) -> str:
        override = self._configured_name_override(
            canonical_service_name,
            discovered_service_name,
            service_uri,
        )
        if override:
            return override

        configured = self._extract_extended_metadata_value(
            extended_metadata,
            self.config.service_name_metadata_key,
            self.config.service_name_metadata_path,
        )
        candidates = [
            configured,
            canonical_service_name,
            service_uri,
            discovered_service_name,
        ]
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            value = candidate.rstrip("/").split("/")[-1]
            try:
                return normalize_agent_name(value)
            except ValueError:
                continue
        return normalize_agent_name(discovered_service_name.split("/")[-1])

    def _snapshot_from_api(self, data: dict[str, Any]) -> AppHubServiceSnapshot:
        raw_name = data.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("AppHub discovered service response is missing a name")

        discovered_service_name = raw_name
        service_uri = get_nested_value(data, "serviceReference.uri")
        properties = (
            data.get("serviceProperties", {})
            if isinstance(data.get("serviceProperties"), dict)
            else {}
        )
        extended_metadata = (
            properties.get("extendedMetadata", {})
            if isinstance(properties.get("extendedMetadata"), dict)
            else {}
        )
        functional_type = get_nested_value(properties, "functionalType.type")
        canonical_service_name = self._extract_extended_metadata_value(
            extended_metadata,
            self.config.connect_meta_metadata_key,
            self.config.connect_meta_metadata_path,
        )
        enrollment_base_url = self._derive_enrollment_base_url(service_uri, extended_metadata)
        capabilities = coerce_capabilities(
            self._extract_extended_metadata_value(
                extended_metadata,
                self.config.capabilities_metadata_key,
                self.config.capabilities_metadata_path,
            )
        )
        agent_name = self._derive_agent_name(
            discovered_service_name,
            service_uri,
            canonical_service_name if isinstance(canonical_service_name, str) else None,
            extended_metadata,
        )

        return AppHubServiceSnapshot(
            discovered_service_name=discovered_service_name,
            agent_name=agent_name,
            service_uri=service_uri if isinstance(service_uri, str) else None,
            canonical_service_name=(
                canonical_service_name if isinstance(canonical_service_name, str) else None
            ),
            functional_type=functional_type if isinstance(functional_type, str) else None,
            capabilities=capabilities,
            enrollment_base_url=enrollment_base_url,
            metadata=extended_metadata,
        )

    async def _resolve_ref(self, service: AppHubServiceRef | str) -> AppHubServiceSnapshot:
        ref = service if isinstance(service, AppHubServiceRef) else AppHubServiceRef(name=service)

        if ref.uri:
            response = await self._request(
                "GET",
                f"/v1/projects/{self.config.project_id}/locations/{self.config.location}/discoveredServices:lookup",
                params={"uri": ref.uri},
            )
            if response:
                return self._snapshot_from_api(response)

        if ref.name:
            name = ref.name.lstrip("/")
            if not name.startswith("projects/"):
                name = (
                    f"projects/{self.config.project_id}/locations/{self.config.location}/"
                    f"discoveredServices/{name}"
                )
            response = await self._request("GET", f"/v1/{name}")
            return self._snapshot_from_api(response)

        raise ValueError("AppHub service reference must include either name or uri")

    async def _resolve_service(
        self,
        service: AppHubServiceRef | AppHubServiceSnapshot | str,
    ) -> AppHubServiceSnapshot:
        if isinstance(service, AppHubServiceSnapshot):
            return service
        return await self._resolve_ref(service)

    async def _list_discovered_services(self) -> list[AppHubServiceSnapshot]:
        snapshots: list[AppHubServiceSnapshot] = []
        page_token: str | None = None

        while True:
            params = {"pageSize": "100"}
            if page_token:
                params["pageToken"] = page_token

            response = await self._request(
                "GET",
                f"/v1/projects/{self.config.project_id}/locations/{self.config.location}/discoveredServices",
                params=params,
            )
            snapshots.extend(
                self._snapshot_from_api(item)
                for item in response.get("discoveredServices", [])
            )
            page_token = response.get("nextPageToken")
            if not page_token:
                break

        return snapshots

    def _build_agent(self, snapshot: AppHubServiceSnapshot, *, strict: bool = True) -> AgentRecord:
        target_host = snapshot.target_host or f"{snapshot.agent_name}.{self.domain}"
        if strict and not snapshot.target_host:
            raise ValueError(
                f"AppHub service '{snapshot.discovered_service_name}' is missing an addressable endpoint"
            )
        if strict and not snapshot.enrollment_base_url:
            raise ValueError(
                f"AppHub service '{snapshot.discovered_service_name}' is missing an enrollment base URL"
            )

        return AgentRecord(
            name=snapshot.agent_name,
            domain=self.domain,
            protocol=self.protocol,
            target_host=target_host,
            capabilities=snapshot.capabilities,
            connect_class="apphub-psc",
            connect_meta=snapshot.connect_meta,
            enroll_uri=(
                urljoin(
                    snapshot.enrollment_base_url.rstrip("/") + "/",
                    ".well-known/agent-connect",
                )
                if snapshot.enrollment_base_url
                else None
            ),
        )

    @staticmethod
    def _matches_state(state: PublishedAgentState, agent: AgentRecord) -> bool:
        return (
            state.protocol == agent.protocol.value
            and state.target_host == agent.target_host
            and state.ttl == agent.ttl
            and sorted(state.capabilities) == sorted(agent.capabilities)
            and state.connect_class == agent.connect_class
            and state.connect_meta == agent.connect_meta
            and state.enroll_uri == agent.enroll_uri
        )

    async def publish(self, service: AppHubServiceRef | AppHubServiceSnapshot | str):
        snapshot = await self._resolve_service(service)
        if (snapshot.functional_type or "").upper() != "AGENT":
            agent = self._build_agent(snapshot, strict=False)
            return PublishResult(
                agent=agent,
                records_created=[],
                zone=agent.domain,
                backend=self.backend.name,
                success=False,
                message="AppHub service is not eligible for AGENT publishing",
            )
        try:
            agent = self._build_agent(snapshot)
        except _APPHUB_RUNTIME_ERRORS as exc:
            fallback_agent = self._build_agent(snapshot, strict=False)
            return PublishResult(
                agent=fallback_agent,
                records_created=[],
                zone=fallback_agent.domain,
                backend=self.backend.name,
                success=False,
                message=str(exc),
            )
        async with self._sync_lock:
            if not await self._ensure_name_is_unique(agent.name, snapshot.connect_meta):
                return PublishResult(
                    agent=agent,
                    records_created=[],
                    zone=agent.domain,
                    backend=self.backend.name,
                    success=False,
                    message=f"Agent name collision for {agent.name}; add an explicit name override",
                )
            return await self._publish_agent_record(agent)

    async def unpublish(self, service: AppHubServiceRef | AppHubServiceSnapshot | str) -> bool:
        try:
            snapshot = await self._resolve_service(service)
            return await self._unpublish_agent_name(snapshot.agent_name)
        except _APPHUB_RUNTIME_ERRORS:
            ref = (
                service
                if isinstance(service, AppHubServiceRef)
                else AppHubServiceRef(name=str(service))
            )
            current_states = await self._list_published_states(connect_class="apphub-psc")
            for state in current_states.values():
                if state.connect_meta in {ref.name, ref.uri}:
                    return await self._unpublish_agent_name(state.name)
            return False

    async def _ensure_name_is_unique(self, agent_name: str, connect_meta: str) -> bool:
        current_states = await self._list_published_states(connect_class="apphub-psc")
        state = current_states.get(f"{agent_name}:{self.protocol.value}")
        return state is None or state.connect_meta == connect_meta

    async def sync(self) -> SyncResult:
        async with self._sync_lock:
            result = SyncResult()
            current_states = await self._list_published_states(connect_class="apphub-psc")
            desired_snapshots = await self._list_discovered_services()

            desired_agents: list[tuple[AppHubServiceSnapshot, AgentRecord]] = []
            collisions: set[str] = set()
            seen_connect_meta: dict[str, str] = {}

            for snapshot in desired_snapshots:
                if (snapshot.functional_type or "").upper() != "AGENT":
                    continue

                try:
                    agent = self._build_agent(snapshot)
                except _APPHUB_RUNTIME_ERRORS as exc:
                    result.errors.append(str(exc))
                    continue

                key = f"{agent.name}:{agent.protocol.value}"
                previous_connect_meta = seen_connect_meta.get(key)
                if previous_connect_meta and previous_connect_meta != snapshot.connect_meta:
                    collisions.add(key)
                    result.errors.append(
                        f"Agent name collision for {agent.name}; add an explicit name override"
                    )
                    continue

                seen_connect_meta[key] = snapshot.connect_meta
                desired_agents.append((snapshot, agent))

            for snapshot, agent in desired_agents:
                key = f"{agent.name}:{agent.protocol.value}"
                if key in collisions:
                    continue

                current = current_states.get(key)
                if current and current.connect_meta not in {snapshot.connect_meta, None}:
                    result.errors.append(
                        f"Existing AppHub record for {agent.name} belongs to {current.connect_meta}; add an explicit name override"
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
                    result.errors.append(f"Failed to unpublish stale AppHub record {stale.name}")

            return result


async def run_polling_sync(publisher: AppHubPublisher, *, once: bool = False) -> SyncResult:
    """Run one or more AppHub reconciliation cycles."""
    last_result = SyncResult()
    while True:
        last_result = await publisher.sync()
        if once:
            return last_result
        await asyncio.sleep(publisher.config.poll_interval_seconds)


async def main_async() -> SyncResult:
    publisher = AppHubPublisher.from_env()
    try:
        once = os.environ.get("APPHUB_RUN_FOREVER", "").lower() not in {"1", "true", "yes"}
        return await run_polling_sync(publisher, once=once)
    finally:
        await publisher.close()


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":  # pragma: no cover
    main()
