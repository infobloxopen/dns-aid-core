# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Google Cloud DNS backend."""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import structlog

from dns_aid.backends.base import DNSBackend
from dns_aid.utils.google_auth import get_google_access_token

logger = structlog.get_logger(__name__)

# Standard SVCB SvcParamKeys that Cloud DNS accepts (RFC 9460).
# Cloud DNS rejects private-use keys (key65280–key65534) with
# "Invalid value for rrdata".
# When publishing, custom DNS-AID params are automatically demoted
# to TXT records so the publish succeeds.
_CLOUD_DNS_SVCB_KEYS = frozenset(
    {
        "mandatory",
        "alpn",
        "no-default-alpn",
        "port",
        "ipv4hint",
        "ipv6hint",
        "ech",
    }
)

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class CloudDNSBackend(DNSBackend):
    """Google Cloud DNS backend using the Cloud DNS REST API."""

    def __init__(
        self,
        project_id: str | None = None,
        managed_zone: str | None = None,
        token_provider: Callable[[], tuple[str, str | None]] | None = None,
        base_url: str = "https://dns.googleapis.com/dns/v1",
    ):
        self._project_id = (
            project_id
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT")
            or os.environ.get("CLOUD_DNS_PROJECT")
        )
        self._managed_zone = managed_zone or os.environ.get("CLOUD_DNS_MANAGED_ZONE")
        self._token_provider = token_provider or (lambda: get_google_access_token(_SCOPES))
        self._base_url = base_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None
        self._zone_cache: dict[str, str] = {}

    @property
    def name(self) -> str:
        return "cloud-dns"

    async def _get_client(self) -> httpx.AsyncClient:
        current_loop_id = id(asyncio.get_running_loop())

        if self._client is not None and self._client_loop_id != current_loop_id:
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None

        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self._base_url, timeout=30.0)
            self._client_loop_id = current_loop_id

        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
        self._client_loop_id = None

    def _resolve_project_id(self, discovered_project: str | None = None) -> str:
        project_id = self._project_id or discovered_project
        if not project_id:
            raise ValueError(
                "Google Cloud project id not configured. Set GOOGLE_CLOUD_PROJECT, "
                "CLOUD_DNS_PROJECT, or pass project_id explicitly."
            )
        self._project_id = project_id
        return project_id

    def _ensure_project_id(self) -> str:
        if self._project_id:
            return self._project_id
        _, discovered_project = self._token_provider()
        return self._resolve_project_id(discovered_project)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        client = await self._get_client()
        token, discovered_project = self._token_provider()
        self._resolve_project_id(discovered_project)

        response = await client.request(
            method=method,
            url=path,
            params=params,
            json=json,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    async def _get_managed_zone_name(self, zone: str) -> str:
        zone_name = zone.rstrip(".")
        if self._managed_zone:
            return self._managed_zone
        if zone_name in self._zone_cache:
            return self._zone_cache[zone_name]

        zones = await self.list_zones()
        for candidate in zones:
            if candidate["dns_name"].rstrip(".") == zone_name:
                self._zone_cache[zone_name] = candidate["name"]
                return candidate["name"]
        raise ValueError(f"No Cloud DNS managed zone found for domain: {zone}")

    @staticmethod
    def _record_name(name: str, zone: str) -> str:
        fqdn = f"{name}.{zone}".rstrip(".")
        return f"{fqdn}."

    @staticmethod
    def _format_svcb_value(priority: int, target: str, params: dict[str, str]) -> str:
        normalized_target = target if target.endswith(".") else f"{target}."
        parts = [f'{key}="{value}"' for key, value in params.items()]
        joined = " ".join(parts)
        return f"{priority} {normalized_target} {joined}".strip()

    async def _change_record_set(
        self,
        zone: str,
        name: str,
        record_type: str,
        ttl: int,
        rrdatas: list[str],
    ) -> str:
        project_id = self._ensure_project_id()
        managed_zone = await self._get_managed_zone_name(zone)
        fqdn = self._record_name(name, zone)
        existing = await self.get_record(zone, name, record_type)

        additions = [{"name": fqdn, "type": record_type, "ttl": ttl, "rrdatas": rrdatas}]
        payload: dict[str, Any] = {"additions": additions}
        if existing:
            payload["deletions"] = [
                {
                    "name": f"{existing['fqdn'].rstrip('.')}.",
                    "type": record_type,
                    "ttl": existing["ttl"],
                    "rrdatas": existing["values"],
                }
            ]

        await self._request(
            "POST",
            f"/projects/{project_id}/managedZones/{managed_zone}/changes",
            json=payload,
        )
        return fqdn.rstrip(".")

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        value = self._format_svcb_value(priority, target, params)
        return await self._change_record_set(zone, name, "SVCB", ttl, [value])

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        quoted_values = [value if value.startswith('"') else f'"{value}"' for value in values]
        return await self._change_record_set(zone, name, "TXT", ttl, quoted_values)

    async def delete_record(self, zone: str, name: str, record_type: str) -> bool:
        project_id = self._ensure_project_id()
        managed_zone = await self._get_managed_zone_name(zone)
        existing = await self.get_record(zone, name, record_type)
        if not existing:
            return False

        await self._request(
            "POST",
            f"/projects/{project_id}/managedZones/{managed_zone}/changes",
            json={
                "deletions": [
                    {
                        "name": f"{existing['fqdn'].rstrip('.')}.",
                        "type": record_type,
                        "ttl": existing["ttl"],
                        "rrdatas": existing["values"],
                    }
                ]
            },
        )
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        project_id = self._ensure_project_id()
        managed_zone = await self._get_managed_zone_name(zone)
        page_token: str | None = None
        zone_clean = zone.rstrip(".")

        while True:
            params = {"maxResults": "1000"}
            if page_token:
                params["pageToken"] = page_token

            response = await self._request(
                "GET",
                f"/projects/{project_id}/managedZones/{managed_zone}/rrsets",
                params=params,
            )

            for record in response.get("rrsets", []):
                fqdn = str(record.get("name", "")).rstrip(".")
                rtype = record.get("type", "")
                if not fqdn or not rtype:
                    continue
                if name_pattern and name_pattern not in fqdn:
                    continue
                if record_type and rtype != record_type:
                    continue

                yield {
                    "name": fqdn.removesuffix(f".{zone_clean}"),
                    "fqdn": fqdn,
                    "type": rtype,
                    "ttl": int(record.get("ttl", 0)),
                    "values": list(record.get("rrdatas", [])),
                }

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    async def zone_exists(self, zone: str) -> bool:
        try:
            await self._get_managed_zone_name(zone)
            return True
        except Exception:
            return False

    async def get_record(self, zone: str, name: str, record_type: str) -> dict[str, Any] | None:
        project_id = self._ensure_project_id()
        managed_zone = await self._get_managed_zone_name(zone)
        fqdn = self._record_name(name, zone)

        response = await self._request(
            "GET",
            f"/projects/{project_id}/managedZones/{managed_zone}/rrsets",
            params={"name": fqdn, "type": record_type, "maxResults": "1"},
        )

        rrsets = response.get("rrsets", [])
        if not rrsets:
            return None

        record = rrsets[0]
        if record.get("name") != fqdn or record.get("type") != record_type:
            return None

        return {
            "name": name,
            "fqdn": fqdn.rstrip("."),
            "type": record_type,
            "ttl": int(record.get("ttl", 0)),
            "values": list(record.get("rrdatas", [])),
        }

    # publish_agent() inherited from DNSBackend base class — automatically
    # demotes private-use SVCB keys to TXT since Cloud DNS rejects them.

    async def list_zones(self) -> list[dict[str, str]]:
        project_id = self._ensure_project_id()
        page_token: str | None = None
        zones: list[dict[str, str]] = []

        while True:
            params = {"maxResults": "1000"}
            if page_token:
                params["pageToken"] = page_token

            response = await self._request(
                "GET", f"/projects/{project_id}/managedZones", params=params
            )
            for zone in response.get("managedZones", []):
                zones.append(
                    {
                        "name": zone["name"],
                        "dns_name": str(zone.get("dnsName", "")).rstrip("."),
                        "visibility": str(zone.get("visibility", "")),
                    }
                )

            page_token = response.get("nextPageToken")
            if not page_token:
                break

        return zones
