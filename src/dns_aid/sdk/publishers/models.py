# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared models for provider-managed agent record publishers."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SyncResult(BaseModel):
    """Outcome summary for a reconciliation cycle."""

    published: int = 0
    updated: int = 0
    unpublished: int = 0
    unchanged: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors


class PublishedAgentState(BaseModel):
    """Parsed view of an already-published agent record."""

    model_config = ConfigDict(frozen=True)

    name: str
    protocol: str
    target_host: str
    ttl: int
    capabilities: list[str] = Field(default_factory=list)
    connect_class: str | None = None
    connect_meta: str | None = None
    enroll_uri: str | None = None


class AppHubPublisherConfig(BaseModel):
    """Configuration for AppHub-backed publishing."""

    project_id: str
    location: str
    domain: str
    protocol: str = "mcp"
    managed_zone: str | None = None
    capabilities_metadata_key: str = "apphub.googleapis.com/agentProperties"
    capabilities_metadata_path: str = "a2a.capabilities"
    service_name_metadata_key: str = "apphub.googleapis.com/agentProperties"
    service_name_metadata_path: str = "serviceName"
    connect_meta_metadata_key: str = "apphub.googleapis.com/agentConnect"
    connect_meta_metadata_path: str = "serviceName"
    enrollment_metadata_key: str = "apphub.googleapis.com/agentConnect"
    enrollment_metadata_path: str = "pscBaseUrl"
    poll_interval_seconds: int = 300
    name_overrides: dict[str, str] = Field(default_factory=dict)


class AppHubServiceRef(BaseModel):
    """Reference used to resolve an AppHub discovered service."""

    name: str | None = None
    uri: str | None = None


class AppHubServiceSnapshot(BaseModel):
    """Resolved AppHub service data used by the publisher."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    discovered_service_name: str
    agent_name: str
    service_uri: str | None = None
    canonical_service_name: str | None = None
    functional_type: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    enrollment_base_url: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def connect_meta(self) -> str:
        return self.canonical_service_name or self.discovered_service_name

    @property
    def target_host(self) -> str:
        candidate = self.enrollment_base_url or self.service_uri or ""
        parsed = urlparse(candidate)
        if parsed.hostname:
            return parsed.hostname.rstrip(".")
        return candidate.rstrip(".")


class LatticePublisherConfig(BaseModel):
    """Configuration for VPC Lattice-backed publishing."""

    domain: str
    protocol: str = "mcp"
    stable_tag_key: str = "stable"
    stable_tag_values: list[str] = Field(default_factory=lambda: ["1", "true", "yes", "stable"])
    dynamic_ttl: int = 30
    stable_ttl: int = 300
    name_overrides: dict[str, str] = Field(default_factory=dict)


class LatticeServiceRef(BaseModel):
    """Reference used to resolve a VPC Lattice service."""

    service_id: str | None = None
    service_arn: str | None = None
    service_name: str | None = None


class LatticeServiceSnapshot(BaseModel):
    """Resolved VPC Lattice service data used by the publisher."""

    model_config = ConfigDict(frozen=True)

    service_id: str
    service_name: str
    service_arn: str
    dns_name: str
    tags: tuple[tuple[str, str], ...] = Field(default_factory=tuple)
    status: str | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value: Any) -> tuple[tuple[str, str], ...]:
        if value is None:
            return ()
        if isinstance(value, dict):
            return tuple(sorted((str(key), str(item)) for key, item in value.items()))
        if isinstance(value, (list, tuple)):
            normalized: list[tuple[str, str]] = []
            for entry in value:
                if (
                    isinstance(entry, (list, tuple))
                    and len(entry) == 2
                ):
                    normalized.append((str(entry[0]), str(entry[1])))
            return tuple(sorted(normalized))
        raise TypeError("tags must be a dict or sequence of key/value pairs")

    @property
    def target_host(self) -> str:
        return self.dns_name.rstrip(".")

    @property
    def tag_map(self) -> dict[str, str]:
        return dict(self.tags)
