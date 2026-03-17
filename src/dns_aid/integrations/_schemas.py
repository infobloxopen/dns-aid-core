# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Framework-agnostic Pydantic input schemas for DNS-AID operations.

These schemas match the full parameter set of ``dns_aid.publish()`` and
``dns_aid.discover()`` so that framework integrations expose all features
without needing to bypass the shared layer.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class PublishInput(BaseModel):
    """Input schema for publishing an agent to DNS."""

    name: str = Field(
        ..., description="Agent identifier in DNS label format (e.g. 'my-agent')"
    )
    domain: str = Field(
        ..., description="Domain to publish under (e.g. 'agents.example.com')"
    )
    protocol: str = Field(
        default="mcp", description="Protocol: 'a2a', 'mcp', or 'https'"
    )
    endpoint: str = Field(
        ..., description="Hostname where the agent is reachable"
    )
    port: int = Field(default=443, description="Port number")
    capabilities: Optional[list[str]] = Field(
        default=None, description="List of agent capabilities"
    )
    version: str = Field(default="1.0.0", description="Agent version")
    description: Optional[str] = Field(
        default=None, description="Human-readable description of the agent"
    )
    use_cases: Optional[list[str]] = Field(
        default=None, description="List of use cases for this agent"
    )
    category: Optional[str] = Field(
        default=None, description="Agent category (e.g. 'network', 'security')"
    )
    ttl: int = Field(default=3600, description="DNS time-to-live in seconds")
    cap_uri: Optional[str] = Field(
        default=None,
        description="URI to capability document (DNS-AID draft-compliant)",
    )
    cap_sha256: Optional[str] = Field(
        default=None,
        description="Base64url-encoded SHA-256 digest of the capability descriptor",
    )
    bap: Optional[list[str]] = Field(
        default=None,
        description="Supported bulk agent protocols (e.g. ['mcp', 'a2a'])",
    )
    policy_uri: Optional[str] = Field(
        default=None, description="URI to agent policy document"
    )
    realm: Optional[str] = Field(
        default=None,
        description="Multi-tenant scope identifier (e.g. 'production')",
    )
    connect_class: Optional[str] = Field(
        default=None,
        description="Connection mediation class (e.g. 'direct', 'lattice')",
    )
    connect_meta: Optional[str] = Field(
        default=None,
        description="Provider-specific connection metadata (e.g. service ARN)",
    )
    enroll_uri: Optional[str] = Field(
        default=None,
        description="Managed enrollment endpoint required before direct connection",
    )
    ipv4_hint: Optional[str] = Field(
        default=None,
        description="IPv4 address hint for SVCB record (RFC 9460 key 4)",
    )
    ipv6_hint: Optional[str] = Field(
        default=None,
        description="IPv6 address hint for SVCB record (RFC 9460 key 6)",
    )


class DiscoverInput(BaseModel):
    """Input schema for discovering agents via DNS."""

    domain: str = Field(
        ..., description="Domain to search for agents (e.g. 'agents.example.com')"
    )
    protocol: Optional[str] = Field(
        default=None,
        description="Filter by protocol: 'a2a', 'mcp', 'https', or None for all",
    )
    name: Optional[str] = Field(
        default=None, description="Filter by specific agent name"
    )
    require_dnssec: bool = Field(
        default=False, description="Require DNSSEC-validated responses"
    )


class UnpublishInput(BaseModel):
    """Input schema for removing an agent from DNS."""

    name: str = Field(..., description="Agent identifier to remove")
    domain: str = Field(..., description="Domain the agent is published under")
    protocol: str = Field(
        default="mcp", description="Protocol: 'a2a', 'mcp', or 'https'"
    )
