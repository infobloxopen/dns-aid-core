# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
SvcParam Schema Registry — canonical mapping between ecosystem fields and DNS-AID SvcParams.

Provides a declarative registry that maps fields from LangServe, LangSmith, and A2A
agent cards to DNS-AID SVCB SvcParamKey values, enabling consistent record construction
across all integration points.

Usage:
    >>> from dns_aid.core.schema_registry import REGISTRY, from_langserve_route
    >>>
    >>> # Convert LangServe route config to SvcParam dict
    >>> params = from_langserve_route(
    ...     path="/my-agent",
    ...     protocol="a2a",
    ...     endpoint="api.example.com",
    ...     capabilities=["search", "summarize"],
    ... )
    >>>
    >>> # Look up a specific mapping
    >>> entry = REGISTRY.lookup("cap_uri")
    >>> print(entry.svcparam_key)
    'key65400'
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from dns_aid.core.models import DNS_AID_KEY_MAP, Protocol, _svcb_param_key


@dataclass(frozen=True)
class SvcParamEntry:
    """A single field-to-SvcParam mapping entry.

    Attributes:
        field_name: Logical field name used in dns-aid-core (e.g. 'cap_uri').
        svcparam_key: Wire-format key (e.g. 'key65400' or 'cap').
        svcparam_name: Human-readable SvcParam name from the IETF draft (e.g. 'cap').
        description: What this parameter represents.
        sources: Which ecosystem systems populate this field.
        serializer: Optional callable to convert a value to wire format string.
    """

    field_name: str
    svcparam_key: str
    svcparam_name: str
    description: str
    sources: list[str] = field(default_factory=list)
    serializer: Callable[[Any], str] | None = None


def _list_serializer(value: list[str] | str) -> str:
    """Serialize a list to comma-separated string."""
    if isinstance(value, list):
        return ",".join(value)
    return str(value)


def _identity_serializer(value: Any) -> str:
    return str(value)


class SchemaRegistry:
    """Registry of field-to-SvcParam mappings.

    The registry is populated at module load with all DNS-AID SvcParamKeys
    and their ecosystem source mappings.
    """

    def __init__(self) -> None:
        self._entries: dict[str, SvcParamEntry] = {}
        self._by_svcparam: dict[str, SvcParamEntry] = {}

    def register(self, entry: SvcParamEntry) -> None:
        """Add or replace a mapping entry."""
        self._entries[entry.field_name] = entry
        self._by_svcparam[entry.svcparam_name] = entry

    def lookup(self, field_name: str) -> SvcParamEntry | None:
        """Look up a mapping by logical field name."""
        return self._entries.get(field_name)

    def lookup_by_svcparam(self, svcparam_name: str) -> SvcParamEntry | None:
        """Look up a mapping by SvcParam name (e.g. 'cap', 'bap')."""
        return self._by_svcparam.get(svcparam_name)

    def all_entries(self) -> list[SvcParamEntry]:
        """Return all registered entries."""
        return list(self._entries.values())

    def field_names(self) -> list[str]:
        """Return all registered field names."""
        return list(self._entries.keys())


# ─── Global registry instance ───────────────────────────────────────────

REGISTRY = SchemaRegistry()

# Standard SVCB params
REGISTRY.register(SvcParamEntry(
    field_name="alpn",
    svcparam_key="alpn",
    svcparam_name="alpn",
    description="Application-Layer Protocol Negotiation identifier",
    sources=["langserve:protocol", "langgraph:protocol", "a2a:url"],
))
REGISTRY.register(SvcParamEntry(
    field_name="port",
    svcparam_key="port",
    svcparam_name="port",
    description="Port number for the service endpoint",
    sources=["langserve:port", "langgraph:port"],
    serializer=lambda v: str(v),
))

# DNS-AID custom SvcParams (IETF draft-01 Section 4.4.3)
REGISTRY.register(SvcParamEntry(
    field_name="cap_uri",
    svcparam_key=_svcb_param_key("cap"),
    svcparam_name="cap",
    description="URI to capability descriptor document",
    sources=["langserve:cap_uri", "a2a:url+/.well-known/agent-card.json", "langsmith:project.metadata.cap_uri"],
))
REGISTRY.register(SvcParamEntry(
    field_name="cap_sha256",
    svcparam_key=_svcb_param_key("cap-sha256"),
    svcparam_name="cap-sha256",
    description="SHA-256 digest of the capability descriptor for integrity",
    sources=["langserve:cap_sha256"],
))
REGISTRY.register(SvcParamEntry(
    field_name="bap",
    svcparam_key=_svcb_param_key("bap"),
    svcparam_name="bap",
    description="Bulk application protocols with versions (e.g. a2a/1, mcp/1)",
    sources=["langserve:protocol(auto)", "langgraph:protocol(auto)", "a2a:defaultInputModes"],
    serializer=_list_serializer,
))
REGISTRY.register(SvcParamEntry(
    field_name="policy_uri",
    svcparam_key=_svcb_param_key("policy"),
    svcparam_name="policy",
    description="URI to agent policy document (jurisdiction, data handling)",
    sources=["langserve:policy_uri", "langsmith:project.metadata.policy_uri"],
))
REGISTRY.register(SvcParamEntry(
    field_name="realm",
    svcparam_key=_svcb_param_key("realm"),
    svcparam_name="realm",
    description="Multi-tenant scope or authz realm identifier",
    sources=["langserve:realm", "langsmith:project.metadata.realm"],
))
REGISTRY.register(SvcParamEntry(
    field_name="sig",
    svcparam_key=_svcb_param_key("sig"),
    svcparam_name="sig",
    description="JWS compact signature for record verification",
    sources=["dns-aid-core:jwks.sign_record"],
))
REGISTRY.register(SvcParamEntry(
    field_name="connect_class",
    svcparam_key=_svcb_param_key("connect-class"),
    svcparam_name="connect-class",
    description="Connection mediation mode (direct, lattice, apphub-psc)",
    sources=["langserve:connect_class"],
))
REGISTRY.register(SvcParamEntry(
    field_name="connect_meta",
    svcparam_key=_svcb_param_key("connect-meta"),
    svcparam_name="connect-meta",
    description="Provider-specific connection metadata (e.g. service ARN)",
    sources=["langserve:connect_meta"],
))
REGISTRY.register(SvcParamEntry(
    field_name="enroll_uri",
    svcparam_key=_svcb_param_key("enroll-uri"),
    svcparam_name="enroll-uri",
    description="Managed enrollment endpoint for overlay access",
    sources=["langserve:enroll_uri"],
))


# ─── Adapter functions ──────────────────────────────────────────────────


def from_langserve_route(
    *,
    path: str,
    protocol: str,
    endpoint: str,
    port: int = 443,
    capabilities: list[str] | None = None,
    version: str = "1.0.0",
    cap_uri: str | None = None,
    policy_uri: str | None = None,
    realm: str | None = None,
) -> dict[str, Any]:
    """Convert LangServe route configuration to DNS-AID publish kwargs.

    Returns a dict suitable for passing to ``dns_aid.publish(**result)``.
    """
    name = path.strip("/").replace("/", "-").replace("_", "-").lower() or "default"
    proto = Protocol(protocol.lower())

    result: dict[str, Any] = {
        "name": name,
        "protocol": proto,
        "endpoint": endpoint,
        "port": port,
        "capabilities": capabilities,
        "version": version,
        "cap_uri": cap_uri,
        "policy_uri": policy_uri,
        "realm": realm,
    }
    return {k: v for k, v in result.items() if v is not None}


def from_a2a_agent_card(card: Any, *, endpoint: str, port: int = 443) -> dict[str, Any]:
    """Convert an A2A Agent Card to DNS-AID publish kwargs.

    Args:
        card: An A2AAgentCard instance.
        endpoint: Hostname where the agent is reachable.
        port: Port number.

    Returns:
        Dict suitable for ``dns_aid.publish(**result)``.
    """
    capabilities = []
    if hasattr(card, "to_capabilities"):
        capabilities = card.to_capabilities()
    elif hasattr(card, "skills"):
        capabilities = [s.id for s in card.skills if hasattr(s, "id")]

    name = getattr(card, "name", "agent").lower().replace(" ", "-")
    # Sanitize to DNS label format
    name = "".join(c if c.isalnum() or c == "-" else "-" for c in name).strip("-")[:63]

    return {
        "name": name,
        "protocol": Protocol.A2A,
        "endpoint": endpoint,
        "port": port,
        "capabilities": capabilities,
        "version": getattr(card, "version", "1.0.0"),
        "description": getattr(card, "description", None),
    }


def from_langsmith_project(
    project: dict[str, Any],
    *,
    domain: str,
    endpoint: str,
    protocol: str = "https",
    port: int = 443,
) -> dict[str, Any]:
    """Convert LangSmith project metadata to DNS-AID publish kwargs.

    Expects a project dict with at minimum a 'name' field, and optionally
    'metadata' containing DNS-AID field overrides.

    Args:
        project: LangSmith project dict (from webhook payload or SDK).
        domain: DNS domain to publish under.
        endpoint: Hostname where the agent is reachable.
        protocol: Default protocol.
        port: Port number.

    Returns:
        Dict suitable for ``dns_aid.publish(**result)``.
    """
    metadata = project.get("metadata", {}) or {}

    name = project.get("name", "agent").lower().replace(" ", "-").replace("_", "-")
    name = "".join(c if c.isalnum() or c == "-" else "-" for c in name).strip("-")[:63]

    result: dict[str, Any] = {
        "name": name,
        "domain": domain,
        "protocol": metadata.get("protocol", protocol),
        "endpoint": metadata.get("endpoint", endpoint),
        "port": metadata.get("port", port),
        "capabilities": metadata.get("capabilities"),
        "version": metadata.get("version", "1.0.0"),
        "description": project.get("description"),
        "cap_uri": metadata.get("cap_uri"),
        "policy_uri": metadata.get("policy_uri"),
        "realm": metadata.get("realm"),
    }
    return {k: v for k, v in result.items() if v is not None}
