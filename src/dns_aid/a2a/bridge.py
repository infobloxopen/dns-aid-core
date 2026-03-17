# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
A2A discovery bridge.

Connects DNS-AID agent discovery (SVCB + TXT records) with Google's
A2A (Agent-to-Agent) protocol agent card standard. This enables:

1. **DNS → A2A**: Discover A2A agents via DNS and fetch their agent
   cards from ``/.well-known/agent-card.json``.

2. **A2A → DNS**: Publish A2A agent card information as DNS-AID
   records so other agents can discover A2A endpoints via DNS.

3. **Conversion**: Convert between DNS-AID ``AgentRecord`` and A2A
   ``AgentCard`` formats.

A2A Agent Card Spec: https://google.github.io/A2A/specification/

Example:
    >>> from dns_aid.a2a import discover_a2a_agents, fetch_agent_card
    >>>
    >>> # Discover A2A agents via DNS, then fetch their agent cards
    >>> agents = await discover_a2a_agents("agents.example.com")
    >>> for agent in agents:
    ...     card = await fetch_agent_card(agent.endpoint, agent.port)
    ...     print(f"{card.name}: {card.description}")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from dns_aid.core.discoverer import discover
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

logger = logging.getLogger(__name__)

# Well-known path for A2A agent cards per the A2A specification.
A2A_AGENT_CARD_PATH = "/.well-known/agent-card.json"


@dataclass
class AgentCardSkill:
    """An A2A agent card skill (capability).

    Represents a discrete capability that an agent can perform,
    as defined in the A2A agent card specification.

    Attributes:
        id: Unique identifier for the skill.
        name: Human-readable name.
        description: What this skill does.
        tags: Categorization tags.
        examples: Example queries or inputs.
    """

    id: str
    name: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)


@dataclass
class AgentCard:
    """A2A agent card representation.

    Models the agent card JSON structure served at
    ``/.well-known/agent-card.json`` per the A2A specification.

    Attributes:
        name: Agent name.
        description: Human-readable description.
        url: Agent endpoint URL.
        version: Agent version string.
        skills: List of agent capabilities/skills.
        provider: Organization providing the agent.
        documentation_url: Link to documentation.
        capabilities: Raw capabilities dict from the card.
        raw: Full raw agent card JSON dict.
    """

    name: str
    description: str = ""
    url: str = ""
    version: str = ""
    skills: list[AgentCardSkill] = field(default_factory=list)
    provider: str = ""
    documentation_url: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCard:
        """Parse an agent card from its JSON dict representation.

        Args:
            data: Raw agent card JSON dict.

        Returns:
            Parsed AgentCard instance.
        """
        skills = []
        for skill_data in data.get("skills", []):
            skills.append(
                AgentCardSkill(
                    id=skill_data.get("id", ""),
                    name=skill_data.get("name", ""),
                    description=skill_data.get("description", ""),
                    tags=skill_data.get("tags", []),
                    examples=skill_data.get("examples", []),
                )
            )

        provider_data = data.get("provider", {})
        provider_name = ""
        if isinstance(provider_data, dict):
            provider_name = provider_data.get("organization", "")
        elif isinstance(provider_data, str):
            provider_name = provider_data

        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            url=data.get("url", ""),
            version=data.get("version", ""),
            skills=skills,
            provider=provider_name,
            documentation_url=data.get("documentationUrl", ""),
            capabilities=data.get("capabilities", {}),
            raw=data,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the agent card to its JSON dict representation.

        Returns:
            Agent card as a JSON-serializable dict.
        """
        result: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "version": self.version,
        }

        if self.skills:
            result["skills"] = [
                {
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    **({"tags": s.tags} if s.tags else {}),
                    **({"examples": s.examples} if s.examples else {}),
                }
                for s in self.skills
            ]

        if self.provider:
            result["provider"] = {"organization": self.provider}

        if self.documentation_url:
            result["documentationUrl"] = self.documentation_url

        if self.capabilities:
            result["capabilities"] = self.capabilities

        return result


async def fetch_agent_card(
    endpoint: str,
    port: int = 443,
    *,
    timeout: float = 10.0,
) -> AgentCard:
    """Fetch an A2A agent card from a host.

    Retrieves the agent card JSON from the standard well-known
    path ``/.well-known/agent-card.json``.

    Args:
        endpoint: Hostname of the agent.
        port: Port number (default 443).
        timeout: HTTP request timeout in seconds.

    Returns:
        Parsed AgentCard.

    Raises:
        httpx.HTTPStatusError: If the HTTP request fails.
        ValueError: If the response is not valid JSON.
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{endpoint}:{port}{A2A_AGENT_CARD_PATH}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

    return AgentCard.from_dict(data)


async def discover_a2a_agents(
    domain: str,
    *,
    require_dnssec: bool = False,
) -> list[AgentRecord]:
    """Discover A2A agents at a domain via DNS-AID.

    Queries DNS-AID SVCB + TXT records filtered for the A2A protocol.

    Args:
        domain: Domain to search (e.g. 'agents.example.com').
        require_dnssec: Require DNSSEC-validated responses.

    Returns:
        List of AgentRecord instances for A2A agents.
    """
    result: DiscoveryResult = await discover(
        domain=domain,
        protocol="a2a",
        require_dnssec=require_dnssec,
    )
    return result.agents


def to_agent_card(agent: AgentRecord) -> AgentCard:
    """Convert a DNS-AID AgentRecord to an A2A AgentCard.

    Maps DNS-AID record fields to the A2A agent card format:
    - ``name`` → ``name``
    - ``description`` → ``description``
    - ``endpoint_url`` → ``url``
    - ``version`` → ``version``
    - ``capabilities`` → ``skills`` (each capability becomes a skill)

    Args:
        agent: DNS-AID AgentRecord from discovery.

    Returns:
        A2A AgentCard with fields populated from the DNS record.
    """
    skills = []
    for cap in agent.capabilities or []:
        skills.append(
            AgentCardSkill(
                id=cap,
                name=cap.replace("-", " ").replace("_", " ").title(),
                description=f"Capability: {cap}",
            )
        )

    return AgentCard(
        name=agent.name,
        description=agent.description or "",
        url=agent.endpoint_url,
        version=agent.version or "",
        skills=skills,
    )


async def publish_a2a_agent(
    card: AgentCard,
    *,
    domain: str,
    name: str | None = None,
    endpoint: str | None = None,
    port: int = 443,
    ttl: int = 3600,
    backend: Any = None,
    backend_name: str | None = None,
) -> dict[str, Any]:
    """Publish an A2A agent card as DNS-AID records.

    Creates SVCB + TXT records from A2A agent card information,
    making the agent discoverable via DNS.

    Args:
        card: A2A AgentCard to publish.
        domain: DNS domain to publish under
            (e.g. 'agents.example.com').
        name: Agent name for DNS label. Defaults to the card name
            (sanitized to DNS label format).
        endpoint: Hostname where the agent is reachable.
            Defaults to extracting from card.url.
        port: Port number.
        ttl: DNS record TTL in seconds.
        backend: Pre-configured DNSBackend instance.
        backend_name: DNS backend name (e.g. 'route53').

    Returns:
        Publish result dict.
    """
    from dns_aid.core.publisher import publish

    agent_name = name or _sanitize_dns_label(card.name)

    # Extract endpoint from card URL if not provided
    resolved_endpoint = endpoint
    if resolved_endpoint is None and card.url:
        from urllib.parse import urlparse

        parsed = urlparse(card.url)
        resolved_endpoint = parsed.hostname or ""
        if parsed.port:
            port = parsed.port

    if not resolved_endpoint:
        raise ValueError(
            "endpoint must be provided or derivable from card.url"
        )

    capabilities = [s.id for s in card.skills] if card.skills else None

    resolved_backend = backend
    if resolved_backend is None and backend_name:
        from dns_aid.backends import create_backend

        resolved_backend = create_backend(backend_name)

    result = await publish(
        name=agent_name,
        domain=domain,
        protocol="a2a",
        endpoint=resolved_endpoint,
        port=port,
        capabilities=capabilities,
        version=card.version or "1.0.0",
        description=card.description,
        ttl=ttl,
        backend=resolved_backend,
    )

    logger.info(
        "DNS-AID: Published A2A agent '%s' at %s",
        agent_name,
        domain,
    )
    return result.model_dump()


async def unpublish_a2a_agent(
    *,
    name: str,
    domain: str,
    backend: Any = None,
    backend_name: str | None = None,
) -> bool:
    """Remove an A2A agent's DNS-AID records.

    Args:
        name: Agent identifier to remove.
        domain: Domain the agent is published under.
        backend: Pre-configured DNSBackend instance.
        backend_name: DNS backend name.

    Returns:
        True if records were deleted, False if not found.
    """
    from dns_aid.core.publisher import unpublish

    resolved_backend = backend
    if resolved_backend is None and backend_name:
        from dns_aid.backends import create_backend

        resolved_backend = create_backend(backend_name)

    deleted = await unpublish(
        name=name,
        domain=domain,
        protocol="a2a",
        backend=resolved_backend,
    )

    if deleted:
        logger.info(
            "DNS-AID: Unpublished A2A agent '%s' from %s",
            name,
            domain,
        )

    return deleted


def _sanitize_dns_label(name: str) -> str:
    """Convert a human-readable name to a DNS-safe label.

    Args:
        name: Human-readable agent name.

    Returns:
        DNS label format string.
    """
    label = name.lower().strip()
    label = label.replace(" ", "-").replace("_", "-")
    # Remove non-alphanumeric chars except hyphens
    label = "".join(c for c in label if c.isalnum() or c == "-")
    # Remove leading/trailing hyphens
    label = label.strip("-")
    return label or "agent"
