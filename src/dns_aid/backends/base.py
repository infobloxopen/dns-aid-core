# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for DNS backends.

All DNS provider implementations (Route53, Infoblox, etc.) must
implement this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dns_aid.core.models import AgentRecord


class DNSBackend(ABC):
    """
    Abstract interface for DNS providers.

    Implementations must handle:
    - Creating SVCB records for agent service binding
    - Creating TXT records for capabilities/metadata
    - Deleting records
    - Listing records in a zone

    Example:
        >>> backend = Route53Backend(zone_id="Z123...")
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier (e.g., 'route53', 'infoblox')."""
        ...

    @abstractmethod
    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """
        Create an SVCB record for agent discovery.

        Args:
            zone: DNS zone (e.g., "example.com")
            name: Record name without zone (e.g., "_chat._a2a._agents")
            priority: SVCB priority (0 for alias, 1+ for service mode)
            target: Target hostname with trailing dot
            params: SVCB parameters (alpn, port, ipv4hint, etc.)
            ttl: Time-to-live in seconds

        Returns:
            FQDN of created record
        """
        ...

    @abstractmethod
    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """
        Create a TXT record for agent capabilities.

        Args:
            zone: DNS zone
            name: Record name without zone
            values: List of TXT values
            ttl: Time-to-live in seconds

        Returns:
            FQDN of created record
        """
        ...

    @abstractmethod
    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """
        Delete a DNS record.

        Args:
            zone: DNS zone
            name: Record name without zone
            record_type: Record type (SVCB, TXT, etc.)

        Returns:
            True if deleted, False if not found
        """
        ...

    @abstractmethod
    def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """
        List DNS records in a zone.

        Args:
            zone: DNS zone
            name_pattern: Optional pattern to filter by name
            record_type: Optional filter by record type

        Yields:
            Dict with record details (name, type, ttl, values)
        """
        ...

    @abstractmethod
    async def zone_exists(self, zone: str) -> bool:
        """
        Check if a DNS zone exists and is accessible.

        Args:
            zone: DNS zone to check

        Returns:
            True if zone exists and is accessible
        """
        ...

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """
        Get a specific DNS record by name and type.

        This method queries the backend API directly (not DNS resolution),
        providing reliable record existence checks for reconciliation.

        Args:
            zone: DNS zone (e.g., "example.com")
            name: Record name without zone (e.g., "_chat._a2a._agents")
            record_type: Record type (SVCB, TXT, etc.)

        Returns:
            Record dict with name, fqdn, type, ttl, values if found, None otherwise
        """
        # Default implementation using list_records - backends can override for efficiency
        async for record in self.list_records(zone, name_pattern=name, record_type=record_type):
            if record.get("name") == name or record.get("fqdn") == f"{name}.{zone}":
                return record
        return None

    async def publish_agent(self, agent: AgentRecord) -> list[str]:
        """
        Publish an agent to DNS (convenience method).

        Creates both SVCB and TXT records for the agent.

        Args:
            agent: Agent to publish

        Returns:
            List of created record FQDNs
        """
        records = []

        # Extract zone from agent's domain
        zone = agent.domain

        # Record name is the part before the zone
        # e.g., "_network._mcp._agents" for "_network._mcp._agents.example.com"
        name = f"_{agent.name}._{agent.protocol.value}._agents"

        # Create SVCB record
        svcb_fqdn = await self.create_svcb_record(
            zone=zone,
            name=name,
            priority=1,
            target=agent.svcb_target,
            params=agent.to_svcb_params(),
            ttl=agent.ttl,
        )
        records.append(f"SVCB {svcb_fqdn}")

        # Create TXT record for capabilities
        txt_values = agent.to_txt_values()
        if txt_values:
            txt_fqdn = await self.create_txt_record(
                zone=zone,
                name=name,
                values=txt_values,
                ttl=agent.ttl,
            )
            records.append(f"TXT {txt_fqdn}")

        return records
