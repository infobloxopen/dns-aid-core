"""
Cloudflare DNS backend.

Creates DNS-AID records (SVCB, TXT) in Cloudflare managed zones.
Supports zone ID or automatic zone lookup by domain name.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

if TYPE_CHECKING:
    from dns_aid.core.models import AgentRecord

logger = structlog.get_logger(__name__)

# Standard SVCB SvcParamKeys that managed DNS providers accept (RFC 9460).
# Cloudflare rejects private-use keys (key65001–key65534) the same way
# Route53 does.  Custom BANDAID params are demoted to TXT automatically.
_CLOUDFLARE_SVCB_KEYS = frozenset(
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


class CloudflareBackend(DNSBackend):
    """
    Cloudflare DNS backend using REST API v4.

    Creates and manages DNS-AID records in Cloudflare zones.

    Example:
        >>> backend = CloudflareBackend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        CLOUDFLARE_API_TOKEN: API token with DNS edit permissions
        CLOUDFLARE_ZONE_ID: Optional zone ID (otherwise looked up by domain)
    """

    def __init__(
        self,
        api_token: str | None = None,
        zone_id: str | None = None,
    ):
        """
        Initialize Cloudflare backend.

        Args:
            api_token: Cloudflare API token (defaults to CLOUDFLARE_API_TOKEN env var)
            zone_id: Optional zone ID. If not provided, will be looked up by domain.
        """
        self._api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN")
        self._zone_id = zone_id or os.environ.get("CLOUDFLARE_ZONE_ID")
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None  # Track which loop the client belongs to
        self._zone_cache: dict[str, str] = {}  # domain -> zone_id
        self._base_url = "https://api.cloudflare.com/client/v4"

    @property
    def name(self) -> str:
        return "cloudflare"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx async client.

        Note: Recreates client if the event loop has changed (e.g., when CLI
        uses multiple asyncio.run() calls). This is necessary because httpx
        clients are bound to the event loop they were created in.
        """
        import asyncio

        current_loop_id = id(asyncio.get_running_loop())

        # Check if we need to recreate the client due to loop change
        if self._client is not None and self._client_loop_id != current_loop_id:
            # Event loop has changed - close old client and create new one
            import contextlib

            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None

        if self._client is None:
            if not self._api_token:
                raise ValueError(
                    "Cloudflare API token not configured. "
                    "Set CLOUDFLARE_API_TOKEN environment variable or pass api_token parameter."
                )
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Bearer {self._api_token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            self._client_loop_id = current_loop_id
        return self._client

    async def _get_zone_id(self, zone: str) -> str:
        """
        Get Cloudflare zone ID for a domain.

        Args:
            zone: Domain name (e.g., "example.com")

        Returns:
            Zone ID

        Raises:
            ValueError: If zone not found
        """
        # Use configured zone ID if set
        if self._zone_id:
            return self._zone_id

        # Check cache
        domain = zone.lower().rstrip(".")
        if domain in self._zone_cache:
            return self._zone_cache[domain]

        client = await self._get_client()

        # List zones and find matching one
        response = await client.get("/zones", params={"name": domain})
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise ValueError(f"Cloudflare API error: {errors}")

        zones = data.get("result", [])
        if not zones:
            raise ValueError(f"No zone found for domain: {zone}")

        zone_id = zones[0]["id"]
        self._zone_cache[domain] = zone_id
        logger.debug("Found zone ID", domain=domain, zone_id=zone_id)
        return zone_id

    async def _get_record_id(
        self,
        zone_id: str,
        fqdn: str,
        record_type: str,
    ) -> str | None:
        """
        Get record ID for a specific record.

        Args:
            zone_id: Cloudflare zone ID
            fqdn: Fully qualified domain name
            record_type: DNS record type (SVCB, TXT, etc.)

        Returns:
            Record ID if found, None otherwise
        """
        client = await self._get_client()

        response = await client.get(
            f"/zones/{zone_id}/dns_records",
            params={"name": fqdn, "type": record_type},
        )
        response.raise_for_status()
        data = response.json()

        records = data.get("result", [])
        if records:
            return records[0]["id"]
        return None

    def _format_svcb_data(
        self,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> dict[str, Any]:
        """
        Format SVCB record data for Cloudflare API.

        Cloudflare uses a structured data object for SVCB records.
        """
        # Ensure target has trailing dot for Cloudflare
        if not target.endswith("."):
            target = f"{target}."

        # Build the value string for SVCB params
        # Format: alpn="mcp" port="443"
        param_parts = []
        for key, value in params.items():
            param_parts.append(f'{key}="{value}"')
        value_str = " ".join(param_parts) if param_parts else ""

        return {
            "priority": priority,
            "target": target,
            "value": value_str,
        }

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record in Cloudflare."""
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        logger.info(
            "Creating SVCB record",
            zone=zone,
            zone_id=zone_id,
            name=fqdn,
            priority=priority,
            target=target,
            params=params,
            ttl=ttl,
        )

        # Check if record exists (for update)
        existing_id = await self._get_record_id(zone_id, fqdn, "SVCB")

        # Prepare request data
        svcb_data = self._format_svcb_data(priority, target, params)
        request_data = {
            "type": "SVCB",
            "name": fqdn,
            "data": svcb_data,
            "ttl": ttl,
        }

        if existing_id:
            # Update existing record
            response = await client.put(
                f"/zones/{zone_id}/dns_records/{existing_id}",
                json=request_data,
            )
        else:
            # Create new record
            response = await client.post(
                f"/zones/{zone_id}/dns_records",
                json=request_data,
            )

        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise ValueError(f"Failed to create SVCB record: {errors}")

        record_id = data["result"]["id"]
        logger.info("SVCB record created", fqdn=fqdn, record_id=record_id)

        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in Cloudflare."""
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        logger.info(
            "Creating TXT record",
            zone=zone,
            zone_id=zone_id,
            name=fqdn,
            values=values,
            ttl=ttl,
        )

        # Check if record exists (for update)
        existing_id = await self._get_record_id(zone_id, fqdn, "TXT")

        # Cloudflare TXT records use "content" field
        # Multiple values are joined with spaces
        content = " ".join(f'"{v}"' for v in values)

        request_data = {
            "type": "TXT",
            "name": fqdn,
            "content": content,
            "ttl": ttl,
        }

        if existing_id:
            # Update existing record
            response = await client.put(
                f"/zones/{zone_id}/dns_records/{existing_id}",
                json=request_data,
            )
        else:
            # Create new record
            response = await client.post(
                f"/zones/{zone_id}/dns_records",
                json=request_data,
            )

        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise ValueError(f"Failed to create TXT record: {errors}")

        record_id = data["result"]["id"]
        logger.info("TXT record created", fqdn=fqdn, record_id=record_id)

        return fqdn

    async def publish_agent(self, agent: AgentRecord) -> list[str]:
        """
        Publish an agent to DNS, demoting unsupported SVCB params to TXT.

        Cloudflare only accepts standard RFC 9460 SvcParamKeys. Custom BANDAID
        params (key65001–key65006) are automatically moved to the TXT record.
        """
        records: list[str] = []
        zone = agent.domain
        name = f"_{agent.name}._{agent.protocol.value}._agents"

        # Split params: standard → SVCB, custom → TXT fallback
        all_params = agent.to_svcb_params()
        standard_params: dict[str, str] = {}
        custom_params: dict[str, str] = {}

        for key, value in all_params.items():
            if key in _CLOUDFLARE_SVCB_KEYS:
                standard_params[key] = value
            else:
                custom_params[key] = value

        if custom_params:
            logger.warning(
                "Cloudflare does not support custom SVCB params; demoting to TXT",
                demoted_keys=list(custom_params.keys()),
            )

        # Create SVCB record with standard params only
        svcb_fqdn = await self.create_svcb_record(
            zone=zone,
            name=name,
            priority=1,
            target=agent.svcb_target,
            params=standard_params,
            ttl=agent.ttl,
        )
        records.append(f"SVCB {svcb_fqdn}")

        # Build TXT values: capabilities/metadata + demoted BANDAID params
        txt_values = agent.to_txt_values()
        for key, value in custom_params.items():
            txt_values.append(f"bandaid_{key}={value}")

        if txt_values:
            txt_fqdn = await self.create_txt_record(
                zone=zone,
                name=name,
                values=txt_values,
                ttl=agent.ttl,
            )
            records.append(f"TXT {txt_fqdn}")

        return records

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from Cloudflare."""
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        logger.info(
            "Deleting record",
            zone=zone,
            name=fqdn,
            type=record_type,
        )

        # Find the record
        record_id = await self._get_record_id(zone_id, fqdn, record_type)
        if not record_id:
            logger.warning("Record not found", fqdn=fqdn, type=record_type)
            return False

        # Delete the record
        response = await client.delete(f"/zones/{zone_id}/dns_records/{record_id}")
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            logger.error("Failed to delete record", errors=errors)
            return False

        logger.info("Record deleted", fqdn=fqdn, type=record_type)
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in Cloudflare zone."""
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        logger.debug(
            "Listing records",
            zone=zone,
            zone_id=zone_id,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        # Build query params
        params: dict[str, Any] = {"per_page": 100}
        if record_type:
            params["type"] = record_type

        page = 1
        while True:
            params["page"] = page
            response = await client.get(f"/zones/{zone_id}/dns_records", params=params)
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                break

            records = data.get("result", [])
            if not records:
                break

            for record in records:
                rname = record["name"]
                rtype = record["type"]

                # Filter by name pattern (simple substring match)
                if name_pattern and name_pattern not in rname:
                    continue

                # Extract values based on record type
                if rtype == "TXT":
                    values = [record.get("content", "")]
                elif rtype == "SVCB":
                    # SVCB records have structured data
                    svcb_data = record.get("data", {})
                    priority = svcb_data.get("priority", 0)
                    target = svcb_data.get("target", "")
                    value = svcb_data.get("value", "")
                    values = [f"{priority} {target} {value}".strip()]
                else:
                    values = [record.get("content", "")]

                yield {
                    "name": rname.replace(f".{zone}", ""),
                    "fqdn": rname,
                    "type": rtype,
                    "ttl": record.get("ttl", 0),
                    "values": values,
                    "id": record.get("id"),
                }

            # Check for more pages
            result_info = data.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in Cloudflare."""
        try:
            await self._get_zone_id(zone)
            return True
        except (ValueError, httpx.HTTPStatusError):
            return False

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """
        Get a specific DNS record by querying Cloudflare API directly.

        More efficient than list_records for single record lookup.
        """
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        try:
            response = await client.get(
                f"/zones/{zone_id}/dns_records",
                params={"name": fqdn, "type": record_type},
            )
            response.raise_for_status()
            data = response.json()

            records = data.get("result", [])
            if not records:
                return None

            record = records[0]

            # Extract values based on record type
            if record_type == "TXT":
                values = [record.get("content", "")]
            elif record_type == "SVCB":
                svcb_data = record.get("data", {})
                priority = svcb_data.get("priority", 0)
                target = svcb_data.get("target", "")
                value = svcb_data.get("value", "")
                values = [f"{priority} {target} {value}".strip()]
            else:
                values = [record.get("content", "")]

            return {
                "name": name,
                "fqdn": fqdn,
                "type": record_type,
                "ttl": record.get("ttl", 0),
                "values": values,
                "id": record.get("id"),
            }

        except Exception as e:
            logger.debug("Record not found", fqdn=fqdn, type=record_type, error=str(e))
            return None

    async def list_zones(self) -> list[dict]:
        """
        List all zones accessible with the API token.

        Returns:
            List of zone info dicts with id, name, status
        """
        client = await self._get_client()
        zones = []

        page = 1
        while True:
            response = await client.get("/zones", params={"page": page, "per_page": 50})
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                break

            for z in data.get("result", []):
                zones.append(
                    {
                        "id": z["id"],
                        "name": z["name"],
                        "status": z["status"],
                        "name_servers": z.get("name_servers", []),
                    }
                )

            result_info = data.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1

        return zones

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
