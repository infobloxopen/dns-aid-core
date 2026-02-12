"""
Infoblox BloxOne DDI backend for DNS-AID.

Creates DNS-AID records (SVCB, TXT) via the BloxOne Cloud API.
This is the cloud-native DDI platform from Infoblox.

API Documentation: https://csp.infoblox.com/apidoc/docs/DnsData
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# BloxOne API constants
DEFAULT_BASE_URL = "https://csp.infoblox.com"
API_VERSION = "/api/ddi/v1"


class InfobloxBloxOneBackend(DNSBackend):
    """
    Infoblox BloxOne DDI backend.

    Creates and manages DNS-AID records via BloxOne Cloud API.

    Example:
        >>> backend = InfobloxBloxOneBackend(
        ...     api_key=os.environ["INFOBLOX_API_KEY"],
        ...     dns_view="default"  # Optional: specify DNS view
        ... )
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        INFOBLOX_API_KEY: API key for BloxOne authentication
        INFOBLOX_BASE_URL: Base URL (default: https://csp.infoblox.com)
        INFOBLOX_DNS_VIEW: DNS view name (default: "default")
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        dns_view: str | None = None,
        timeout: float = 30.0,
    ):
        """
        Initialize BloxOne backend.

        Args:
            api_key: BloxOne API key. Defaults to INFOBLOX_API_KEY env var.
            base_url: API base URL. Defaults to https://csp.infoblox.com
            dns_view: DNS view name (e.g., "default"). Defaults to INFOBLOX_DNS_VIEW env var.
            timeout: HTTP request timeout in seconds.
        """
        self._api_key = api_key or os.environ.get("INFOBLOX_API_KEY")
        if not self._api_key:
            raise ValueError(
                "Infoblox API key required. Set INFOBLOX_API_KEY environment variable "
                "or pass api_key parameter."
            )

        self._base_url = (base_url or os.environ.get("INFOBLOX_BASE_URL", DEFAULT_BASE_URL)).rstrip(
            "/"
        )
        self._dns_view = dns_view or os.environ.get("INFOBLOX_DNS_VIEW", "default")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None  # Track which loop the client belongs to
        self._zone_cache: dict[str, dict] = {}  # domain -> zone info
        self._view_cache: dict[str, str] = {}  # view_name -> view_id

    @property
    def name(self) -> str:
        return "bloxone"

    @property
    def dns_view(self) -> str:
        """Get the configured DNS view name."""
        return self._dns_view

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client.

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

        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Token {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self._timeout,
            )
            self._client_loop_id = current_loop_id
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """
        Make an API request to BloxOne.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint (without base URL)
            json: Request body as dict
            params: Query parameters

        Returns:
            Response JSON as dict

        Raises:
            httpx.HTTPStatusError: On API errors
        """
        client = await self._get_client()
        url = f"{API_VERSION}{endpoint}"

        logger.debug(
            "BloxOne API request",
            method=method,
            url=url,
            params=params,
        )

        response = await client.request(
            method=method,
            url=url,
            json=json,
            params=params,
        )

        # Log response status
        logger.debug(
            "BloxOne API response",
            status=response.status_code,
            url=url,
        )

        response.raise_for_status()

        if response.status_code == 204:
            return {}

        return response.json()

    async def _get_view_id(self, view_name: str) -> str | None:
        """
        Get DNS view ID from view name.

        Args:
            view_name: DNS view name (e.g., "default")

        Returns:
            View ID or None if not found
        """
        if view_name in self._view_cache:
            return self._view_cache[view_name]

        response = await self._request(
            "GET",
            "/dns/view",
            params={"_filter": f'name=="{view_name}"'},
        )

        results = response.get("results", [])
        if results:
            view_id = results[0].get("id")
            self._view_cache[view_name] = view_id
            return view_id

        return None

    async def _get_zone_info(self, zone: str) -> dict:
        """
        Get zone information from BloxOne.

        Args:
            zone: Domain name (e.g., "example.com")

        Returns:
            Zone info dict with 'id', 'fqdn', etc.

        Raises:
            ValueError: If zone not found in the configured DNS view
        """
        # Check cache (include view in cache key)
        domain = zone.lower().rstrip(".")
        cache_key = f"{domain}:{self._dns_view}"
        if cache_key in self._zone_cache:
            return self._zone_cache[cache_key]

        # Build filter - always filter by fqdn
        filter_parts = [f'fqdn=="{domain}."']

        # Add view filter if view is specified (resolve name to ID first)
        if self._dns_view:
            view_id = await self._get_view_id(self._dns_view)
            if view_id:
                filter_parts.append(f'view=="{view_id}"')

        filter_str = " and ".join(filter_parts)

        # Query BloxOne for zones
        response = await self._request(
            "GET",
            "/dns/auth_zone",
            params={"_filter": filter_str},
        )

        results = response.get("results", [])
        if not results:
            raise ValueError(f"No zone found for domain: {zone} in DNS view: {self._dns_view}")

        zone_info = results[0]
        self._zone_cache[cache_key] = zone_info

        logger.debug(
            "Found BloxOne zone",
            domain=domain,
            zone_id=zone_info.get("id"),
            view=self._dns_view,
        )

        return zone_info

    def _format_svcb_rdata(
        self,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> dict:
        """
        Format SVCB rdata for BloxOne API.

        BloxOne SVCB rdata format uses only target_name.
        Priority defaults to 0 (alias mode) in BloxOne.

        Note: BloxOne currently supports basic SVCB without SVC params.
        For full SVCB with alpn/port params, use the TXT record for metadata.
        """
        # Ensure target has trailing dot
        if not target.endswith("."):
            target = f"{target}."

        # BloxOne only accepts target_name for SVCB
        # Priority and svc_params are not supported in current API
        return {
            "target_name": target,
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
        """Create SVCB record in BloxOne."""
        zone_info = await self._get_zone_info(zone)
        zone_id = zone_info["id"]

        # Build record name (without zone suffix)
        # name comes as "_agent._mcp._agents"
        name_in_zone = name

        # Build FQDN for logging
        fqdn = f"{name}.{zone}"

        # Format rdata
        rdata = self._format_svcb_rdata(priority, target, params)

        logger.info(
            "Creating SVCB record in BloxOne",
            zone=zone,
            name=name_in_zone,
            fqdn=fqdn,
            target=target,
            ttl=ttl,
        )

        # Create record via API
        payload = {
            "name_in_zone": name_in_zone,
            "zone": zone_id,
            "type": "SVCB",
            "rdata": rdata,
            "ttl": ttl,
            "comment": f"DNS-AID: SVCB record for {name}",
        }

        response = await self._request("POST", "/dns/record", json=payload)

        record_id = response.get("result", {}).get("id")
        logger.info(
            "SVCB record created in BloxOne",
            fqdn=fqdn,
            record_id=record_id,
        )

        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in BloxOne."""
        zone_info = await self._get_zone_info(zone)
        zone_id = zone_info["id"]

        # Build FQDN
        fqdn = f"{name}.{zone}"

        # TXT rdata format: {"text": "value"}
        # For multiple values, create multiple TXT records or join
        # BloxOne supports multiple strings in a single TXT record
        rdata = {"text": " ".join(f'"{v}"' for v in values)}

        logger.info(
            "Creating TXT record in BloxOne",
            zone=zone,
            name=name,
            fqdn=fqdn,
            values=values,
            ttl=ttl,
        )

        payload = {
            "name_in_zone": name,
            "zone": zone_id,
            "type": "TXT",
            "rdata": rdata,
            "ttl": ttl,
            "comment": f"DNS-AID: TXT record for {name}",
        }

        response = await self._request("POST", "/dns/record", json=payload)

        record_id = response.get("result", {}).get("id")
        logger.info(
            "TXT record created in BloxOne",
            fqdn=fqdn,
            record_id=record_id,
        )

        return fqdn

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from BloxOne."""
        try:
            await self._get_zone_info(zone)  # Verify zone exists

            # Build FQDN to search
            fqdn = f"{name}.{zone}"
            if not fqdn.endswith("."):
                fqdn_search = f"{fqdn}."
            else:
                fqdn_search = fqdn

            logger.info(
                "Searching for record to delete",
                zone=zone,
                name=name,
                fqdn=fqdn_search,
                type=record_type,
            )

            # Find the record
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": f'absolute_name_spec=="{fqdn_search}" and type=="{record_type}"',
                },
            )

            results = response.get("results", [])
            if not results:
                logger.warning(
                    "Record not found in BloxOne",
                    fqdn=fqdn,
                    type=record_type,
                )
                return False

            # Delete the record
            # record_id is full path like "dns/record/abc123", so use it directly
            record_id = results[0]["id"]
            await self._request("DELETE", f"/{record_id}")

            logger.info(
                "Record deleted from BloxOne",
                fqdn=fqdn,
                type=record_type,
                record_id=record_id,
            )
            return True

        except Exception as e:
            logger.exception("Failed to delete record from BloxOne", error=str(e))
            return False

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in BloxOne zone."""
        zone_info = await self._get_zone_info(zone)
        zone_id = zone_info["id"]

        logger.debug(
            "Listing records in BloxOne",
            zone=zone,
            zone_id=zone_id,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        # Build filter
        filters = [f'zone=="{zone_id}"']
        if record_type:
            filters.append(f'type=="{record_type}"')
        if name_pattern:
            # Use contains filter for pattern matching
            filters.append(f'name_in_zone~"{name_pattern}"')

        filter_str = " and ".join(filters)

        # Paginate through results
        offset = 0
        limit = 100

        while True:
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": filter_str,
                    "_limit": str(limit),
                    "_offset": str(offset),
                },
            )

            results = response.get("results", [])
            if not results:
                break

            for record in results:
                # Extract record details
                rdata = record.get("rdata", {})
                values = []

                # Handle different record types
                rtype = record.get("type", "")
                if rtype == "TXT":
                    values = [rdata.get("text", "")]
                elif rtype == "SVCB":
                    target = rdata.get("target_name", "")
                    # BloxOne SVCB only supports alias mode (priority 0)
                    # The API doesn't return priority in rdata, but always uses 0
                    svc_params = rdata.get("svc_params", "")
                    values = [f"0 {target} {svc_params}".strip()]
                else:
                    # Generic handling
                    values = [str(rdata)]

                yield {
                    "name": record.get("name_in_zone", ""),
                    "fqdn": record.get("absolute_name_spec", "").rstrip("."),
                    "type": rtype,
                    "ttl": record.get("ttl", 0),
                    "values": values,
                    "id": record.get("id"),
                }

            offset += limit

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in BloxOne."""
        try:
            await self._get_zone_info(zone)
            return True
        except ValueError:
            return False

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """
        Get a specific record by querying BloxOne API directly.
        """
        try:
            # Build FQDN to search
            fqdn = f"{name}.{zone}"
            if not fqdn.endswith("."):
                fqdn_search = f"{fqdn}."
            else:
                fqdn_search = fqdn

            # Query BloxOne API
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": f'absolute_name_spec=="{fqdn_search}" and type=="{record_type}"',
                },
            )

            results = response.get("results", [])
            if not results:
                return None

            record = results[0]
            rdata = record.get("rdata", {})
            values = []

            # Handle different record types
            if record_type == "TXT":
                values = [rdata.get("text", "")]
            elif record_type == "SVCB":
                target = rdata.get("target_name", "")
                svc_params = rdata.get("svc_params", "")
                values = [f"0 {target} {svc_params}".strip()]
            else:
                values = [str(rdata)]

            return {
                "name": record.get("name_in_zone", ""),
                "fqdn": record.get("absolute_name_spec", "").rstrip("."),
                "type": record_type,
                "ttl": record.get("ttl", 0),
                "values": values,
                "id": record.get("id"),
            }

        except Exception as e:
            logger.debug(f"Record not found: {e}")
            return None

    async def list_zones(self) -> list[dict]:
        """
        List all authoritative zones in BloxOne.

        Returns:
            List of zone info dicts with id, name, etc.
        """
        response = await self._request("GET", "/dns/auth_zone")

        zones = []
        for zone in response.get("results", []):
            zones.append(
                {
                    "id": zone.get("id"),
                    "name": zone.get("fqdn", "").rstrip("."),
                    "fqdn": zone.get("fqdn", ""),
                    "comment": zone.get("comment", ""),
                    "dnssec_enabled": zone.get("dnssec_enabled", False),
                    "primary_type": zone.get("primary_type", ""),
                }
            )

        return zones

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
