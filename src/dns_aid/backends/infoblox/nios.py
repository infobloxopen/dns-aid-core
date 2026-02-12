# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Infoblox NIOS (on-premises) backend for DNS-AID.

Creates DNS-AID records via the NIOS WAPI (Web API).
This is the traditional on-premises DDI platform from Infoblox.

API Documentation: https://docs.infoblox.com/display/nios/WAPI+Versioning

Status: PLANNED - Not yet implemented
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from dns_aid.backends.base import DNSBackend


class InfobloxNIOSBackend(DNSBackend):
    """
    Infoblox NIOS WAPI backend (on-premises).

    NOT YET IMPLEMENTED - Placeholder for future development.

    This backend will support:
    - NIOS WAPI v2.x authentication (basic auth or certificate)
    - SVCB record creation (requires NIOS 8.6+)
    - TXT record creation
    - Zone management via WAPI

    Example (planned):
        >>> backend = InfobloxNIOSBackend(
        ...     host="nios.example.com",
        ...     username="admin",
        ...     password=os.environ["NIOS_PASSWORD"],
        ...     wapi_version="2.12",
        ... )
        >>> await backend.create_svcb_record(...)

    Environment Variables (planned):
        NIOS_HOST: NIOS Grid Master hostname
        NIOS_USERNAME: WAPI username
        NIOS_PASSWORD: WAPI password
        NIOS_WAPI_VERSION: WAPI version (default: 2.12)
        NIOS_VERIFY_SSL: Verify SSL certificates (default: true)
    """

    def __init__(
        self,
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
        wapi_version: str = "2.12",
        verify_ssl: bool = True,
    ):
        """
        Initialize NIOS backend.

        Args:
            host: NIOS Grid Master hostname
            username: WAPI username
            password: WAPI password
            wapi_version: WAPI version (e.g., "2.12")
            verify_ssl: Whether to verify SSL certificates
        """
        raise NotImplementedError(
            "InfobloxNIOSBackend is not yet implemented. "
            "Use InfobloxBloxOneBackend for cloud deployments, "
            "or contribute the NIOS implementation!"
        )

    @property
    def name(self) -> str:
        return "nios"

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record in NIOS."""
        raise NotImplementedError("NIOS backend not yet implemented")

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in NIOS."""
        raise NotImplementedError("NIOS backend not yet implemented")

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from NIOS."""
        raise NotImplementedError("NIOS backend not yet implemented")

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in NIOS zone."""
        raise NotImplementedError("NIOS backend not yet implemented")
        yield  # Make this a generator

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in NIOS."""
        raise NotImplementedError("NIOS backend not yet implemented")
