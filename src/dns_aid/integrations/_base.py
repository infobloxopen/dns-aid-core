# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Framework-agnostic DNS-AID operations for integrations."""

from __future__ import annotations

import json
from typing import Any, Optional

from dns_aid.integrations._async_bridge import run_async


class DnsAidOperations:
    """Shared DNS-AID operations that any framework integration can delegate to.

    Handles backend resolution, async execution, and JSON serialization
    so framework-specific wrappers only need to adapt to their tool interface.

    Args:
        backend_name: DNS backend name (e.g. 'route53', 'cloudflare', 'mock').
        backend: Pre-configured DNSBackend instance. Takes priority over backend_name.
    """

    def __init__(
        self,
        backend_name: Optional[str] = None,
        backend: Any = None,
    ) -> None:
        self.backend_name = backend_name
        self.backend = backend

    def _get_backend(self) -> Any:
        """Resolve the DNS backend instance."""
        if self.backend is not None:
            return self.backend
        if self.backend_name:
            from dns_aid.backends import create_backend

            return create_backend(self.backend_name)
        return None

    # -- Async operations --

    async def discover_async(
        self,
        domain: str,
        protocol: Optional[str] = None,
        name: Optional[str] = None,
        require_dnssec: bool = False,
    ) -> str:
        """Discover agents at a domain. Returns JSON string."""
        import dns_aid

        result = await dns_aid.discover(
            domain=domain,
            protocol=protocol,
            name=name,
            require_dnssec=require_dnssec,
        )
        return json.dumps(result.model_dump(), default=str)

    async def publish_async(
        self,
        name: str,
        domain: str,
        protocol: str = "mcp",
        endpoint: str = "",
        port: int = 443,
        capabilities: Optional[list[str]] = None,
        version: str = "1.0.0",
        description: Optional[str] = None,
        ttl: int = 3600,
    ) -> str:
        """Publish an agent to DNS. Returns JSON string."""
        import dns_aid

        result = await dns_aid.publish(
            name=name,
            domain=domain,
            protocol=protocol,
            endpoint=endpoint,
            port=port,
            capabilities=capabilities,
            version=version,
            description=description,
            ttl=ttl,
            backend=self._get_backend(),
        )
        return json.dumps(result.model_dump(), default=str)

    async def unpublish_async(
        self,
        name: str,
        domain: str,
        protocol: str = "mcp",
    ) -> str:
        """Remove an agent from DNS. Returns JSON string."""
        import dns_aid

        deleted = await dns_aid.unpublish(
            name=name,
            domain=domain,
            protocol=protocol,
            backend=self._get_backend(),
        )
        if deleted:
            return json.dumps(
                {"success": True, "message": f"Agent '{name}' unpublished from {domain}"}
            )
        return json.dumps(
            {"success": False, "message": f"Agent '{name}' not found at {domain}"}
        )

    # -- Sync wrappers --

    def discover_sync(
        self,
        domain: str,
        protocol: Optional[str] = None,
        name: Optional[str] = None,
        require_dnssec: bool = False,
    ) -> str:
        """Discover agents (sync wrapper). Returns JSON string."""
        return run_async(
            self.discover_async(
                domain=domain, protocol=protocol, name=name, require_dnssec=require_dnssec
            )
        )

    def publish_sync(
        self,
        name: str,
        domain: str,
        protocol: str = "mcp",
        endpoint: str = "",
        port: int = 443,
        capabilities: Optional[list[str]] = None,
        version: str = "1.0.0",
        description: Optional[str] = None,
        ttl: int = 3600,
    ) -> str:
        """Publish an agent (sync wrapper). Returns JSON string."""
        return run_async(
            self.publish_async(
                name=name,
                domain=domain,
                protocol=protocol,
                endpoint=endpoint,
                port=port,
                capabilities=capabilities,
                version=version,
                description=description,
                ttl=ttl,
            )
        )

    def unpublish_sync(
        self,
        name: str,
        domain: str,
        protocol: str = "mcp",
    ) -> str:
        """Remove an agent (sync wrapper). Returns JSON string."""
        return run_async(
            self.unpublish_async(name=name, domain=domain, protocol=protocol)
        )
