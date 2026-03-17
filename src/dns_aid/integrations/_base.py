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
        if backend is not None and backend_name is not None:
            raise ValueError(
                "Specify either 'backend' or 'backend_name', not both."
            )
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
        use_cases: Optional[list[str]] = None,
        category: Optional[str] = None,
        ttl: int = 3600,
        cap_uri: Optional[str] = None,
        cap_sha256: Optional[str] = None,
        bap: Optional[list[str]] = None,
        policy_uri: Optional[str] = None,
        realm: Optional[str] = None,
        connect_class: Optional[str] = None,
        connect_meta: Optional[str] = None,
        enroll_uri: Optional[str] = None,
        ipv4_hint: Optional[str] = None,
        ipv6_hint: Optional[str] = None,
    ) -> str:
        """Publish an agent to DNS. Returns JSON string.

        Supports the full parameter set of ``dns_aid.publish()``. See
        :func:`dns_aid.core.publisher.publish` for detailed parameter docs.
        """
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
            use_cases=use_cases,
            category=category,
            ttl=ttl,
            backend=self._get_backend(),
            cap_uri=cap_uri,
            cap_sha256=cap_sha256,
            bap=bap,
            policy_uri=policy_uri,
            realm=realm,
            connect_class=connect_class,
            connect_meta=connect_meta,
            enroll_uri=enroll_uri,
            ipv4_hint=ipv4_hint,
            ipv6_hint=ipv6_hint,
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
        use_cases: Optional[list[str]] = None,
        category: Optional[str] = None,
        ttl: int = 3600,
        cap_uri: Optional[str] = None,
        cap_sha256: Optional[str] = None,
        bap: Optional[list[str]] = None,
        policy_uri: Optional[str] = None,
        realm: Optional[str] = None,
        connect_class: Optional[str] = None,
        connect_meta: Optional[str] = None,
        enroll_uri: Optional[str] = None,
        ipv4_hint: Optional[str] = None,
        ipv6_hint: Optional[str] = None,
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
                use_cases=use_cases,
                category=category,
                ttl=ttl,
                cap_uri=cap_uri,
                cap_sha256=cap_sha256,
                bap=bap,
                policy_uri=policy_uri,
                realm=realm,
                connect_class=connect_class,
                connect_meta=connect_meta,
                enroll_uri=enroll_uri,
                ipv4_hint=ipv4_hint,
                ipv6_hint=ipv6_hint,
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
