# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Base protocol handler abstraction.

Each protocol (MCP, A2A, HTTPS) implements this interface to handle
the wire-level details of agent invocation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx

from dns_aid.sdk.models import InvocationStatus


@dataclass
class RawResponse:
    """Raw response from a protocol handler, before signal enrichment."""

    # Outcome
    success: bool
    status: InvocationStatus
    data: dict | str | list | None = None

    # HTTP details
    http_status_code: int | None = None
    error_type: str | None = None
    error_message: str | None = None

    # Timing (ms)
    invocation_latency_ms: float = 0.0
    ttfb_ms: float | None = None

    # Quality
    response_size_bytes: int | None = None
    tls_version: str | None = None

    # Cost (from response headers)
    cost_units: float | None = None
    cost_currency: str | None = None

    # Raw response headers for extensibility
    headers: dict[str, str] = field(default_factory=dict)


class ProtocolHandler(ABC):
    """Abstract base for protocol-specific invocation handlers."""

    @abstractmethod
    async def invoke(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str | None,
        arguments: dict | None,
        timeout: float,
    ) -> RawResponse:
        """
        Invoke an agent at the given endpoint.

        Args:
            client: Shared httpx async client for connection pooling.
            endpoint: Full URL of the agent endpoint.
            method: Protocol-specific method name (e.g., "tools/call" for MCP).
            arguments: Method arguments / request payload.
            timeout: Timeout in seconds.

        Returns:
            RawResponse with timing, status, and payload.
        """
        ...

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Return the protocol identifier (e.g., 'mcp', 'a2a', 'https')."""
        ...
