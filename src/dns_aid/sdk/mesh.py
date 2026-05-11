# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Mesh transport abstraction for DNS-AID agent-to-agent connectivity.

Provides a pluggable transport layer that decouples *how bytes travel*
(direct HTTPS, Ziti overlay, future meshes) from *what the bytes mean*
(MCP, A2A, HTTPS protocol handlers).

Architecture::

    ProtocolHandler (MCP / A2A / HTTPS)
            │
    MeshConnection (async read/write/close)
            │
    MeshTransport (direct / ziti / future)

Transport is orthogonal to protocol.  MCP over Ziti, A2A over direct,
custom protocol over a future mesh — all combinations work.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType

import httpx
import structlog

logger = structlog.get_logger(__name__)


class MeshConnection(ABC):
    """Bidirectional async byte stream over a mesh (or direct) connection.

    This is the fundamental primitive for agent-to-agent communication.
    Protocol handlers frame messages on top of this connection.
    The connection may travel through a direct HTTPS path, a Ziti
    service mesh, or any future agent mesh transport.
    """

    @abstractmethod
    async def open(
        self,
        *,
        target: str,
        port: int = 443,
        mesh_meta: str | None = None,
    ) -> None:
        """Open the connection to the target.

        Args:
            target: Target hostname or service name.
            port: Target port.
            mesh_meta: Mesh-specific metadata (e.g., Ziti service name as JSON).
        """
        ...

    @abstractmethod
    async def read(self, n: int = -1) -> bytes:
        """Read up to *n* bytes.  -1 means read until EOF."""
        ...

    @abstractmethod
    async def write(self, data: bytes) -> None:
        """Write *data* to the connection."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close the connection and release resources."""
        ...

    async def __aenter__(self) -> MeshConnection:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()


class MeshTransport(ABC):
    """Factory for mesh connections.  Registered per-client or globally."""

    @property
    @abstractmethod
    def mesh_name(self) -> str:
        """Transport identifier, e.g. ``"direct"``, ``"ziti"``."""
        ...

    @abstractmethod
    async def connect(
        self,
        *,
        target: str,
        port: int = 443,
        mesh_meta: str | None = None,
    ) -> MeshConnection:
        """Create and open a connection through this mesh.

        Args:
            target: Target hostname or service name.
            port: Target port.
            mesh_meta: Mesh-specific metadata (JSON string or plain value).

        Returns:
            An opened :class:`MeshConnection`.
        """
        ...

    async def close(self) -> None:  # noqa: B027
        """Cleanup hook (identity teardown, context shutdown)."""


class MeshNotAvailableError(Exception):
    """Raised when an agent requires a mesh transport that is not registered."""

    def __init__(self, mesh: str) -> None:
        self.mesh = mesh
        super().__init__(
            f"Mesh transport '{mesh}' required by agent but not registered. "
            f"Install the mesh provider package and call "
            f"client.register_mesh('{mesh}', provider)."
        )


# ── Direct (default) transport ──────────────────────────────────


class DirectMeshConnection(MeshConnection):
    """Default: wraps httpx.AsyncClient for backward compat with HTTP-based handlers.

    This is what existing MCP/A2A/HTTPS handlers use during the transition period.
    The connection exposes the underlying ``httpx.AsyncClient`` so that legacy
    ``ProtocolHandler.invoke()`` callers can continue to use it directly.
    """

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._http_client = http_client
        self._owns_client = http_client is None
        self._target: str | None = None
        self._port: int = 443

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Access the underlying httpx client for legacy handlers."""
        if self._http_client is None:
            raise RuntimeError("DirectMeshConnection not opened")
        return self._http_client

    async def open(
        self,
        *,
        target: str,
        port: int = 443,
        mesh_meta: str | None = None,
    ) -> None:
        self._target = target
        self._port = port
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
            )
            self._owns_client = True

    async def read(self, n: int = -1) -> bytes:
        raise NotImplementedError(
            "DirectMeshConnection does not support raw read(); "
            "use http_client for HTTP-based protocols."
        )

    async def write(self, data: bytes) -> None:
        raise NotImplementedError(
            "DirectMeshConnection does not support raw write(); "
            "use http_client for HTTP-based protocols."
        )

    async def close(self) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None


class DirectMeshTransport(MeshTransport):
    """Default mesh — plain HTTPS via httpx.  No overlay."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._http_client = http_client

    @property
    def mesh_name(self) -> str:
        return "direct"

    async def connect(
        self,
        *,
        target: str,
        port: int = 443,
        mesh_meta: str | None = None,
    ) -> DirectMeshConnection:
        conn = DirectMeshConnection(http_client=self._http_client)
        await conn.open(target=target, port=port, mesh_meta=mesh_meta)
        return conn


# ── Module-level default registry ───────────────────────────────

_MESH_TRANSPORTS: dict[str, MeshTransport] = {}


def register_default_mesh(mesh: str, transport: MeshTransport) -> None:
    """Register a mesh transport in the module-level default registry.

    Typically called by entry_point plugins at import time.
    """
    _MESH_TRANSPORTS[mesh] = transport


def get_default_mesh(mesh: str) -> MeshTransport | None:
    """Look up a mesh transport from the module-level registry."""
    return _MESH_TRANSPORTS.get(mesh)
