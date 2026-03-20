# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""AuthHandler abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx


class AuthHandler(ABC):
    """Apply authentication to an outgoing HTTP request.

    Implementations modify the request in-place (adding headers, query
    params, or signatures) before the protocol handler sends it.
    """

    @abstractmethod
    async def apply(self, request: httpx.Request) -> httpx.Request:
        """Mutate *request* with authentication credentials and return it."""
        ...

    @property
    @abstractmethod
    def auth_type(self) -> str:
        """Return the canonical auth type identifier (e.g., 'bearer')."""
        ...
