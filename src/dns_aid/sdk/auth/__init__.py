# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
SDK Auth Handlers — automatic authentication for agent invocations.

Phase 5.6: Reads ``auth_type`` + ``auth_config`` from discovery metadata
and applies credentials to outgoing requests before they reach protocol
handlers.
"""

from __future__ import annotations

from dns_aid.sdk.auth.base import AuthHandler
from dns_aid.sdk.auth.registry import resolve_auth_handler

__all__ = ["AuthHandler", "resolve_auth_handler"]
