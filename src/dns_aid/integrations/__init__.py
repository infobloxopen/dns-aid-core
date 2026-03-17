# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Shared integration layer for DNS-AID framework integrations.

Provides framework-agnostic operations, input schemas, and async/sync
bridging that any framework integration can build upon.
"""

from dns_aid.integrations._async_bridge import run_async
from dns_aid.integrations._base import DnsAidOperations
from dns_aid.integrations._schemas import (
    DiscoverInput,
    PublishInput,
    UnpublishInput,
)

__all__ = [
    "DnsAidOperations",
    "DiscoverInput",
    "PublishInput",
    "UnpublishInput",
    "run_async",
]
