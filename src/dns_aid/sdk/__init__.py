# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Tier 1 Execution Telemetry SDK.

Wraps agent invocations, collects telemetry signals, and exports them
to the directory database, OpenTelemetry, or console.

Example:
    >>> from dns_aid.sdk import AgentClient
    >>> async with AgentClient() as client:
    ...     result = await client.invoke(agent, method="tools/call", arguments={"name": "ping"})
    ...     print(result.signal.invocation_latency_ms)
"""

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.models import (
    AgentScorecard,
    InvocationResult,
    InvocationSignal,
    InvocationStatus,
)

__all__ = [
    "AgentClient",
    "SDKConfig",
    "InvocationSignal",
    "InvocationResult",
    "InvocationStatus",
    "AgentScorecard",
]
