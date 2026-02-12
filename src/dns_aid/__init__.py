# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID: DNS-based Agent Identification and Discovery

Reference implementation for IETF draft-mozleywilliams-dnsop-bandaid-02.
Enables AI agents to discover each other via DNS using SVCB records.

Example:
    >>> import dns_aid
    >>>
    >>> # Discover agents at a domain
    >>> result = await dns_aid.discover("example.com")
    >>>
    >>> # Invoke an agent and capture telemetry
    >>> resp = await dns_aid.invoke(result.agents[0], method="tools/list")
    >>> print(resp.signal.invocation_latency_ms)
    >>>
    >>> # Publish an agent to DNS
    >>> await dns_aid.publish(
    ...     name="my-agent",
    ...     domain="example.com",
    ...     protocol="mcp",
    ...     endpoint="agent.example.com"
    ... )
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dns_aid.core.discoverer import discover
from dns_aid.core.models import AgentRecord, DiscoveryResult, DNSSECError, Protocol, PublishResult
from dns_aid.core.publisher import publish, unpublish

# Tier 0: DNS validation
from dns_aid.core.validator import verify

# Tier 1: Execution Telemetry SDK
from dns_aid.sdk import AgentClient, InvocationResult, InvocationSignal, SDKConfig

if TYPE_CHECKING:
    from dns_aid.sdk.ranking.ranker import RankedAgent

# Alias for convenience
delete = unpublish

__version__ = "0.6.0"
__all__ = [
    # Core functions (Tier 0)
    "publish",
    "unpublish",
    "delete",
    "discover",
    "verify",
    # SDK functions (Tier 1)
    "invoke",
    "rank",
    # SDK classes
    "AgentClient",
    "SDKConfig",
    "InvocationResult",
    "InvocationSignal",
    # Models
    "AgentRecord",
    "DiscoveryResult",
    "PublishResult",
    "Protocol",
    # Exceptions
    "DNSSECError",
    # Version
    "__version__",
]


async def invoke(
    agent: AgentRecord,
    *,
    method: str | None = None,
    arguments: dict | None = None,
    timeout: float | None = None,
    config: SDKConfig | None = None,
) -> InvocationResult:
    """
    Invoke an agent and capture telemetry — convenience wrapper.

    Creates a one-shot AgentClient, calls the agent, and returns the result
    with an attached telemetry signal. For multiple calls or connection reuse,
    use ``AgentClient`` directly.

    Args:
        agent: An AgentRecord from ``dns_aid.discover()``.
        method: Protocol-specific method (e.g., ``"tools/list"`` for MCP).
        arguments: Method arguments / payload.
        timeout: Request timeout in seconds (default: 30).
        config: Optional SDKConfig. Defaults to ``SDKConfig.from_env()``.

    Returns:
        InvocationResult with the response data and telemetry signal.

    Example::

        import dns_aid

        result = await dns_aid.discover("example.com", protocol="mcp")
        agent = result.agents[0]

        resp = await dns_aid.invoke(agent, method="tools/list")
        print(f"Latency: {resp.signal.invocation_latency_ms}ms")
        print(f"Status:  {resp.signal.status}")
        print(f"Data:    {resp.data}")
    """
    async with AgentClient(config=config) as client:
        return await client.invoke(
            agent,
            method=method,
            arguments=arguments,
            timeout=timeout,
        )


async def rank(
    agents: list[AgentRecord],
    *,
    method: str | None = None,
    arguments: dict | None = None,
    config: SDKConfig | None = None,
) -> list[RankedAgent]:
    """
    Invoke multiple agents and rank them by telemetry performance.

    Calls each agent, collects signals, and returns agents sorted by
    composite score (reliability, latency, cost, freshness).

    Args:
        agents: List of AgentRecords from ``dns_aid.discover()``.
        method: Protocol-specific method to invoke on each agent.
        arguments: Method arguments / payload.
        config: Optional SDKConfig.

    Returns:
        List of RankedAgent sorted best-to-worst.

    Example::

        import dns_aid

        result = await dns_aid.discover("example.com", protocol="mcp")
        ranked = await dns_aid.rank(result.agents, method="tools/list")

        for r in ranked:
            print(f"{r.agent_fqdn}: score={r.composite_score:.1f}")
    """
    async with AgentClient(config=config) as client:
        for agent in agents:
            await client.invoke(
                agent,
                method=method,
                arguments=arguments,
            )
        return client.rank()
