"""
DNS-AID: DNS-based Agent Identification and Discovery

Reference implementation for IETF draft-mozleywilliams-dnsop-bandaid-02.
Enables AI agents to discover each other via DNS using SVCB records.

Example:
    >>> import dns_aid
    >>>
    >>> # Publish an agent to DNS
    >>> await dns_aid.publish(
    ...     name="my-agent",
    ...     domain="example.com",
    ...     protocol="mcp",
    ...     endpoint="agent.example.com"
    ... )
    >>>
    >>> # Discover agents at a domain
    >>> agents = await dns_aid.discover("example.com")
    >>> for agent in agents:
    ...     print(f"{agent.name}: {agent.endpoint_url}")
    >>>
    >>> # Remove an agent from DNS
    >>> await dns_aid.unpublish(name="my-agent", domain="example.com", protocol="mcp")
"""

from dns_aid.core.discoverer import discover
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol, PublishResult
from dns_aid.core.publisher import publish, unpublish
from dns_aid.core.validator import verify

# Alias for convenience
delete = unpublish

__version__ = "0.4.8"
__all__ = [
    # Core functions
    "publish",
    "unpublish",
    "delete",  # Alias for unpublish
    "discover",
    "verify",
    # Models
    "AgentRecord",
    "DiscoveryResult",
    "PublishResult",
    "Protocol",
    # Version
    "__version__",
]
