# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""A2A (Agent-to-Agent) discovery bridge for DNS-AID.

Bridges DNS-AID agent discovery with the A2A agent card protocol,
enabling DNS-based discovery of A2A agents and conversion between
DNS-AID records and A2A agent cards.
"""

from dns_aid.a2a.bridge import (
    AgentCard,
    AgentCardSkill,
    discover_a2a_agents,
    fetch_agent_card,
    publish_a2a_agent,
    to_agent_card,
    unpublish_a2a_agent,
)

__all__ = [
    "AgentCard",
    "AgentCardSkill",
    "discover_a2a_agents",
    "fetch_agent_card",
    "publish_a2a_agent",
    "to_agent_card",
    "unpublish_a2a_agent",
]
