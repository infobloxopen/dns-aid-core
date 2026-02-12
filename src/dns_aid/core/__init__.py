# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Core DNS-AID functionality: models, publisher, discoverer, validator."""

from dns_aid.core.a2a_card import (
    A2AAgentCard,
    A2AAuthentication,
    A2AProvider,
    A2ASkill,
    fetch_agent_card,
    fetch_agent_card_from_domain,
)
from dns_aid.core.agent_metadata import AgentMetadata, AuthType, TransportType
from dns_aid.core.capability_model import Action, ActionIntent, ActionSemantics, CapabilitySpec
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol, PublishResult

__all__ = [
    "A2AAgentCard",
    "A2AAuthentication",
    "A2AProvider",
    "A2ASkill",
    "Action",
    "ActionIntent",
    "ActionSemantics",
    "AgentMetadata",
    "AgentRecord",
    "AuthType",
    "CapabilitySpec",
    "DiscoveryResult",
    "Protocol",
    "PublishResult",
    "TransportType",
    "fetch_agent_card",
    "fetch_agent_card_from_domain",
]
