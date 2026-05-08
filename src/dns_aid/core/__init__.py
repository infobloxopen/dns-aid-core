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
    publish_agent_card,
)
from dns_aid.core.agent_metadata import AgentMetadata, AuthType, TransportType
from dns_aid.core.capability_model import Action, ActionIntent, ActionSemantics, CapabilitySpec
from dns_aid.core.dcv import DCVChallenge, DCVVerifyResult, issue, place, revoke
from dns_aid.core.dcv import verify as dcv_verify
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
    "DCVChallenge",
    "DCVVerifyResult",
    "DiscoveryResult",
    "Protocol",
    "PublishResult",
    "TransportType",
    "dcv_verify",
    "fetch_agent_card",
    "fetch_agent_card_from_domain",
    "issue",
    "place",
    "publish_agent_card",
    "revoke",
]
