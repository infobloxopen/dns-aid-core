# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Policy Document schema.

Defines the JSON schema for documents served at policy_uri.
Each rule is annotated with enforcement_layers to indicate
where it can be enforced (Layer 0=bind-aid, 1=caller SDK, 2=target SDK).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class PolicyEnforcementLayer(StrEnum):
    """Enforcement layer where a policy rule can be applied."""

    DNS = "layer0"  # bind-aid (DNS resolver)
    CALLER = "layer1"  # Caller SDK (AgentClient)
    TARGET = "layer2"  # Target SDK (middleware)


class RateLimitConfig(BaseModel):
    """Rate limiting configuration for an agent endpoint."""

    max_per_minute: int | None = None
    max_per_hour: int | None = None


class AvailabilityConfig(BaseModel):
    """Time-of-day availability window for an agent."""

    hours: str  # "08:00-22:00"
    timezone: str = "UTC"


class CELRule(BaseModel):
    """A custom policy rule expressed in CEL (Common Expression Language).

    Expressions evaluate against ``request.*`` variables mapped from PolicyContext.
    CEL guarantees termination and hermetic evaluation (no I/O, no loops).
    """

    id: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    expression: str = Field(..., min_length=1, max_length=2048)
    effect: Literal["deny", "warn"] = "deny"
    message: str = Field(default="", max_length=512)
    enforcement_layers: list[str] | None = None  # e.g., ["layer1", "layer2"]

    @field_validator("enforcement_layers")
    @classmethod
    def validate_layers(cls, v: list[str] | None) -> list[str] | None:
        """Validate enforcement layers are valid."""
        valid = {"layer0", "layer1", "layer2"}
        if v:
            for layer in v:
                if layer not in valid:
                    raise ValueError(f"Invalid enforcement layer: {layer}. Must be one of {valid}")
        return v


class PolicyRules(BaseModel):
    """All 16 native policy rule types plus optional CEL custom rules."""

    required_protocols: list[str] | None = None
    required_auth_types: list[str] | None = None
    require_dnssec: bool = False
    require_mutual_tls: bool = False
    min_tls_version: str | None = None
    required_caller_trust_score: float | None = None
    rate_limits: RateLimitConfig | None = None
    max_payload_bytes: int | None = None
    allowed_caller_domains: list[str] | None = None
    blocked_caller_domains: list[str] | None = None
    allowed_methods: list[str] | None = None
    allowed_intents: list[str] | None = None
    geo_restrictions: list[str] | None = None
    availability: AvailabilityConfig | None = None
    data_classification: str | None = None
    consent_required: bool = False
    cel_rules: list[CELRule] | None = Field(default=None, max_length=64)

    @field_validator("min_tls_version")
    @classmethod
    def validate_tls_version(cls, v: str | None) -> str | None:
        """Validate TLS version is 1.2 or 1.3."""
        if v and v not in ("1.2", "1.3"):
            raise ValueError(f"Invalid TLS version: {v}. Must be '1.2' or '1.3'")
        return v

    @field_validator("data_classification")
    @classmethod
    def validate_classification(cls, v: str | None) -> str | None:
        """Validate data classification level."""
        valid = {"public", "internal", "confidential", "restricted"}
        if v and v not in valid:
            raise ValueError(f"Invalid classification: {v}. Must be one of {valid}")
        return v


# bind-aid compile target annotations per rule
RULE_ENFORCEMENT_LAYERS: dict[str, list[PolicyEnforcementLayer]] = {
    "required_protocols": [PolicyEnforcementLayer.DNS, PolicyEnforcementLayer.CALLER],
    "required_auth_types": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "require_dnssec": [PolicyEnforcementLayer.CALLER],
    "require_mutual_tls": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "min_tls_version": [PolicyEnforcementLayer.CALLER],
    "required_caller_trust_score": [PolicyEnforcementLayer.CALLER],
    "rate_limits": [
        PolicyEnforcementLayer.CALLER,
        PolicyEnforcementLayer.TARGET,
    ],  # L1=warn, L2=enforce
    "max_payload_bytes": [PolicyEnforcementLayer.TARGET],  # L2 only — requires HTTP body inspection
    "allowed_caller_domains": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "blocked_caller_domains": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "allowed_methods": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "allowed_intents": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "geo_restrictions": [
        PolicyEnforcementLayer.DNS,
        PolicyEnforcementLayer.CALLER,
        PolicyEnforcementLayer.TARGET,
    ],  # L1=partial
    "availability": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
    "data_classification": [PolicyEnforcementLayer.CALLER],
    "consent_required": [PolicyEnforcementLayer.CALLER, PolicyEnforcementLayer.TARGET],
}


class PolicyDocument(BaseModel):
    """JSON document served at policy_uri."""

    version: str = "1.0"
    agent: str  # FQDN of the agent this policy applies to
    rules: PolicyRules = Field(default_factory=PolicyRules)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate policy document version."""
        if v not in ("1.0", "1.1"):
            raise ValueError(f"Unsupported policy version: {v}")
        return v
