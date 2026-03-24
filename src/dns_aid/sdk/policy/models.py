# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Policy evaluation models.

Provides the context, result, and error types used by the policy evaluator
to decide whether a caller is allowed to invoke a target agent.
"""

from __future__ import annotations

from pydantic import BaseModel


class PolicyContext(BaseModel):
    """Context for evaluating a policy -- represents the caller's identity and request."""

    caller_id: str | None = None
    caller_domain: str | None = None
    protocol: str | None = None
    method: str | None = None
    intent: str | None = None
    auth_type: str | None = None
    dnssec_validated: bool = False
    tls_version: str | None = None
    caller_trust_score: float | None = None
    geo_country: str | None = None
    payload_bytes: int | None = None
    has_mutual_tls: bool = False
    consent_token: str | None = None
    tool_name: str | None = None
    target_circuit_state: str | None = None


class PolicyViolation(BaseModel):
    """A single policy rule violation."""

    rule: str  # e.g., "required_auth_types"
    detail: str  # e.g., "oauth2 required, got bearer"
    layer: str  # "layer1" or "layer2"


class PolicyResult(BaseModel):
    """Result of policy evaluation."""

    allowed: bool
    violations: list[PolicyViolation] = []
    warnings: list[PolicyViolation] = []

    @property
    def denied(self) -> bool:
        """True when the policy evaluation denied the request."""
        return not self.allowed

    @property
    def reason(self) -> str:
        """Human-readable summary of violations, or 'allowed'."""
        if self.violations:
            return "; ".join(f"{v.rule}: {v.detail}" for v in self.violations)
        return "allowed"


class PolicyViolationError(Exception):
    """Raised in strict mode when policy denies invocation."""

    def __init__(self, result: PolicyResult) -> None:
        self.result = result
        super().__init__(f"Policy violation: {result.reason}")
