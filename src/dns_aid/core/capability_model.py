"""
Machine-readable capability model for DNS-AID Agent Metadata Contract.

Status: Experimental — defined but not yet wired into discover()/publish().

Defines action intents and semantics that let orchestrators (LangGraph, CrewAI)
make routing decisions: Is this action safe to retry? Read-only? Requires
transaction handling?

Phase 5.5 — Agent Metadata Contract.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ActionIntent(StrEnum):
    """Purpose classification for an agent action.

    Orchestrators use this to decide caching, retry, and composition strategies.
    """

    query = "query"
    """Read-only data retrieval — safe to cache and parallelize."""

    command = "command"
    """State-changing operation — fire-and-forget, may not be idempotent."""

    transaction = "transaction"
    """Multi-step operation requiring rollback/commit semantics."""

    subscription = "subscription"
    """Long-lived streaming operation — requires connection lifecycle management."""


class ActionSemantics(StrEnum):
    """Safety profile for an agent action.

    Tells orchestrators whether an action modifies state and whether
    it can be safely retried on failure.
    """

    read = "read"
    """No side effects — safe to run in parallel or cache."""

    write = "write"
    """Modifies state — NOT safe to retry blindly."""

    idempotent = "idempotent"
    """Modifies state but safe to retry — same input always yields same outcome."""


class Action(BaseModel):
    """A single action an agent can perform.

    Combines human-readable metadata (name, description, tags) with
    machine-readable routing hints (intent, semantics).
    """

    name: str = Field(..., min_length=1, max_length=255, description="Action identifier")
    description: str | None = Field(None, max_length=2000, description="Human-readable description")
    intent: ActionIntent = Field(
        ActionIntent.query, description="Purpose classification for routing decisions"
    )
    semantics: ActionSemantics = Field(
        ActionSemantics.read, description="Safety profile for retry/caching decisions"
    )
    tags: list[str] = Field(default_factory=list, description="Freeform tags for filtering")


class CapabilitySpec(BaseModel):
    """Structured capability specification for an agent.

    Goes beyond a flat list of capability strings — provides schema discovery,
    streaming support, and per-action intent/semantics.
    """

    schema_discovery: str | None = Field(
        None,
        max_length=512,
        description="URL to capability schema document (e.g., OpenAPI, MCP schema)",
    )
    supports_streaming: bool = Field(
        False, description="Whether the agent supports streaming responses"
    )
    actions: list[Action] = Field(
        default_factory=list, description="Machine-readable action descriptors"
    )
