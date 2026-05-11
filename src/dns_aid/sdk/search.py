# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Typed result models for cross-domain agent search (Path B).

Every Path B response from the dns-aid-directory backend is deserialized into the typed
models below, never returned to callers as raw dicts. Models are immutable
(``frozen=True``) and forward-compatible (``extra="ignore"``) so directory schema additions
do not break SDK consumers; removed/renamed fields surface as Pydantic
``ValidationError`` and are mapped to :class:`~dns_aid.sdk.exceptions.DirectoryUnavailableError`
by the SDK, prompting the caller to retry or upgrade.

The shape of these models faithfully mirrors the directory's
``dns_aid_directory.api.schemas.AgentResponse`` / ``SearchResultItem`` /
``SearchResponse`` contract. The directory exposes trust + provenance signals as flat
fields on each agent; the SDK's wire-shape adapter
(:func:`~dns_aid.sdk.client._adapt_search_payload`) lifts those flat fields into the
typed nested objects below before validation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from dns_aid.core.models import AgentRecord


class TrustAttestation(BaseModel):
    """
    Pre-computed trust signals from the directory.

    Carries the signals a caller needs to decide whether to invoke an agent directly or
    to re-verify via Path A first. Field shape mirrors the directory's flat
    ``AgentResponse`` exactly: aggregate scores live on the 0..100 scale,
    per-signal verification flags are tri-state (``True`` / ``False`` / ``None``),
    and ``threat_flags`` is an open extensible map keyed by signal name.

    Every field has a sensible default so the model is constructable from sparse
    directory data — a freshly indexed agent that hasn't been crawl-verified yet will
    still produce a valid ``TrustAttestation`` (with all verification flags ``None``
    and scores defaulting to 0).
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    # Aggregate scores (always present in directory output, default 0)
    security_score: Annotated[int, Field(ge=0, le=100)] = Field(
        default=0,
        description="Aggregate security score, 0..100. 0 if not yet computed.",
    )
    trust_score: Annotated[int, Field(ge=0, le=100)] = Field(
        default=0,
        description="Overall trust score combining security, reliability, and community signals, 0..100.",
    )
    popularity_score: Annotated[int, Field(ge=0, le=100)] = Field(
        default=0,
        description="Caller-popularity score, 0..100. Driven by directory telemetry.",
    )

    # Trust tier ladder
    trust_tier: Annotated[int, Field(ge=0, le=3)] = Field(
        default=0,
        description="Discrete trust tier: 0 untiered, 1 basic, 2 enhanced, 3 continuous.",
    )

    # Safety status (gate for invocation)
    safety_status: Literal["active", "blocked"] = Field(
        default="active",
        description="Directory's safety verdict. ``blocked`` agents should not be invoked.",
    )

    # Per-signal verification flags. ``None`` = not yet evaluated; ``True``/``False`` = evaluated.
    dnssec_valid: bool | None = Field(
        default=None,
        description="DNSSEC validation passed for the agent's DNS records.",
    )
    dane_valid: bool | None = Field(
        default=None,
        description="DANE/TLSA binding verified.",
    )
    svcb_valid: bool | None = Field(
        default=None,
        description="SVCB record schema is valid.",
    )
    endpoint_reachable: bool | None = Field(
        default=None,
        description="Crawler successfully reached the agent's endpoint.",
    )
    protocol_verified: bool | None = Field(
        default=None,
        description="Endpoint implements the claimed protocol (A2A agent card, MCP initialize).",
    )

    # Threat indicators — extensible map keyed by signal name.
    threat_flags: dict[str, Any] = Field(
        default_factory=dict,
        description="Threat-detection flags from the directory's safety pipeline.",
    )

    # Optional rich evidence — directory may expose these for advanced callers.
    breakdown: dict[str, Any] | None = Field(
        default=None,
        description="Per-signal trust score breakdown (directory's ``trust_breakdown``).",
    )
    badges: list[str] | None = Field(
        default=None,
        description="Trust badges (directory's ``trust_badges``), e.g., 'Verified', 'DNSSEC'.",
    )


class Provenance(BaseModel):
    """
    Crawler provenance attribution for a directory-indexed agent.

    Surfaces *when* the directory first observed an agent, when it last refreshed the
    record, and how it was discovered. Field shape mirrors the directory's flat
    ``AgentResponse`` exactly. ``first_seen`` and ``last_seen`` are required because the
    directory always populates them on insert.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    discovery_level: Annotated[int, Field(ge=0, le=3)] = Field(
        default=0,
        description="0 observed, 1 DNS beacon detected, 2 manifest published, 3 federated.",
    )
    first_seen: datetime = Field(
        description="When the directory first added this agent to the index."
    )
    last_seen: datetime = Field(
        description="Wall-clock time of the directory's most recent crawl of this agent."
    )
    last_verified: datetime | None = Field(
        default=None,
        description="Wall-clock time of the directory's last successful verification crawl.",
    )
    company: dict[str, Any] | None = Field(
        default=None,
        description="Opaque company / organization metadata (directory's ``CompanyMetadata``).",
    )


class SearchResult(BaseModel):
    """
    A single ranked result from a directory query.

    ``agent`` reuses the existing :class:`~dns_aid.core.models.AgentRecord` model so the
    composition pattern (Path B → Path A re-verify) can pass the agent directly into
    ``discover()`` without translation. ``score`` is the directory's relevance score
    (raw float; the directory does not normalize), and ``trust`` carries pre-computed
    trust signals so the caller can reason about re-verification without a second round
    trip.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    agent: AgentRecord = Field(description="The agent payload, validated against AgentRecord.")
    score: Annotated[float, Field(ge=0.0)] = Field(
        description="Directory's relevance score (raw — higher is more relevant). Not normalized.",
    )
    trust: TrustAttestation = Field(
        default_factory=TrustAttestation,
        description="Pre-computed trust evidence lifted from the directory's flat agent fields.",
    )
    provenance: Provenance | None = Field(
        default=None,
        description="Crawler provenance metadata lifted from the directory's flat agent fields.",
    )


class SearchResponse(BaseModel):
    """
    Full response envelope for a single :meth:`AgentClient.search` invocation.

    Carries the echo of the request (``query`` — just the ``q`` string the directory
    sends back), the ranked results page (``results``), and pagination state
    (``total``, ``limit``, ``offset``). Helper properties ``has_more`` and
    ``next_offset`` make iterating subsequent pages a one-liner.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    query: str | None = Field(
        default=None,
        description="Echo of the ``q`` parameter the directory accepted (or None if not echoed).",
    )
    results: list[SearchResult] = Field(
        description="Ranked results page; length is at most ``limit``."
    )
    total: Annotated[int, Field(ge=0)] = Field(
        description="Total number of matching agents across all pages."
    )
    limit: Annotated[int, Field(ge=1, le=10000)] = Field(description="Effective page size.")
    offset: Annotated[int, Field(ge=0)] = Field(description="Effective pagination offset.")

    @property
    def has_more(self) -> bool:
        """True when at least one matching agent exists beyond this page's window."""
        return self.offset + len(self.results) < self.total

    @property
    def next_offset(self) -> int | None:
        """Offset to pass on the next page, or ``None`` if this page exhausts the result set."""
        if not self.has_more:
            return None
        return self.offset + len(self.results)
