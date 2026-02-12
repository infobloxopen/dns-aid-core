"""
Data models for DNS-AID.

These models represent agents, discovery results, and DNS records
as specified in IETF draft-mozleywilliams-dnsop-bandaid-02.
"""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# BANDAID custom SVCB param key mapping (IETF draft-02, Section 4.4.3)
# These are provisional private-use key numbers in the range 65001-65534.
# Once IANA assigns official SvcParamKey numbers, update these values.
BANDAID_KEY_MAP: dict[str, str] = {
    "cap": "key65001",
    "cap-sha256": "key65002",
    "bap": "key65003",
    "policy": "key65004",
    "realm": "key65005",
    "sig": "key65006",
}

BANDAID_KEY_MAP_REVERSE: dict[str, str] = {v: k for k, v in BANDAID_KEY_MAP.items()}


def _use_string_keys() -> bool:
    """Check if human-readable string keys should be used instead of keyNNNNN.

    Set DNS_AID_SVCB_STRING_KEYS=1 to emit string names (for DNS providers
    that don't support keyNNNNN format or for human readability).
    Default is keyNNNNN format per RFC 9460 requirements.
    """
    return os.environ.get("DNS_AID_SVCB_STRING_KEYS", "").lower() in ("1", "true", "yes")


class DNSSECError(Exception):
    """Raised when DNSSEC validation is required but the DNS response is unsigned.

    This error indicates that ``require_dnssec=True`` was passed to
    :func:`dns_aid.discover` but the recursive resolver did not set the
    AD (Authenticated Data) flag in its response, meaning the DNS answer
    cannot be trusted as DNSSEC-validated.
    """


class Protocol(StrEnum):
    """
    Supported agent communication protocols.

    Per IETF draft, these map to ALPN identifiers in SVCB records.

    BANDAID draft-02 gap (deferred):
        The draft is internally inconsistent on what `alpn` should contain.
        Section 3.1 uses alpn="a2a" (agent protocol), while Section 5.2.3's
        zonefile example uses alpn="h2,h3" (transport protocol) with the agent
        protocol moved to the `bap` SVCB parameter. The draft's own note says
        "need to check if this is necessary????" (Section 4.4.3).

        We currently place the agent protocol in `alpn` (matching Section 3.1).
        Once the draft stabilizes on this point, we may need to change `alpn`
        to transport-level values (h2, h3) and rely solely on `bap` for
        agent protocol advertisement. This would require re-publishing all
        existing DNS records.
    """

    A2A = "a2a"  # Agent-to-Agent (Google's protocol)
    MCP = "mcp"  # Model Context Protocol (Anthropic's protocol)
    HTTPS = "https"  # Standard HTTPS


class AgentRecord(BaseModel):
    """
    Represents an AI agent published via DNS-AID.

    Maps to SVCB + TXT records in DNS per the BANDAID specification:
    - SVCB: _{name}._{protocol}._agents.{domain} → service binding
    - TXT: capabilities, version, metadata

    Example:
        >>> agent = AgentRecord(
        ...     name="network-specialist",
        ...     domain="example.com",
        ...     protocol=Protocol.MCP,
        ...     target_host="mcp.example.com",
        ...     capabilities=["ipam", "dns", "vpn"]
        ... )
        >>> agent.fqdn
        '_network-specialist._mcp._agents.example.com'
        >>> agent.endpoint_url
        'https://mcp.example.com:443'
    """

    # Identity
    name: str = Field(
        ...,
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
        description="Agent identifier (DNS label format, e.g., 'chat', 'network-specialist')",
    )
    domain: str = Field(
        ..., min_length=1, description="Domain where agent is published (e.g., 'example.com')"
    )
    protocol: Protocol = Field(..., description="Communication protocol (a2a, mcp, https)")

    # Endpoint
    target_host: str = Field(..., min_length=1, description="Hostname where agent is reachable")
    port: int = Field(default=443, ge=1, le=65535, description="Port number")
    ipv4_hint: str | None = Field(default=None, description="IPv4 address hint for performance")
    ipv6_hint: str | None = Field(default=None, description="IPv6 address hint for performance")

    # Metadata
    capabilities: list[str] = Field(default_factory=list, description="List of agent capabilities")
    version: str = Field(default="1.0.0", description="Agent version")
    description: str | None = Field(default=None, description="Human-readable description")
    use_cases: list[str] = Field(
        default_factory=list, description="List of use cases for this agent"
    )
    category: str | None = Field(
        default=None, description="Agent category (e.g., 'network', 'security')"
    )

    # BANDAID custom SVCB parameters (IETF draft-02 compliant)
    #
    # These correspond to provisional SvcParamKeys defined in Section 4.4.3.
    #
    # BANDAID draft-02 gap (deferred — keyNNNNN encoding):
    #     The draft specifies that unregistered SVCB params MUST use numeric
    #     keyNNNNN presentation form (e.g., key65001="cap=..." instead of
    #     cap="...") until IANA assigns official SvcParamKey numbers.
    #     We use human-readable string names for now because:
    #     (a) IANA registration has not occurred yet,
    #     (b) DNS providers (Route 53, Cloudflare) may not support keyNNNNN, and
    #     (c) the string form is compatible with the draft's illustrative examples.
    #     Once IANA assigns key numbers, update to_svcb_params() to emit
    #     keyNNNNN format and update _parse_svcb_custom_params() to parse it.
    #
    # BANDAID draft-02 gap (deferred — mandatory list):
    #     The draft says clients that require custom params MUST verify their
    #     presence via the `mandatory` key (e.g., mandatory=alpn,port,key65001).
    #     Per RFC 9460, clients that don't understand a mandatory key MUST skip
    #     the record. We currently only set mandatory=alpn,port to avoid breaking
    #     non-BANDAID-aware clients. Once keyNNNNN encoding is adopted, we should
    #     add custom keys to the mandatory list for downgrade safety.
    cap_uri: str | None = Field(
        default=None,
        description="URI or URN to capability descriptor (per BANDAID draft Section 4.4.3 'cap')",
    )
    cap_sha256: str | None = Field(
        default=None,
        description="Base64url-encoded SHA-256 digest of the capability descriptor "
        "for integrity checks and cache revalidation (per BANDAID draft 'cap-sha256')",
    )
    bap: list[str] = Field(
        default_factory=list,
        description="BANDAID Application Protocols with versions understood by the endpoint "
        "(e.g., ['mcp/1', 'a2a/1']). Distinct from transport-level alpn per draft Section 4.4.3.",
    )
    policy_uri: str | None = Field(
        default=None,
        description="URI or URN identifying a policy bundle for this agent "
        "(e.g., jurisdiction, data handling class)",
    )
    realm: str | None = Field(
        default=None,
        description="Opaque token for multi-tenant scoping or authz realm selection "
        "(e.g., 'production', 'staging')",
    )

    # JWS signature for application-layer verification (alternative to DNSSEC)
    sig: str | None = Field(
        default=None,
        description="JWS compact signature for record verification when DNSSEC unavailable. "
        "Contains signed payload with fqdn, target, port, alpn, iat, exp.",
    )

    # Capability source tracking
    capability_source: Literal["cap_uri", "txt_fallback", "none"] | None = Field(
        default=None,
        description="Where capabilities were sourced from: 'cap_uri' (SVCB cap param), "
        "'txt_fallback' (TXT record), or 'none'",
    )

    # DNS settings
    ttl: int = Field(default=3600, ge=60, le=86400, description="Time-to-live in seconds")

    # Optional direct endpoint (overrides target_host:port for HTTP index agents)
    endpoint_override: str | None = Field(
        default=None, description="Direct endpoint URL (e.g., 'https://booking.example.com/mcp')"
    )

    # Endpoint source - where the endpoint information came from
    endpoint_source: (
        Literal[
            "dns_svcb",
            "dns_svcb_enriched",
            "http_index",
            "http_index_fallback",
            "direct",
            "directory",
        ]
        | None
    ) = Field(
        default=None,
        description="Source of endpoint: 'dns_svcb' (from DNS SVCB record), "
        "'dns_svcb_enriched' (DNS + .well-known/agent.json path), "
        "'http_index' (DNS + HTTP index endpoint), "
        "'http_index_fallback' (HTTP index without DNS), 'direct' (explicitly provided), "
        "'directory' (from directory API search, Phase 5.7)",
    )

    # A2A Agent Card (populated from .well-known/agent.json when available)
    agent_card: Any | None = Field(
        default=None,
        description="Full A2A Agent Card from .well-known/agent.json. "
        "Contains skills, authentication, provider info. Type: A2AAgentCard",
        exclude=True,  # Exclude from serialization by default
    )

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure name is lowercase (DNS is case-insensitive)."""
        if isinstance(v, str):
            return v.lower()
        return v

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Normalize domain to lowercase without trailing dot."""
        return v.lower().rstrip(".")

    @property
    def fqdn(self) -> str:
        """
        Fully qualified domain name for DNS-AID record.

        Format: _{name}._{protocol}._agents.{domain}
        Per IETF draft section 3.1
        """
        return f"_{self.name}._{self.protocol.value}._agents.{self.domain}"

    @property
    def endpoint_url(self) -> str:
        """Full URL to reach the agent."""
        if self.endpoint_override:
            return self.endpoint_override
        return f"https://{self.target_host}:{self.port}"

    @property
    def svcb_target(self) -> str:
        """Target for SVCB record (with trailing dot)."""
        return f"{self.target_host}."

    def to_svcb_params(self) -> dict[str, str]:
        """
        Generate SVCB parameters for DNS record.

        Returns dict suitable for creating SVCB record.
        Per BANDAID draft, includes mandatory parameter to indicate
        required params for agent discovery, plus custom BANDAID params
        (cap, bap, policy, realm) when present.
        """
        params = {
            "alpn": self.protocol.value,
            "port": str(self.port),
            # BANDAID compliance: indicate alpn and port are mandatory
            "mandatory": "alpn,port",
        }
        if self.ipv4_hint:
            params["ipv4hint"] = self.ipv4_hint
        if self.ipv6_hint:
            params["ipv6hint"] = self.ipv6_hint
        # BANDAID custom SVCB params (IETF draft-02, Section 4.4.3)
        # Emit keyNNNNN format by default (RFC 9460 compliant for unregistered keys).
        # Set DNS_AID_SVCB_STRING_KEYS=1 for human-readable string names.
        use_strings = _use_string_keys()

        def _key(name: str) -> str:
            return name if use_strings else BANDAID_KEY_MAP.get(name, name)

        if self.cap_uri:
            params[_key("cap")] = self.cap_uri
        if self.cap_sha256:
            params[_key("cap-sha256")] = self.cap_sha256
        if self.bap:
            params[_key("bap")] = ",".join(self.bap)
        if self.policy_uri:
            params[_key("policy")] = self.policy_uri
        if self.realm:
            params[_key("realm")] = self.realm
        # JWS signature for application-layer verification
        if self.sig:
            params[_key("sig")] = self.sig
        return params

    def to_txt_values(self) -> list[str]:
        """
        Generate TXT record values for capabilities/metadata.

        Returns list of strings for TXT record.
        """
        values = []
        if self.capabilities:
            values.append(f"capabilities={','.join(self.capabilities)}")
        values.append(f"version={self.version}")
        if self.description:
            values.append(f"description={self.description}")
        if self.use_cases:
            values.append(f"use_cases={','.join(self.use_cases)}")
        if self.category:
            values.append(f"category={self.category}")
        return values


class DiscoveryResult(BaseModel):
    """
    Result of a DNS-AID discovery query.

    Contains discovered agents and metadata about the query.
    """

    query: str = Field(..., description="The DNS query made")
    domain: str = Field(..., description="Domain that was queried")
    agents: list[AgentRecord] = Field(default_factory=list, description="Discovered agents")
    dnssec_validated: bool = Field(default=False, description="Whether DNSSEC was verified")
    cached: bool = Field(default=False, description="Whether result was from cache")
    query_time_ms: float = Field(default=0.0, description="Query latency in milliseconds")

    @property
    def count(self) -> int:
        """Number of agents discovered."""
        return len(self.agents)


class PublishResult(BaseModel):
    """
    Result of publishing an agent to DNS.

    Contains the published agent and created DNS records.
    """

    agent: AgentRecord = Field(..., description="The published agent")
    records_created: list[str] = Field(default_factory=list, description="DNS records created")
    zone: str = Field(..., description="DNS zone used")
    backend: str = Field(..., description="DNS backend used")
    success: bool = Field(default=True, description="Whether publish succeeded")
    message: str | None = Field(default=None, description="Status message")


class VerifyResult(BaseModel):
    """
    Result of verifying an agent's DNS records.

    Contains security validation results.
    """

    fqdn: str = Field(..., description="FQDN that was verified")
    record_exists: bool = Field(default=False, description="DNS record exists")
    svcb_valid: bool = Field(default=False, description="SVCB record is valid")
    dnssec_valid: bool = Field(default=False, description="DNSSEC chain validated")
    dane_valid: bool | None = Field(
        default=None, description="DANE/TLSA verified (None if not configured)"
    )
    dnssec_note: str = Field(
        default="Checks AD flag from resolver; no independent DNSSEC chain validation",
        description="Limitation note for DNSSEC validation",
    )
    dane_note: str = Field(
        default="Checks TLSA record existence only; no certificate matching performed",
        description="Limitation note for DANE validation",
    )
    endpoint_reachable: bool = Field(default=False, description="Endpoint responds")
    endpoint_latency_ms: float | None = Field(default=None, description="Endpoint response time")

    @property
    def security_score(self) -> int:
        """
        Calculate security score (0-100).

        Scoring:
        - Record exists: 20 points
        - SVCB valid: 20 points
        - DNSSEC valid: 30 points
        - DANE valid: 15 points
        - Endpoint reachable: 15 points
        """
        score = 0
        if self.record_exists:
            score += 20
        if self.svcb_valid:
            score += 20
        if self.dnssec_valid:
            score += 30
        if self.dane_valid:
            score += 15
        if self.endpoint_reachable:
            score += 15
        return score

    @property
    def security_rating(self) -> Literal["Excellent", "Good", "Fair", "Poor"]:
        """Human-readable security rating."""
        score = self.security_score
        if score >= 85:
            return "Excellent"
        elif score >= 70:
            return "Good"
        elif score >= 50:
            return "Fair"
        else:
            return "Poor"
