"""
DNS-AID Discoverer: Query DNS to find AI agents.

This module handles discovering agents via DNS queries for SVCB and TXT
records as specified in IETF draft-mozleywilliams-dnsop-bandaid-02.
"""

from __future__ import annotations

import time
from typing import Literal

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import structlog

from dns_aid.core.cap_fetcher import fetch_cap_document
from dns_aid.core.http_index import HttpIndexAgent, fetch_http_index_or_empty
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

logger = structlog.get_logger(__name__)


async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    require_dnssec: bool = False,  # Default False for now, True in production
    use_http_index: bool = False,
) -> DiscoveryResult:
    """
    Discover AI agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records under _agents.{domain} and returns
    discovered agent endpoints.

    Args:
        domain: Domain to search for agents (e.g., "example.com")
        protocol: Filter by protocol ("a2a", "mcp", or None for all)
        name: Filter by specific agent name (or None for all)
        require_dnssec: Require DNSSEC validation (raises if invalid)
        use_http_index: If True, fetch agent list from HTTP endpoint
                        (/.well-known/agents-index.json) instead of using
                        DNS-only discovery. Default False (pure DNS).

    Returns:
        DiscoveryResult with list of discovered agents

    Example:
        >>> result = await discover("example.com", protocol="mcp")
        >>> for agent in result.agents:
        ...     print(f"{agent.name}: {agent.endpoint_url}")

        # Using HTTP index for richer metadata
        >>> result = await discover("example.com", use_http_index=True)
    """
    start_time = time.perf_counter()

    # Normalize protocol
    if isinstance(protocol, str):
        protocol = Protocol(protocol.lower())

    # Build query based on filters
    if name and protocol:
        # Specific agent
        query = f"_{name}._{protocol.value}._agents.{domain}"
    elif protocol:
        # All agents with specific protocol - query index
        query = f"_index._{protocol.value}._agents.{domain}"
    else:
        # All agents - query general index
        query = f"_index._agents.{domain}"

    # Adjust query string for HTTP index mode
    if use_http_index:
        query = f"https://_index._aiagents.{domain}/index-wellknown"

    logger.info(
        "Discovering agents via DNS",
        domain=domain,
        protocol=protocol.value if protocol else None,
        name=name,
        query=query,
        use_http_index=use_http_index,
    )

    agents: list[AgentRecord] = []
    dnssec_validated = False

    try:
        if use_http_index:
            # Use HTTP index to discover agents
            agents = await _discover_via_http_index(domain, protocol, name)
        elif name and protocol:
            # First try specific query if name is provided
            agent = await _query_single_agent(domain, name, protocol)
            if agent:
                agents.append(agent)
        else:
            # Try to discover multiple agents via DNS
            agents = await _discover_agents_in_zone(domain, protocol)

    except dns.resolver.NXDOMAIN:
        logger.debug("No DNS-AID records found", query=query)
    except dns.resolver.NoAnswer:
        logger.debug("No answer for query", query=query)
    except dns.resolver.NoNameservers:
        logger.error("No nameservers available", domain=domain)
    except Exception as e:
        logger.exception("DNS query failed", error=str(e))

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    result = DiscoveryResult(
        query=query,
        domain=domain,
        agents=agents,
        dnssec_validated=dnssec_validated,
        cached=False,
        query_time_ms=elapsed_ms,
    )

    logger.info(
        "Discovery complete",
        domain=domain,
        agents_found=result.count,
        time_ms=f"{elapsed_ms:.2f}",
        use_http_index=use_http_index,
    )

    return result


async def _query_single_agent(
    domain: str,
    name: str,
    protocol: Protocol,
) -> AgentRecord | None:
    """Query DNS for a specific agent's SVCB record."""
    fqdn = f"_{name}._{protocol.value}._agents.{domain}"

    try:
        resolver = dns.asyncresolver.Resolver()

        # Query SVCB record
        # Note: dnspython uses type 64 for SVCB
        try:
            answers = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            # Try HTTPS record as fallback (type 65)
            try:
                answers = await resolver.resolve(fqdn, "HTTPS")
            except dns.resolver.NoAnswer:
                return None

        for rdata in answers:
            # Parse SVCB record
            target = str(rdata.target).rstrip(".")
            # Note: priority (rdata.priority) available but not currently used

            # Extract standard parameters
            port = 443
            ipv4_hint = None
            ipv6_hint = None

            if hasattr(rdata, "port") and rdata.port:
                port = rdata.port

            # Extract BANDAID custom params from SVCB presentation format.
            # dnspython stores params as a dict keyed by SvcParamKey integers.
            # Custom/private-use params may appear as string keys in the
            # presentation format. We parse the text representation to extract them.
            svcb_text = str(rdata)
            custom_params = _parse_svcb_custom_params(svcb_text)

            cap_uri = custom_params.get("cap")
            cap_sha256 = custom_params.get("cap-sha256")
            bap_str = custom_params.get("bap", "")
            bap = [b.strip() for b in bap_str.split(",") if b.strip()] if bap_str else []
            policy_uri = custom_params.get("policy")
            realm = custom_params.get("realm")

            # Discovery priority: cap URI first, then TXT fallback
            capabilities: list[str] = []
            capability_source: Literal["cap_uri", "txt_fallback", "none"] = "none"

            if cap_uri:
                cap_doc = await fetch_cap_document(cap_uri)
                if cap_doc and cap_doc.capabilities:
                    capabilities = cap_doc.capabilities
                    capability_source = "cap_uri"
                    logger.debug(
                        "Capabilities fetched from cap URI",
                        fqdn=fqdn,
                        cap_uri=cap_uri,
                        capabilities=capabilities,
                    )

            if not capabilities:
                capabilities = await _query_capabilities(fqdn)
                if capabilities:
                    capability_source = "txt_fallback"

            return AgentRecord(
                name=name,
                domain=domain,
                protocol=protocol,
                target_host=target,
                port=port,
                ipv4_hint=ipv4_hint,
                ipv6_hint=ipv6_hint,
                capabilities=capabilities,
                cap_uri=cap_uri,
                cap_sha256=cap_sha256,
                bap=bap,
                policy_uri=policy_uri,
                realm=realm,
                capability_source=capability_source,
                endpoint_source="dns_svcb",  # Endpoint resolved via DNS SVCB lookup
            )

    except Exception as e:
        logger.debug("Failed to query agent", fqdn=fqdn, error=str(e))

    return None


def _parse_svcb_custom_params(svcb_text: str) -> dict[str, str]:
    """
    Parse BANDAID custom params from SVCB record text representation.

    SVCB records in presentation format look like:
        1 mcp.example.com. alpn="mcp" port="443" cap="https://..." bap="mcp,a2a"

    This extracts key=value pairs where the key matches known BANDAID params.

    Args:
        svcb_text: String representation of an SVCB rdata.

    Returns:
        Dict of custom param names to their string values.
    """
    custom_params: dict[str, str] = {}
    bandaid_keys = {"cap", "cap-sha256", "bap", "policy", "realm"}

    # Split on spaces, then look for key="value" or key=value patterns
    parts = svcb_text.split()
    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key in bandaid_keys:
            # Remove surrounding quotes if present
            value = value.strip('"').strip("'")
            custom_params[key] = value

    return custom_params


async def _query_capabilities(fqdn: str) -> list[str]:
    """Query TXT record for agent capabilities (fallback only).

    Per BANDAID draft-02 Section 4.4.3, rich agent metadata (description,
    use_cases, category) is sourced from the **capability document** fetched
    via the ``cap`` SVCB parameter URI, or from the HTTP index
    (``/.well-known/agent-index.json``).

    This TXT parser intentionally extracts only ``capabilities=`` as a
    lightweight fallback when neither cap URI nor HTTP index is available.
    The publisher writes description/use_cases/category to TXT for human
    readability (``dig TXT``), but the discoverer does NOT parse them here —
    that metadata should come from the structured cap document or HTTP index.
    """
    capabilities = []

    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(fqdn, "TXT")

        for rdata in answers:
            # TXT records can have multiple strings
            for txt_string in rdata.strings:
                txt = txt_string.decode("utf-8")
                if txt.startswith("capabilities="):
                    caps = txt[len("capabilities=") :]
                    capabilities.extend(caps.split(","))

    except Exception:
        pass  # TXT record is optional

    return capabilities


async def _discover_agents_in_zone(
    domain: str,
    protocol: Protocol | None = None,
) -> list[AgentRecord]:
    """
    Discover all agents in a domain's _agents zone.

    First tries the TXT index at _index._agents.{domain} via direct DNS query.
    Falls back to probing hardcoded common names if the index is unavailable.
    """
    from dns_aid.core.indexer import read_index_via_dns

    agents = []

    # Try TXT index first (direct DNS query, no backend credentials needed)
    index_entries = await read_index_via_dns(domain)

    if index_entries:
        logger.debug(
            "Using TXT index for discovery",
            domain=domain,
            entry_count=len(index_entries),
        )
        for entry in index_entries:
            try:
                entry_protocol = Protocol(entry.protocol.lower())
            except ValueError:
                continue

            if protocol and entry_protocol != protocol:
                continue

            agent = await _query_single_agent(domain, entry.name, entry_protocol)
            if agent:
                agents.append(agent)

        return agents

    # Fallback: probe hardcoded common names
    logger.debug("No TXT index found, falling back to common name probing", domain=domain)

    common_names = [
        "chat",
        "assistant",
        "network",
        "data-cleaner",
        "index",
        "multiagent",
        "api",
        "help",
        "support",
        "agent",
    ]

    protocols_to_try = [protocol] if protocol else [Protocol.MCP, Protocol.A2A]

    for proto in protocols_to_try:
        for name in common_names:
            agent = await _query_single_agent(domain, name, proto)
            if agent:
                agents.append(agent)

    return agents


def _parse_fqdn(fqdn: str) -> tuple[str | None, str | None]:
    """
    Parse agent name and protocol from a DNS-AID FQDN.

    FQDN format: _{name}._{protocol}._agents.{domain}

    Returns:
        (name, protocol_str) or (None, None) if parsing fails.
    """
    if not fqdn or not fqdn.startswith("_"):
        return None, None

    parts = fqdn.split(".")
    if len(parts) < 3:
        return None, None

    name_part = parts[0]  # _name
    protocol_part = parts[1]  # _protocol

    if not name_part.startswith("_") or not protocol_part.startswith("_"):
        return None, None

    return name_part[1:], protocol_part[1:]


async def _discover_via_http_index(
    domain: str,
    protocol: Protocol | None = None,
    name: str | None = None,
) -> list[AgentRecord]:
    """
    Discover agents using HTTP index endpoint.

    Fetches agent list from HTTP and resolves each via DNS SVCB.
    Protocol and agent name are extracted from the FQDN in the HTTP index,
    not from separate fields — the FQDN is the single source of truth.

    Args:
        domain: Domain to fetch HTTP index from
        protocol: Filter by protocol (or None for all)
        name: Filter by specific agent name (or None for all)

    Returns:
        List of AgentRecord objects
    """
    agents: list[AgentRecord] = []

    # Fetch HTTP index
    http_agents = await fetch_http_index_or_empty(domain)

    if not http_agents:
        logger.debug("No agents found in HTTP index", domain=domain)
        return agents

    logger.debug(
        "HTTP index fetched",
        domain=domain,
        agent_count=len(http_agents),
    )

    for http_agent in http_agents:
        # Apply name filter (against HTTP index key)
        if name and http_agent.name != name:
            continue

        # Extract name and protocol from FQDN (single source of truth)
        dns_agent_name, fqdn_protocol_str = _parse_fqdn(http_agent.fqdn)

        if not dns_agent_name or not fqdn_protocol_str:
            logger.debug(
                "Cannot parse FQDN from HTTP index entry",
                agent=http_agent.name,
                fqdn=http_agent.fqdn,
            )
            continue

        # Resolve protocol from FQDN
        try:
            agent_protocol = Protocol(fqdn_protocol_str.lower())
        except ValueError:
            logger.debug(
                "Unknown protocol in FQDN",
                agent=http_agent.name,
                fqdn=http_agent.fqdn,
                protocol=fqdn_protocol_str,
            )
            continue

        # Apply protocol filter
        if protocol and agent_protocol != protocol:
            continue

        # Resolve via DNS SVCB to get authoritative endpoint
        agent = await _query_single_agent(domain, dns_agent_name, agent_protocol)

        if agent:
            # Enhance with HTTP index metadata
            if http_agent.description:
                agent.description = http_agent.description
            if (
                http_agent.capability
                and http_agent.capability.modality
                and http_agent.capability.modality not in agent.use_cases
            ):
                agent.use_cases.append(f"modality:{http_agent.capability.modality}")
            agents.append(agent)
        else:
            # If DNS lookup fails, create agent from HTTP index data only
            logger.debug(
                "DNS lookup failed for HTTP index agent, using HTTP data only",
                agent=http_agent.name,
                fqdn=http_agent.fqdn,
            )
            agent = _http_agent_to_record(http_agent, domain, dns_agent_name, agent_protocol)
            if agent:
                agents.append(agent)

    return agents


def _http_agent_to_record(
    http_agent: HttpIndexAgent,
    domain: str,
    dns_name: str | None = None,
    dns_protocol: Protocol | None = None,
) -> AgentRecord | None:
    """
    Convert HttpIndexAgent to AgentRecord.

    Used as fallback when DNS SVCB lookup fails.
    Protocol is extracted from FQDN by the caller; only falls back
    to http_agent.primary_protocol if not provided.
    """
    # Use caller-provided protocol (from FQDN), or fall back to HTTP index field
    if dns_protocol:
        agent_protocol = dns_protocol
    else:
        proto_str = http_agent.primary_protocol
        if not proto_str:
            return None
        try:
            agent_protocol = Protocol(proto_str.lower())
        except ValueError:
            return None

    agent_name = dns_name or http_agent.name

    # Use direct endpoint if provided in HTTP index
    if http_agent.endpoint:
        from urllib.parse import urlparse

        parsed = urlparse(http_agent.endpoint)
        target_host = parsed.netloc.split(":")[0] if parsed.netloc else domain
        port = parsed.port or 443
    else:
        # Default to domain
        target_host = domain
        port = 443

        # If FQDN is a non-standard hostname (not _agents format), use it as target
        if (
            http_agent.fqdn
            and "._agents." not in http_agent.fqdn
            and not http_agent.fqdn.startswith("_")
        ):
            target_host = http_agent.fqdn.rstrip(".")

    return AgentRecord(
        name=agent_name,
        domain=domain,
        protocol=agent_protocol,
        target_host=target_host,
        port=port,
        capabilities=[],
        description=http_agent.description,
        endpoint_override=http_agent.endpoint,
        endpoint_source="http_index_fallback",
    )


async def discover_at_fqdn(fqdn: str) -> AgentRecord | None:
    """
    Discover agent at a specific FQDN.

    Args:
        fqdn: Full DNS-AID record name (e.g., "_chat._a2a._agents.example.com")

    Returns:
        AgentRecord if found, None otherwise
    """
    # Parse FQDN to extract components
    # Format: _{name}._{protocol}._agents.{domain}
    parts = fqdn.split(".")

    if len(parts) < 4:
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    # Extract components
    name_part = parts[0]  # _name
    protocol_part = parts[1]  # _protocol

    if not name_part.startswith("_") or not protocol_part.startswith("_"):
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    name = name_part[1:]  # Remove leading underscore
    protocol_str = protocol_part[1:]  # Remove leading underscore

    # Find _agents marker to determine domain
    try:
        agents_idx = parts.index("_agents")
        domain = ".".join(parts[agents_idx + 1 :])
    except ValueError:
        logger.error("Missing _agents in FQDN", fqdn=fqdn)
        return None

    try:
        protocol = Protocol(protocol_str)
    except ValueError:
        logger.error("Unknown protocol", protocol=protocol_str)
        return None

    return await _query_single_agent(domain, name, protocol)
