"""
DNS-AID Discoverer: Query DNS to find AI agents.

This module handles discovering agents via DNS queries for SVCB and TXT
records as specified in IETF draft-mozleywilliams-dnsop-bandaid-02.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal
from urllib.parse import urlparse

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import structlog

from dns_aid.core.a2a_card import fetch_agent_card
from dns_aid.core.cap_fetcher import fetch_cap_document
from dns_aid.core.http_index import HttpIndexAgent, fetch_http_index_or_empty
from dns_aid.core.models import AgentRecord, DiscoveryResult, DNSSECError, Protocol

logger = structlog.get_logger(__name__)


def _normalize_protocol(protocol: str | Protocol | None) -> Protocol | None:
    """Convert string protocol to Protocol enum if needed."""
    if isinstance(protocol, str):
        return Protocol(protocol.lower())
    return protocol


async def _execute_discovery(
    domain: str,
    protocol: Protocol | None,
    name: str | None,
    use_http_index: bool,
    query: str,
) -> list[AgentRecord]:
    """Execute the appropriate discovery strategy and handle DNS errors."""
    try:
        if use_http_index:
            return await _discover_via_http_index(domain, protocol, name)
        elif name and protocol:
            agent = await _query_single_agent(domain, name, protocol)
            return [agent] if agent else []
        else:
            return await _discover_agents_in_zone(domain, protocol)
    except dns.resolver.NXDOMAIN:
        logger.debug("No DNS-AID records found", query=query)
    except dns.resolver.NoAnswer:
        logger.debug("No answer for query", query=query)
    except dns.resolver.NoNameservers:
        logger.error("No nameservers available", domain=domain)
    except Exception as e:
        logger.exception("DNS query failed", error=str(e))
    return []


async def _apply_post_discovery(
    agents: list[AgentRecord],
    require_dnssec: bool,
    enrich_endpoints: bool,
    verify_signatures: bool,
    domain: str,
) -> bool:
    """Apply DNSSEC enforcement, endpoint enrichment, and JWS verification.

    Returns whether DNSSEC was validated.
    """
    dnssec_validated = False

    if agents and require_dnssec:
        from dns_aid.core.validator import _check_dnssec

        dnssec_validated = await _check_dnssec(agents[0].fqdn)
        if not dnssec_validated:
            raise DNSSECError(
                f"DNSSEC validation required but DNS response for "
                f"{agents[0].fqdn} is not authenticated (AD flag not set)"
            )

    if enrich_endpoints and agents:
        try:
            await _enrich_agents_with_endpoint_paths(agents)
        except Exception:
            logger.debug("Endpoint enrichment failed (non-fatal)", exc_info=True)

    if verify_signatures and agents:
        await _verify_agent_signatures(agents, domain, dnssec_validated)

    return dnssec_validated


async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    require_dnssec: bool = False,  # Default False for now, True in production
    use_http_index: bool = False,
    enrich_endpoints: bool = True,
    verify_signatures: bool = False,
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
        enrich_endpoints: If True (default), fetch .well-known/agent.json
                         from each discovered agent's host to resolve
                         protocol-specific endpoint paths (e.g., /mcp).
        verify_signatures: If True, verify JWS signatures on agents that have
                          a `sig` parameter but no DNSSEC validation. Invalid
                          signatures are logged but don't block discovery.

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

    protocol = _normalize_protocol(protocol)

    # Build query based on filters
    if name and protocol:
        query = f"_{name}._{protocol.value}._agents.{domain}"
    elif protocol:
        query = f"_index._{protocol.value}._agents.{domain}"
    else:
        query = f"_index._agents.{domain}"

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

    agents = await _execute_discovery(domain, protocol, name, use_http_index, query)
    dnssec_validated = await _apply_post_discovery(
        agents, require_dnssec, enrich_endpoints, verify_signatures, domain
    )

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
                cap_doc = await fetch_cap_document(cap_uri, expected_sha256=cap_sha256)
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

    Accepts both human-readable string names and RFC 9460 keyNNNNN format:
        String form: cap="https://..." bap="mcp,a2a" realm="demo"
        Numeric form: key65001="https://..." key65003="mcp,a2a" key65005="demo"

    Args:
        svcb_text: String representation of an SVCB rdata.

    Returns:
        Dict of custom param names (always string form) to their string values.
    """
    from dns_aid.core.models import BANDAID_KEY_MAP_REVERSE

    custom_params: dict[str, str] = {}
    bandaid_keys = {"cap", "cap-sha256", "bap", "policy", "realm", "sig"}

    # Split on spaces, then look for key="value" or key=value patterns
    parts = svcb_text.split()
    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()

        # Normalize keyNNNNN to string name
        if key in BANDAID_KEY_MAP_REVERSE:
            key = BANDAID_KEY_MAP_REVERSE[key]

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


def _build_index_tasks(
    index_entries: list[Any],
    protocol: Protocol | None,
    query_fn: Any,
) -> list[Any]:
    """Build async tasks from index entries, filtering by protocol."""
    tasks = []
    for entry in index_entries:
        try:
            entry_protocol = Protocol(entry.protocol.lower())
        except ValueError:
            continue
        if protocol and entry_protocol != protocol:
            continue
        tasks.append(query_fn(entry.name, entry_protocol))
    return tasks


def _collect_agent_results(results: list[Any]) -> list[AgentRecord]:
    """Filter asyncio.gather results for successful AgentRecord instances."""
    return [r for r in results if isinstance(r, AgentRecord)]


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

    index_entries = await read_index_via_dns(domain)

    sem = asyncio.Semaphore(20)

    async def _query_with_sem(name: str, proto: Protocol) -> AgentRecord | None:
        async with sem:
            return await _query_single_agent(domain, name, proto)

    if index_entries:
        logger.debug(
            "Using TXT index for discovery",
            domain=domain,
            entry_count=len(index_entries),
        )
        tasks = _build_index_tasks(index_entries, protocol, _query_with_sem)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return _collect_agent_results(results)

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

    tasks = []
    for proto in protocols_to_try:
        for agent_name in common_names:
            tasks.append(_query_with_sem(agent_name, proto))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return _collect_agent_results(results)


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


def _enrich_from_http_index(agent: AgentRecord, http_agent: HttpIndexAgent) -> None:
    """Merge HTTP index metadata into a DNS-discovered agent record."""
    if http_agent.description:
        agent.description = http_agent.description
    if (
        http_agent.capability
        and http_agent.capability.modality
        and http_agent.capability.modality not in agent.use_cases
    ):
        agent.use_cases.append(f"modality:{http_agent.capability.modality}")

    if http_agent.endpoint and not agent.endpoint_override:
        parsed = urlparse(http_agent.endpoint)
        if parsed.path and parsed.path != "/":
            agent.endpoint_override = http_agent.endpoint
            agent.endpoint_source = "http_index"
            logger.debug(
                "Merged HTTP index endpoint path",
                agent=agent.name,
                endpoint=http_agent.endpoint,
            )


async def _process_http_agent(
    http_agent: HttpIndexAgent,
    domain: str,
    protocol: Protocol | None,
    name: str | None,
) -> AgentRecord | None:
    """Process a single HTTP index entry: parse FQDN, filter, resolve via DNS."""
    if name and http_agent.name != name:
        return None

    dns_agent_name, fqdn_protocol_str = _parse_fqdn(http_agent.fqdn)
    if not dns_agent_name or not fqdn_protocol_str:
        logger.debug(
            "Cannot parse FQDN from HTTP index entry",
            agent=http_agent.name,
            fqdn=http_agent.fqdn,
        )
        return None

    try:
        agent_protocol = Protocol(fqdn_protocol_str.lower())
    except ValueError:
        logger.debug(
            "Unknown protocol in FQDN",
            agent=http_agent.name,
            fqdn=http_agent.fqdn,
            protocol=fqdn_protocol_str,
        )
        return None

    if protocol and agent_protocol != protocol:
        return None

    agent = await _query_single_agent(domain, dns_agent_name, agent_protocol)

    if agent:
        _enrich_from_http_index(agent, http_agent)
        return agent

    logger.debug(
        "DNS lookup failed for HTTP index agent, using HTTP data only",
        agent=http_agent.name,
        fqdn=http_agent.fqdn,
    )
    return _http_agent_to_record(http_agent, domain, dns_agent_name, agent_protocol)


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
    http_agents = await fetch_http_index_or_empty(domain)

    if not http_agents:
        logger.debug("No agents found in HTTP index", domain=domain)
        return []

    logger.debug(
        "HTTP index fetched",
        domain=domain,
        agent_count=len(http_agents),
    )

    agents: list[AgentRecord] = []
    for http_agent in http_agents:
        agent = await _process_http_agent(http_agent, domain, protocol, name)
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


async def _enrich_agents_with_endpoint_paths(agents: list[AgentRecord]) -> None:
    """
    Enrich discovered agents with data from .well-known/agent.json (A2A Agent Card).

    For agents without an endpoint_override, fetches .well-known/agent.json
    from their target host and:
    1. Extracts protocol-specific endpoint path (e.g., endpoints.mcp = "/mcp")
    2. Stores the full A2AAgentCard on the agent for skills, auth, etc.

    Modifies agents in place. Failures are silently skipped.
    """
    # Only enrich agents that don't already have an endpoint_override
    agents_to_enrich = [a for a in agents if not a.endpoint_override]
    if not agents_to_enrich:
        return

    # Deduplicate by target_host to avoid redundant fetches
    hosts_to_agents: dict[str, list[AgentRecord]] = {}
    for agent in agents_to_enrich:
        hosts_to_agents.setdefault(agent.target_host, []).append(agent)

    # Fetch .well-known/agent.json concurrently for all unique hosts
    async def _fetch_and_enrich(host: str, host_agents: list[AgentRecord]) -> None:
        # Use typed A2AAgentCard fetcher
        card = await fetch_agent_card(f"https://{host}")
        if not card:
            return

        for agent in host_agents:
            # Store the full agent card for downstream use
            agent.agent_card = card

            # Extract endpoint path from card metadata if available
            endpoints = card.metadata.get("endpoints")
            if isinstance(endpoints, dict):
                protocol_key = agent.protocol.value  # "mcp", "a2a", "https"
                path = endpoints.get(protocol_key)
                if path and isinstance(path, str):
                    # Construct full endpoint URL with path
                    agent.endpoint_override = f"https://{agent.target_host}:{agent.port}{path}"
                    agent.endpoint_source = "dns_svcb_enriched"
                    logger.debug(
                        "Enriched agent endpoint from .well-known/agent.json",
                        agent=agent.name,
                        endpoint=agent.endpoint_override,
                        path=path,
                    )

            logger.debug(
                "Attached A2A Agent Card to agent",
                agent=agent.name,
                card_name=card.name,
                skills_count=len(card.skills),
            )

    await asyncio.gather(
        *[_fetch_and_enrich(host, host_agents) for host, host_agents in hosts_to_agents.items()],
        return_exceptions=True,
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


async def _verify_agent_signatures(
    agents: list[AgentRecord],
    domain: str,
    dnssec_validated: bool,
) -> None:
    """
    Verify JWS signatures on agents that have sig parameter but no DNSSEC.

    For each agent:
    - If DNSSEC validated: skip (stronger verification already done)
    - If has sig parameter: verify against domain's JWKS
    - Log warnings for invalid/missing signatures but don't remove agents

    Args:
        agents: List of agents to verify (modified in place with verification status)
        domain: Domain to fetch JWKS from
        dnssec_validated: Whether DNSSEC validation passed
    """
    if dnssec_validated:
        logger.debug("DNSSEC validated, skipping JWS verification")
        return

    # Find agents with signatures to verify
    agents_with_sig = [a for a in agents if a.sig]

    if not agents_with_sig:
        logger.debug("No agents with JWS signatures to verify")
        return

    logger.info(
        "Verifying JWS signatures",
        agents_count=len(agents_with_sig),
        domain=domain,
    )

    from dns_aid.core.jwks import verify_record_signature

    for agent in agents_with_sig:
        try:
            is_valid, payload = await verify_record_signature(domain, agent.sig)

            if is_valid:
                logger.info(
                    "JWS signature verified",
                    agent=agent.name,
                    fqdn=agent.fqdn,
                )
                # Could add a verified flag to AgentRecord in future
            else:
                logger.warning(
                    "JWS signature verification failed",
                    agent=agent.name,
                    fqdn=agent.fqdn,
                )
        except Exception as e:
            logger.warning(
                "JWS verification error",
                agent=agent.name,
                error=str(e),
            )
