# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Shared agent invocation functions for A2A and MCP protocols.

This module is the single source of truth for building protocol payloads
and invoking remote agents. Both the CLI and MCP server delegate here
instead of implementing their own HTTP + payload logic.

When the SDK is installed, invocations go through AgentClient for automatic
telemetry capture. Otherwise, a lightweight httpx fallback is used.

Example::

    from dns_aid.core.invoke import send_a2a_message, call_mcp_tool

    result = await send_a2a_message("https://agent.example.com", "Hello")
    result = await call_mcp_tool("https://mcp.example.com/mcp", "analyze", {"domain": "x.com"})
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional SDK import — enables telemetry when installed
# ---------------------------------------------------------------------------

_sdk_available = False
try:
    from dns_aid.sdk import AgentClient, SDKConfig

    _sdk_available = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class InvokeResult:
    """Protocol-agnostic invocation result.

    Returned by all public functions in this module. Both CLI and MCP server
    consume this to build their own output format.
    """

    success: bool
    data: dict | str | list | None = None
    error: str | None = None
    telemetry: dict | None = field(default=None)


# ---------------------------------------------------------------------------
# Pure utility functions (no I/O)
# ---------------------------------------------------------------------------


def normalize_endpoint(url: str) -> str:
    """Normalize an endpoint URL, adding https:// if missing."""
    url = url.rstrip("/")
    if not url.startswith("http"):
        url = f"https://{url}"
    return url


def build_a2a_message_params(text: str) -> dict:
    """Build the ``params`` dict for an A2A ``message/send`` request.

    Returns only the params — the JSON-RPC 2.0 envelope (jsonrpc, method, id)
    is added by the SDK's A2AProtocolHandler or by ``_invoke_raw_a2a``.
    """
    return {
        "message": {
            "messageId": str(uuid.uuid4()),
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
        }
    }


def extract_a2a_response_text(data: dict) -> str | None:
    """Extract human-readable text from an A2A JSON-RPC response.

    Handles multiple response formats:
    - ``result.artifacts[].parts[].text`` (standard A2A spec)
    - ``result.parts[].text`` (simplified)
    - ``result.content[].text`` (alternative implementations)

    Joins multiple text parts with newlines.
    """
    result = data.get("result", {})

    # Try artifacts[].parts[].text (standard A2A)
    artifacts = result.get("artifacts", [])
    if artifacts:
        texts: list[str] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            for part in artifact.get("parts", []):
                if not isinstance(part, dict):
                    continue
                if part.get("kind") == "text" or "text" in part:
                    texts.append(part.get("text") or "")
        if texts:
            return "\n".join(texts)

    # Try result.parts[].text
    parts = result.get("parts", [])
    if parts:
        texts = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if part.get("kind") == "text" or "text" in part:
                texts.append(part.get("text") or "")
        if texts:
            return "\n".join(texts)

    # Try result.content[].text (some implementations)
    content = result.get("content", [])
    if content:
        texts = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                texts.append(item.get("text") or "")
            elif isinstance(item, str):
                texts.append(item)
        if texts:
            return "\n".join(texts)

    return None


def extract_mcp_content(result: dict) -> dict | str | list | None:
    """Extract meaningful content from an MCP JSON-RPC result.

    Handles:
    - ``result.result.content[0].text`` — MCP content array pattern
    - ``result.result`` — raw result passthrough
    """
    rpc_result = result.get("result")
    if rpc_result is None:
        return None

    # MCP content array pattern
    content = rpc_result.get("content") if isinstance(rpc_result, dict) else None
    if content and isinstance(content, list) and len(content) > 0:
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    return rpc_result


# ---------------------------------------------------------------------------
# MCP endpoint path resolution
# ---------------------------------------------------------------------------

# DNS SVCB records give host:port but not the path where the MCP JSON-RPC
# handler lives (could be /mcp, /api/mcp, etc.). This helper discovers the
# correct path via /.well-known/agent.json or falls back to the /mcp convention.

_MCP_CONVENTIONAL_PATH = "/mcp"


async def resolve_mcp_endpoint(endpoint: str, *, timeout: float = 5.0) -> str:
    """Resolve the full MCP JSON-RPC endpoint URL including path.

    DNS SVCB records provide only host:port. The actual MCP handler may live
    at a sub-path (e.g. ``/mcp``). This function discovers the correct path:

    1. If *endpoint* already contains a non-root path → return as-is.
    2. Fetch ``/.well-known/agent.json`` → use ``endpoints.mcp`` if present.
    3. Fallback → append ``/mcp`` (the emerging convention).

    Args:
        endpoint: Base endpoint URL, typically from DNS discovery.
        timeout: HTTP timeout for the agent.json probe.

    Returns:
        Fully-qualified MCP endpoint URL with path.
    """
    base = normalize_endpoint(endpoint)
    parsed = urlparse(base)

    # Already has a meaningful path — caller knows what they're doing
    if parsed.path and parsed.path not in ("/", ""):
        return base

    # Try /.well-known/agent.json for the authoritative path
    agent_json_url = f"{base}/.well-known/agent.json"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
            resp = await client.get(agent_json_url)
        if resp.status_code == 200:
            data = resp.json()
            endpoints = data.get("endpoints", {})
            if isinstance(endpoints, dict):
                mcp_path = endpoints.get("mcp")
                if mcp_path and isinstance(mcp_path, str):
                    # Absolute path from agent.json
                    resolved = (
                        f"{base}{mcp_path}" if mcp_path.startswith("/") else f"{base}/{mcp_path}"
                    )
                    logger.debug("resolve_mcp.from_agent_json", path=mcp_path, url=resolved)
                    return resolved
    except Exception:
        pass  # agent.json unavailable — fall through to convention

    # Convention fallback
    logger.debug("resolve_mcp.convention_fallback", path=_MCP_CONVENTIONAL_PATH)
    return f"{base}{_MCP_CONVENTIONAL_PATH}"


# ---------------------------------------------------------------------------
# Shared helper: build AgentRecord from endpoint URL
# ---------------------------------------------------------------------------


def _build_agent_record_from_endpoint(endpoint: str, protocol: str = "mcp"):
    """Build a synthetic AgentRecord from an endpoint URL for SDK telemetry."""
    from dns_aid.core.models import AgentRecord, Protocol

    parsed = urlparse(endpoint)
    hostname = parsed.hostname or "unknown"
    port = parsed.port or 443

    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    name = parts[0] if parts[0] not in ("www", "api", "mcp", "a2a") else "agent"

    proto_map = {"mcp": Protocol.MCP, "a2a": Protocol.A2A, "https": Protocol.HTTPS}

    # Preserve the full URL (including path) as endpoint_override so that
    # agent.endpoint_url returns the complete URL, not just host:port.
    endpoint_override = endpoint if parsed.path and parsed.path != "/" else None

    return AgentRecord(
        name=name,
        domain=domain,
        protocol=proto_map.get(protocol, Protocol.MCP),
        target_host=hostname,
        port=port,
        endpoint_override=endpoint_override,
    )


# ---------------------------------------------------------------------------
# SDK invocation path (with telemetry)
# ---------------------------------------------------------------------------


async def _invoke_via_sdk(
    endpoint: str,
    protocol: str,
    method: str,
    arguments: dict | None,
    timeout: float,
    caller_id: str,
) -> InvokeResult:
    """Invoke an agent through the SDK for automatic telemetry capture.

    Wraps the SDK client call and normalizes the result into an InvokeResult.
    All exceptions are caught and returned as failed InvokeResults to maintain
    consistency with the raw httpx fallback path.
    """
    import os

    try:
        agent = _build_agent_record_from_endpoint(endpoint, protocol=protocol)
        config = SDKConfig(
            timeout_seconds=timeout,
            console_signals=False,
            caller_id=caller_id,
            http_push_url=os.getenv("DNS_AID_SDK_HTTP_PUSH_URL"),
        )

        async with AgentClient(config=config) as client:
            result = await client.invoke(
                agent,
                method=method,
                arguments=arguments,
                timeout=timeout,
            )

        telemetry = {
            "latency_ms": round(result.signal.invocation_latency_ms, 2),
            "status": result.signal.status.value,
        }

        if result.success:
            return InvokeResult(success=True, data=result.data, telemetry=telemetry)
        else:
            # Build a meaningful error from signal + data
            error_msg = str(result.data) if result.data else ""
            if not error_msg.strip() or error_msg in ("None", "{}", "False"):
                error_msg = f"Invocation failed (status: {result.signal.status.value})"
            return InvokeResult(success=False, error=error_msg, telemetry=telemetry)

    except httpx.TimeoutException:
        return InvokeResult(
            success=False,
            error=f"Agent did not respond within {timeout}s (SDK path).",
        )
    except httpx.ConnectError as e:
        return InvokeResult(
            success=False,
            error=f"Connection failed: {e}",
        )
    except Exception as e:
        error_msg = str(e).strip()
        if not error_msg:
            error_msg = f"SDK invocation failed: {type(e).__name__}"
        return InvokeResult(success=False, error=error_msg)


# ---------------------------------------------------------------------------
# Raw httpx invocation paths (no SDK / no telemetry)
# ---------------------------------------------------------------------------


async def _invoke_raw_a2a(endpoint: str, message: str, timeout: float) -> InvokeResult:
    """Send an A2A message via raw httpx (no telemetry)."""
    url = normalize_endpoint(endpoint)
    params = build_a2a_message_params(message)

    a2a_request = {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": params,
        "id": str(uuid.uuid4()),
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            resp = await client.post(
                url,
                json=a2a_request,
                headers={"Content-Type": "application/json"},
            )

        if resp.status_code == 403:
            return InvokeResult(
                success=False,
                error="Agent requires authentication (HTTP 403). "
                "The endpoint is reachable but blocks unauthenticated requests.",
            )

        if resp.status_code >= 400:
            return InvokeResult(
                success=False,
                error=f"Agent returned HTTP {resp.status_code}: {resp.text[:500]}",
            )

        data = resp.json()
        return InvokeResult(success=True, data=data)

    except httpx.TimeoutException:
        return InvokeResult(
            success=False,
            error=f"Agent did not respond within {timeout} seconds.",
        )
    except httpx.ConnectError:
        return InvokeResult(
            success=False,
            error=f"Could not connect to agent at {endpoint}.",
        )
    except Exception as e:
        return InvokeResult(success=False, error=f"Unexpected error: {e}")


async def _invoke_raw_mcp(
    endpoint: str,
    method: str,
    params: dict | None,
    timeout: float,
) -> InvokeResult:
    """Send an MCP JSON-RPC request via raw httpx (no telemetry)."""
    url = normalize_endpoint(endpoint)

    mcp_request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": 1,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                url,
                json=mcp_request,
                headers={"Content-Type": "application/json"},
            )

        if resp.status_code != 200:
            return InvokeResult(
                success=False,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )

        result = resp.json()

        # Check for JSON-RPC error
        if "error" in result:
            rpc_error = result["error"]
            msg = (
                rpc_error.get("message", str(rpc_error))
                if isinstance(rpc_error, dict)
                else str(rpc_error)
            )
            return InvokeResult(success=False, error=msg)

        return InvokeResult(success=True, data=result)

    except httpx.TimeoutException:
        return InvokeResult(
            success=False,
            error=f"Timeout connecting to {endpoint}",
        )
    except httpx.ConnectError as e:
        return InvokeResult(
            success=False,
            error=f"Connection failed: {e}",
        )
    except Exception as e:
        return InvokeResult(success=False, error=str(e))


# ---------------------------------------------------------------------------
# Agent card + discovery resolution
# ---------------------------------------------------------------------------


@dataclass
class ResolvedAgent:
    """Result of resolving an A2A agent endpoint via discovery + agent card."""

    endpoint: str
    agent_name: str | None = None
    agent_description: str | None = None
    skills: list[str] = field(default_factory=list)
    resolved_via: str = "direct"  # "direct", "agent_card", "dns_discover"


async def resolve_a2a_endpoint(
    endpoint: str | None = None,
    *,
    domain: str | None = None,
    name: str | None = None,
) -> ResolvedAgent:
    """Resolve an A2A agent's canonical endpoint.

    Resolution chain (most to least authoritative):
    1. If ``domain`` + ``name`` given: DNS discover → get endpoint from SVCB
    2. Fetch agent card from ``/.well-known/agent-card.json`` → use ``card.url``
    3. Fall back to the raw ``endpoint`` as-is

    The agent card provides the canonical URL the agent actually listens on,
    preventing LLM hallucination of paths like ``/api`` or ``/v1``.
    """
    from dns_aid.core.a2a_card import fetch_agent_card

    # Path 1: DNS discovery — domain + name → endpoint
    if domain and name:
        try:
            from dns_aid.core.discoverer import discover

            result = await discover(domain=domain, protocol="a2a", name=name)
            if result.agents:
                agent = result.agents[0]
                discovered_endpoint = agent.endpoint_url
                logger.debug(
                    "resolve.dns_discovered",
                    domain=domain,
                    name=name,
                    endpoint=discovered_endpoint,
                )

                # Try to fetch agent card for metadata (name, skills, description).
                # Use card.url ONLY if it shares the same host as the DNS endpoint,
                # otherwise it may be an internal URL (e.g., Bedrock AgentCore runtime)
                # that isn't publicly reachable via the same proxy/CDN.
                card = await fetch_agent_card(discovered_endpoint, timeout=5.0)
                if card:
                    card_host = urlparse(card.url).hostname if card.url else None
                    dns_host = urlparse(discovered_endpoint).hostname
                    use_card_url = card_host == dns_host if card_host else False
                    if not use_card_url and card_host:
                        logger.debug(
                            "resolve.card_host_mismatch",
                            card_host=card_host,
                            dns_host=dns_host,
                        )

                    return ResolvedAgent(
                        endpoint=card.url if use_card_url else discovered_endpoint,
                        agent_name=card.name,
                        agent_description=card.description,
                        skills=[s.name for s in card.skills],
                        resolved_via="dns_discover+agent_card",
                    )

                return ResolvedAgent(
                    endpoint=discovered_endpoint,
                    agent_name=agent.name,
                    resolved_via="dns_discover",
                )
            else:
                logger.warning("resolve.no_agents_found", domain=domain, name=name)
        except Exception as exc:
            logger.warning("resolve.dns_discovery_failed", domain=domain, name=name, error=str(exc))

    if not endpoint:
        return ResolvedAgent(
            endpoint="",
            resolved_via="error",
        )

    # Path 2: Fetch agent card from the given endpoint for metadata.
    # Use card.url only if it matches the host we were given.
    normalized = normalize_endpoint(endpoint)
    try:
        card = await fetch_agent_card(normalized, timeout=5.0)
        if card:
            card_host = urlparse(card.url).hostname if card.url else None
            given_host = urlparse(normalized).hostname
            use_card_url = card_host == given_host if card_host else False

            return ResolvedAgent(
                endpoint=card.url if use_card_url else normalized,
                agent_name=card.name,
                agent_description=card.description,
                skills=[s.name for s in card.skills],
                resolved_via="agent_card",
            )
    except Exception:
        pass  # Fall through to direct endpoint

    # Path 3: Use endpoint as-is
    return ResolvedAgent(endpoint=normalized, resolved_via="direct")


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------


async def send_a2a_message(
    endpoint: str | None = None,
    message: str = "",
    *,
    domain: str | None = None,
    name: str | None = None,
    timeout: float = 25.0,
    caller_id: str = "dns-aid",
) -> InvokeResult:
    """Send a message to an A2A agent.

    Resolves the agent's canonical endpoint before sending, using:
    1. DNS discovery (if ``domain`` + ``name`` given)
    2. Agent card fetch (``/.well-known/agent-card.json``) for canonical URL
    3. Raw endpoint as fallback

    Then tries the SDK path (for telemetry), falling back to raw httpx.

    Args:
        endpoint: A2A agent endpoint URL (optional if domain+name given).
        message: Text message to send.
        domain: Domain to discover agent on (e.g., "ai.infoblox.com").
        name: Agent name to discover (e.g., "security-analyzer").
        timeout: Request timeout in seconds.
        caller_id: Identifies the caller for telemetry.

    Returns:
        InvokeResult with the agent's response data. When agent card is
        available, ``data`` includes ``agent_info`` with name, description,
        and skills.
    """
    # Resolve canonical endpoint
    resolved = await resolve_a2a_endpoint(endpoint, domain=domain, name=name)
    target = resolved.endpoint

    if not target:
        return InvokeResult(
            success=False,
            error="No endpoint provided and DNS discovery failed. "
            "Provide either endpoint URL or domain+name.",
        )

    # Build agent info metadata from resolution
    agent_info: dict[str, str | list[str]] = {}
    if resolved.agent_name:
        agent_info["name"] = resolved.agent_name
    if resolved.agent_description:
        agent_info["description"] = resolved.agent_description
    if resolved.skills:
        agent_info["skills"] = resolved.skills
    agent_info["resolved_via"] = resolved.resolved_via
    if endpoint and target != normalize_endpoint(endpoint):
        agent_info["original_endpoint"] = endpoint
        agent_info["canonical_endpoint"] = target

    # Invoke the agent
    if _sdk_available:
        params = build_a2a_message_params(message)
        result = await _invoke_via_sdk(
            target,
            protocol="a2a",
            method="message/send",
            arguments=params,
            timeout=timeout,
            caller_id=caller_id,
        )
    else:
        result = await _invoke_raw_a2a(target, message, timeout)

    # Post-process: extract text from response
    if result.success and isinstance(result.data, dict):
        text = extract_a2a_response_text(result.data)
        if text:
            result.data = {"response_text": text, "raw": result.data}
    if agent_info:
        if isinstance(result.data, dict):
            result.data["agent_info"] = agent_info
        else:
            result.data = {"response_text": result.data, "agent_info": agent_info}
    return result


async def call_mcp_tool(
    endpoint: str,
    tool_name: str,
    arguments: dict | None = None,
    *,
    timeout: float = 30.0,
    caller_id: str = "dns-aid",
) -> InvokeResult:
    """Call a tool on a remote MCP agent.

    Automatically resolves the MCP endpoint path if only host:port is given
    (common with DNS-discovered agents whose SVCB records lack path info).

    Args:
        endpoint: MCP agent endpoint URL.
        tool_name: Name of the tool to call.
        arguments: Arguments to pass to the tool.
        timeout: Request timeout in seconds.
        caller_id: Identifies the caller for telemetry.

    Returns:
        InvokeResult with the tool's response.
    """
    endpoint = await resolve_mcp_endpoint(endpoint)
    mcp_args = {"name": tool_name, "arguments": arguments or {}}

    if _sdk_available:
        result = await _invoke_via_sdk(
            endpoint,
            protocol="mcp",
            method="tools/call",
            arguments=mcp_args,
            timeout=timeout,
            caller_id=caller_id,
        )
        return result

    result = await _invoke_raw_mcp(endpoint, "tools/call", mcp_args, timeout)
    # Post-process: extract content from raw JSON-RPC result
    if result.success and isinstance(result.data, dict):
        result.data = extract_mcp_content(result.data)
    return result


async def list_mcp_tools(
    endpoint: str,
    *,
    timeout: float = 30.0,
    caller_id: str = "dns-aid",
) -> InvokeResult:
    """List available tools on a remote MCP agent.

    Automatically resolves the MCP endpoint path if only host:port is given.

    Args:
        endpoint: MCP agent endpoint URL.
        timeout: Request timeout in seconds.
        caller_id: Identifies the caller for telemetry.

    Returns:
        InvokeResult with ``data`` containing the tools list.
    """
    endpoint = await resolve_mcp_endpoint(endpoint)

    if _sdk_available:
        result = await _invoke_via_sdk(
            endpoint,
            protocol="mcp",
            method="tools/list",
            arguments=None,
            timeout=timeout,
            caller_id=caller_id,
        )
        # Normalize tools list from SDK response
        if result.success:
            data = result.data
            if isinstance(data, dict):
                result.data = data.get("tools", [])
            elif not isinstance(data, list):
                result.data = []
        return result

    result = await _invoke_raw_mcp(endpoint, "tools/list", {}, timeout)
    # Extract tools list from raw JSON-RPC result
    if result.success and isinstance(result.data, dict):
        rpc_result = result.data.get("result", {})
        result.data = rpc_result.get("tools", []) if isinstance(rpc_result, dict) else []
    return result
