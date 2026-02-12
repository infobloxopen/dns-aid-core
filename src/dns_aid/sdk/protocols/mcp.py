# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) handler.

Implements JSON-RPC 2.0 over HTTPS for MCP agent invocation,
with latency measurement and cost header extraction.
"""

from __future__ import annotations

import json
import time

import httpx

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.base import ProtocolHandler, RawResponse


class MCPProtocolHandler(ProtocolHandler):
    """Handles MCP JSON-RPC 2.0 invocations over HTTPS."""

    @property
    def protocol_name(self) -> str:
        return "mcp"

    async def invoke(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str | None,
        arguments: dict | None,
        timeout: float,
    ) -> RawResponse:
        """
        Send a JSON-RPC 2.0 request to an MCP agent.

        The MCP protocol uses JSON-RPC with methods like:
        - "tools/list" — enumerate available tools
        - "tools/call" — call a specific tool (arguments.name + arguments.arguments)

        """
        mcp_method = method or "tools/list"
        params = arguments or {}

        rpc_request = {
            "jsonrpc": "2.0",
            "method": mcp_method,
            "params": params,
            "id": 1,
        }

        start = time.perf_counter()
        ttfb_ms: float | None = None

        try:
            response = await client.post(
                endpoint,
                json=rpc_request,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            ttfb_ms = (time.perf_counter() - start) * 1000
            invocation_latency_ms = ttfb_ms  # For simple request/response, TTFB ~ total

        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.TIMEOUT,
                error_type="TimeoutError",
                error_message=f"Timeout after {timeout}s connecting to {endpoint}",
                invocation_latency_ms=elapsed,
            )
        except httpx.ConnectError as e:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.REFUSED,
                error_type="ConnectError",
                error_message=str(e),
                invocation_latency_ms=elapsed,
            )
        except httpx.HTTPError as e:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                error_type=type(e).__name__,
                error_message=str(e),
                invocation_latency_ms=elapsed,
            )

        # Extract cost from response headers (convention: X-Cost-Units, X-Cost-Currency)
        cost_units = _parse_float_header(response.headers, "x-cost-units")
        cost_currency = response.headers.get("x-cost-currency")

        # Extract TLS version
        tls_version = _extract_tls_version(response)

        # Response size
        response_size_bytes = len(response.content)

        # Parse HTTP error status
        if response.status_code != 200:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                http_status_code=response.status_code,
                error_type="HTTPError",
                error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=ttfb_ms,
                response_size_bytes=response_size_bytes,
                cost_units=cost_units,
                cost_currency=cost_currency,
                tls_version=tls_version,
                headers=dict(response.headers),
            )

        # Parse JSON-RPC response
        try:
            result = response.json()
        except json.JSONDecodeError as e:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                http_status_code=200,
                error_type="JSONDecodeError",
                error_message=f"Invalid JSON response: {e}",
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=ttfb_ms,
                response_size_bytes=response_size_bytes,
                tls_version=tls_version,
                headers=dict(response.headers),
            )

        # Check for JSON-RPC error
        if "error" in result:
            rpc_error = result["error"]
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                data=rpc_error,
                http_status_code=200,
                error_type="RPCError",
                error_message=rpc_error.get("message", str(rpc_error)),
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=ttfb_ms,
                response_size_bytes=response_size_bytes,
                cost_units=cost_units,
                cost_currency=cost_currency,
                tls_version=tls_version,
                headers=dict(response.headers),
            )

        # Extract content from MCP response
        data = _extract_mcp_content(result)

        return RawResponse(
            success=True,
            status=InvocationStatus.SUCCESS,
            data=data,
            http_status_code=200,
            invocation_latency_ms=invocation_latency_ms,
            ttfb_ms=ttfb_ms,
            response_size_bytes=response_size_bytes,
            cost_units=cost_units,
            cost_currency=cost_currency,
            tls_version=tls_version,
            headers=dict(response.headers),
        )


def _extract_mcp_content(result: dict) -> dict | str | list | None:
    """Extract meaningful content from MCP JSON-RPC result."""
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


def _parse_float_header(headers: httpx.Headers, name: str) -> float | None:
    """Parse a float value from a response header."""
    value = headers.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _extract_tls_version(response: httpx.Response) -> str | None:
    """Extract TLS version from the response's underlying connection, if available."""
    try:
        stream = response.stream
        if hasattr(stream, "_stream") and hasattr(stream._stream, "get_extra_info"):
            ssl_object = stream._stream.get_extra_info("ssl_object")
            if ssl_object:
                return ssl_object.version()
    except Exception:
        pass
    return None
