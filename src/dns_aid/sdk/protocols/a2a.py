# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
A2A (Agent-to-Agent) protocol handler.

Implements Google's A2A protocol — HTTP POST with JSON payload.
"""

from __future__ import annotations

import json
import time

import httpx

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.base import ProtocolHandler, RawResponse


class A2AProtocolHandler(ProtocolHandler):
    """Handles A2A agent invocations over HTTPS."""

    @property
    def protocol_name(self) -> str:
        return "a2a"

    async def invoke(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str | None,
        arguments: dict | None,
        timeout: float,
    ) -> RawResponse:
        """
        Send an A2A request to an agent.

        A2A uses HTTP POST with a JSON body containing the task/method.
        """
        payload = {
            "method": method or "task",
            **(arguments or {}),
        }

        start = time.perf_counter()

        try:
            response = await client.post(
                endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            elapsed = (time.perf_counter() - start) * 1000

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

        response_size = len(response.content)
        cost_units = _parse_float_header(response.headers, "x-cost-units")
        cost_currency = response.headers.get("x-cost-currency")

        if response.status_code >= 400:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                http_status_code=response.status_code,
                error_type="HTTPError",
                error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                invocation_latency_ms=elapsed,
                ttfb_ms=elapsed,
                response_size_bytes=response_size,
                cost_units=cost_units,
                cost_currency=cost_currency,
                headers=dict(response.headers),
            )

        try:
            data = response.json()
        except json.JSONDecodeError:
            data = response.text

        return RawResponse(
            success=True,
            status=InvocationStatus.SUCCESS,
            data=data,
            http_status_code=response.status_code,
            invocation_latency_ms=elapsed,
            ttfb_ms=elapsed,
            response_size_bytes=response_size,
            cost_units=cost_units,
            cost_currency=cost_currency,
            headers=dict(response.headers),
        )


def _parse_float_header(headers: httpx.Headers, name: str) -> float | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None
