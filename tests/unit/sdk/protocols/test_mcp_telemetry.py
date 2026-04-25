# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MCP transport telemetry capture (event-hook based)."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from dns_aid.sdk.protocols._mcp_telemetry import (
    _make_telemetry_factory,
    _TelemetryCapture,
)


@pytest.mark.asyncio
async def test_request_hook_records_start_time() -> None:
    capture = _TelemetryCapture()
    request = httpx.Request("POST", "https://example.com/mcp")

    assert capture.start_perf is None
    await capture.on_request(request)
    assert capture.start_perf is not None
    assert capture.start_perf > 0


@pytest.mark.asyncio
async def test_request_hook_resets_per_request_fields() -> None:
    capture = _TelemetryCapture(
        ttfb_perf=1.0,
        total_perf=2.0,
        response_size_bytes=100,
        cost_units=0.5,
        cost_currency="USD",
        tls_version="TLSv1.2",
        http_status_code=500,
        headers={"old-key": "old-value"},
    )
    request = httpx.Request("POST", "https://example.com/mcp")

    await capture.on_request(request)

    assert capture.ttfb_perf is None
    assert capture.total_perf is None
    assert capture.response_size_bytes == 0
    assert capture.cost_units is None
    assert capture.cost_currency is None
    assert capture.tls_version is None
    assert capture.http_status_code is None
    assert capture.headers == {}


@pytest.mark.asyncio
async def test_response_hook_records_status_and_headers() -> None:
    capture = _TelemetryCapture(start_perf=0.0)
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(
        200,
        request=request,
        headers={"Content-Type": "application/json", "Server": "nginx"},
        content=b'{"result": "ok"}',
    )

    await capture.on_response(response)

    assert capture.http_status_code == 200
    # Headers stored with lowercased keys
    assert capture.headers["content-type"] == "application/json"
    assert capture.headers["server"] == "nginx"
    assert capture.ttfb_perf is not None
    assert capture.total_perf is not None
    assert capture.response_size_bytes == len(b'{"result": "ok"}')


@pytest.mark.asyncio
async def test_response_hook_parses_cost_headers() -> None:
    capture = _TelemetryCapture(start_perf=0.0)
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(
        200,
        request=request,
        headers={"X-Cost-Units": "0.05", "X-Cost-Currency": "USD"},
        content=b"{}",
    )

    await capture.on_response(response)

    assert capture.cost_units == 0.05
    assert capture.cost_currency == "USD"


@pytest.mark.asyncio
async def test_response_hook_handles_missing_cost_headers() -> None:
    capture = _TelemetryCapture(start_perf=0.0)
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(200, request=request, content=b"{}")

    await capture.on_response(response)

    assert capture.cost_units is None
    assert capture.cost_currency is None


@pytest.mark.asyncio
async def test_response_hook_handles_malformed_cost_units() -> None:
    capture = _TelemetryCapture(start_perf=0.0)
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(
        200,
        request=request,
        headers={"X-Cost-Units": "not-a-number"},
        content=b"{}",
    )

    await capture.on_response(response)

    assert capture.cost_units is None


@pytest.mark.asyncio
async def test_response_hook_extracts_tls_version_when_available() -> None:
    """Verify TLS version extraction works when network_stream extension exposes ssl_object."""
    capture = _TelemetryCapture(start_perf=0.0)
    request = httpx.Request("POST", "https://example.com/mcp")

    ssl_object = MagicMock()
    ssl_object.version.return_value = "TLSv1.3"
    network_stream = MagicMock()
    network_stream.get_extra_info.return_value = ssl_object

    response = httpx.Response(200, request=request, content=b"{}")
    response.extensions["network_stream"] = network_stream

    await capture.on_response(response)

    assert capture.tls_version == "TLSv1.3"
    network_stream.get_extra_info.assert_called_once_with("ssl_object")


@pytest.mark.asyncio
async def test_response_hook_handles_missing_tls_info_gracefully() -> None:
    capture = _TelemetryCapture(start_perf=0.0)
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(200, request=request, content=b"{}")
    # No network_stream extension set.

    await capture.on_response(response)

    assert capture.tls_version is None


@pytest.mark.asyncio
async def test_invocation_latency_ms_computed_after_full_lifecycle() -> None:
    capture = _TelemetryCapture()
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(200, request=request, content=b"{}")

    assert capture.invocation_latency_ms is None

    await capture.on_request(request)
    await capture.on_response(response)

    latency = capture.invocation_latency_ms
    assert latency is not None
    assert latency >= 0


@pytest.mark.asyncio
async def test_ttfb_ms_computed_after_response_headers_received() -> None:
    capture = _TelemetryCapture()
    request = httpx.Request("POST", "https://example.com/mcp")
    response = httpx.Response(200, request=request, content=b"{}")

    assert capture.ttfb_ms is None

    await capture.on_request(request)
    await capture.on_response(response)

    ttfb = capture.ttfb_ms
    assert ttfb is not None
    assert ttfb >= 0


def test_make_telemetry_factory_returns_async_client() -> None:
    capture = _TelemetryCapture()
    factory = _make_telemetry_factory(capture)

    client = factory(headers=None, timeout=None, auth=None)
    assert isinstance(client, httpx.AsyncClient)


def test_factory_attaches_event_hooks_for_capture() -> None:
    capture = _TelemetryCapture()
    factory = _make_telemetry_factory(capture)

    client = factory(headers={"X-Test": "1"}, timeout=httpx.Timeout(5.0), auth=None)

    request_hooks = client.event_hooks.get("request", [])
    response_hooks = client.event_hooks.get("response", [])
    assert capture.on_request in request_hooks
    assert capture.on_response in response_hooks


def test_factory_propagates_headers_and_auth() -> None:
    capture = _TelemetryCapture()
    factory = _make_telemetry_factory(capture)

    auth = MagicMock(spec=httpx.Auth)
    client = factory(
        headers={"X-Caller": "test.example.com"},
        timeout=httpx.Timeout(10.0),
        auth=auth,
    )

    assert client.headers.get("x-caller") == "test.example.com"
    assert client.auth is auth
